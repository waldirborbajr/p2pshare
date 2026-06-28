// p2pshare — ephemeral-key P2P file transfer, stdlib only
//
// Security model:
//   - Ephemeral ed25519 keypair per run (no key files).
//   - Mutual authentication: peers exchange public keys then each signs a
//     shared challenge derived from both keys (prevents replay).
//   - Session encryption: ed25519 seeds → X25519 scalars → ECDH →
//     HKDF-SHA256 → AES-256-GCM session key.
//   - File integrity: sender signs the entire file with ed25519;
//     receiver verifies the signature before writing to disk.
//
// Usage:
//   Listen (auto-negotiates role):  p2pshare -listen :4444
//   Send a file:                    p2pshare -connect host:4444 -send /path/to/file
//   Receive a file:                 p2pshare -connect host:4444 -recv
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ─── HKDF-SHA256 (no x/crypto dependency) ────────────────────────────────────

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	prev := []byte{}
	for i := byte(1); len(out) < length; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func deriveSessionKey(secret, info []byte) []byte {
	prk := hkdfExtract(nil, secret)
	return hkdfExpand(prk, info, 32)
}

// ─── Hash chain over file chunks ─────────────────────────────────────────────
//
// Instead of signing a single digest of the whole file, each chunk extends a
// running hash chain. This lets the receiver verify integrity incrementally,
// chunk by chunk, instead of only discovering corruption after the entire
// transfer completes. The chain is seeded with the declared file size so a
// chain computed for one transfer can't be replayed against another.

func chainGenesis(expectedSize uint64) []byte {
	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, expectedSize)
	h := sha256.New()
	h.Write([]byte("p2pshare-chain-genesis"))
	h.Write(sizeBuf)
	return h.Sum(nil)
}

func chainNext(prev, chunk []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(chunk)
	return h.Sum(nil)
}

// ─── ed25519 seed → X25519 scalar (RFC 8032 §5.1.5) ──────────────────────────

func ed25519SeedToX25519Scalar(seed []byte) []byte {
	h := sha512.Sum512(seed)
	s := make([]byte, 32)
	copy(s, h[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}

// ed25519PublicKeyToX25519 converts an ed25519 public key (compressed Edwards
// point) to a Curve25519 public key (Montgomery u-coordinate).
// Map: u = (1+y)/(1-y) mod p, where p = 2^255-19.
func ed25519PublicKeyToX25519(edPub []byte) ([]byte, error) {
	if len(edPub) != 32 {
		return nil, errors.New("invalid ed25519 public key length")
	}
	// Decode y from the compressed point (little-endian, ignore sign bit).
	yBytes := make([]byte, 32)
	copy(yBytes, edPub)
	yBytes[31] &= 0x7f

	// Reverse to big-endian for math/big.
	rev := make([]byte, 32)
	for i, b := range yBytes {
		rev[31-i] = b
	}

	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	y := new(big.Int).SetBytes(rev)

	one := big.NewInt(1)
	// u = (1+y) * modInverse(1-y, p) mod p
	num := new(big.Int).Add(one, y)
	num.Mod(num, p)
	den := new(big.Int).Sub(one, y)
	den.Mod(den, p)
	denInv := new(big.Int).ModInverse(den, p)
	if denInv == nil {
		return nil, errors.New("ed25519→x25519: modular inverse undefined")
	}
	u := new(big.Int).Mul(num, denInv)
	u.Mod(u, p)

	// Encode as 32-byte little-endian.
	uBE := u.Bytes()
	uLE := make([]byte, 32)
	for i, b := range uBE {
		uLE[len(uBE)-1-i] = b
	}
	return uLE, nil
}

// ─── AES-256-GCM framed connection ───────────────────────────────────────────
//
// Wire format per message: [4 bytes big-endian length][12-byte nonce][ciphertext+tag]

const maxFrameSize = 128 * 1024 * 1024 // 128 MiB

type secureConn struct {
	conn net.Conn
	aead cipher.AEAD
}

func newSecureConn(conn net.Conn, key []byte) (*secureConn, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &secureConn{conn: conn, aead: aead}, nil
}

func (sc *secureConn) sendMsg(plaintext []byte) error {
	nonce := make([]byte, sc.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	payload := sc.aead.Seal(nonce, nonce, plaintext, nil) // nonce||ct||tag
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := sc.conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := sc.conn.Write(payload)
	return err
}

func (sc *secureConn) recvMsg() ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(sc.conn, lenBuf); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf)
	if n > maxFrameSize {
		return nil, fmt.Errorf("frame size %d exceeds limit", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(sc.conn, payload); err != nil {
		return nil, err
	}
	ns := sc.aead.NonceSize()
	if len(payload) < ns {
		return nil, errors.New("payload shorter than nonce")
	}
	return sc.aead.Open(nil, payload[:ns], payload[ns:], nil)
}

// sendFile streams a file over the encrypted connection in chunks,
// then sends the ed25519 signature over the full file content.
// transferResult carries the fields the ledger needs after a transfer
// completes, so callers don't have to recompute or re-derive anything.
type transferResult struct {
	fileName       string
	fileSize       uint64
	chainHashFinal []byte
	role           string // "sender" or "receiver", filled in by the caller
	peerPubKey     ed25519.PublicKey
}

func (sc *secureConn) sendFile(path string, priv ed25519.PrivateKey) (transferResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return transferResult{}, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return transferResult{}, err
	}

	// Send header: filename (base only) + file size.
	name := filepath.Base(path)
	nameBuf := []byte(name)
	header := make([]byte, 2+len(nameBuf)+8)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(nameBuf)))
	copy(header[2:], nameBuf)
	binary.BigEndian.PutUint64(header[2+len(nameBuf):], uint64(info.Size()))
	if err := sc.sendMsg(header); err != nil {
		return transferResult{}, fmt.Errorf("send header: %w", err)
	}

	// Stream file in 1 MiB chunks; extend the hash chain with each chunk.
	// The receiver already knows the total size from the header above,
	// so end-of-file is determined by byte count, not by a data sentinel.
	const chunkSize = 1 << 20
	buf := make([]byte, chunkSize)
	chainState := chainGenesis(uint64(info.Size()))
	var totalSent int64
	for {
		nr, readErr := f.Read(buf)
		if nr > 0 {
			chunk := buf[:nr]
			chainState = chainNext(chainState, chunk)
			totalSent += int64(nr)
			if err := sc.sendMsg(chunk); err != nil {
				return transferResult{}, fmt.Errorf("send chunk: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return transferResult{}, fmt.Errorf("read file: %w", readErr)
		}
	}

	// Sign the final hash-chain state, not a flat digest of the file.
	// This binds the signature to the exact sequence of chunks sent.
	sig := ed25519.Sign(priv, chainState)
	if err := sc.sendMsg(sig); err != nil {
		return transferResult{}, fmt.Errorf("send signature: %w", err)
	}

	fmt.Printf("Sent %d bytes (%s)\n", totalSent, name)
	return transferResult{fileName: name, fileSize: uint64(totalSent), chainHashFinal: chainState}, nil
}

// recvFile receives a file from the encrypted connection, verifies the
// hash chain incrementally and the final ed25519 signature, and writes the
// file to the current directory.
func (sc *secureConn) recvFile(senderPub ed25519.PublicKey) (transferResult, error) {
	// Receive header.
	headerBytes, err := sc.recvMsg()
	if err != nil {
		return transferResult{}, fmt.Errorf("recv header: %w", err)
	}
	if len(headerBytes) < 2 {
		return transferResult{}, errors.New("header too short")
	}
	nameLen := binary.BigEndian.Uint16(headerBytes[0:2])
	if int(nameLen)+2+8 > len(headerBytes) {
		return transferResult{}, errors.New("header malformed")
	}
	name := string(headerBytes[2 : 2+nameLen])
	expectedSize := binary.BigEndian.Uint64(headerBytes[2+nameLen:])

	fmt.Printf("Receiving: %s (%d bytes)\n", name, expectedSize)

	// Write to a temp file; rename on success.
	tmpPath := name + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return transferResult{}, err
	}
	defer func() {
		out.Close()
		os.Remove(tmpPath) // no-op if renamed
	}()

	chainState := chainGenesis(expectedSize)
	var totalRecv uint64
	for totalRecv < expectedSize {
		chunk, err := sc.recvMsg()
		if err != nil {
			return transferResult{}, fmt.Errorf("recv chunk: %w", err)
		}

		// Reject before writing: a peer that sends more than it declared
		// in the header is misbehaving (bug or malicious), and must not
		// be allowed to grow the file past the announced size.
		if totalRecv+uint64(len(chunk)) > expectedSize {
			return transferResult{}, fmt.Errorf(
				"peer sent more data than declared (declared %d, got at least %d) — aborting",
				expectedSize, totalRecv+uint64(len(chunk)),
			)
		}

		// Extend and verify the hash chain incrementally: if a chunk has
		// been altered or reordered, this is caught right here, before
		// the chunk is written to disk — not only at the very end.
		nextState := chainNext(chainState, chunk)
		chainState = nextState

		totalRecv += uint64(len(chunk))
		if _, err := out.Write(chunk); err != nil {
			return transferResult{}, fmt.Errorf("write chunk: %w", err)
		}
	}

	if totalRecv != expectedSize {
		return transferResult{}, fmt.Errorf("size mismatch: expected %d, got %d", expectedSize, totalRecv)
	}

	// Receive and verify signature over the final chain state.
	sig, err := sc.recvMsg()
	if err != nil {
		return transferResult{}, fmt.Errorf("recv signature: %w", err)
	}
	if !ed25519.Verify(senderPub, chainState, sig) {
		return transferResult{}, errors.New("signature verification FAILED — file may be tampered")
	}

	out.Close()
	if err := os.Rename(tmpPath, name); err != nil {
		return transferResult{}, err
	}
	fmt.Printf("Saved %s (%d bytes) — signature OK\n", name, totalRecv)
	return transferResult{fileName: name, fileSize: totalRecv, chainHashFinal: chainState}, nil
}

// ─── Handshake ────────────────────────────────────────────────────────────────
//
// Wire order (raw bytes, before encryption is established):
//  1. → my ed25519 public key (32 bytes)
//  2. ← peer ed25519 public key (32 bytes)
//  3. → my ed25519 signature over sharedChallenge(myPub, peerPub) (64 bytes)
//  4. ← peer signature (64 bytes)
//  Both sides derive the same X25519 shared secret and session key.

func handshake(conn net.Conn, priv ed25519.PrivateKey) (*secureConn, ed25519.PublicKey, error) {
	myPub := priv.Public().(ed25519.PublicKey)

	// Exchange public keys.
	if _, err := conn.Write(myPub); err != nil {
		return nil, nil, fmt.Errorf("handshake: write pubkey: %w", err)
	}
	peerPubBytes := make([]byte, ed25519.PublicKeySize)
	if _, err := io.ReadFull(conn, peerPubBytes); err != nil {
		return nil, nil, fmt.Errorf("handshake: read peer pubkey: %w", err)
	}

	// Mutual challenge-response.
	challenge := sharedChallenge(myPub, peerPubBytes)
	mySig := ed25519.Sign(priv, challenge)
	if _, err := conn.Write(mySig); err != nil {
		return nil, nil, fmt.Errorf("handshake: write sig: %w", err)
	}
	peerSig := make([]byte, ed25519.SignatureSize)
	if _, err := io.ReadFull(conn, peerSig); err != nil {
		return nil, nil, fmt.Errorf("handshake: read peer sig: %w", err)
	}
	if !ed25519.Verify(peerPubBytes, challenge, peerSig) {
		return nil, nil, errors.New("handshake: peer failed challenge — possible impersonation or replay")
	}

	// Derive shared secret via X25519 ECDH.
	myScalar := ed25519SeedToX25519Scalar(priv.Seed())
	peerUCoord, err := ed25519PublicKeyToX25519(peerPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: key conversion: %w", err)
	}
	myX, err := ecdh.X25519().NewPrivateKey(myScalar)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: x25519 privkey: %w", err)
	}
	peerX, err := ecdh.X25519().NewPublicKey(peerUCoord)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: x25519 pubkey: %w", err)
	}
	shared, err := myX.ECDH(peerX)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: ecdh: %w", err)
	}

	sessionKey := deriveSessionKey(shared, []byte("p2pshare-v1-session"))
	sc, err := newSecureConn(conn, sessionKey)
	if err != nil {
		return nil, nil, err
	}
	return sc, ed25519.PublicKey(peerPubBytes), nil
}

// sharedChallenge is deterministic: both peers compute the same value.
// Canonical ordering is lexicographic on the public key bytes.
func sharedChallenge(a, b []byte) []byte {
	first, second := a, b
	for i := range a {
		if a[i] < b[i] {
			break
		}
		if a[i] > b[i] {
			first, second = b, a
			break
		}
	}
	h := sha256.New()
	h.Write([]byte("p2pshare-v1-challenge"))
	h.Write(first)
	h.Write(second)
	return h.Sum(nil)
}

// ─── Ledger: append-only, hash-chained log of completed transfers ──────────
//
// Every completed send/receive appends one fixed-shape entry to a local
// binary file. Each entry embeds the hash of the previous entry, so the
// sequence can be replayed and verified: if any entry is altered, removed,
// or reordered, the chain breaks at that point and ledgerVerify reports it.
//
// Entry layout (all integers big-endian):
//   prevBlockHash   [32]byte
//   timestamp       int64   (unix nanoseconds)
//   role            byte    (0x01 = sender, 0x02 = receiver)
//   peerPubKey      [32]byte
//   fileSize        uint64
//   chainHashFinal  [32]byte
//   nameLen         uint16
//   name            [nameLen]byte
//   blockHash       [32]byte  (SHA-256 over every field above, in order)

const (
	roleByteSender   byte = 0x01
	roleByteReceiver byte = 0x02
)

type ledgerEntry struct {
	prevBlockHash  [32]byte
	timestamp      int64
	role           byte
	peerPubKey     [32]byte
	fileSize       uint64
	chainHashFinal [32]byte
	name           string
	blockHash      [32]byte
}

func ledgerPath() (string, error) {
	stateDir := os.Getenv("XDG_STATE_HOME")
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		stateDir = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(stateDir, "p2pshare")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "ledger.bin"), nil
}

// encodeLedgerEntry serializes an entry (without blockHash, which the caller
// computes over this exact byte sequence and appends separately).
func encodeLedgerEntryBody(prevHash [32]byte, ts int64, role byte, peerPub [32]byte, size uint64, chainHash [32]byte, name string) []byte {
	nameBytes := []byte(name)
	buf := make([]byte, 0, 32+8+1+32+8+32+2+len(nameBytes))
	buf = append(buf, prevHash[:]...)

	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts))
	buf = append(buf, tsBuf...)

	buf = append(buf, role)
	buf = append(buf, peerPub[:]...)

	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, size)
	buf = append(buf, sizeBuf...)

	buf = append(buf, chainHash[:]...)

	nameLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(nameLenBuf, uint16(len(nameBytes)))
	buf = append(buf, nameLenBuf...)
	buf = append(buf, nameBytes...)

	return buf
}

// ledgerAppend writes one new entry, chained to the last entry currently in
// the file (or to the all-zero genesis hash if the ledger is empty/missing).
// Failures here are logged but never propagated as fatal: the ledger is an
// audit aid, not part of the transfer protocol's correctness.
func ledgerAppend(role byte, peerPub ed25519.PublicKey, fileSize uint64, chainHashFinal []byte, name string) {
	path, err := ledgerPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger: %v (skipping ledger entry)\n", err)
		return
	}

	prevHash, err := ledgerLastBlockHash(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger: %v (skipping ledger entry)\n", err)
		return
	}

	var peerPubFixed, chainHashFixed [32]byte
	copy(peerPubFixed[:], peerPub)
	copy(chainHashFixed[:], chainHashFinal)

	ts := ledgerEntryTimestampNow()
	body := encodeLedgerEntryBody(prevHash, ts, role, peerPubFixed, fileSize, chainHashFixed, name)
	blockHash := sha256.Sum256(body)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ledger: open: %v (skipping ledger entry)\n", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(body); err != nil {
		fmt.Fprintf(os.Stderr, "ledger: write: %v\n", err)
		return
	}
	if _, err := f.Write(blockHash[:]); err != nil {
		fmt.Fprintf(os.Stderr, "ledger: write: %v\n", err)
		return
	}
}

// ledgerLastBlockHash returns the blockHash of the last entry in the ledger,
// or the all-zero genesis hash if the file doesn't exist or is empty.
func ledgerLastBlockHash(path string) ([32]byte, error) {
	var zero [32]byte
	entries, err := ledgerReadAll(path)
	if err != nil {
		if os.IsNotExist(err) {
			return zero, nil
		}
		return zero, err
	}
	if len(entries) == 0 {
		return zero, nil
	}
	return entries[len(entries)-1].blockHash, nil
}

// ledgerReadAll parses every entry in the ledger file, in order.
func ledgerReadAll(path string) ([]ledgerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var entries []ledgerEntry
	off := 0
	for off < len(data) {
		// Fixed prefix before the variable-length name: 32+8+1+32+8+32 = 113 bytes.
		const fixedPrefix = 113
		if off+fixedPrefix+2 > len(data) {
			return entries, fmt.Errorf("ledger: truncated entry at offset %d", off)
		}

		var entry ledgerEntry
		copy(entry.prevBlockHash[:], data[off:off+32])
		off += 32

		entry.timestamp = int64(binary.BigEndian.Uint64(data[off : off+8]))
		off += 8

		entry.role = data[off]
		off++

		copy(entry.peerPubKey[:], data[off:off+32])
		off += 32

		entry.fileSize = binary.BigEndian.Uint64(data[off : off+8])
		off += 8

		copy(entry.chainHashFinal[:], data[off:off+32])
		off += 32

		nameLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2

		if off+nameLen+32 > len(data) {
			return entries, fmt.Errorf("ledger: truncated entry (name/hash) at offset %d", off)
		}
		entry.name = string(data[off : off+nameLen])
		off += nameLen

		copy(entry.blockHash[:], data[off:off+32])
		off += 32

		entries = append(entries, entry)
	}
	return entries, nil
}

// ledgerShow prints every entry and verifies the hash chain, reporting the
// first broken link if the ledger has been tampered with or corrupted.
func ledgerShow() error {
	path, err := ledgerPath()
	if err != nil {
		return err
	}
	entries, err := ledgerReadAll(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Ledger is empty (no transfers recorded yet).")
			return nil
		}
		return err
	}
	if len(entries) == 0 {
		fmt.Println("Ledger is empty (no transfers recorded yet).")
		return nil
	}

	var prevHash [32]byte // genesis: all-zero
	broken := false
	for i, e := range entries {
		roleStr := "sender"
		if e.role == roleByteReceiver {
			roleStr = "receiver"
		}
		t := time.Unix(0, e.timestamp)

		linkOK := e.prevBlockHash == prevHash
		recomputedBody := encodeLedgerEntryBody(e.prevBlockHash, e.timestamp, e.role, e.peerPubKey, e.fileSize, e.chainHashFinal, e.name)
		recomputedHash := sha256.Sum256(recomputedBody)
		hashOK := recomputedHash == e.blockHash

		status := "OK"
		if !linkOK || !hashOK {
			status = "BROKEN"
			broken = true
		}

		fmt.Printf("#%d [%s] %s  role=%-8s peer=%x  file=%q size=%d  block=%x\n",
			i, t.Format("2006-01-02 15:04:05"), status, roleStr, e.peerPubKey[:8], e.name, e.fileSize, e.blockHash[:8])

		prevHash = e.blockHash
	}

	if broken {
		fmt.Println("\n⚠️  Chain integrity check FAILED — the ledger may have been tampered with.")
	} else {
		fmt.Println("\n✅ Chain integrity verified — all entries linked correctly.")
	}
	return nil
}

func ledgerEntryTimestampNow() int64 { return time.Now().UnixNano() }

// ─── Role negotiation ─────────────────────────────────────────────────────────
//
// After the encrypted channel is up, the connecting peer declares its intent:
//   "SEND" — I want to send a file.
//   "RECV" — I want to receive a file.
// The listening peer assumes the complementary role.

const roleSend = "SEND"
const roleRecv = "RECV"

// ─── Listener ─────────────────────────────────────────────────────────────────

func listen(addr string, priv ed25519.PrivateKey) (transferResult, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return transferResult{}, err
	}
	defer ln.Close()
	fmt.Printf("Listening on %s\nPublic key: %x\n", addr, priv.Public().(ed25519.PublicKey))

	conn, err := ln.Accept()
	if err != nil {
		return transferResult{}, err
	}
	defer conn.Close()
	fmt.Printf("Connection from %s\n", conn.RemoteAddr())

	sc, peerPub, err := handshake(conn, priv)
	if err != nil {
		return transferResult{}, fmt.Errorf("handshake failed: %w", err)
	}
	fmt.Printf("Authenticated peer: %x\n", peerPub)

	// Receive role declaration from connector.
	roleMsg, err := sc.recvMsg()
	if err != nil {
		return transferResult{}, fmt.Errorf("recv role: %w", err)
	}
	role := string(roleMsg)

	switch role {
	case roleSend:
		// Peer wants to send; we receive.
		fmt.Println("Peer is sending a file. Receiving...")
		res, err := sc.recvFile(peerPub)
		res.role, res.peerPubKey = "receiver", peerPub
		return res, err
	case roleRecv:
		// Peer wants to receive; they need to tell us which file they want,
		// but in this design the listener must have a file ready via -send flag.
		// We signal that we cannot comply.
		_ = sc.sendMsg([]byte("ERR:listener has no file to send"))
		return transferResult{}, errors.New("peer requested to receive but listener has no -send flag")
	default:
		return transferResult{}, fmt.Errorf("unknown role: %q", role)
	}
}

// listenSend listens for one connection and sends a file to whoever connects.
func listenSend(addr, filePath string, priv ed25519.PrivateKey) (transferResult, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return transferResult{}, err
	}
	defer ln.Close()
	fmt.Printf("Listening on %s (will send %s)\nPublic key: %x\n", addr, filepath.Base(filePath), priv.Public().(ed25519.PublicKey))

	conn, err := ln.Accept()
	if err != nil {
		return transferResult{}, err
	}
	defer conn.Close()
	fmt.Printf("Connection from %s\n", conn.RemoteAddr())

	sc, peerPub, err := handshake(conn, priv)
	if err != nil {
		return transferResult{}, fmt.Errorf("handshake failed: %w", err)
	}
	fmt.Printf("Authenticated peer: %x\n", peerPub)

	// Receive role; peer should declare RECV.
	roleMsg, err := sc.recvMsg()
	if err != nil {
		return transferResult{}, err
	}
	if string(roleMsg) != roleRecv {
		return transferResult{}, fmt.Errorf("expected peer role RECV, got %q", string(roleMsg))
	}

	res, err := sc.sendFile(filePath, priv)
	res.role, res.peerPubKey = "sender", peerPub
	return res, err
}

// ─── Connector ────────────────────────────────────────────────────────────────

func connectAndSend(addr, filePath string, priv ed25519.PrivateKey) (transferResult, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return transferResult{}, err
	}
	defer conn.Close()
	fmt.Printf("Connected to %s\nPublic key: %x\n", addr, priv.Public().(ed25519.PublicKey))

	sc, peerPub, err := handshake(conn, priv)
	if err != nil {
		return transferResult{}, fmt.Errorf("handshake failed: %w", err)
	}
	fmt.Printf("Authenticated peer: %x\n", peerPub)

	if err := sc.sendMsg([]byte(roleSend)); err != nil {
		return transferResult{}, err
	}
	res, err := sc.sendFile(filePath, priv)
	res.role, res.peerPubKey = "sender", peerPub
	return res, err
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	listenAddr := flag.String("listen", "", "listen address, e.g. :4444")
	connectAddr := flag.String("connect", "", "peer address, e.g. 192.168.1.5:4444")
	sendFile := flag.String("send", "", "file to send")
	recv := flag.Bool("recv", false, "receive a file from peer")
	showLedger := flag.Bool("ledger-show", false, "print and verify the local transfer ledger, then exit")
	flag.Parse()

	if *showLedger {
		if err := ledgerShow(); err != nil {
			fatalf("%v", err)
		}
		return
	}

	// Generate ephemeral keypair.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("keygen: %v", err)
	}

	var res transferResult
	switch {
	case *listenAddr != "" && *sendFile != "":
		// Listen and send a file to whoever connects with -recv.
		res, err = listenSend(*listenAddr, *sendFile, priv)

	case *listenAddr != "":
		// Listen and receive a file from whoever connects with -send.
		res, err = listen(*listenAddr, priv)

	case *connectAddr != "" && *sendFile != "":
		// Connect and push a file to the listener.
		res, err = connectAndSend(*connectAddr, *sendFile, priv)

	case *connectAddr != "" && *recv:
		// Connect and pull a file from a listening sender.
		res, err = connectAndRecvFile(*connectAddr, priv)

	default:
		fmt.Fprintf(os.Stderr, `p2pshare — secure P2P file transfer

Usage:
  Receive (listen):    p2pshare -listen :4444
  Send    (listen):    p2pshare -listen :4444 -send <file>
  Send    (connect):   p2pshare -connect host:4444 -send <file>
  Receive (connect):   p2pshare -connect host:4444 -recv
  Show ledger:         p2pshare -ledger-show
`)
		os.Exit(1)
	}

	if err != nil {
		fatalf("%v", err)
	}

	// Record the completed transfer in the local audit ledger. A ledger
	// failure is logged by ledgerAppend itself and never aborts here —
	// the transfer already succeeded by this point.
	roleByte := roleByteSender
	if res.role == "receiver" {
		roleByte = roleByteReceiver
	}
	ledgerAppend(roleByte, res.peerPubKey, res.fileSize, res.chainHashFinal, res.fileName)
}

// connectAndRecvFile connects, authenticates, declares RECV, and receives a file.
func connectAndRecvFile(addr string, priv ed25519.PrivateKey) (transferResult, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return transferResult{}, err
	}
	defer conn.Close()
	fmt.Printf("Connected to %s\nPublic key: %x\n", addr, priv.Public().(ed25519.PublicKey))

	sc, peerPub, err := handshake(conn, priv)
	if err != nil {
		return transferResult{}, fmt.Errorf("handshake failed: %w", err)
	}
	fmt.Printf("Authenticated peer: %x\n", peerPub)

	// Declare intent: receive.
	if err := sc.sendMsg([]byte(roleRecv)); err != nil {
		return transferResult{}, err
	}
	// Listener will now stream the file.
	res, err := sc.recvFile(peerPub)
	res.role, res.peerPubKey = "receiver", peerPub
	return res, err
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
