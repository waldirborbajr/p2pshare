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
func (sc *secureConn) sendFile(path string, priv ed25519.PrivateKey) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	// Send header: filename (base only) + file size.
	name := filepath.Base(path)
	nameBuf := []byte(name)
	header := make([]byte, 2+len(nameBuf)+8)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(nameBuf)))
	copy(header[2:], nameBuf)
	binary.BigEndian.PutUint64(header[2+len(nameBuf):], uint64(info.Size()))
	if err := sc.sendMsg(header); err != nil {
		return fmt.Errorf("send header: %w", err)
	}

	// Stream file in 1 MiB chunks; accumulate content for signature.
	const chunkSize = 1 << 20
	buf := make([]byte, chunkSize)
	hasher := sha256.New()
	var totalSent int64
	for {
		nr, readErr := f.Read(buf)
		if nr > 0 {
			chunk := buf[:nr]
			hasher.Write(chunk)
			totalSent += int64(nr)
			if err := sc.sendMsg(chunk); err != nil {
				return fmt.Errorf("send chunk: %w", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read file: %w", readErr)
		}
	}

	// Signal end of file.
	if err := sc.sendMsg([]byte("EOF")); err != nil {
		return fmt.Errorf("send EOF marker: %w", err)
	}

	// Sign the SHA-256 digest of the file content.
	digest := hasher.Sum(nil)
	sig := ed25519.Sign(priv, digest)
	if err := sc.sendMsg(sig); err != nil {
		return fmt.Errorf("send signature: %w", err)
	}

	fmt.Printf("Sent %d bytes (%s)\n", totalSent, name)
	return nil
}

// recvFile receives a file from the encrypted connection, verifies the
// ed25519 signature, and writes the file to the current directory.
func (sc *secureConn) recvFile(senderPub ed25519.PublicKey) error {
	// Receive header.
	headerBytes, err := sc.recvMsg()
	if err != nil {
		return fmt.Errorf("recv header: %w", err)
	}
	if len(headerBytes) < 2 {
		return errors.New("header too short")
	}
	nameLen := binary.BigEndian.Uint16(headerBytes[0:2])
	if int(nameLen)+2+8 > len(headerBytes) {
		return errors.New("header malformed")
	}
	name := string(headerBytes[2 : 2+nameLen])
	expectedSize := binary.BigEndian.Uint64(headerBytes[2+nameLen:])

	fmt.Printf("Receiving: %s (%d bytes)\n", name, expectedSize)

	// Write to a temp file; rename on success.
	tmpPath := name + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer func() {
		out.Close()
		os.Remove(tmpPath) // no-op if renamed
	}()

	hasher := sha256.New()
	var totalRecv int64
	for {
		chunk, err := sc.recvMsg()
		if err != nil {
			return fmt.Errorf("recv chunk: %w", err)
		}
		if string(chunk) == "EOF" {
			break
		}
		hasher.Write(chunk)
		totalRecv += int64(len(chunk))
		if _, err := out.Write(chunk); err != nil {
			return fmt.Errorf("write chunk: %w", err)
		}
	}

	if uint64(totalRecv) != expectedSize {
		return fmt.Errorf("size mismatch: expected %d, got %d", expectedSize, totalRecv)
	}

	// Receive and verify signature.
	sig, err := sc.recvMsg()
	if err != nil {
		return fmt.Errorf("recv signature: %w", err)
	}
	digest := hasher.Sum(nil)
	if !ed25519.Verify(senderPub, digest, sig) {
		return errors.New("signature verification FAILED — file may be tampered")
	}

	out.Close()
	if err := os.Rename(tmpPath, name); err != nil {
		return err
	}
	fmt.Printf("Saved %s (%d bytes) — signature OK\n", name, totalRecv)
	return nil
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

// ─── Role negotiation ─────────────────────────────────────────────────────────
//
// After the encrypted channel is up, the connecting peer declares its intent:
//   "SEND" — I want to send a file.
//   "RECV" — I want to receive a file.
// The listening peer assumes the complementary role.

const roleSend = "SEND"
const roleRecv = "RECV"

// ─── Listener ─────────────────────────────────────────────────────────────────

func listen(addr string, priv ed25519.PrivateKey) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("Listening on %s\nPublic key: %x\n", addr, priv.Public().(ed25519.PublicKey))

	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("Connection from %s\n", conn.RemoteAddr())

	sc, peerPub, err := handshake(conn, priv)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	fmt.Printf("Authenticated peer: %x\n", peerPub)

	// Receive role declaration from connector.
	roleMsg, err := sc.recvMsg()
	if err != nil {
		return fmt.Errorf("recv role: %w", err)
	}
	role := string(roleMsg)

	switch role {
	case roleSend:
		// Peer wants to send; we receive.
		fmt.Println("Peer is sending a file. Receiving...")
		return sc.recvFile(peerPub)
	case roleRecv:
		// Peer wants to receive; they need to tell us which file they want,
		// but in this design the listener must have a file ready via -send flag.
		// We signal that we cannot comply.
		_ = sc.sendMsg([]byte("ERR:listener has no file to send"))
		return errors.New("peer requested to receive but listener has no -send flag")
	default:
		return fmt.Errorf("unknown role: %q", role)
	}
}

// listenSend listens for one connection and sends a file to whoever connects.
func listenSend(addr, filePath string, priv ed25519.PrivateKey) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("Listening on %s (will send %s)\nPublic key: %x\n", addr, filepath.Base(filePath), priv.Public().(ed25519.PublicKey))

	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("Connection from %s\n", conn.RemoteAddr())

	sc, peerPub, err := handshake(conn, priv)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	fmt.Printf("Authenticated peer: %x\n", peerPub)

	// Receive role; peer should declare RECV.
	roleMsg, err := sc.recvMsg()
	if err != nil {
		return err
	}
	if string(roleMsg) != roleRecv {
		return fmt.Errorf("expected peer role RECV, got %q", string(roleMsg))
	}

	return sc.sendFile(filePath, priv)
}

// ─── Connector ────────────────────────────────────────────────────────────────

func connectAndSend(addr, filePath string, priv ed25519.PrivateKey) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("Connected to %s\nPublic key: %x\n", addr, priv.Public().(ed25519.PublicKey))

	sc, peerPub, err := handshake(conn, priv)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	fmt.Printf("Authenticated peer: %x\n", peerPub)

	if err := sc.sendMsg([]byte(roleSend)); err != nil {
		return err
	}
	return sc.sendFile(filePath, priv)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	listenAddr := flag.String("listen", "", "listen address, e.g. :4444")
	connectAddr := flag.String("connect", "", "peer address, e.g. 192.168.1.5:4444")
	sendFile := flag.String("send", "", "file to send")
	recv := flag.Bool("recv", false, "receive a file from peer")
	flag.Parse()

	// Generate ephemeral keypair.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("keygen: %v", err)
	}

	switch {
	case *listenAddr != "" && *sendFile != "":
		// Listen and send a file to whoever connects with -recv.
		err = listenSend(*listenAddr, *sendFile, priv)

	case *listenAddr != "":
		// Listen and receive a file from whoever connects with -send.
		err = listen(*listenAddr, priv)

	case *connectAddr != "" && *sendFile != "":
		// Connect and push a file to the listener.
		err = connectAndSend(*connectAddr, *sendFile, priv)

	case *connectAddr != "" && *recv:
		// Connect and pull a file from a listening sender.
		err = connectAndRecvFile(*connectAddr, priv)

	default:
		fmt.Fprintf(os.Stderr, `p2pshare — secure P2P file transfer

Usage:
  Receive (listen):    p2pshare -listen :4444
  Send    (listen):    p2pshare -listen :4444 -send <file>
  Send    (connect):   p2pshare -connect host:4444 -send <file>
  Receive (connect):   p2pshare -connect host:4444 -recv
`)
		os.Exit(1)
	}

	if err != nil {
		fatalf("%v", err)
	}
}

// connectAndRecvFile connects, authenticates, declares RECV, and receives a file.
func connectAndRecvFile(addr string, priv ed25519.PrivateKey) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("Connected to %s\nPublic key: %x\n", addr, priv.Public().(ed25519.PublicKey))

	sc, peerPub, err := handshake(conn, priv)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	fmt.Printf("Authenticated peer: %x\n", peerPub)

	// Declare intent: receive.
	if err := sc.sendMsg([]byte(roleRecv)); err != nil {
		return err
	}
	// Listener will now stream the file.
	return sc.recvFile(peerPub)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
