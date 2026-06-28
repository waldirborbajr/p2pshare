<p align="center">
  <img width="256" height="256" src="./assets/logo.png" />
</p>
<h1 align="center">Share files with Security written in Go</h1>

# p2pshare

> secure · ephemeral · direct

P2P file transfer over a direct TCP connection. No broker, no relay, no stored keys. Every run generates a fresh ed25519 keypair; when the process exits, the keys are gone.

---

## Security model

Three independent layers protect every transfer.

**Mutual authentication** — both peers exchange ed25519 public keys and each signs a shared challenge derived from both keys. The challenge is key-bound, so replaying a captured handshake with a different key fails immediately.

**Encrypted channel** — the ed25519 seed is converted to an X25519 scalar (SHA-512 + RFC 8032 clamping), both sides run X25519 ECDH, and the resulting shared secret is fed through HKDF-SHA256 to produce a 32-byte AES-256-GCM session key. Every message frame gets a fresh random 12-byte nonce.

**File integrity** — each chunk extends a running hash chain seeded with the declared file size (`chainHash₀ = SHA-256("p2pshare-chain-genesis" || size)`, `chainHashᵢ = SHA-256(chainHashᵢ₋₁ || chunkᵢ)`). The sender signs the final chain hash with its ed25519 key once all chunks are sent. The receiver recomputes the chain as each chunk arrives, so a tampered or reordered chunk is caught immediately — not only after the whole file has been received. The final signature is verified before calling `rename()`; a failed verification deletes the temp file and exits non-zero.

### Wire protocol (per connection)

```
[raw TCP — pre-encryption]
  → 32 bytes  ed25519 public key
  ← 32 bytes  ed25519 public key
  → 64 bytes  ed25519 sig over sharedChallenge(myPub, peerPub)
  ← 64 bytes  ed25519 sig

[AES-256-GCM frames from here — each: 4-byte length | 12-byte nonce | ciphertext+tag]
  → "SEND" or "RECV"   role declaration
  → header             [2-byte name len | filename | 8-byte file size]
  → chunk …            1 MiB chunks, until declared file size is reached
  → 64 bytes           ed25519 sig over the final hash-chain state
```

End-of-file is determined by byte count against the size declared in the
header — there is no longer a separate "EOF" marker. This closes two issues
with the old sentinel-based framing: a chunk that happened to contain the
literal bytes `EOF` could trigger a false end-of-file, and a peer could
keep streaming past its declared size with nothing to stop it before disk
filled up. The receiver now rejects any chunk that would push the total
past the declared size, before writing it.

---

## Requirements

- Go 1.22 or later
- No external dependencies — stdlib only (`crypto/ed25519`, `crypto/ecdh`, `crypto/aes`, `math/big`, …)

---

## Installation

```sh
git clone https://github.com/waldirborbajr/p2pshare
cd p2pshare
go build -o p2pshare .
```

Or run directly without building:

```sh
# Receive mode (listener)
go run main.go -listen :4444

# Send mode (connector pushes file)
go run main.go -connect host:4444 -send ./myfile.zip

# Listener pushes, connector pulls
go run main.go -listen :4444 -send ./myfile.zip
go run main.go -connect host:4444 -recv
```

---

## Usage

There are four modes. Pick the combination that matches who is behind NAT.

### Connector pushes a file to a listening receiver

```sh
# receiver — listens and waits
p2pshare -listen :4444

# sender — connects and pushes
p2pshare -connect 192.168.1.10:4444 -send ./archive.tar.gz
```

### Listener offers a file; connector pulls it

Useful when the sender is behind NAT and the receiver has a public address.

```sh
# sender — listens with a file ready
p2pshare -listen :4444 -send ./archive.tar.gz

# receiver — connects and pulls
p2pshare -connect 192.168.1.10:4444 -recv
```

### Flag reference

| flag | description |
|---|---|
| `-listen <addr>` | bind and accept one connection, e.g. `:4444` |
| `-connect <addr>` | connect to a listening peer, e.g. `192.168.1.10:4444` |
| `-send <file>` | file to send (combine with `-listen` or `-connect`) |
| `-recv` | receive a file (combine with `-connect`) |
| `-ledger-show` | print and verify the local transfer ledger, then exit |

---

## Example session output

```
# Sender side
Listening on :4444 (will send report.pdf)
Public key: 9f4d67a852e6081e...
Connection from 10.0.0.5:51234
Authenticated peer: 47601b73840d80ca...
Sent 2048312 bytes (report.pdf)

# Receiver side
Connected to 10.0.0.3:4444
Public key: 47601b73840d80ca...
Authenticated peer: 9f4d67a852e6081e...
Receiving: report.pdf (2048312 bytes)
Saved report.pdf (2048312 bytes) — signature OK
```

---

## Audit ledger

Every completed transfer — sent or received — is appended to a local,
hash-chained ledger. Each entry stores the previous entry's hash, so the
sequence can be verified end to end: corrupting, removing, or reordering
any entry breaks the chain at that point, and `-ledger-show` reports
exactly where.

```sh
p2pshare -ledger-show
```

```
#0 [2026-06-28 00:21:13] OK  role=sender   peer=c13c0c18bf4caf8b  file="report.pdf" size=2048312  block=50bc39190983ac63
#1 [2026-06-28 00:21:30] OK  role=receiver peer=8f202fd90e47a239  file="notes.txt"  size=58       block=58fe25e59fda3872

✅ Chain integrity verified — all entries linked correctly.
```

The ledger lives at `$XDG_STATE_HOME/p2pshare/ledger.bin` (defaulting to
`~/.local/state/p2pshare/ledger.bin`) and records, per entry: timestamp,
role, the remote peer's public key, filename, size, and the transfer's
final hash-chain value. It's an audit trail, not part of the transfer
protocol — a failed write to the ledger is logged to stderr and never
aborts an otherwise-successful transfer.

---

## Design notes

**Why ephemeral keys?** Persistent keys require secure storage and a trust-on-first-use model. Ephemeral keys sidestep both problems: the security guarantee is "I spoke to whoever was listening on that address right now," which is the correct model for ad-hoc transfers on a trusted local network or VPN.

**Why ed25519 for both auth and encryption?** ed25519 is a signing scheme, not a KEM. The trick is the birational map between the Edwards curve (ed25519) and the Montgomery curve (Curve25519 / X25519): given the same seed, you can derive both a signing key and a Diffie-Hellman key. This means one keypair serves both purposes with no extra key material.

**Why AES-256-GCM instead of ChaCha20-Poly1305?** ChaCha20-Poly1305 requires `golang.org/x/crypto`, which is an external dependency. AES-256-GCM is in the Go stdlib (`crypto/aes` + `crypto/cipher`) and hardware-accelerated on any modern CPU with AES-NI.

**Frame size cap** — frames larger than 128 MiB are rejected to prevent memory exhaustion from a malicious peer. Files larger than 128 MiB are split into 1 MiB chunks automatically.

---

## What it does not do

- Key pinning / TOFU — there is no way to verify you connected to the same peer as last time (by design, since keys are ephemeral)
- Resume / partial transfer
- Multi-file or directory transfer
- Relay or NAT traversal (use a VPN or SSH tunnel if needed)
- Compression

---

## License

MIT
