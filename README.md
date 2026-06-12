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

**File integrity** — the sender signs `SHA-256(file)` with its ed25519 key after streaming all chunks. The receiver verifies the signature before calling `rename()`. A failed verification deletes the temp file and exits non-zero.

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
  → chunk …            1 MiB chunks
  → "EOF"
  → 64 bytes           ed25519 sig over SHA-256(file)
```

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
go run p2pshare.go -listen :4444

# Send mode (connector pushes file)
go run p2pshare.go -connect host:4444 -send ./myfile.zip

# Listener pushes, connector pulls
go run p2pshare.go -listen :4444 -send ./myfile.zip
go run p2pshare.go -connect host:4444 -recv
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

