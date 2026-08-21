<p align="center">
  <img width="256" height="256" src="./assets/logo.png" />
</p>
<h1 align="center">Share files with Security written in Go</h1>

> secure · ephemeral · direct · encrypted

P2P file transfer over a direct TCP connection. No broker, no relay, no stored keys. Every run generates a fresh ed25519 keypair; when the process exits, the keys are gone.

## ✨ Features

- 🔐 **Mutual authentication** — ed25519 signatures with challenge-response
- 🔒 **Encrypted channel** — X25519 ECDH + AES-256-GCM (hardware accelerated)
- 📦 **File integrity** — SHA-256 hash chain verification
- 📁 **Directory support** — Send entire directories (compressed as .tar.gz)
- 📊 **Progress bar** — Visual feedback during transfers
- ⏱️ **Configurable timeouts** — Handshake, read, write, idle
- 🔑 **PSK support** — Optional Pre-Shared Key for extra security
- 📝 **Structured logging** — JSON or human-readable format
- 🗜️ **Compression** — Optional gzip compression
- 📋 **Audit ledger** — Hash-chained transfer history

## 🔒 Security Model

Three independent layers protect every transfer.

1. **Mutual authentication** — both peers exchange ed25519 public keys and sign a shared challenge
2. **Encrypted channel** — X25519 ECDH + HKDF-SHA256 + AES-256-GCM
3. **File integrity** — SHA-256 hash chain with final signature

## 📦 Installation

```bash
git clone https://github.com/waldirborbajr/p2pshare
cd p2pshare
go build -o p2pshare .