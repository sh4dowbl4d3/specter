# devastator — Hash & Cipher Identification/Cracking Toolkit

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A fast web application for hash type detection, dictionary/brute-force cracking, and classical cipher encode/decode/detection. Built for CTF and educational use.

## Architecture

```
devastator/             # Cargo workspace
├── crates/
│   ├── hash_id/        # Hash type detection (length/charset heuristics)
│   ├── cracker/        # Dictionary + brute-force cracking engines
│   ├── cipher_tools/   # Classical cipher codecs + auto-detection
│   └── web/            # Actix-web HTTP server + REST API
├── frontend/           # Single-page web UI (Vite + GSAP + Three.js)
├── wordlists/          # Dictionary files (gitignored for large files)
└── Cargo.toml          # Workspace definition
```

## Quick Start

```bash
# 1. Start the backend API server
cargo run -p web

# 2. In another terminal, start the frontend dev server
cd frontend && npm install && npm run dev

# 3. Open http://localhost:5173
```

For production, serve the built frontend from the Rust server:
```bash
cd frontend && npm install && npm run build
cargo run -p web
# Open http://127.0.0.1:8080
```

## API Reference

All endpoints accept `POST` with `Content-Type: application/json`.

### Hash Identification

```bash
curl -X POST http://localhost:8080/api/hash/identify \
  -H 'Content-Type: application/json' \
  -d '{"hash":"5f4dcc3b5aa765d61d8327deb882cf99"}'
```

Response:
```json
[{"hash_type":"Md5","confidence":0.9,"length":32,"charset":"lower+digit"}]
```

### Dictionary Crack

```bash
curl -X POST http://localhost:8080/api/hash/crack \
  -H 'Content-Type: application/json' \
  -d '{"hash":"5f4dcc3b5aa765d61d8327deb882cf99","wordlist_path":"wordlists/rockyou.txt"}'
```

### Brute-Force

```bash
curl -X POST http://localhost:8080/api/hash/bruteforce \
  -H 'Content-Type: application/json' \
  -d '{"hash":"5f4dcc3b5aa765d61d8327deb882cf99","max_length":4,"charset":"lowerdigit"}'
```

### Cipher Decode

```bash
curl -X POST http://localhost:8080/api/cipher/decode \
  -H 'Content-Type: application/json' \
  -d '{"text":"aGVsbG8gd29ybGQ=","cipher":"base64"}'
```

### Cipher Encode

```bash
curl -X POST http://localhost:8080/api/cipher/encode \
  -H 'Content-Type: application/json' \
  -d '{"text":"hello world","cipher":"hex"}'
```

### Cipher Auto-Detect

```bash
curl -X POST http://localhost:8080/api/cipher/detect \
  -H 'Content-Type: application/json' \
  -d '{"text":"aGVsbG8gd29ybGQ="}'
```

## Supported Hash Types

| Type | Length | Pattern |
|------|--------|---------|
| MD5 | 32 | hex (lower) |
| SHA-1 | 40 | hex |
| SHA-224 | 56 | hex |
| SHA-256 | 64 | hex |
| SHA-384 | 96 | hex |
| SHA-512 | 128 | hex |
| bcrypt | 60 | `$2[aby]$` prefix |
| NTLM | 32 | uppercase hex |
| MySQL < 4.1 | 16 | hex |
| MySQL 4.1+ | 41 | `*` prefix + hex |
| RIPEMD-160 | 40 | hex |
| SHA3-224/256/384/512 | 56/64/96/128 | hex |

## Supported Ciphers

- Caesar (brute-force all 25 shifts)
- ROT13
- Atbash
- Base64
- Hex
- Binary
- Vigenère (key-based)

## Rate Limiting

- Brute-force capped at 20M hash computations per request
- `max_length` limited to 6 characters via API
- Use responsibly — this is for education and CTF challenges

## Development

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=info cargo run -p web

# Build a specific crate
cargo build -p hash_id
```
