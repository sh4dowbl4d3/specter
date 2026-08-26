# devastator — Hash & Cipher Identification/Cracking Toolkit

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A browser-based hash type detector, dictionary/brute-force cracker, and classical cipher encode/decode/detection toolkit. All processing runs **entirely in the browser** via WebAssembly — no server needed.

## Try It

Deployed at: `https://<user>.github.io/devastator/`

## Architecture

```
devastator/                      # Cargo workspace
├── crates/
│   ├── core/                    # Pure algorithm crate (no I/O, no threading)
│   │   ├── hash_id/             # Hash type detection (length/charset heuristics)
│   │   ├── cracker/             # Dictionary + brute-force cracking engines
│   │   └── cipher_tools/        # Classical cipher codecs + auto-detection
│   └── wasm-frontend/           # WASM browser frontend (Trunk + wasm-bindgen)
├── wordlists/                   # Dictionary files (gitignored for large files)
└── Cargo.toml                   # Workspace definition
```

## Quick Start (WASM Frontend)

```bash
# Prerequisites
cargo install trunk
rustup target add wasm32-unknown-unknown

# Build
cd crates/wasm-frontend && trunk build --release

# Serve locally (hot-reload)
trunk serve --port 8080
# Open http://localhost:8080
```

## Usage

Upload a wordlist or paste hashes directly in the browser. All operations run client-side:

- **Identify**: Paste a hash to detect candidate types (MD5, SHA-1/2/3, NTLM, bcrypt, MySQL, etc.)
- **Crack**: Dictionary attack (upload or paste a wordlist) or bounded brute-force (20M attempts maximum)
- **Ciphers**: Encode, decode, or auto-detect 7 classical ciphers (Base64, Hex, Binary, ROT13, Atbash, Caesar, Vigenère)
- **Files**: Upload files to compute byte-accurate MD5/SHA-1/224/256/384/512 hashes or apply text cipher transforms (64 MiB limit)

## Deploy to GitHub Pages

Push to `main` — the [GitHub Actions workflow](.github/workflows/deploy.yml) auto-deploys to Pages.

Manual build for Pages (uses repo name as base path):

```bash
trunk build --release --public-url "./"
```

## Detected Hash Types

The identifier reports candidate types from format heuristics. Dictionary cracking is implemented for MD5, SHA-1/2, NTLM, and MySQL formats; the remaining types are detection-only.

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

## Development

```bash
# Run all tests
cargo test --workspace --all-targets

# Check the actual WASM target
cargo check -p wasm-frontend --target wasm32-unknown-unknown

# Quality gates
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```
