# Specter — Browser-Native Cryptanalysis & Cyber Toolkit

[![Build & Deploy](https://github.com/sh4dowbl4d3/specter/actions/workflows/deploy.yml/badge.svg)](https://github.com/sh4dowbl4d3/specter/actions/workflows/deploy.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 2021](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](https://www.rust-lang.org/)
[![WebAssembly](https://img.shields.io/badge/Compute-WebAssembly-654FF0.svg)](https://webassembly.org/)
[![Zero Telemetry](https://img.shields.io/badge/Privacy-Zero_Telemetry-2bee4b.svg)](#privacy--security-architecture)

> **Specter** is a fast, offline-first, client-side cybersecurity toolkit built with **Rust + WebAssembly**. It provides cryptographic hash identification, multi-algorithm checksum generation, dictionary & bounded brute-force hash cracking, classical cipher codecs & statistical heuristic detection, and file forensics — running **100% inside your browser** with zero external network requests.

---

## ⚡ Live Workbench

Access the live desk deployed directly on GitHub Pages:
🔗 **`https://sh4dowbl4d3.github.io/specter/`**

---

## 🧭 Toolkit Instruments

Specter is organized into four primary workbench desks:

### 1. Hash Identification & Generation Desk (`#tab-identify`)
- **Format Heuristic Identification**: Evaluates digest length, alphabet patterns, and signatures against known cryptographic hash families (MD5, SHA-1, SHA-224/256/384/512, SHA-3 family, bcrypt, NTLM, MySQL <4.1, MySQL 4.1+, RIPEMD-160) with confidence scoring and Hashcat/John attack mode guidance.
- **Single & Multi-Hash Digest Generator**: Computes 9 cryptographic and legacy digests (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, NTLM, MySQL3, MySQL4.1) simultaneously in a single pass.
- **Hash Signature Comparison**: Compares two digests with case-insensitive normalization, length checking, and algorithm signature validation.

### 2. Hash Cracking Desk (`#tab-crack`)
- **Dictionary Attack**: Memory-efficient streaming candidate matching against pasted wordlists or uploaded dictionary files (`.txt`, `.lst`).
- **Batched Asynchronous Brute-Force**: Non-blocking exhaustive keyspace exploration using cooperative JS event-loop yields (`setTimeout(0)`). Features search space estimation, attempt budget limits (~20M max), cancellation support, and live progress indicators without locking the UI.

### 3. Classical Ciphers & Encodings Desk (`#tab-ciphers`)
- **Comprehensive Codec Library**:
  - **Encodings**: Base64, Hexadecimal (with delimiter support), Binary (8-bit binary strings), ASCII Decimal (space/comma/semicolon/newline delimiters), URL / Percent Encoding.
  - **Classical Ciphers**: Caesar (with full 25-shift brute-force analysis), ROT13, Atbash, Vigenère (key-based), Affine cipher, Baconian cipher, Morse Code, Rail Fence transposition cipher, and XOR key streaming.
  - **Transformation Pipelines**: Chained sequence execution for layered encoding/decoding.
- **Statistical Auto-Detection Engine**: Evaluates Shannon entropy, character set distributions, English quadgram frequencies, decodability heuristics, and dictionary rankings to score and identify unknown ciphertext.

### 4. File Forensics & Object Transform Desk (`#tab-files`)
- **Local File Checksumming**: Computes single or multi-hash digests on arbitrary files up to 64 MiB using client-side chunked streaming buffers with downloadable JSON audit reports.
- **Text File Cipher Transforms**: Direct client-side encoding and decoding of text files with Base64, Hex, ROT13, and Atbash with immediate result download.

### 5. Ephemeral Session Audit Log & Privacy Drawer
- **In-Memory Ring Buffer**: Records operations in client RAM with FIFO capacity eviction (100 entries).
- **One-Click Privacy Wipe**: Instantly purges all inputs, textareas, file memory, and history buffers.
- **Audit Export**: Generates and downloads structured Markdown audit reports and formatted JSON session logs.

---

## 🔒 Privacy & Security Architecture

Specter follows a strict **zero-telemetry, zero-persistence** security model:

1. **100% In-Browser Computation**: All cryptography, hash generation, cracking loops, and cipher transforms run in WebAssembly on the host CPU.
2. **Zero Server Requests**: No inputs, hashes, plaintext, wordlists, or uploaded files are ever transmitted to any remote server.
3. **No Persistent Tracking**: Zero cookies, zero `localStorage`, and zero `indexedDB` storage. Closing the browser tab destroys all memory buffers.
4. **Strict Content Security Policy (CSP)**: `default-src 'self'` with explicit rules restricting external connections, disallowing object embeds, and isolating execution.

---

## ⌨️ Global Keyboard Shortcuts

| Shortcut | Action | Scope |
|---|---|---|
| <kbd>Alt</kbd> + <kbd>1</kbd> | Switch to **Identify** Desk | Global |
| <kbd>Alt</kbd> + <kbd>2</kbd> | Switch to **Crack** Desk | Global |
| <kbd>Alt</kbd> + <kbd>3</kbd> | Switch to **Ciphers** Desk | Global |
| <kbd>Alt</kbd> + <kbd>4</kbd> | Switch to **Files** Desk | Global |
| <kbd>Alt</kbd> + <kbd>H</kbd> / <kbd>Ctrl</kbd> + <kbd>H</kbd> | Toggle **Session Audit Drawer** | Global |
| <kbd>Ctrl</kbd> + <kbd>Enter</kbd> / <kbd>Cmd</kbd> + <kbd>Enter</kbd> | Execute primary action for active desk / input | Global / Focused input |
| <kbd>Escape</kbd> | Close session drawer / dismiss toast notifications | Global |

---

## 🏗️ Repository Architecture

The workspace strictly decouples pure algorithmic logic from browser DOM interactions:

```
specter/
├── Cargo.toml                       # Workspace configuration & release profile
├── Cargo.lock
├── README.md                        # Documentation
├── STRUCTURE.md                     # Architectural layout
├── LICENSE                          # MIT license
│
├── crates/
│   ├── core/                        # specter-core: Pure Rust algorithm library
│   │   ├── Cargo.toml               # md5, sha1, sha2, md4, base64, hex, serde
│   │   ├── src/
│   │   │   ├── lib.rs               # Module exports
│   │   │   ├── hash_id/             # Heuristic hash detector & candidate ranking
│   │   │   ├── hasher/              # Cryptographic text & chunked streaming hasher
│   │   │   ├── cracker/             # Dictionary & batched brute-force engines
│   │   │   ├── cipher_tools/        # Classical ciphers, pipeline & detector
│   │   │   └── history/             # In-memory session history data model & audit exporter
│   │   └── tests/
│   │       └── integration.rs       # Cross-module integration tests (42 tests)
│   │
│   └── wasm-frontend/               # wasm-frontend: WebAssembly browser client
│       ├── Cargo.toml               # wasm-bindgen, web-sys, js-sys
│       ├── Trunk.toml               # Trunk build configuration
│       ├── index.html               # Semantic HTML app shell & ARIA regions
│       ├── 404.html                 # SPA fallback redirector for GitHub Pages
│       ├── manifest.json            # Web app manifest for PWA installation
│       ├── style.css                # Responsive stylesheet & design system
│       ├── motion.js                # Three.js canvas & GSAP scroll interactions
│       └── src/
│           └── lib.rs               # DOM event listeners, WASM start, UI wiring
│
└── .github/
    └── workflows/
        └── deploy.yml               # CI/CD: Quality gates, security audit & Pages deployment
```

---

## 🛠️ Development & Building

### Prerequisites

- [Rust](https://www.rust-lang.org/) (2021 edition, `1.80+` or newer)
- WebAssembly target:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- [Trunk](https://trunkrs.dev/):
  ```bash
  cargo install trunk --version 0.21.14 --locked
  ```
- `wasm-bindgen-cli`:
  ```bash
  cargo install wasm-bindgen-cli --version 0.2.126 --locked
  ```

### Local Development Server

Run the development server with live-reloading:

```bash
cd crates/wasm-frontend
trunk serve --port 8080
```
Then visit `http://localhost:8080` in your browser.

### Production Release Build

Compile the optimized release WebAssembly bundle:

```bash
cd crates/wasm-frontend
trunk build --release --public-url "./"
```
Distribution artifacts will be generated in `crates/wasm-frontend/dist/`.

---

## 🧪 Quality Gates & Testing

Specter maintains strict testing and linting standards:

```bash
# Run all unit and integration tests (125 tests)
cargo test --workspace --all-targets

# Verify code formatting
cargo fmt --all -- --check

# Run Clippy with zero warnings permitted
cargo clippy --workspace --all-targets -- -D warnings

# Build WASM target directly
cargo check -p wasm-frontend --target wasm32-unknown-unknown

# Generate documentation
cargo doc --workspace --no-deps
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
