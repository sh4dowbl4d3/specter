# Project Structure — devastator

A browser-based toolkit for hash identification, checksum calculation, dictionary & brute-force hash cracking, classical cipher encoding/decoding/detection, file forensics, and session auditing. Everything runs **client-side in WebAssembly** — there is no server.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Browser (WASM)                        │
│                                                             │
│  wasm-frontend (Rust → WASM via Trunk + wasm-bindgen)       │
│    ├── UI: DOM building, tabs, keyboard shortcuts, toasts   │
│    ├── File handling: upload / drag & drop / streaming read │
│    ├── Ephemeral session history & privacy wipe             │
│    └── calls into ▼                                         │
│                                                             │
│  devastator-core (pure Rust algorithm library)              │
│    ├── hash_id      — hash type heuristics & rankings       │
│    ├── hasher       — single/multi-hash & chunked streaming │
│    ├── cracker      — dictionary & batched brute-force      │
│    ├── cipher_tools — codecs, heuristics & pipeline engine  │
│    └── history      — bounded RAM session buffer & exporter │
└─────────────────────────────────────────────────────────────┘
```

The architectural boundary: **all algorithms live in `crates/core`**, a pure-Rust crate with no DOM dependencies, no network I/O, and no threading constraints beyond standard WASM capabilities. The frontend crate (`crates/wasm-frontend`) wires that logic to the DOM via `wasm-bindgen` and `web-sys`. This architecture ensures all algorithms are unit-tested and benchmarked on the host with standard `cargo test`.

---

## Repository Layout

```
devastator/
├── Cargo.toml                       # Workspace root & release optimizations
├── Cargo.lock
├── README.md                        # User-facing manual & quick start
├── STRUCTURE.md                     # Architectural documentation
├── LICENSE                          # MIT license
├── .gitignore
│
├── crates/
│   ├── core/                        # devastator-core — pure algorithm crate
│   │   ├── Cargo.toml               # md5, sha1, sha2, md4, base64, hex, serde
│   │   ├── src/
│   │   │   ├── lib.rs               # Re-exports core modules
│   │   │   ├── hash_id/             # Hash type heuristics & attack mode mapping
│   │   │   │   ├── mod.rs
│   │   │   │   └── identifier.rs    # HashType enum, identify() heuristics
│   │   │   ├── hasher/              # Cryptographic hash generator & streaming
│   │   │   │   ├── mod.rs
│   │   │   │   ├── algorithms.rs    # HashAlgorithm enum & compute functions
│   │   │   │   └── streaming.rs     # Chunked IncrementalHasher
│   │   │   ├── cracker/             # Cracking engines
│   │   │   │   ├── mod.rs
│   │   │   │   ├── dictionary.rs    # Streaming crack_from_list()
│   │   │   │   └── brute_force.rs   # Step-based BruteForceSession & budget caps
│   │   │   ├── cipher_tools/        # Classical ciphers & detection
│   │   │   │   ├── mod.rs
│   │   │   │   ├── ciphers.rs       # Caesar, ROT13, Atbash, Base64, Hex, Binary,
│   │   │   │   │                    # Vigenere, Affine, Bacon, Morse, Rail Fence,
│   │   │   │   │                    # URL, Decimal, XOR & Pipeline execution
│   │   │   │   ├── detector.rs      # Entropy, quadgrams & scoring heuristics
│   │   │   │   └── error.rs         # CipherError type
│   │   │   └── history/             # Ephemeral in-memory session audit log
│   │   │       └── mod.rs           # SessionHistory, HistoryEntry, Markdown/JSON export
│   │   └── tests/
│   │       └── integration.rs       # Cross-module integration tests (42 tests)
│   │
│   └── wasm-frontend/               # wasm-frontend — browser UI (cdylib)
│       ├── Cargo.toml               # wasm-bindgen, web-sys, js-sys; depends on core
│       ├── Trunk.toml               # Trunk build & asset copy configuration
│       ├── index.html               # App shell (static panels, header, drawer, ARIA)
│       ├── 404.html                 # SPA fallback redirector for GitHub Pages
│       ├── manifest.json            # Web App Manifest (PWA metadata)
│       ├── style.css                # Visual design system, drawer & animations
│       ├── motion.js                # Three.js canvas & GSAP scroll interactions
│       └── src/
│           └── lib.rs               # #[wasm_bindgen(start)] entry point & UI handlers
│
├── .github/
│   └── workflows/
│       └── deploy.yml               # CI/CD: Quality gates, security audit & Pages deploy
│
└── wordlists/                       # Dictionary files (large files gitignored)
```

---

## The Core Crate (`crates/core`)

### `hash_id`
Format-heuristic hash identification. `HashType` enumerates known types (MD5, SHA-1, SHA-224/256/384/512, SHA-3 family, bcrypt, NTLM, MySQL <4.1, MySQL 4.1+, RIPEMD-160). `identify(input)` scores strings by length and character patterns, returning ranked `Identification` candidates with attack guidance.

### `hasher`
Cryptographic digest calculation engine.
- `compute_hash` / `compute_hash_text`: Computes individual digests.
- `compute_all_hashes` / `compute_all_hashes_text`: Computes all 9 supported algorithms in a single pass.
- `compare_hashes`: Normalizes and compares two hash digests.
- `IncrementalHasher`: Chunked streaming buffer for memory-efficient hashing of large payloads.

### `cracker`
Two cracking engines:
- **Dictionary** (`dictionary.rs`): Streaming candidate verification across MD5, SHA-1/2, NTLM, and MySQL formats against wordlists.
- **Brute Force** (`brute_force.rs`): Step-based non-blocking keyspace search (`BruteForceSession`) yielding to the browser event loop, with search space estimations and a 20M attempt safety cap.

### `cipher_tools`
- **Codecs** (`ciphers.rs`): Base64, Hexadecimal, Binary, ASCII Decimal, URL encoding, Caesar (all shifts), ROT13, Atbash, Vigenère, Affine, Bacon, Morse Code, Rail Fence, XOR streaming, and chained `TransformationPipeline`.
- **Heuristic Detector** (`detector.rs`): Scores cipher candidates using Shannon entropy, charset distributions, English quadgrams, and dictionary decodability ranking.

### `history`
- **In-Memory Buffer** (`history.rs`): Thread-safe, bounded ring buffer storing recent operations (`HistoryEntry`).
- **Exporters**: Client-side Markdown audit report generator (`export_markdown()`) and formatted JSON log generator (`export_json()`).

---

## The Frontend Crate (`crates/wasm-frontend`)

Single-crate WebAssembly client compiled with [Trunk](https://trunkrs.dev/):
- **DOM Architecture**: `index.html` statically defines the layout, tab panels, and drawer modal.
- **Event Wiring**: `src/lib.rs` initializes listeners, handles tab switching, manages clipboard copy actions, registers global keyboard shortcuts, and orchestrates async cracking steps.
- **Memory Wipe**: Dedicated routine purges `SESSION_HISTORY` and resets all UI controls.
- **SPA 404 Routing**: `404.html` fallback preserves routes and parameters on GitHub Pages.

---

## Build & Quality Gates

```bash
# Host tests across all crates (125 tests)
cargo test --workspace --all-targets

# WASM target check
cargo check -p wasm-frontend --target wasm32-unknown-unknown

# Linter & formatting checks
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Release build
cd crates/wasm-frontend && trunk build --release --public-url "./"
```
