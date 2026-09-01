# Project Structure — specter

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
│  specter-core (pure Rust algorithm library)                 │
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
specter/
├── Cargo.toml                       # Workspace root & release optimizations
├── Cargo.lock
├── README.md                        # User-facing manual & quick start
├── STRUCTURE.md                     # Architectural documentation
├── LICENSE                          # MIT license
├── .gitignore
│
├── crates/
│   ├── core/                        # specter-core — pure algorithm crate
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
- `IncrementalHasher`: Streaming chunk processor for files.

### `cracker`
Hash cracking implementations.
- `dictionary`: Iterates candidate lists, hashes each according to the target algorithm, and returns the match.
- `brute_force`: State-machine `BruteForceSession` that tests character combinations incrementally with configurable character sets (`lowerdigit`, `lower`, `alnum`) and max length caps up to 20,000,000 attempts.

### `cipher_tools`
Ciphers, encodings, and statistical detection.
- `ciphers`: Pure-Rust implementations of classical ciphers (Caesar with brute-force, ROT13, Atbash, Vigenère, Affine, Bacon, Morse, Rail Fence, XOR) and encodings (Base64, Hex, Binary, ASCII Decimal, URL), with pipeline support.
- `detector`: Statistical analyzer calculating Shannon entropy, character set distribution, quadgram scoring, and format patterns to rank candidate ciphers.

### `history`
Session audit log.
- `SessionHistory`: Bounded RAM ring buffer (capacity 100) storing `HistoryEntry` records.
- Export capabilities to formatted JSON and structured Markdown documents.
