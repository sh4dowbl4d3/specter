# Project Structure — devastator

A browser-based toolkit for hash identification, hash cracking, and classical cipher
encode/decode/detect. Everything runs **client-side in WebAssembly** — there is no server.
This document explains how the repository is laid out and how the pieces fit together.

## High-Level Architecture

```
┌───────────────────────────────────────────────┐
│                Browser (WASM)                 │
│                                               │
│  wasm-frontend (Rust → WASM via Trunk)        │
│    ├── UI: DOM building, tabs, events         │
│    ├── File handling: upload / drag & drop    │
│    └── calls into ▼                           │
│                                               │
│  devastator-core (pure Rust library)          │
│    ├── hash_id      — hash type detection     │
│    ├── cracker      — dictionary + brute force│
│    └── cipher_tools — ciphers + detection     │
└───────────────────────────────────────────────┘
```

The key design split: **all algorithms live in `crates/core`**, a pure-Rust crate with no
DOM access, no I/O, and no threading constraints beyond what WASM allows. The frontend
crate (`crates/wasm-frontend`) only wires that logic up to the DOM via `wasm-bindgen`.
This keeps the algorithms testable with plain `cargo test` on the host.

## Repository Layout

```
devastator/
├── Cargo.toml                  # Workspace root (members + release profile)
├── Cargo.lock
├── README.md                   # User-facing docs (usage, build, deploy)
├── LICENSE
├── .gitignore
│
├── crates/
│   ├── core/                   # devastator-core — pure algorithm library
│   │   ├── Cargo.toml          # serde, thiserror, md5/sha1/sha2/md4, base64, hex
│   │   ├── src/
│   │   │   ├── lib.rs          # Re-exports the three modules below
│   │   │   ├── hash_id/
│   │   │   │   ├── mod.rs
│   │   │   │   └── identifier.rs   # HashType enum + identify() heuristics
│   │   │   ├── cracker/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── dictionary.rs   # crack_from_list() + hash_* helpers
│   │   │   │   └── brute_force.rs  # BruteForceConfig/Result + brute_force_crack()
│   │   │   └── cipher_tools/
│   │   │       ├── mod.rs
│   │   │       ├── ciphers.rs      # encode/decode for each cipher
│   │   │       ├── detector.rs     # detect_cipher() scoring engine
│   │   │       └── error.rs        # CipherError type
│   │   └── tests/
│   │       └── integration.rs      # Cross-module integration tests
│   │
│   └── wasm-frontend/          # wasm-frontend — browser UI (cdylib)
│       ├── Cargo.toml          # wasm-bindgen, web-sys, js-sys; depends on core
│       ├── Trunk.toml          # Trunk build config
│       ├── index.html          # App shell (all sections/tabs defined statically)
│       ├── style.css           # Styling
│       ├── motion.js           # Small JS helper for animations
│       └── src/
│           └── lib.rs          # #[wasm_bindgen(start)] entry point + all UI wiring
│
├── .github/
│   └── workflows/
│       └── deploy.yml          # CI: fmt/clippy/test/audit → trunk build → GitHub Pages
│
└── wordlists/                  # Dictionary files (large ones gitignored)
```

## The Core Crate (`crates/core`)

Three modules, re-exported from `src/lib.rs`:

### `hash_id`
Format-heuristic hash identification. `HashType` enumerates known types (MD5, SHA-1,
SHA-2 family, SHA-3 family, bcrypt, NTLM, MySQL, RIPEMD-160); `identify(input)` scores an
input string by length and charset patterns and returns ranked `Identification` candidates.
Detection-only — it never attempts to crack anything.

### `cracker`
Two engines:

- **Dictionary** (`dictionary.rs`) — `crack_from_list(hash, wordlist)` hashes candidate
  words and compares against the target. Implements hashing for MD5, SHA-1/224/256/384/512,
  NTLM (MD4 of UTF-16LE), MySQL <4.1 and MySQL 4.1+ formats. The `hash_*` functions are
  also used by the file-hashing feature.
- **Brute force** (`brute_force.rs`) — bounded exhaustive search over a configurable
  charset/length range (`BruteForceConfig` → `BruteForceResult`). Hard-capped so a browser
  tab can't hang indefinitely (~20M attempts max).

### `cipher_tools`
- `ciphers.rs` — encode/decode implementations: Caesar (plus full-shift brute force),
  ROT13, Atbash, Base64, Hex, Binary, Vigenère.
- `detector.rs` — `detect_cipher(input)` returns scored `CipherDetection` candidates based
  on statistical properties of the input (charset shape, entropy signals, decodability).
- `error.rs` — `CipherError`, used by the lossy decode paths (Base64/Hex/Binary).

Integration tests live in `tests/integration.rs` and exercise the modules together
(e.g., identify → crack round-trips, encode → detect → decode).

## The Frontend Crate (`crates/wasm-frontend`)

A single-crate WASM app built with [Trunk](https://trunkrs.dev):

- `index.html` is the static shell — all tabs/panels/buttons exist as DOM elements;
  the Rust code never creates top-level layout, it only fills and toggles them.
- `src/lib.rs` is the whole application:
  - A `#[wasm_bindgen(start)]` function runs on load: installs the panic hook, then wires
    up tabs, copy buttons, keyboard shortcuts, and one setup function per feature area
    (`setup_hash_identify`, `setup_crack`, `setup_cipher_tools`, `setup_file_tools`).
  - Small DOM helpers (`el`, `val`, `text`, `show`/`hide`, `toast`) keep the web-sys
    boilerplate readable.
  - `thread_local!` cells hold session state: the loaded wordlist and pending files for
    hash/cipher file uploads.
  - Feature areas map 1:1 onto core modules: hash identification, cracking (paste or
    upload wordlist), cipher tools, and file hashing/transforms (64 MiB cap).

There is no framework and no virtual DOM — direct `web_sys` manipulation throughout.

## Build & Toolchain

```bash
cargo install trunk
rustup target add wasm32-unknown-unknown

# Dev server with hot reload
cd crates/wasm-frontend && trunk serve --port 8080

# Release build
trunk build --release            # add --public-url "./" for Pages-style subpaths

# Tests & quality gates (run on the host target, no WASM needed)
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The workspace release profile enables `lto = true`, `codegen-units = 1`,
`panic = "abort"`, and `strip = true` to keep the shipped WASM binary small and fast.

## CI / Deployment

`.github/workflows/deploy.yml` runs on every push to `main` (and PRs):

1. fmt check → clippy `-D warnings` → tests → `cargo audit`
2. `trunk build --release --public-url "./"`
3. Uploads `crates/wasm-frontend/dist` and deploys to **GitHub Pages**

So the deployed site is fully static — one HTML page, one WASM blob, CSS, and a small JS
helper served from Pages.
