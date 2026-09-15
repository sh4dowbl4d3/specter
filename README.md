# Specter

Fast, offline-first cryptanalysis and cybersecurity toolkit built with Rust and WebAssembly.

Specter provides in-browser cryptographic hash identification, multi-algorithm checksum generation, dictionary and bounded brute-force hash cracking, classical cipher codecs with statistical heuristic detection, and client-side file forensics. All computations run on the client machine via WebAssembly without external network requests.

## Live workbench

The production build is deployed on GitHub Pages:

https://sh4dowbl4d3.github.io/specter/

## Preview

![Specter Cryptanalysis Workbench](screenshots/screenshot.png)

## Key capabilities

- Zero-network architecture: all algorithms, cracking loops, and cipher transforms run locally inside the browser without transmitting data off your device.
- Memory safety and execution speed: core algorithms are written in Rust and compiled to WebAssembly.
- Non-blocking execution: long-running brute-force cracking and streaming file hashing yield cooperatively to the browser event loop to keep the UI responsive.
- Ephemeral session security: an in-memory ring buffer tracks session history with one-click privacy purge and export options.

## Toolkit instruments

Specter is organized into four operational desks and an audit drawer:

### 1. Hash identification and generation desk

- Heuristic hash identification analyzes digest length, character set, and format signatures against known cryptographic hash families (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-3 variants, bcrypt, NTLM, MySQL 3.23, MySQL 4.1+, and RIPEMD-160). It outputs confidence scores, format notes, and Hashcat/John attack mode numbers.
- Simultaneous multi-hash generation computes 9 digest algorithms in a single streaming pass (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, NTLM, MySQL 3.23, and MySQL 4.1+).
- Hash signature comparison checks two digests with case-insensitive normalization, length checking, and algorithm signature validation.

### 2. Hash cracking desk

- Dictionary attacks match candidates against custom wordlists pasted directly or loaded from local `.txt` or `.lst` files.
- Batched asynchronous brute-force searches configurable character sets (lowercase, alphanumeric, digits) with a 20,000,000 computation budget, real-time keyspace estimation, and cancel/resume controls.

### 3. Classical ciphers and encodings desk

- Encoding formats: Base64 (RFC 4648), hexadecimal with delimiter formatting, binary (8-bit bytes), ASCII decimal (space, comma, semicolon, newline delimiters), and URL / percent encoding.
- Classical ciphers: Caesar (with a full 25-shift cryptanalysis preview), ROT13, Atbash, Vigenère (key-based), Affine, Baconian, Morse code, Rail Fence transposition, and XOR key streaming.
- Chained transformation pipelines support multi-step encoding and decoding workflows.
- Statistical auto-detection analyzes Shannon entropy, character set distributions, English quadgram frequencies, decodability heuristics, and dictionary rankings to identify and score unknown ciphertext.

### 4. File forensics and object transform desk

- Client-side file checksumming streams and hashes files up to 64 MiB in 64 KiB memory chunks without loading the full file into DOM memory.
- Text file cipher transforms apply Base64, Hex, ROT13, and Atbash directly to text files with immediate browser download.

### 5. Ephemeral session audit drawer

- In-memory ring buffer stores recent operations in RAM with a 100-entry limit.
- One-click privacy wipe clears form inputs, memory buffers, and session records.
- Structured audit export outputs session history as formatted Markdown (`specter-session-audit.md`) or machine-readable JSON (`specter-session-audit.json`).

## Supported algorithms and codecs

| Category | Algorithms / Formats | Execution Target |
|---|---|---|
| Cryptographic hashes | MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | Rust / WebAssembly |
| Legacy / system hashes | NTLM (MD4 UTF-16LE), MySQL 3.23, MySQL 4.1+ | Rust / WebAssembly |
| Hash identification | MD5, SHA-1, SHA-2, SHA-3, bcrypt, NTLM, MySQL, RIPEMD | Heuristic Engine |
| Standard encodings | Base64, Hexadecimal, Binary, ASCII Decimal, URL Percent | Rust / WebAssembly |
| Classical ciphers | Caesar, ROT13, Atbash, Vigenère, Affine, Baconian, Morse, Rail Fence, XOR | Rust / WebAssembly |

## Privacy and threat model

Specter is designed for private, local execution:

1. Zero server transmission: inputs, hashes, candidate wordlists, and files are never sent to remote servers.
2. Zero persistent storage: no tracking cookies, `localStorage`, or `indexedDB`. Refreshing or closing the tab clears all runtime state.
3. Strict Content Security Policy: uses `default-src 'self'` with directives restricting external connections, disallowing object embeds, and isolating execution.
4. Offline capability: Progressive Web App (PWA) manifest support allows caching and running completely offline.

## Global keyboard shortcuts

| Shortcut | Action | Scope |
|---|---|---|
| `Alt` + `1` | Switch to Identify desk | Global |
| `Alt` + `2` | Switch to Crack desk | Global |
| `Alt` + `3` | Switch to Ciphers desk | Global |
| `Alt` + `4` | Switch to Files desk | Global |
| `Alt` + `H` / `Ctrl` + `H` | Toggle session history drawer | Global |
| `Ctrl` + `Enter` / `Cmd` + `Enter` | Execute primary action for active desk | Global / Input focus |
| `Escape` | Close session drawer / dismiss notifications | Global |

## Project structure

The workspace separates core cryptographic logic from the browser frontend:

```
specter/
├── Cargo.toml                       # Workspace definition and release profiles
├── Cargo.lock
├── README.md                        # Documentation
├── STRUCTURE.md                     # Architectural layout
├── LICENSE                          # MIT License
├── screenshots/
│   └── screenshot.png               # Workbench interface preview
│
├── crates/
│   ├── core/                        # specter-core: Pure Rust algorithm library
│   │   ├── Cargo.toml               # md5, sha1, sha2, md4, base64, hex, serde
│   │   ├── src/
│   │   │   ├── lib.rs               # Module exports
│   │   │   ├── hash_id/             # Heuristic hash identification
│   │   │   ├── hasher/              # Cryptographic and streaming hashers
│   │   │   ├── cracker/             # Dictionary and brute-force engines
│   │   │   ├── cipher_tools/        # Ciphers, encoders, and auto-detect
│   │   │   └── history/             # Session audit buffer and exporters
│   │   └── tests/
│   │       ├── integration.rs       # Cross-module integration tests
│   │       └── e2e_real_vectors.rs  # NIST and RFC real-vector test suite
│   │
│   └── wasm-frontend/               # wasm-frontend: WebAssembly browser client
│       ├── Cargo.toml               # wasm-bindgen, web-sys, js-sys
│       ├── Trunk.toml               # Trunk build configuration
│       ├── index.html               # Semantic HTML application shell
│       ├── 404.html                 # Single-page application redirector
│       ├── manifest.json            # PWA manifest
│       ├── style.css                # Obsidian design system stylesheet
│       ├── motion.js                # Canvas background animation
│       └── src/
│           └── lib.rs               # DOM event listeners and WASM entry point
│
└── .github/
    └── workflows/
        └── deploy.yml               # CI/CD: Quality gates, security audit, Pages deploy
```

## Local development and building

### Prerequisites

- Rust (2021 edition, version 1.80 or newer):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- WebAssembly target:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- Trunk:
  ```bash
  cargo install trunk --version 0.21.14 --locked
  ```
- wasm-bindgen-cli:
  ```bash
  cargo install wasm-bindgen-cli --version 0.2.126 --locked
  ```

### Development server

Run the development server with hot-reloading:

```bash
cd crates/wasm-frontend
trunk serve --port 8080
```

Open `http://localhost:8080` in your browser.

### Production build

Compile optimized WebAssembly release artifacts:

```bash
cd crates/wasm-frontend
trunk build --release --public-url "./"
```

Build artifacts are written to `crates/wasm-frontend/dist/`.

## Quality assurance and testing

Run the workspace test and verification suite:

```bash
# Run all 139 tests across the workspace
cargo test --workspace --all-targets

# Check code formatting
cargo fmt --all -- --check

# Run Clippy with warnings treated as errors
cargo clippy --workspace --all-targets -- -D warnings

# Validate WebAssembly compilation
cargo check -p wasm-frontend --target wasm32-unknown-unknown

# Generate API documentation
cargo doc --workspace --no-deps
```

### Automated test coverage

- 83 unit tests verify algorithmic correctness across hashing, cracking, classical ciphers, and history tracking.
- 42 integration tests verify cross-module pipelines, streaming equivalence, and state isolation.
- 14 real-vector verification tests validate outputs against RFC 1321 (MD5), RFC 3174 (SHA-1), FIPS 180-4 (SHA-2), Windows SAM (NTLM), and CyberChef test vectors.

## License

This project is licensed under the [MIT License](LICENSE).
