# AIGCCore

[![Rust](https://img.shields.io/badge/Rust-dea584?style=flat-square&logo=rust&logoColor=white)](#) [![TypeScript](https://img.shields.io/badge/TypeScript-3178c6?style=flat-square&logo=typescript&logoColor=white)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> Most AI apps leak data by default and audit by accident. AIGCCore flips that — offline-first, hash-chained audit trail, provably deterministic outputs

AIGCCore is a local-first governance and audit engine for privacy-first desktop AI applications. It acts as a shared backbone for multiple specialized desktop Packs — each Pack inherits strict privacy boundaries, deterministic artifact generation, and a tamper-evident audit trail without rebuilding that infrastructure from scratch.

## Features

- **Offline-by-default enforcement** — the app runs fully offline; any online capability is explicitly gated, network egress is allowlisted, and local model adapters are restricted to loopback (127.0.0.1)
- **Deterministic outputs** — given identical inputs, config, and model identity pin the system produces identical computed metrics, exports, and hashes; controlled by a locked ruleset
- **Hash-chained audit trail** — every action is recorded as a canonicalized audit event; events are hash-chained so any tampering is detectable without an external service
- **Evidence Bundle v1 exports** — locked bundle contract includes all artifacts, hashes, and metadata needed for third-party verification
- **Eval gates** — stable-ID quality and security correctness gates run before any bundle export is finalized

## Quick Start

### Prerequisites

- Rust stable toolchain (via [rustup](https://rustup.rs))
- Node.js 18+
- pnpm 8+
- macOS, Windows, or Linux

### Installation

```bash
git clone https://github.com/saagpatel/AIGCCore.git
cd AIGCCore
pnpm install
```

### Usage

```bash
# Development mode
pnpm dev

# Low-disk development mode
pnpm lean:dev

# Run tests
pnpm test

# Production build
pnpm tauri build

# Clean heavy build artifacts
pnpm clean:heavy
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Desktop shell | Tauri 2 |
| Core logic | Rust (aes-gcm, sha2, serde) |
| UI | React + TypeScript |
| Build | Vite |
| Storage | SQLite + blob artifact store |
| Cryptography | AES-256-GCM, ChaCha20-Poly1305, SHA-256 |
| Audit chaining | Custom hash-chain canonicalization (Rust) |

## Architecture

The Rust `core` crate is the single source of truth for all governance logic — audit event canonicalization, hash chaining, determinism enforcement, and bundle assembly. It has no network access; any adapter that needs to call a local model does so only through the allowlisted loopback adapter interface defined in Annex B. The Tauri shell exposes a minimal command surface to the React frontend; the frontend cannot directly modify audit state. Evidence bundles are assembled by the `bundle_validator` tool, which runs the full `Bundle_Validator_Checklist_v3` before producing a signed ZIP output.

## License

MIT
