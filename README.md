# AIGCCore

[![Rust](https://img.shields.io/badge/Rust-dea584?style=flat-square&logo=rust&logoColor=white)](#) [![TypeScript](https://img.shields.io/badge/TypeScript-3178c6?style=flat-square&logo=typescript&logoColor=white)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> Most AI apps leak data by default and audit by accident. AIGCCore flips that — offline-first, hash-chained audit trail, deterministic artifact serialization

AIGCCore is a local-first governance and audit kernel for privacy-first desktop AI applications, with EvidenceOS as its sole pack. EvidenceOS maps evidence to capability-based controls and produces citation-grounded exports through the kernel's deterministic bundle and audit pipeline. The scope decision is recorded in [ADR 0011](docs/adr/0011-scope-kernel-and-evidenceos.md).

## Features

- **Offline-by-default enforcement** — the app runs fully offline; any online capability is explicitly gated, network egress is allowlisted, and local model adapters are restricted to literal IPv4 loopback addresses or ::1
- **Deterministic outputs** — canonical JSON and ZIP serialization are deterministic for identical bundle contents; runtime audit timestamps can change complete bundle hashes between runs
- **Hash-chained audit trail** — recorded audit events are canonicalized and hash-chained; local verification detects edits inconsistent with the stored hash chain without an external service
- **Evidence Bundle v1 exports** — locked bundle contract includes all artifacts, hashes, and metadata needed for third-party verification
- **Eval gates** — stable-ID quality and security correctness gates run before any bundle export is finalized
- **Fuzz/property tests** — a cargo-fuzz target exercises the Rust authority-integrity loopback policy boundary; fast-check property tests cover the UI request handoff before Rust validation

## OpenSSF Best Practices

AIGCCore is preparing OpenSSF Best Practices badge registration. The registration
plan and closure criteria live in [`docs/openssf-best-practices.md`](docs/openssf-best-practices.md).

## Setup

### Prerequisites

- Rust **1.97.1**, pinned in `rust-toolchain.toml` with rustfmt and Clippy
  (install [rustup](https://rustup.rs); Cargo selects the pin automatically).
- Node.js **26.11.1**, pinned in `.node-version`; the supported major is 26.
- pnpm **10.29.2**, pinned by `packageManager` in `package.json`.
- Make and the [Tauri platform prerequisites](https://tauri.app/start/prerequisites/)
  for macOS, Windows, or Linux. On Windows, use a Make-compatible shell.

After cloning, one command installs the committed dependency graph and Chromium,
then checks every shipped language surface:

```bash
make setup && make check
```

`make setup` uses only frozen pnpm installs. `make check` checks Rust formatting
and Clippy, lint/typecheck, Rust and JS tests, authority integrity, integration
gates, and UI regression without rewriting source or lockfiles. `make test`
runs just the tests; `make build` builds the desktop app. Native platform
dependencies must be installed first; Linux browser hosts may additionally need
`pnpm exec playwright install-deps chromium`.

### Usage

For fixture tests, static checks, and the full CI verification lane, see
[Contributing: verification](CONTRIBUTING.md#verification). Release and cleanup
commands below are separate operations, not verification prerequisites.

```bash
# Development mode
pnpm dev

# Low-disk development mode
pnpm lean:dev

# Run tests
pnpm test

# Run the authority-integrity loopback policy fuzzer
cargo install cargo-fuzz
cargo fuzz run authority_integrity_loopback

# Production build
pnpm tauri build

# Production macOS direct-distribution release
pnpm release:macos

# Clean heavy build artifacts
pnpm clean:heavy
```

`pnpm release:macos` is the only production macOS distribution path. It
requires a usable Developer ID identity plus complete Apple notarization
credentials, builds the app separately in a non-File-Provider Cargo target,
normalizes unsafe extended attributes, packages a metadata-clean DMG, mounts
the image to verify the embedded app, and requires Gatekeeper and stapled-ticket
validation. The multi-platform release workflow uses this path for macOS;
Windows and Linux jobs currently prove packaging and checksums, not platform
signing.

AIGCCore does not currently claim an in-app Tauri updater, automatic upgrade,
downgrade, or rollback channel. A rollback is a manual reinstall of a separately
qualified prior artifact and requires its own execution receipt.

## Status

Active infrastructure development is focused on the governance kernel and its sole
pack, EvidenceOS. The Rust core owns governance logic, audit canonicalization,
hash chaining, determinism enforcement, and bundle assembly.

### Stack

| Layer          | Technology                                |
| -------------- | ----------------------------------------- |
| Desktop shell  | Tauri 2                                   |
| Core logic     | Rust (aes-gcm, sha2, serde)               |
| UI             | React + TypeScript                        |
| Build          | Vite                                      |
| Storage        | File-backed vault for SQLite bytes and blob artifacts |
| Cryptography   | AES-256-GCM, XChaCha20-Poly1305, SHA-256   |
| Audit chaining | Custom hash-chain canonicalization (Rust) |

### Known risks

- Any online capability must remain explicitly gated and allowlisted.
- Audit canonicalization and hash chaining must remain deterministic.
- Evidence Bundle v1 validity requires the validator checklist to pass.
- The React frontend must use the Tauri command surface to modify audit state.
- Desktop builds regenerate the tracked Tauri permission schemas from the locked
  dependencies. CI checks that this deterministic regeneration leaves no diff.

### Next steps

Keep future work focused on deterministic bundle validation, audit-chain integrity,
and offline enforcement. Dependency major upgrades and robustness work are
separate follow-up waves.

## Architecture

The Rust `aigc_core` crate in `core/` is the single source of truth for all governance logic — audit event canonicalization, hash chaining, determinism enforcement, and bundle assembly. It has no network access; any adapter that needs to call a local model does so only through the allowlisted loopback adapter interface defined in Annex B. The Tauri shell exposes a minimal [command surface](docs/command-surface.md) to the React frontend; the frontend cannot directly modify audit state. `src-tauri/src/lib.rs` wires the app, `commands/` owns the entry points, and `export/` owns the EvidenceOS bundle path. Evidence bundles are assembled by `EvidenceBundleBuilder` in the Rust core; `RunManager` runs eval gates and v3 bundle validation before finalizing exports. The `bundle_validator` tool validates existing ZIPs and reports results; bundle ZIPs are SHA-256 hashed, without cryptographic signatures.

## License

MIT
