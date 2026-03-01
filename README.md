# AIGC Core (Private AI Governance Core)
Local-first governance + audit core for privacy-first desktop Packs.

## What this is
**AIGC Core** is a **local-first, offline-by-default** governance engine and desktop app foundation that enables **provably auditable** AI workflows on a single machine.

It is designed to be the shared “spine” behind multiple monetizable desktop **Packs** (specialized applications) that need:
- strict privacy boundaries
- deterministic artifacts
- verifiable audit trails
- optional, explicitly gated online features

**Fixed stack**
- Desktop: **Tauri**
- Core logic: **Rust**
- UI: **React + TypeScript**
- Storage: **SQLite + blob artifact store**
- Local model integration: adapters over **127.0.0.1** only

## What it does (high level)
AIGC Core provides four pillars:

### 1) Offline-by-default enforcement
The app runs fully offline by default.
- Any online capability is **explicitly gated**
- Network egress is **allowlisted**
- Local model adapters are restricted to **loopback (127.0.0.1)**

### 2) Deterministic, reproducible outputs
Given the same inputs, config, and model identity pin, the system produces the same:
- computed metrics
- exported bundles
- reports
- hashes

Determinism is controlled by a locked ruleset and verified by a validator checklist.

### 3) Provable audit trail (hash-chained)
Every relevant action is recorded as an **audit event**:
- events are canonicalized
- events are **hash-chained**
- exports contain the evidence needed for third-party verification

This enables tamper-evidence without relying on any external service.

### 4) Evidence Bundle exports (locked v1 contract)
The system exports an **Evidence Bundle v1** that includes:
- a strict directory layout
- a manifest + audit chain artifacts
- deterministic file ordering/format rules
- citations + redaction metadata (when applicable)

Bundles are intended to be verifiable by a separate validator toolchain.

## Why we’re doing it
Most AI-enabled apps fail the “prove it” test:
- they can’t demonstrate what happened
- they can’t reproduce results
- they can’t show which model/version was used
- they blur privacy boundaries when “helpful” features phone home

AIGC Core exists so our desktop Packs can be:
- **trustworthy** (verifiable evidence, not vibes)
- **safe by design** (offline-first, least privilege networking)
- **auditable** (hash chain + deterministic exports)
- **commercially viable** (shared governance core reduces per-Pack build cost)

## Who this is for
- Independent professionals and teams who need local privacy
- Security/compliance-conscious orgs evaluating AI workflows
- Builders shipping desktop AI products that must be auditable

## What ships first
Phase 2 focuses on the “hard guarantees”:
- offline enforcement proof
- audit hash-chain canonicalization rules
- deterministic export rules + determinism matrix
- bundle structure + validator requirements
- citations/redaction requirements + gating
- model identity/version pinning rules
- eval gates (quality/security correctness gates)

## Where to look next (in this repo)
If you are implementing or reviewing the system, start here:
- **Phase_2_5_Lock_Addendum_v2.5-lock-4.md** (non-negotiable locks)
- **Annex_A_Evidence_Bundle_v1_Spec.md** (locked bundle contract)
- **Annex_B_Adapter_Interface_v1_Spec.md** (locked adapter contract)
- **Bundle_Validator_Checklist_v3.md** (what “valid” means)
- **docs/spec-compliance-map.md** (requirement-to-implementation traceability)

## Non-negotiables (summary)
- Offline-by-default; online is opt-in + allowlisted
- Local model adapters only via 127.0.0.1
- Deterministic exports when determinism mode enabled
- Audit events are canonicalized and hash-chained
- Evidence Bundle v1 layout is honored
- Eval gates are stable-ID and enforced

---
**Status:** Spec packet finalized for Codex implementation.

## Development Modes

### Normal dev (faster warm starts, larger disk footprint)
- Start app: `pnpm dev`
- Behavior:
  - Uses standard local cache/build locations.
  - Rust artifacts grow under `target/`.
  - Vite cache grows under `node_modules/.vite`.

### Lean dev (lower disk growth, slower cold starts)
- Start app: `pnpm lean:dev`
- Behavior:
  - Starts Tauri dev normally, but with temporary cache locations.
  - Uses a temporary `CARGO_TARGET_DIR` for Rust build artifacts.
  - Uses a temporary Vite cache directory.
  - Cleans heavy project build artifacts automatically on exit.

## Cleanup Commands

### Targeted cleanup (heavy build artifacts only)
- Command: `pnpm clean:heavy`
- Removes:
  - `dist/`
  - `target/`
  - `src-tauri/target/`
  - `.vite/`
  - `node_modules/.vite/`

### Full local cleanup (all reproducible local caches/deps)
- Command: `pnpm clean:full-local`
- Removes everything from targeted cleanup, plus:
  - `node_modules/`
  - root `*.tsbuildinfo`

## Disk vs Speed Tradeoff
- `pnpm dev`:
  - Faster after first compile.
  - Uses more disk over time (especially Rust `target/`).
- `pnpm lean:dev`:
  - Keeps repository disk usage low after each session.
  - Rebuilds more often, so startup can be slower.
