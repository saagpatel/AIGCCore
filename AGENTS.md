# AGENTS.md (Repo Root) — AIGC Core

This file defines canonical project commands, paths, and repo-specific conventions for this workspace.

## Canonical Paths
- Rust domain core: `/Users/d/Projects/AIGCCore/core`
- Tauri shell + command handlers: `/Users/d/Projects/AIGCCore/src-tauri`
- React UI: `/Users/d/Projects/AIGCCore/src`
- Local validator CLI(s): `/Users/d/Projects/AIGCCore/tools`
- Packet-driven docs created in-repo: `/Users/d/Projects/AIGCCore/docs`

## Canonical Commands
Primary runner is `pnpm` and Rust `cargo`.

- Install deps: `pnpm install`
- Dev (desktop): `pnpm dev`
- Build (desktop): `pnpm build`
- Run all eval gates locally: `pnpm gate:all`
- Rust tests: `cargo test --workspace`

Source of truth for scripts is `/Users/d/Projects/AIGCCore/package.json`.

## Hard Rules (Packet-Aligned)
- Offline-by-default is enforced in Rust core; UI must not have direct egress.
- Adapters are loopback-only (`127.0.0.1`) and must implement Annex B v1.
- Evidence Bundle exports must comply with Annex A v1 + Phase 2.5 lock addendum.
- Determinism mode must follow Addendum A + ZIP hardening rules.
- Audit trail must be canonicalized and hash-chained per lock addendum and taxonomy.


## Codex Reliability Contract

### Canonical Verification Commands (Source of Truth)
Source: `.codex/verify.commands` (derived from `AGENTS.md` and `package.json`)
- lint: `pnpm lint`
- format-check: `N/A (no standalone formatter check defined in AGENTS/CI)`
- typecheck: `N/A (no standalone typecheck command defined in AGENTS/CI)`
- unit-test: `pnpm test`; `cargo test --workspace`
- integration-test: `pnpm gate:all`
- build: `pnpm build`

### Definition of Done
- All commands in `.codex/verify.commands` pass via `.codex/scripts/run_verify_commands.sh`.
- No open `critical` or `high` `ReviewFindingV1` findings.
- Diff scope matches approved task scope.
- Security checks (secrets, dependency, and SAST) are clean or explicitly waived with owner + expiry.

### Agent Contract
- Reviewer agent: read-only and emits only `ReviewFindingV1` findings.
- Fixer agent: applies accepted findings in severity order and reports exact file patches + verification.
- Final verifier: re-runs `.codex/scripts/run_verify_commands.sh` and summarizes `GateReportV1`.

## UI Hard Gates (Required for frontend/UI changes)

1) Read-only reviewer outputs `UIFindingV1[]` (`/Users/d/.codex/contracts/UIFindingV1.schema.json`).
2) Fixer applies accepted findings in severity order: `P0 -> P1 -> P2 -> P3`.
3) Required state coverage per changed UI surface: loading, empty, error, success, disabled, focus-visible.
4) Required pre-done gates:
   - `pnpm ui:gate:static`
   - `pnpm ui:gate:regression`
   - Lighthouse CI workflow (`.github/workflows/lighthouse.yml`)
5) Done-state is blocked if any required UI gate is `fail` or `not-run`.

## Definition of Done: Tests + Docs (Blocking)

- Any production code change must include meaningful test updates in the same PR.
- Meaningful tests must include at least:
  - one primary behavior assertion
  - two non-happy-path assertions (edge, boundary, invalid input, or failure mode)
- Trivial assertions are forbidden (`expect(true).toBe(true)`, snapshot-only without semantic assertions, render-only smoke tests without behavior checks).
- Mock only external boundaries (network, clock, randomness, third-party SDKs). Do not mock the unit under test.
- UI changes must cover state matrix: loading, empty, error, success, disabled, focus-visible.
- API/command surface changes must update generated contract artifacts and request/response examples.
- Architecture-impacting changes must include an ADR in `/docs/adr/`.
- Required checks are blocking when `fail` or `not-run`: lint, typecheck, tests, coverage, diff coverage, docs check.
- Reviewer -> fixer -> reviewer loop is required before merge.
