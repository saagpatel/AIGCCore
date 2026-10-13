# AIGC Core agent instructions

<!-- comm-contract:start -->

## Communication Contract (Global)

- Inherit global Codex communication and reporting rules from `~/.codex/AGENTS.override.md` and `~/.codex/policies/communication/BigPictureReportingV1.md`.
- Repo-specific instructions below add project constraints only; do not restate global voice or status-reporting rules here.
- Honor toggles literally: `simple mode`, `show receipts`, `tech mode`, `debug mode`.
<!-- comm-contract:end -->

## Purpose

Keep changes scoped, reviewable, and consistent with the local-first kernel contracts.
Product scope and current status live in README.md.

## Layout

- `core/`: Rust governance, audit, determinism, and bundle assembly.
- `src-tauri/`: desktop shell and command handlers.
- `src/`: React UI; `tools/`: validators and gate runner.
- `docs/`: packet contracts, command examples, and ADRs.

## Setup

Use the pins in `rust-toolchain.toml`, `.node-version`, and `package.json`.
Install the README platform prerequisites, then run `make setup`.
All pnpm installs must use `--frozen-lockfile`; Cargo verification uses `--locked`.
Package scripts in `package.json` are the command source of truth.

## Checks

- `make check`: Rust fmt/clippy, lint/typecheck, Rust and JS tests, authority-integrity,
  integration gates, and UI regression. Checks must not rewrite source or lockfiles.
- `make test`: Rust/JS tests and the authority-integrity suite.
- `make build`: desktop build; tracked files must remain unchanged.
- Run `bash .codex/scripts/run_verify_commands.sh` for canonical verification;
  `.codex/verify.commands` lists its commands.
- For UI changes, a read-only reviewer emits `UIFindingV1[]` using
  `~/.codex/contracts/UIFindingV1.schema.json`; fix accepted findings P0 through P3.
  Cover loading, empty, error, success, disabled, and focus-visible states.
  `pnpm ui:gate:static`, `pnpm ui:gate:regression`, and the Lighthouse CI workflow
  are required; any failed or unrun UI gate blocks done.
- Production code changes require meaningful test updates in the same PR:
  one primary behavior assertion and two edge, boundary, invalid-input, or failure assertions.
  No trivial, snapshot-only, or render-only tests. Mock only external boundaries,
  never the unit under test.
- Lint, typecheck, tests, coverage, diff coverage, and docs checks block delivery
  when failed or unrun.

## Boundaries

- Offline-by-default is enforced in Rust core; UI must not have direct egress.
- Adapters are loopback-only (literal IPv4 loopback addresses or `::1`) and must implement Annex B v1.
- Evidence Bundle exports must comply with Annex A v1 + Phase 2.5 lock addendum.
- Determinism mode must follow Addendum A + ZIP hardening rules.
- Audit trail must be canonicalized and hash-chained per lock addendum and taxonomy.
- Preserve unrelated changes. The UI must use Tauri commands to modify audit state.
- Toolchain pins describe the verified baseline, not a claimed minimum Rust version.

## Delivery

- Keep the diff within approved scope. No open critical/high `ReviewFindingV1` findings.
- Reviewers are read-only and emit `ReviewFindingV1`; fix accepted findings in severity
  order and report exact patches and verification. Reviewer → fixer → reviewer is
  required before merge.
- The final verifier reruns the canonical script and reports `GateReportV1`.
- Security checks (secrets, dependencies, SAST) must pass or have an explicit waiver
  with owner and expiry.
- API/command changes update generated contracts and request/response examples.
  Architecture changes require an ADR in `docs/adr/`.
- Distinguish local verification from hosted CI, deployment, and human acceptance.
