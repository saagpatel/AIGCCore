# ADR 0002: Signed Desktop Release Workflow With Blocking Gates

- Status: Accepted
- Date: 2026-02-22

## Context

Release posture was incomplete: placeholder app metadata, no explicit signed artifact workflow, and no operator-ready release checklist.

## Decision

Adopt a release workflow that enforces:

1. Canonical verify commands before packaging.
2. Presence of signing secrets (`TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`).
3. Cross-platform artifact generation (macOS, Windows, Linux).
4. SHA-256 checksum generation and artifact upload for each platform.

Associated process docs:

- `docs/release-checklist.md`
- `docs/runbooks/operator-runbook.md`

## Consequences

- Unsigned release builds are blocked in CI release workflow.
- Version and identifier metadata are now production values and must be maintained each release.
- Release responsibility can transfer to a non-author operator using documented steps.
