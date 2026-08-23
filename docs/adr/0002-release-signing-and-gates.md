# ADR 0002: Desktop Release Workflow With Blocking Gates

- Status: Accepted
- Date: 2026-02-22

## Context

Release posture was incomplete: placeholder app metadata, no explicit signed artifact workflow, and no operator-ready release checklist.

## Decision

Adopt a release workflow that enforces:

1. Canonical verify commands before packaging.
2. Developer ID signing and notarization prerequisites for macOS.
3. Cross-platform artifact generation (macOS, Windows, Linux), without
   implying that Windows or Linux packages are signed unless their own
   platform-specific evidence is present.
4. SHA-256 checksum generation and artifact upload for each platform.

`TAURI_SIGNING_PRIVATE_KEY` signs Tauri updater artifacts; it does not sign the
application bundle for Developer ID distribution. This product does not
currently configure or claim an in-app Tauri updater, so updater signing keys
are not a desktop-release prerequisite.

Associated process docs:

- `docs/release-checklist.md`
- `docs/runbooks/operator-runbook.md`

## Consequences

- Unnotarized or non-Developer-ID macOS releases are blocked in CI.
- Windows and Linux artifact signing remains unclaimed until separately
  configured and evidenced.
- Version and identifier metadata are now production values and must be maintained each release.
- Release responsibility can transfer to a non-author operator using documented steps.
