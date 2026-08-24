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

The canonical `pnpm build` entrypoint is platform-aware. On macOS it builds
only the `.app` bundle, preventing Tauri's styled DMG staging from mutating the
signed app or replacing the separately accepted release DMG. Other platforms
retain their native default bundle targets. Local macOS builds use Tauri's
documented ad-hoc identity (`-`) so the emitted application bundle is complete
and strict-verifiable; `APPLE_SIGNING_IDENTITY` overrides that default for the
Developer ID release workflow.

CI imports the base64-encoded Developer ID certificate into an ephemeral
keychain, verifies that the configured identity is actually present, and
removes the keychain after the release step. Merely setting an identity name or
an updater-signing key is not accepted as application-signing proof.

`TAURI_SIGNING_PRIVATE_KEY` signs Tauri updater artifacts; it does not sign the
application bundle for Developer ID distribution. This product does not
currently configure or claim an in-app Tauri updater, so updater signing keys
are not a desktop-release prerequisite.

Associated process docs:

- `docs/release-checklist.md`
- `docs/runbooks/operator-runbook.md`

## Consequences

- Unnotarized or non-Developer-ID macOS releases are blocked in CI.
- A local canonical macOS build is ad-hoc signed and is not a distributable or
  notarized release; only `pnpm release:macos` may make that claim.
- Windows and Linux artifact signing remains unclaimed until separately
  configured and evidenced.
- Version and identifier metadata are now production values and must be maintained each release.
- Release responsibility can transfer to a non-author operator using documented steps.
