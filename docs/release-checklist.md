# Release Checklist

Use this checklist for every production desktop release.

## 1) Pre-Release Gates (Blocking)

- Confirm branch is up to date with main.
- Run canonical verification gates:
  - `bash .codex/scripts/run_verify_commands.sh`
  - `pnpm gate:all`
  - `pnpm ui:gate:regression`
- Confirm all required CI workflows are green on the release candidate commit:
  - `quality-gates`
  - `ui-quality`
  - `codex-quality-security`

## 2) Version and Metadata (Blocking)

- Confirm release version is updated:
  - `package.json`
  - `src-tauri/tauri.conf.json`
  - `core/Cargo.toml`
  - `src-tauri/Cargo.toml`
- Confirm app identifier is production value:
  - `src-tauri/tauri.conf.json` -> `com.aigc.core`
- Confirm changelog/release notes are ready.

## 3) Signing and Build (Blocking)

- For macOS, confirm GitHub secrets are present:
  - `APPLE_CERTIFICATE`
  - `APPLE_CERTIFICATE_PASSWORD`
  - `APPLE_SIGNING_IDENTITY`
  - `APPLE_ID`
  - `APPLE_PASSWORD`
  - `APPLE_TEAM_ID`
- Run `.github/workflows/release-desktop.yml` using `workflow_dispatch` or release tag.
- Confirm release artifacts uploaded for:
  - macOS
  - Windows
  - Linux
- Confirm `SHA256SUMS.txt` exists in each artifact bundle.
- Confirm the macOS job passes strict signature, Gatekeeper, stapled-ticket,
  disk-image, and mounted-payload verification.
- Record Windows and Linux signature status as `UNKNOWN` unless independently
  configured and verified; packaging success is not signature proof.

## 4) Post-Build Validation (Blocking)

- Validate extracted bundle signatures/checksums at each supported platform
  boundary. Do not infer installer validation from workflow success.
- Smoke-test installation and launch on at least one host per target platform,
  retaining exact artifact and host receipts.
- Verify pack commands produce successful bundle exports:
  - RedlineOS
  - IncidentOS
  - FinanceOS
  - HealthcareOS

## 5) Manual Rollback Readiness (Blocking)

- Confirm previous stable release artifacts are still available.
- Confirm rollback owner and communication channel are assigned.
- Confirm rollback trigger conditions are defined:
  - critical install failure
  - critical data-corruption risk
  - security finding rated high/critical

The product does not currently claim an in-app updater, automatic upgrade,
downgrade, or rollback channel. Rollback means reinstalling a separately
qualified prior artifact; it is not proven until that path is exercised.

## 6) Release Closeout

- Publish release notes with:
  - version
  - checksums
  - known issues
- Archive gate evidence and workflow links.
- Create follow-up issues for any waived non-blocking items.
