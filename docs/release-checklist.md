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

- Confirm GitHub secrets are present:
  - `TAURI_SIGNING_PRIVATE_KEY`
  - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- Run `.github/workflows/release-desktop.yml` using `workflow_dispatch` or release tag.
- Confirm release artifacts uploaded for:
  - macOS
  - Windows
  - Linux
- Confirm `SHA256SUMS.txt` exists in each artifact bundle.

## 4) Post-Build Validation (Blocking)

- Validate extracted bundle signatures/checksums.
- Smoke-test installation on at least one host per target platform.
- Verify pack commands produce successful bundle exports:
  - RedlineOS
  - IncidentOS
  - FinanceOS
  - HealthcareOS

## 5) Rollback Readiness (Blocking)

- Confirm previous stable release artifacts are still available.
- Confirm rollback owner and communication channel are assigned.
- Confirm rollback trigger conditions are defined:
  - critical install failure
  - critical data-corruption risk
  - security finding rated high/critical

## 6) Release Closeout

- Publish release notes with:
  - version
  - checksums
  - known issues
- Archive gate evidence and workflow links.
- Create follow-up issues for any waived non-blocking items.
