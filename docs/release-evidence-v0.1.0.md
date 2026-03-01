# Release Evidence Packet: v0.1.0

Date: 2026-03-01
Status: Final

## Release Identity

- Target version: `0.1.0`
- Release artifact baseline SHA: `9f6bcb6a91513afe4dc1d397424fe1d49a617229`
- Latest master governance/hardening SHA: `1f30d2bcda8de71b16634d6f63c582af80b95a6d`
- Tag: `v0.1.0-week1-stable` (`c77d6c289ccd8f5908c8696748f2cf4b9e8e7952`)

## Release Workflow Evidence

- workflow: `release-desktop`
- run URL: `https://github.com/saagar210/AIGCCore/actions/runs/22538435713`
- conclusion: `success`
- matrix:
  - `build_signed_artifacts (ubuntu-22.04)`: success
  - `build_signed_artifacts (windows-latest)`: success
  - `build_signed_artifacts (macos-latest)`: success
- latest ceremony rerun URL: `https://github.com/saagar210/AIGCCore/actions/runs/22546166401` (`success`)
- published release URL: `https://github.com/saagar210/AIGCCore/releases/tag/v0.1.0-week1-stable`

## Artifact Checksums (from CI Artifacts)

- `de54be075544f52bb89068e75f7012e95c84bca21b06be8a0f748c2642f6b7d7` `release-windows-latest-0.1.0/nsis/AIGC Core_0.1.0_x64-setup.exe`
- `d86963068555fce3fa647dfa00ab5420af344dd9ba54734afe1e267bede730cb` `release-windows-latest-0.1.0/msi/AIGC Core_0.1.0_x64_en-US.msi`
- `8338b028f52add88c22b2f00495e33760f0f3bf22bdd6df58955ddf9c2d1fad8` `release-macos-latest-0.1.0/dmg/AIGC Core_0.1.0_aarch64.dmg`
- `bd70a7cd9f52017fb90884a194d29083b8cae825ced39e421d503e37e60195bf` `release-ubuntu-22.04-0.1.0/deb/AIGC Core_0.1.0_amd64.deb`
- `014244aa94d46956812846173249a7ee82e209a23edf8595edc1371e41e899a8` `release-ubuntu-22.04-0.1.0/rpm/AIGC Core-0.1.0-1.x86_64.rpm`
- `9d142ab6d3d78cfcc638cd44be62a3053bb61b6104238b79332ea0d8679ffd12` `release-ubuntu-22.04-0.1.0/appimage/AIGC Core_0.1.0_amd64.AppImage`

Checksum manifest sanity:

- Ubuntu `SHA256SUMS.txt`: no self-hash entries
- macOS `SHA256SUMS.txt`: no self-hash entries
- Windows `SHA256SUMS.txt`: no self-hash entries

## CI / Security Snapshot (Latest Master)

For SHA `1f30d2bcda8de71b16634d6f63c582af80b95a6d`:

- `quality-gates`: success (`https://github.com/saagar210/AIGCCore/actions/runs/22545500268`)
- `codex-quality-security`: success (`https://github.com/saagar210/AIGCCore/actions/runs/22545500277`)
- `CodeQL` (default setup): success (`https://github.com/saagar210/AIGCCore/actions/runs/22545500145`)
- `ui-quality` (latest PR lane): success (`https://github.com/saagar210/AIGCCore/actions/runs/22545349089`)

## Hardening Fixes Applied During Release Burn-Down

- PR #20 (`9fe5207...`): fixed Windows icon config for bundling
- PR #21 (`d3d4836...`): fixed Windows checksum file-lock behavior
- PR #22 (`9f6bcb6...`): fixed Unix checksum self-hash behavior
- PR #23 (`44ac636...`): fixed TruffleHog duplicate `--fail` in security workflow
- PR #25 (`267a088...`): switched CodeQL Advanced workflow to manual-only to avoid default-setup conflict
- PR #28 (`20a8f1b...`): Phase 4/5 runtime and governance closeout merged
- PR #29 (`db86d52...`): fixed TruffleHog duplicate fail-flag regression on `master`
- PR #30 (`1f30d2b...`): final closeout of dependency backlog, docs evidence sync, and policy re-tightening verification
- PR #33 (`pending merge`): Windows release ceremony remediations
  - add `.ico` icon mapping in Tauri bundle config
  - exclude `SHA256SUMS.txt` self-hash race in Windows checksum step

## Branch Protection Snapshot

- `required_approving_review_count = 1` (re-tightened on 2026-03-01)
- required contexts: `quality-gates`, `verify`, `ui-gates`

## Smoke Test Outcomes

- Desktop bundle launch smoke: `PASS` (local runtime launch smoke on built binary; process started and was cleanly terminated after health interval)
- Canonical command invoke smoke (`run_*` pack paths): covered by release job `Run canonical verification` on all three runners
