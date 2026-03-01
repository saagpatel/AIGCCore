# Release Evidence Packet: v0.1.0

Date: 2026-03-01

## Release Identity

- Target version: `0.1.0`
- Release artifact SHA baseline: `9f6bcb6a91513afe4dc1d397424fe1d49a617229`
- Latest master governance/hardening SHA: `44ac636112a7b57b1638db8516005135d1ce52e6`
- Tag: `v0.1.0-week1-stable` (`c77d6c289ccd8f5908c8696748f2cf4b9e8e7952`)

## Release Workflow Evidence

- release workflow: `release-desktop`
- run URL: `https://github.com/saagar210/AIGCCore/actions/runs/22538435713`
- conclusion: `success`
- matrix status:
  - `build_signed_artifacts (ubuntu-22.04)`: success
  - `build_signed_artifacts (windows-latest)`: success
  - `build_signed_artifacts (macos-latest)`: success

## Artifact Checksum Evidence (CI Artifacts)

From run `22538435713` downloaded artifacts:

- `de54be075544f52bb89068e75f7012e95c84bca21b06be8a0f748c2642f6b7d7`  `release-windows-latest-0.1.0/nsis/AIGC Core_0.1.0_x64-setup.exe`
- `d86963068555fce3fa647dfa00ab5420af344dd9ba54734afe1e267bede730cb`  `release-windows-latest-0.1.0/msi/AIGC Core_0.1.0_x64_en-US.msi`
- `8338b028f52add88c22b2f00495e33760f0f3bf22bdd6df58955ddf9c2d1fad8`  `release-macos-latest-0.1.0/dmg/AIGC Core_0.1.0_aarch64.dmg`
- `bd70a7cd9f52017fb90884a194d29083b8cae825ced39e421d503e37e60195bf`  `release-ubuntu-22.04-0.1.0/deb/AIGC Core_0.1.0_amd64.deb`
- `014244aa94d46956812846173249a7ee82e209a23edf8595edc1371e41e899a8`  `release-ubuntu-22.04-0.1.0/rpm/AIGC Core-0.1.0-1.x86_64.rpm`
- `9d142ab6d3d78cfcc638cd44be62a3053bb61b6104238b79332ea0d8679ffd12`  `release-ubuntu-22.04-0.1.0/appimage/AIGC Core_0.1.0_amd64.AppImage`

Checksum manifest sanity:
- Ubuntu `SHA256SUMS.txt` has no self-hash entry
- macOS `SHA256SUMS.txt` has no self-hash entry
- Windows `SHA256SUMS.txt` has no self-hash entry

## CI / Security Snapshot (Latest Master)

For SHA `44ac636112a7b57b1638db8516005135d1ce52e6`:

- `quality-gates`: success (`https://github.com/saagar210/AIGCCore/actions/runs/22542653008`)
- `codex-quality-security`: success (`https://github.com/saagar210/AIGCCore/actions/runs/22542652981`)
- `CodeQL`: success (`https://github.com/saagar210/AIGCCore/actions/runs/22542652836`)
- `CodeQL Advanced`: failure (`https://github.com/saagar210/AIGCCore/actions/runs/22542652998`)

## Hardening Fixes Applied During Release Burn-Down

- PR #20 (`9fe5207...`): fixed Windows icon config for bundling
- PR #21 (`d3d4836...`): fixed Windows checksum file-lock behavior
- PR #22 (`9f6bcb6...`): fixed Unix checksum self-hash behavior
- PR #23 (`44ac636...`): fixed TruffleHog duplicate `--fail` flag in `codex-quality-security`

## Branch Protection Snapshot

- `required_approving_review_count = 0` (temporary)
- required contexts: `quality-gates`, `verify`, `ui-gates`

## Smoke Test Outcomes

- Desktop bundle launch smoke: `Unknown`
- Basic pack command behavior: covered via canonical verification in release jobs (`Run canonical verification` step passed on all three OS runners)
