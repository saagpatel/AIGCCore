# Release Ceremony Signoff: v0.1.0

Date: 2026-03-01
Status: Complete

## Scope

Formal release ceremony for `0.1.0` using the release workflow with verification, signing checks, and artifact checksum capture.

## Trigger

- Workflow: `release-desktop`
- Attempt 1 (master): `https://github.com/saagar210/AIGCCore/actions/runs/22545721368` (`failure`)
- Attempt 2 (fix branch): `https://github.com/saagar210/AIGCCore/actions/runs/22545911071` (`failure`)
- Attempt 3 (fix branch): `https://github.com/saagar210/AIGCCore/actions/runs/22546166401` (`success`)
- Trigger mode: `workflow_dispatch`
- Input version: `0.1.0`

## Attempt Notes

- Attempt 1 root cause: Windows wix packaging could not locate configured `.ico` icon.
  - remediation: add `icons/icon.ico` and sized icons in `src-tauri/tauri.conf.json`.
- Attempt 2 root cause: Windows checksum step attempted to hash output `SHA256SUMS.txt` while writing the same file.
  - remediation: update `.github/workflows/release-desktop.yml` to precompute file list and exclude `SHA256SUMS.txt`.
- Attempt 3 outcome: all OS lanes succeeded after checksum-step remediation.

## Checklist

- [x] Metadata version alignment validated in workflow
- [x] Signing prerequisites enforced in workflow
- [x] Multi-platform signed artifact jobs completed
- [x] Artifact checksums captured in release evidence packet
- [x] Distribution publication evidence captured
- [x] Final signoff status set to `Complete`

## Distribution Evidence

- GitHub Release object: `https://github.com/saagar210/AIGCCore/releases/tag/v0.1.0-week1-stable`
- External store upload evidence: `N/A` (distribution channel for this release is GitHub Releases)
- Installer validation evidence: `Pass` (release workflow matrix success on Windows/macOS/Linux)

## Go/No-Go

Current decision: `Go`.
