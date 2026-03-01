# Release Evidence Packet: v0.1.0

Date: 2026-02-22

## Release Identity

- Target version: `0.1.0`
- Merge SHA baseline: `a5ddca1f9887892e39fe62db3e6b978ee2c17b4e` (`origin/master` at assessment time)
- Tag: `Unknown` (not created in this local workspace)

## Local Verification Evidence

| Command | Result | Source |
|---|---|---|
| `bash .codex/scripts/run_verify_commands.sh` | PASS | `.codex/scripts/run_verify_commands.sh`, `.codex/verify.commands` |
| `pnpm gate:all` | PASS | `package.json`, `tools/gates/run-all.mjs` |
| `pnpm ui:gate:regression` | PASS | `package.json` |
| `pnpm test:unit:coverage` | PASS | `package.json` |
| `python3 -m diff_cover.diff_cover_tool coverage/lcov.info --compare-branch=origin/master --fail-under=90` | PASS (98%) | `.github/workflows/quality-gates.yml` |

## Build Artifact Evidence (Local)

- App bundle path: `/Users/d/Projects/MoneyPRJsViaGPT/AIGCCore/target/release/bundle/macos/AIGC Core.app`
- DMG path: `/Users/d/Projects/MoneyPRJsViaGPT/AIGCCore/target/release/bundle/dmg/AIGC Core_0.1.0_aarch64.dmg`
- Artifact checksums (local):
  - `c925f33fb7ee81bbb31e540c9bcebdaf21000f6518d2b9073a4379ac4b378fce`  `target/release/bundle/dmg/AIGC Core_0.1.0_aarch64.dmg`
  - `be83de1dd778351159be89b3bb2d0e3c202a528c4c42fd34823ab2380866102d`  `target/release/bundle/macos/AIGC Core.app/Contents/MacOS/aigc_core_tauri`

## CI / Release Workflow Evidence

- latest successful `quality-gates`: `https://github.com/saagar210/AIGCCore/actions/runs/22416608809` (`headSha=fb2720dacec91783d0148833db35da7039f8acd9`)
- latest successful `ui-quality`: `https://github.com/saagar210/AIGCCore/actions/runs/22080409966` (`headSha=57bfe071845d3c83859af548871edda622ccd227`)
- latest successful `codex-quality-security`: `https://github.com/saagar210/AIGCCore/actions/runs/22416608773` (`headSha=fb2720dacec91783d0148833db35da7039f8acd9`)
- `release-desktop` workflow run URL: `Unknown` (`release-desktop.yml` not present on current default branch)

Notes:
- On merge-sha baseline `a5ddca1f9887892e39fe62db3e6b978ee2c17b4e`, recorded runs include failures:
  - `quality-gates`: `https://github.com/saagar210/AIGCCore/actions/runs/22277362811` (failure)
  - `codex-quality-security`: `https://github.com/saagar210/AIGCCore/actions/runs/22309564942` (failure)

## Branch Protection Snapshot

- `required_approving_review_count = 0`
- required contexts: `quality`, `quality-gates`

## Smoke Test Outcomes

- Desktop bundle launch smoke: `Unknown`
- Basic command invoke smoke (`run_incidentos`/`run_financeos`/`run_healthcareos`): PASS via local command/test suite
- Regression test summary: PASS (Playwright visual + a11y)
