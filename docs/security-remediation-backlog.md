# Security Remediation Backlog (Hardening Cycle)

Date: 2026-03-01  
Source: security audit findings + hardening pass

## Priority Sequence

| Priority | Item                                                                    | Severity    | Owner                            | Status              |
| -------- | ----------------------------------------------------------------------- | ----------- | -------------------------------- | ------------------- |
| P0       | Harden fallback KEK file/directory permissions                          | High        | Core runtime owner               | Done                |
| P0       | Harden preflight temp artifacts + guaranteed cleanup                    | Medium-High | Core runtime owner               | Done                |
| P0       | Distinguish synthetic egress proof events in audit stream               | Medium      | Core runtime owner               | Done                |
| P1       | Codify ownership and disclosure process (`CODEOWNERS`, `SECURITY.md`)   | Medium      | Repo admin / security owner      | Done                |
| P1       | Re-tighten branch approvals to `>=1` with named reviewer rotation       | High        | Repo admin / engineering manager | Done                |
| P1       | Decide CodeQL operating model (default setup only vs advanced workflow) | Medium      | Security owner / repo admin      | Done                |
| P1       | Close npm dependency vulnerability backlog                              | High        | Security owner / release owner   | Done                |
| P2       | Resolve `glib` advisory via upstream stack migration plan               | Medium      | Runtime owner                    | Planned (Issue #31) |
| P2       | Add backup security owner staffing in runbook + security policy         | Medium      | PM owner / repo admin            | Done                |

## Remediation Details

## P0-1: Fallback KEK Permissions

- Why: reduce key disclosure risk on permissive local ACL/umask configurations.
- Implemented:
  - owner-only file mode hardening on Unix (`0o600`)
  - owner-only parent directory hardening on Unix (`0o700`)
  - regression tests for creation, invalid-length rejection, and lax-permission repair
- Acceptance:
  - key file is `0o600` on Unix after create/load path
  - invalid fallback KEK length still blocks execution

## P0-2: Preflight Artifact Hardening

- Why: preflight eval bundle can contain sensitive artifacts; temp outputs must be least privilege and cleanup-safe.
- Implemented:
  - scoped preflight artifact manager with `Drop` cleanup
  - Unix permission hardening for preflight directory and zip file
  - tests for cleanup and permission mask behavior
- Acceptance:
  - preflight temp artifacts are removed on scope exit
  - Unix directory/file mode assertions pass

## P0-3: Synthetic Egress Event Marking

- Why: avoid audit ambiguity between control-proof simulation and live runtime egress attempts.
- Implemented:
  - `details.evidence_origin = CONTROL_SIMULATION` on synthetic `EGRESS_REQUEST_BLOCKED`
  - docs/runbook updates for operator interpretation
  - regression test verifying marker presence
- Acceptance:
  - synthetic marker appears in required event set
  - operator runbook documents interpretation

## P1-1: Branch Approval Re-tightening

- Why: temporary `0` required approvals reduces independent review control.
- Implemented:
  - `required_approving_review_count` set to `1` on `master`
  - required blocking checks preserved: `quality-gates`, `verify`, `ui-gates`
- Acceptance:
  - branch protection reflects `>=1` approval
  - required checks remain unchanged and blocking

## P1-2: CodeQL Model Finalization

- Why: advanced workflow is manual-only; reliance on platform default must remain explicit and verified.
- Implemented:
  - standardized on GitHub default CodeQL setup
  - removed redundant advanced workflow file to avoid dual-setup drift/conflict
- Acceptance:
  - single active CodeQL model documented and CI-verified
  - no dual-setup SARIF conflict path

## P2-1: Backup Ownership Staffing

- Why: single-owner concentration increases operational risk.
- Implemented:
  - security policy now specifies repository admin as backup owner
- Implemented (drill):
  - backup-owner incident drill executed and logged in `docs/runbooks/backup-owner-drill-2026-03-01.md`
- Acceptance:
  - backup owner is non-`Unknown` (done)
  - drill evidence captured in release/readiness docs

## Dependency Backlog Closure

- npm advisories were remediated by lockfile hardening and transitive override pins in `package.json`:
  - `minimatch` `3.1.4` / `9.0.7`
  - `basic-ftp` `5.2.0`
  - `rollup` `4.59.0`
  - `esbuild` `0.25.0`
  - `ajv` `6.14.0`
  - `lodash` `4.17.23`
  - `tmp` `0.2.4`
- Rust advisory (`glib`, GHSA-wrw7-89jp-8q8g):
  - direct upgrade to `glib >= 0.20.0` is blocked by current `tauri`/`gtk` dependency constraints (`gtk = ^0.18`)
  - remediation planning tracked at `https://github.com/saagar210/AIGCCore/issues/31`
  - target decision date: 2026-04-15

## Reviewer Sustainability Follow-up

- repository currently has one write/admin collaborator; this is tracked as sustainability gap:
  - `https://github.com/saagar210/AIGCCore/issues/32`
- target completion date: 2026-03-15
- close criteria:
  - add second write-capable reviewer
  - update `.github/CODEOWNERS` backup ownership mapping
