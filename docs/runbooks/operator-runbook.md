# Operator Runbook: EvidenceOS Export and Recovery

## Scope

This runbook covers local operator actions for diagnosing failed EvidenceOS exports and recovering safely. See `docs/command-surface.md` for the current IPC contract.

## Common Failure Signals

- Rejected `generate_evidenceos_bundle` invocation with a string error.
- A completed command returns `status = COMPLETED`; blocked/failed exports reject.
- Bundle missing or bundle validation failure.
- Required CI gates fail (`quality-gates`, `ui-quality`, `codex-quality-security`).

## Triage Procedure

1. Reproduce locally with canonical commands:
   - `bash .codex/scripts/run_verify_commands.sh`
   - `pnpm gate:all`
2. Run focused checks:
   - `cargo test --workspace`
   - `pnpm ui:gate:static`
3. Inspect latest runtime export directory and `audit.ndjson` for:
   - `EXPORT_BLOCKED`
   - `EVAL_GATE_RESULT`
   - `BUNDLE_VALIDATION_RESULT`
   - `EGRESS_REQUEST_BLOCKED` `details.evidence_origin`:
     - `CONTROL_SIMULATION` => policy-proof synthetic event
     - `RUNTIME_OBSERVATION` => actual runtime egress decision
     - absent/other => malformed or ambiguous; fail closed and do not infer live execution
   - `run_manifest.json:evidence_authority`:
     - confirm `RUN_MANIFEST_V2` / `EVIDENCE_AUTHORITY_V1`
     - confirm source, executable, arguments, environment, and audit digests match the case
     - confirm `valid_until_utc` is current for any current-capability claim
     - confirm the requested downstream claim is explicitly in `may_satisfy`
     - never use `CONTROL_SIMULATION` for a claim listed in `must_not_satisfy`
4. Determine failure class:
   - Input payload issue (malformed/missing artifact payload)
   - Policy block (citations/redactions/determinism gate)
   - Bundle format/validator failure
   - UI regression or packaging failure

## Command Error Triage

The EvidenceOS command rejects with a string on artifact generation, filesystem,
audit, export, or bound-manifest errors. It has no pack error-code response.
For `EvidenceOS export did not complete`, inspect the reported status/block
reason and the runtime audit log. For `failed to export EvidenceOS bundle`,
inspect the underlying kernel error. Preserve the original inputs and evidence
before retrying.

## Recovery Actions

### Input Issues

- Check the six EvidenceOS input fields against `docs/command-surface.md`.
- Confirm capability and control-family selection, evidence text, and claim.
- Inspect citation mapping and missing-control output for completed exports.

### Policy or Gate Blocks

- Check gate ID and message in audit events.
- Fix citation mapping or redaction coverage for affected deliverables.
- Re-run `pnpm gate:all` after patch.

### Build/Packaging Failures

- Re-run `pnpm build`.
- Re-run `cargo check -p aigc_core_tauri`.
- For macOS, confirm Developer ID certificate and notarization credentials are
  available before the release workflow. Do not substitute Tauri updater keys
  for application signing.

## Rollback Procedure

1. Stop release promotion immediately.
2. Revert to latest known-good release tag/artifact.
3. Communicate rollback in release channel with impact summary.
4. Open incident ticket with:
   - failing commit SHA
   - failing gate/stack trace
   - mitigation and ETA

## Evidence to Capture

- Command outputs for:
  - `.codex/scripts/run_verify_commands.sh`
  - `pnpm gate:all`
  - `pnpm ui:gate:regression`
- CI workflow URLs and failing step names.
- Any produced `bundle.zip` + `audit.ndjson` for failed run reproduction.

## Escalation Owner Matrix

| Area                               | Primary Owner        | Backup Owner       | Escalation Trigger                                        |
| ---------------------------------- | -------------------- | ------------------ | --------------------------------------------------------- |
| EvidenceOS command failures | Core runtime owner   | QA owner           | rejected EvidenceOS invocation                  |
| CI/gate pipeline failures          | Release owner        | Core runtime owner | required CI check red for release branch                  |
| Release packaging/signing failures | Release owner        | Repo admin         | release workflow fails its platform-specific artifact gates |
| Security/compliance incidents      | Security owner       | Repo admin         | policy/gate bypass, audit-chain anomaly, secret leak risk |

If role assignment is not staffed, treat owner as `Unknown` and escalate directly to repo admin.

## Release Incident Triage Workflow

1. Halt release promotion and freeze new merges to release branch.
2. Capture failing SHA, failing workflow URL, and failing command output.
3. Classify incident:
   - command/runtime failure
   - gate policy failure
   - packaging/signing failure
4. Execute minimal safe rollback:
   - revert to latest known-good tag
   - re-run canonical verify + `pnpm gate:all`
5. Publish incident note with:
   - impact
   - mitigation
   - owner
   - ETA to restore release lane

## Rollback Ownership Mapping

- Code rollback decision: Core runtime owner.
- Release artifact rollback execution: Release owner.
- Branch protection or merge-policy override: Repo admin.
- Stakeholder notification: PM owner.

## Reviewer Escalation Coverage

Primary reviewer capacity:

- `@saagar210` (write/admin)

Backup reviewer capacity:

- `@gemini-code-assist` (write invite created 2026-03-01, invitation id `309160608`, pending acceptance)
- `@claude` (write invite created 2026-03-01, invitation id `309160557`, pending acceptance)

Escalation sequence for blocked approval windows:

1. Request review from primary owner.
2. Request review from invited backup reviewer(s).
3. If no write-capable backup has accepted by release cutoff, escalate to repo admin for staffing action and do not rely on policy relaxation as default operating mode.

## Drill Reference

- Latest backup-owner execution drill:
  - `docs/runbooks/backup-owner-drill-2026-03-01.md`
- Latest operator handoff drill:
  - `docs/runbooks/operator-handoff-drill-2026-03-01.md`
