# Operator Runbook: Pack Execution and Recovery

## Scope

This runbook covers local operator actions for diagnosing failed pack runs and recovering safely.

## Common Failure Signals

- `status = BLOCKED` from pack command response.
- `status = FAILED` from pack command response.
- `error_code` is present on `BLOCKED`/`FAILED` response.
- `run_id`/`audit_path` are present for failures that progressed into export/audit initialization.
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
     - absent/other => inspect as real runtime network attempt
4. Determine failure class:
   - Input payload issue (malformed/missing artifact payload)
   - Policy block (citations/redactions/determinism gate)
   - Bundle format/validator failure
   - UI regression or packaging failure

## Error Code Triage Map

- `ARTIFACT_PAYLOAD_MISSING`: artifact referenced in command input does not have a matching payload entry.
  - Action: ensure each declared artifact has one payload object with matching `artifact_id`.
- `ARTIFACT_PAYLOAD_DUPLICATE`: multiple payload entries exist for the same artifact.
  - Action: submit exactly one payload entry per `artifact_id`.
- `ARTIFACT_PAYLOAD_EMPTY`: payload exists but does not include non-empty content.
  - Action: populate `content_text` or `content_base64`.
- `ARTIFACT_PAYLOAD_INVALID_BASE64`: payload bytes are malformed base64.
  - Action: regenerate payload bytes and re-encode base64.
- `ARTIFACT_PAYLOAD_INVALID_UTF8`: text payload cannot be decoded.
  - Action: provide UTF-8 text in `content_text` or binary-safe `content_base64`.
- `ARTIFACT_PAYLOAD_TOO_LARGE`: payload exceeds runtime size limits.
  - Action: reduce payload size (text <= 5 MiB, binary <= 20 MiB) or split artifacts.
- `ARTIFACT_SHA256_INVALID`: declared hash is present but not valid 64-hex.
  - Action: provide valid lowercase/uppercase 64-hex hash or use approved legacy placeholder format.
- `ARTIFACT_SHA256_MISMATCH`: declared valid hash does not match decoded payload bytes.
  - Action: recompute hash from source artifact bytes and update request.
- `ARTIFACT_CONTENT_TYPE_UNSUPPORTED`: artifact payload field shape does not match expected type.
  - Action: send binary artifacts via `content_base64`; send text artifacts via `content_text` (or UTF-8 base64).
- `REDLINE_ARTIFACT_NOT_PDF`: Redline artifact bytes failed PDF preflight.
  - Action: ensure uploaded bytes are real PDF content and base64-encoded.
- `INCIDENT_LOG_INVALID_FORMAT`: IncidentOS log payload cannot be parsed as JSON/NDJSON.
  - Action: validate log schema and line delimiters.
- `FINANCE_STATEMENT_INVALID_FORMAT`: FinanceOS statement JSON invalid/missing required fields.
  - Action: validate statement schema before invoke.
- `HEALTHCAREOS_WORKFLOW_INVALID_INPUT`: HealthcareOS rejected transcript/consent policy conditions.
  - Action: validate consent status/patient alignment and transcript schema.
- `EXPORT_BLOCKED`: policy/eval gate blocked export after workflow.
  - Action: inspect `audit.ndjson` and gate results for citations/redaction/determinism reasons.
- `EXPORT_FAILED`: export pipeline/runtime failure.
  - Action: inspect `audit.ndjson`, bundle validator output, and retry after root-cause fix.

## Recovery Actions

### Input Payload Issues

- Verify payload IDs match artifact IDs in command input.
- Verify `content_base64` for binary payloads (RedlineOS).
- Verify `content_text` is valid JSON/NDJSON for structured packs.
- If 64-hex `sha256` is provided, verify exact byte hash parity before invoke.

### Policy or Gate Blocks

- Check gate ID and message in audit events.
- Fix citation mapping or redaction coverage for affected deliverables.
- Re-run `pnpm gate:all` after patch.

### Build/Packaging Failures

- Re-run `pnpm build`.
- Re-run `cargo check -p aigc_core_tauri`.
- Confirm signing secrets are available before release workflow.

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
| Runtime command failures (`run_*`) | Core runtime owner   | QA owner           | `FAILED` status on required command path                  |
| Ingestion contract failures        | Data ingestion owner | Core runtime owner | repeated `BLOCKED` with same `error_code` after input fix |
| CI/gate pipeline failures          | Release owner        | Core runtime owner | required CI check red for release branch                  |
| Release packaging/signing failures | Release owner        | Repo admin         | release workflow fails to produce signed artifacts        |
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

## Drill Reference

- Latest backup-owner execution drill:
  - `docs/runbooks/backup-owner-drill-2026-03-01.md`
- Latest operator handoff drill:
  - `docs/runbooks/operator-handoff-drill-2026-03-01.md`
