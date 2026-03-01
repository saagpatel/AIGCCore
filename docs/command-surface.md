# Local Command Surface (Tauri Invoke)

This project does not expose an external HTTP API. The primary runtime interface is the local Tauri command surface.

## Contract Notes (Phase 5)

- Command names and request/response schema remain backward-compatible.
- Runtime export directories are permission-hardened on Unix (`0o700`).
- Healthcare run fingerprinting is based on sorted input artifact descriptors.
- Bundled `audit_log.ndjson` now includes final validation lifecycle evidence before export result is returned.

## Command: `run_redlineos`

Purpose: Run contract review and export a RedlineOS Evidence Bundle.

Request shape:

```json
{
  "schema_version": "REDLINEOS_INPUT_V1",
  "contract_artifacts": [
    {
      "artifact_id": "a_contract_001",
      "sha256": "optional-client-hash",
      "filename": "contract.pdf"
    }
  ],
  "extraction_mode": "NATIVE_PDF",
  "jurisdiction_hint": "US-CA",
  "review_profile": "default",
  "artifact_payloads": [
    {
      "artifact_id": "a_contract_001",
      "content_base64": "<base64-pdf-bytes>"
    }
  ]
}
```

Response shape:

```json
{
  "status": "SUCCESS|BLOCKED|FAILED",
  "message": "human-readable status",
  "error_code": "optional-machine-readable-failure-code",
  "run_id": "optional-run-id",
  "audit_path": "optional-audit-log-path",
  "bundle_path": "/tmp/.../evidence_bundle_redlineos_v1.zip",
  "bundle_sha256": "hex-sha256"
}
```

Validation notes:

- Redline payload must be provided in `content_base64` and decode to PDF-like bytes.
- Text-only payloads for binary artifacts are blocked with `ARTIFACT_CONTENT_TYPE_UNSUPPORTED`.

Standard failure codes used across pack commands:

- `ARTIFACT_PAYLOAD_MISSING`: required payload object is missing for a declared artifact.
- `ARTIFACT_PAYLOAD_DUPLICATE`: multiple payload objects exist for the same `artifact_id`.
- `ARTIFACT_PAYLOAD_EMPTY`: payload exists but has no usable `content_text`/`content_base64`.
- `ARTIFACT_PAYLOAD_INVALID_BASE64`: `content_base64` is not valid base64.
- `ARTIFACT_PAYLOAD_INVALID_UTF8`: text payload cannot be decoded as UTF-8.
- `ARTIFACT_PAYLOAD_TOO_LARGE`: payload exceeds command contract size limit (text: 5 MiB, binary: 20 MiB).
- `ARTIFACT_SHA256_INVALID`: declared artifact hash is present but not valid 64-hex.
- `ARTIFACT_SHA256_MISMATCH`: declared valid hash does not match decoded payload bytes.
- `ARTIFACT_CONTENT_TYPE_UNSUPPORTED`: payload field shape does not match expected artifact type.
- `REDLINE_ARTIFACT_NOT_PDF`: Redline payload bytes are not PDF-like (`%PDF-` preflight failed).
- `*_INPUT_INVALID` / `*_WORKFLOW_INVALID_INPUT`: pack-specific schema/workflow validation blocked execution.
- `EXPORT_BLOCKED` / `EXPORT_FAILED`: export pipeline blocked or failed after workflow execution began.

SHA policy:

- If `artifact.sha256` is valid 64-hex, runtime enforces exact byte hash match.
- If `artifact.sha256` is missing or legacy placeholder (non-64 length), runtime treats it as non-enforced compatibility mode and continues.

## Command: `run_incidentos`

Purpose: Parse incident logs, generate customer/internal deliverables, export IncidentOS bundle.

Request shape:

```json
{
  "schema_version": "INCIDENTOS_INPUT_V1",
  "incident_artifacts": [
    {
      "artifact_id": "incident_log_001",
      "sha256": "optional-client-hash",
      "source_type": "syslog"
    }
  ],
  "timeline_start_hint": null,
  "timeline_end_hint": null,
  "customer_redaction_profile": "STRICT",
  "artifact_payloads": [
    {
      "artifact_id": "incident_log_001",
      "content_text": "<ndjson-or-json-log-content>"
    }
  ]
}
```

Response: same `PackCommandStatus` structure as above.

Validation notes:

- Text payloads can be supplied via `content_text` or base64-decoded UTF-8 in `content_base64`.
- Duplicate payload entries per artifact are blocked.

## Command: `run_financeos`

Purpose: Detect finance exceptions, generate audit outputs, export FinanceOS bundle.

Request shape:

```json
{
  "schema_version": "FINANCEOS_INPUT_V1",
  "finance_artifacts": [
    {
      "artifact_id": "statement_001",
      "sha256": "optional-client-hash",
      "artifact_kind": "statement"
    }
  ],
  "period": "2026-01",
  "exception_rules_profile": "default",
  "retention_profile": "ret_min",
  "artifact_payloads": [
    {
      "artifact_id": "statement_001",
      "content_text": "<statement-json>"
    }
  ]
}
```

Response: same `PackCommandStatus` structure as above.

Validation notes:

- Statement payload must be valid JSON and schema-compliant for workflow parsing.
- Text payload size > 5 MiB is blocked before workflow execution.

## Command: `run_healthcareos`

Purpose: Run consent-gated clinical draft workflow and export HealthcareOS bundle.

Request shape:

```json
{
  "schema_version": "HEALTHCAREOS_INPUT_V1",
  "consent_artifacts": [
    {
      "artifact_id": "consent_001",
      "sha256": "optional-client-hash",
      "artifact_kind": "consent"
    }
  ],
  "transcript_artifacts": [
    {
      "artifact_id": "transcript_001",
      "sha256": "optional-client-hash",
      "artifact_kind": "transcript"
    }
  ],
  "draft_template_profile": "soap",
  "verifier_identity": "clinician_1",
  "artifact_payloads": [
    {
      "artifact_id": "consent_001",
      "content_text": "<consent-json>"
    },
    {
      "artifact_id": "transcript_001",
      "content_text": "<transcript-json>"
    }
  ]
}
```

Response: same `PackCommandStatus` structure as above.

Validation notes:

- Both transcript and consent payloads are required for runtime execution.
- Payload schema/content failures are blocked before export pipeline handoff.

## Command: `generate_evidenceos_bundle`

Purpose: Run Phase 3 EvidenceOS capability mapping + strict citation export.

Request and response are unchanged from prior implementation and remain exposed in `src-tauri/src/main.rs`.
