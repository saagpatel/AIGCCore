# ADR 0001: Standardized Pack Export Runtime Contract

- Status: Accepted
- Date: 2026-02-22

## Context

Pack handlers for IncidentOS, FinanceOS, and HealthcareOS were scaffold-only and did not execute the export pipeline. RedlineOS used a demo `include_bytes!` path, which prevented production-grade artifact ingestion.

## Decision

All pack commands now follow a standardized runtime contract:

1. Validate workflow input via pack ingest state.
2. Resolve artifact payloads through `artifact_payloads` with:
   - `artifact_id`
   - `content_text` (text inputs)
   - `content_base64` (binary inputs)
3. Execute pack workflow and produce deterministic deliverables.
4. Build canonical Evidence Bundle inputs.
5. Export through `RunManager::export_run`.
6. Return structured status with:
   - `bundle_path`
   - `bundle_sha256`
   - `error_code` (required when status is `BLOCKED` or `FAILED`)
   - `run_id` (when available)
   - `audit_path` (when available)
7. Normalize payload validation failures into deterministic error codes:
   - `ARTIFACT_PAYLOAD_MISSING`
   - `ARTIFACT_PAYLOAD_EMPTY`
   - `ARTIFACT_PAYLOAD_INVALID_BASE64`
   - `ARTIFACT_PAYLOAD_INVALID_UTF8`

## Consequences

- RedlineOS no longer depends on hardcoded demo PDF bytes.
- Non-Redline packs now produce validated bundles through the same governance path.
- UI and tests must provide and validate artifact payload mappings.
- Operators can triage failures without parsing free-form exception strings.

## Phase 3 Addendum (Ingestion Hardening)

1. Added shared ingestion validation path across all pack handlers.
2. Runtime now blocks duplicate payload records by `artifact_id`.
3. Runtime enforces payload size limits:
   - text payloads: 5 MiB
   - binary payloads: 20 MiB
4. SHA policy is compatibility-safe:
   - valid 64-hex `sha256` values are strictly enforced against decoded payload bytes
   - non-64 legacy placeholder values are accepted and treated as non-enforced mode
5. New deterministic ingestion failure codes:
   - `ARTIFACT_PAYLOAD_DUPLICATE`
   - `ARTIFACT_PAYLOAD_TOO_LARGE`
   - `ARTIFACT_SHA256_INVALID`
   - `ARTIFACT_SHA256_MISMATCH`
   - `ARTIFACT_CONTENT_TYPE_UNSUPPORTED`
   - `REDLINE_ARTIFACT_NOT_PDF`
6. UI runtime defaults switched to real-input mode; sample payloads require explicit operator action.

## Phase 5 Addendum (Critical Runtime Hardening)

1. Runtime directory creation now hardens Unix permissions to owner-only (`0o700`).
2. Healthcare input fingerprinting now uses sorted artifact descriptors to maintain deterministic run identity regardless input order.
3. Export bundle embedding now refreshes bundled `audit_log.ndjson` with post-validation lifecycle events.
4. Runtime command helper audit timestamps now use runtime UTC generation instead of fixed literals.
