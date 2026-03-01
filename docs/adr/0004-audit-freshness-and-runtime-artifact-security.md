# ADR 0004: Audit Freshness and Runtime Artifact Security

- Status: Accepted
- Date: 2026-02-22

## Context

Three production risks were identified in runtime execution:

1. runtime temp directories were created without explicit permission hardening;
2. HealthcareOS manifest fingerprint logic did not use sorted artifact input ordering;
3. bundled `audit_log.ndjson` could be captured before final export lifecycle events were appended.

## Decision

1. Harden runtime directory permissions on Unix to owner-only (`0o700`) immediately after creation.
2. Compute HealthcareOS `manifest_inputs_fingerprint` using sorted `artifact_id:sha256` parts.
3. Refresh bundled audit contents from `AuditLog` after validation events are appended so bundle audit evidence includes final validation lifecycle state.
4. Keep command-surface compatibility unchanged (no command rename, no schema break).

## Consequences

1. Runtime export artifacts are better protected on Unix hosts.
2. Healthcare run fingerprinting is deterministic across input ordering.
3. Exported bundle audit evidence includes `EXPORT_REQUESTED` and `BUNDLE_VALIDATION_RESULT`.
4. Determinism is preserved for bundle hashing tests.
