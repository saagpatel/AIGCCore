# Addendum B — Audit Event Taxonomy v2 (LOCKED)

**Document status:** Normative current audit event taxonomy.

Version: audit_event_taxonomy_v2  
Status: LOCKED (Core + Packs MUST emit these events via Core; Packs MUST NOT invent parallel audit logs)  
Purpose: Stable, machine-verified audit trail used for proof bundles, validators, and pack consistency.

---

## 1) Audit Event Envelope (Normative)

Each NDJSON line MUST be a JSON object containing at minimum:

- `ts_utc` (RFC3339 UTC string)
- `event_type` (string enum; Section 3)
- `run_id` (string)
- `vault_id` (string)
- `actor` (`system` | `user`)
- `details` (object; may be empty)
- `prev_event_hash` (hex, 64 chars)
- `event_hash` (hex, 64 chars)

Compatibility rule:

- Additional fields MAY exist only under `details.meta` (e.g., `details.meta.event_id`, `details.meta.session_id`).
- No other top-level keys are permitted in v1.

Hash-chain canonicalization and hashing MUST follow Phase 2.5 Lock Addendum.

---

## 2) Run Lifecycle State Machine (Normative)

Run states:

1. `CREATED`
2. `INGESTING`
3. `READY`
4. `EXECUTING`
5. `EVALUATING`
6. `EXPORTING`
7. Terminal: `COMPLETED` | `FAILED` | `CANCELLED`

Rules:

- State transitions MUST be recorded via `RUN_STATE_CHANGED`.
- EXPORTING must not occur unless EVALUATING completed and gates permit export.
- Export failure MUST be recorded via `EXPORT_BLOCKED` (policy/gate block) or `EXPORT_FAILED` (unexpected failure).

---

## 3) Event Types (LOCKED ENUM)

### 3.1 Required events for EVERY run (minimum)

- `RUN_CREATED`
- `RUN_STATE_CHANGED`
- `POLICY_APPLIED`
- `NETWORK_MODE_SET`
- `ALLOWLIST_UPDATED`
- `ARTIFACT_INGEST_STARTED`
- `ARTIFACT_INGESTED`
- `ARTIFACT_INGEST_COMPLETED`
- `EVAL_STARTED`
- `EVAL_GATE_RESULT`
- `EVAL_COMPLETED`
- `EXPORT_REQUESTED`
- `EXPORT_BLOCKED` OR `EXPORT_COMPLETED`
- `RUN_COMPLETED` OR `RUN_FAILED` OR `RUN_CANCELLED`

### 3.2 Network enforcement

- `EGRESS_REQUEST_ALLOWED`
- `EGRESS_REQUEST_BLOCKED`

### 3.3 Model events

- `MODEL_SELECTION_RESOLVED`
- `MODEL_CALL_STARTED`
- `MODEL_CALL_COMPLETED`
- `MODEL_CALL_FAILED`
- `NO_AI_MODE_USED`

### 3.4 Redaction & citation

- `REDACTION_APPLIED`
- `REDACTION_VALIDATION_RESULT`
- `CITATION_VALIDATION_RESULT`

### 3.5 Determinism

- `DETERMINISM_PROFILE_SET`
- `DETERMINISM_DOWNGRADED`
- `DETERMINISM_VALIDATION_RESULT`

### 3.6 Bundle generation & validation

- `BUNDLE_GENERATION_STARTED`
- `BUNDLE_GENERATION_COMPLETED`
- `BUNDLE_VALIDATION_STARTED`
- `BUNDLE_VALIDATION_RESULT`

### 3.7 Vault crypto & deletion (required capabilities)

- `VAULT_ENCRYPTION_STATUS`
- `VAULT_KEY_ROTATED`
- `DELETION_REQUESTED`
- `DELETION_COMPLETED`

---

## 4) Required `details` payload keys by event type (Normative)

All lists in `details` MUST be stable-sorted where applicable.

### 4.1 RUN_CREATED

details MUST include:

- `pack_id`
- `pack_version`
- `policy_pack_id`
- `policy_pack_version`
- `determinism_enabled` (boolean)

### 4.2 RUN_STATE_CHANGED

details MUST include:

- `from_state`
- `to_state`
- `reason` (string)

### 4.3 POLICY_APPLIED

details MUST include:

- `policy_mode` (`STRICT` | `BALANCED` | `DRAFT_ONLY`)
- `rules_enabled` (list; sorted)
- `export_requirements` object with:
  - `citations_required` (boolean)
  - `redaction_required` (boolean)
  - `pinning_required` (boolean)

### 4.4 NETWORK_MODE_SET

details MUST include:

- `network_mode` (`OFFLINE` | `ONLINE_ALLOWLISTED`)
- `proof_level` (`OFFLINE_STRICT` | `ONLINE_ALLOWLIST_CORE_ONLY` | `ONLINE_ALLOWLIST_WITH_OS_FIREWALL_PROFILE`)
- `ui_remote_fetch_disabled` (boolean)

### 4.5 ALLOWLIST_UPDATED

details MUST include:

- `allowlist_hash_sha256`
- `allowlist_count`

### 4.6 ARTIFACT_INGEST_STARTED

details MUST include:

- `source_type` (`FOLDER` | `ZIP` | `FILE_PICKER` | `API`)
- `source_ref` (string; redacted if required)

### 4.7 ARTIFACT_INGESTED

details MUST include:

- `artifact_id`
- `artifact_sha256`
- `content_type`
- `size_bytes`
- `origin_path` (may be redacted)
- `ingest_transformations` (list; sorted)

### 4.8 ARTIFACT_INGEST_COMPLETED

details MUST include:

- `artifact_count`

### 4.9 MODEL_SELECTION_RESOLVED

details MUST include:

- `task_type` (`LLM` | `EMBED` | `STT` | `VLM`)
- `selected_model_id`
- `pinning_level` (`CRYPTO_PINNED` | `VERSION_PINNED` | `NAME_ONLY`)
- `adapter_id`
- `adapter_endpoint` (loopback)

### 4.10 MODEL_CALL_STARTED

details MUST include:

- `call_id`
- `task_type`
- `input_artifact_refs` (list of artifact_ids; sorted)
- `request_hash_sha256`
- `timeout_ms`

### 4.11 MODEL_CALL_COMPLETED

details MUST include:

- `call_id`
- `response_hash_sha256`
- `duration_ms`

### 4.12 MODEL_CALL_FAILED

details MUST include:

- `call_id`
- `error_category` (`TIMEOUT` | `ADAPTER_UNAVAILABLE` | `INVALID_REQUEST` | `MODEL_ERROR` | `POLICY_BLOCKED`)
- `error_code`
- `error_message_redacted`

### 4.13 NO_AI_MODE_USED

details MUST include:

- `reason` (`USER_SELECTED` | `POLICY_REQUIRED` | `ADAPTER_UNAVAILABLE`)
- `affected_tasks` (list; sorted)

### 4.14 EGRESS_REQUEST_ALLOWED

details MUST include:

- `destination` object: `scheme`, `host`, `port`, `path`
- `allowlist_rule_id`
- `request_hash_sha256`

### 4.15 EGRESS_REQUEST_BLOCKED

details MUST include:

- `destination`
- `block_reason` (`OFFLINE_MODE` | `NOT_ALLOWLISTED` | `UI_DIRECT_EGRESS_BLOCKED`)
- `request_hash_sha256`

### 4.16 REDACTION_APPLIED

details MUST include:

- `artifact_id`
- `redaction_type` (`TEXT_SPAN` | `IMAGE_BBOX`)
- `region` (type-specific)
- `reason` (`PII` | `PCI` | `PHI` | `SECRET` | `CUSTOM`)
- `policy_rule_id`

### 4.17 REDACTION_VALIDATION_RESULT

details MUST include:

- `result` (`PASS` | `FAIL`)
- `missing_required_redactions` (int)

### 4.18 CITATION_VALIDATION_RESULT

**Schema references (normative):**

- `locator_schema_version` MUST be `LOCATOR_SCHEMA_V1` (defined in `Phase_2_5_Lock_Addendum_v2.5-lock-4.md`).
- If `result=FAIL`, details MUST include failing claim IDs and locator parse errors.

details MUST include:

- `result` (`PASS` | `FAIL`)
- `claims_total`
- `claims_missing_citations`
- `locator_schema_version` (`LOCATOR_SCHEMA_V1`)

### 4.19 EVAL_STARTED

details MUST include:

- `registry_version`

### 4.20 EVAL_GATE_RESULT

details MUST include:

- `gate_id`
- `result` (`PASS` | `FAIL` | `NOT_APPLICABLE`)
- `severity` (`BLOCKER` | `MAJOR` | `MINOR`)
- `evidence_pointers` (list; sorted)
- `message` (string; deterministic content)

### 4.21 EVAL_COMPLETED

details MUST include:

- `gates_executed`
- `gates_failed_blocker`
- `gates_failed_total`

### 4.22 EXPORT_REQUESTED

details MUST include:

- `requested_by` (`user` | `system`)
- `export_targets` (list; sorted)
- `policy_mode`

### 4.23 EXPORT_BLOCKED

details MUST include:

- `block_reason` (`EVAL_FAILED` | `MISSING_CITATIONS` | `MISSING_REDACTIONS` | `INSUFFICIENT_PINNING` | `OFFLINE_PROOF_INSUFFICIENT` | `DETERMINISM_FAILED` | `BUNDLE_VALIDATION_FAILED`)
- `failed_gate_ids` (list; sorted)

### 4.24 EXPORT_COMPLETED

details MUST include:

- `bundle_path` (relative)
- `bundle_sha256`
- `bundle_version` (`EVIDENCE_BUNDLE_V1`)
- `validator_result` (`PASS`)

### 4.25 BUNDLE_VALIDATION_RESULT

details MUST include:

- `result` (`PASS` | `FAIL`)
- `failed_checks` (list; sorted)
- `validator_version` (`bundle_validator_v1`)

### 4.26 VAULT_ENCRYPTION_STATUS

details MUST include:

- `encryption_at_rest` (boolean)
- `algorithm` (`XCHACHA20_POLY1305` | `AES_256_GCM`)
- `key_storage` (`MACOS_KEYCHAIN` | `WINDOWS_DPAPI`)

### 4.27 VAULT_KEY_ROTATED

details MUST include:

- `old_key_id`
- `new_key_id`

### 4.28 DELETION_REQUESTED

details MUST include:

- `artifact_ids` (list; sorted)
- `requested_by`

### 4.29 DELETION_COMPLETED

details MUST include:

- `artifact_ids_deleted` (list; sorted)
- `blob_delete_method` (`unlink_only` | `overwrite_then_unlink` | `fs_unsupported`)
- `sqlite_compaction_attempted` (boolean)
- `result` (`PASS` | `FAIL`)

---

## 5) Ordering and Stability Rules (Normative)

- Events MUST be appended in chronological order by `ts_utc`.
- If two events share identical `ts_utc`:
  1. order by event_type priority:
     RUN/STATE > POLICY/NETWORK > INGEST > MODEL > EVAL > EXPORT > BUNDLE > VAULT/DELETION
  2. then by `details.meta.event_id` if present, else stable insertion order

End.
