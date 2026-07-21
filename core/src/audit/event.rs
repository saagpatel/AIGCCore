use crate::determinism::json_canonical;
use crate::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    System,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub ts_utc: String, // RFC3339 UTC string
    pub event_type: String,
    pub run_id: String,
    pub vault_id: String,
    pub actor: Actor,
    pub details: serde_json::Value,
    pub prev_event_hash: String, // hex 64
    pub event_hash: String,      // hex 64
}

pub const ZERO_HASH_64: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// Lock addendum requires event_hash = SHA-256(canonical_event_bytes) with canonical JSON rules.
//
// The packet does not explicitly state whether `event_hash` is included in the canonical bytes.
// To avoid key omission (and to keep the canonical envelope exactly as defined), we hash the
// canonical bytes of the full envelope with `event_hash` forced to ZERO_HASH_64 during hashing.
pub fn compute_event_hash(event: &AuditEvent) -> CoreResult<String> {
    // enforce no extra top-level keys by only hashing this struct.
    let mut e = event.clone();
    e.event_hash = ZERO_HASH_64.to_string();
    let bytes = json_canonical::to_canonical_bytes(&e)?;
    let mut h = Sha256::new();
    h.update(bytes);
    Ok(hex::encode(h.finalize()))
}

pub fn finalize_event(mut event: AuditEvent) -> CoreResult<AuditEvent> {
    if event.prev_event_hash.len() != 64
        || !event.prev_event_hash.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(CoreError::InvalidInput(
            "prev_event_hash must be 64 hex chars".to_string(),
        ));
    }
    validate_event_taxonomy(&event)?;
    let eh = compute_event_hash(&event)?;
    event.event_hash = eh;
    Ok(event)
}

fn validate_event_taxonomy(event: &AuditEvent) -> CoreResult<()> {
    let allowed = [
        "RUN_CREATED",
        "RUN_STATE_CHANGED",
        "POLICY_APPLIED",
        "NETWORK_MODE_SET",
        "ALLOWLIST_UPDATED",
        "ARTIFACT_INGEST_STARTED",
        "ARTIFACT_INGESTED",
        "ARTIFACT_INGEST_COMPLETED",
        "EVAL_STARTED",
        "EVAL_GATE_RESULT",
        "EVAL_COMPLETED",
        "EXPORT_REQUESTED",
        "EXPORT_BLOCKED",
        "EXPORT_COMPLETED",
        "RUN_COMPLETED",
        "RUN_FAILED",
        "RUN_CANCELLED",
        "EGRESS_REQUEST_ALLOWED",
        "EGRESS_REQUEST_BLOCKED",
        "MODEL_SELECTION_RESOLVED",
        "MODEL_CALL_STARTED",
        "MODEL_CALL_COMPLETED",
        "MODEL_CALL_FAILED",
        "NO_AI_MODE_USED",
        "REDACTION_APPLIED",
        "REDACTION_VALIDATION_RESULT",
        "CITATION_VALIDATION_RESULT",
        "DETERMINISM_PROFILE_SET",
        "DETERMINISM_DOWNGRADED",
        "DETERMINISM_VALIDATION_RESULT",
        "BUNDLE_GENERATION_STARTED",
        "BUNDLE_GENERATION_COMPLETED",
        "BUNDLE_VALIDATION_STARTED",
        "BUNDLE_VALIDATION_RESULT",
        "VAULT_ENCRYPTION_STATUS",
        "VAULT_KEY_ROTATED",
        "DELETION_REQUESTED",
        "DELETION_COMPLETED",
        "EXPORT_FAILED",
    ];
    if !allowed.contains(&event.event_type.as_str()) {
        return Err(CoreError::InvalidInput(format!(
            "unknown event_type {}",
            event.event_type
        )));
    }
    let required = required_detail_keys(&event.event_type);
    for k in required {
        if event.details.get(k).is_none() {
            return Err(CoreError::InvalidInput(format!(
                "event {} missing details.{}",
                event.event_type, k
            )));
        }
    }
    if matches!(
        event.event_type.as_str(),
        "EGRESS_REQUEST_ALLOWED" | "EGRESS_REQUEST_BLOCKED"
    ) {
        let origin = event
            .details
            .get("evidence_origin")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if !matches!(origin, "CONTROL_SIMULATION" | "RUNTIME_OBSERVATION") {
            return Err(CoreError::InvalidInput(format!(
                "event {} requires explicit evidence_origin CONTROL_SIMULATION or RUNTIME_OBSERVATION",
                event.event_type
            )));
        }
    }
    Ok(())
}

fn required_detail_keys(event_type: &str) -> &'static [&'static str] {
    match event_type {
        "RUN_CREATED" => &[
            "pack_id",
            "pack_version",
            "policy_pack_id",
            "policy_pack_version",
            "determinism_enabled",
        ],
        "RUN_STATE_CHANGED" => &["from_state", "to_state", "reason"],
        "POLICY_APPLIED" => &["policy_mode", "rules_enabled", "export_requirements"],
        "NETWORK_MODE_SET" => &["network_mode", "proof_level", "ui_remote_fetch_disabled"],
        "ALLOWLIST_UPDATED" => &["allowlist_hash_sha256", "allowlist_count"],
        "ARTIFACT_INGEST_STARTED" => &["source_type", "source_ref"],
        "ARTIFACT_INGESTED" => &[
            "artifact_id",
            "artifact_sha256",
            "content_type",
            "size_bytes",
            "origin_path",
            "ingest_transformations",
        ],
        "ARTIFACT_INGEST_COMPLETED" => &["artifact_count"],
        "MODEL_SELECTION_RESOLVED" => &[
            "task_type",
            "selected_model_id",
            "pinning_level",
            "adapter_id",
            "adapter_endpoint",
        ],
        "MODEL_CALL_STARTED" => &[
            "call_id",
            "task_type",
            "input_artifact_refs",
            "request_hash_sha256",
            "timeout_ms",
        ],
        "MODEL_CALL_COMPLETED" => &["call_id", "response_hash_sha256", "duration_ms"],
        "MODEL_CALL_FAILED" => &[
            "call_id",
            "error_category",
            "error_code",
            "error_message_redacted",
        ],
        "NO_AI_MODE_USED" => &["reason", "affected_tasks"],
        "EGRESS_REQUEST_ALLOWED" => &[
            "destination",
            "allowlist_rule_id",
            "request_hash_sha256",
            "evidence_origin",
        ],
        "EGRESS_REQUEST_BLOCKED" => &[
            "destination",
            "block_reason",
            "request_hash_sha256",
            "evidence_origin",
        ],
        "REDACTION_APPLIED" => &[
            "artifact_id",
            "redaction_type",
            "region",
            "reason",
            "policy_rule_id",
        ],
        "REDACTION_VALIDATION_RESULT" => &["result", "missing_required_redactions"],
        "CITATION_VALIDATION_RESULT" => &[
            "result",
            "claims_total",
            "claims_missing_citations",
            "locator_schema_version",
        ],
        "EVAL_STARTED" => &["registry_version"],
        "EVAL_GATE_RESULT" => &[
            "gate_id",
            "result",
            "severity",
            "evidence_pointers",
            "message",
        ],
        "EVAL_COMPLETED" => &[
            "gates_executed",
            "gates_failed_blocker",
            "gates_failed_total",
        ],
        "EXPORT_REQUESTED" => &["requested_by", "export_targets", "policy_mode"],
        "EXPORT_BLOCKED" => &["block_reason", "failed_gate_ids"],
        "EXPORT_COMPLETED" => &[
            "bundle_path",
            "bundle_sha256",
            "bundle_version",
            "validator_result",
        ],
        "BUNDLE_VALIDATION_RESULT" => &["result", "failed_checks", "validator_version"],
        "VAULT_ENCRYPTION_STATUS" => &["encryption_at_rest", "algorithm", "key_storage"],
        "VAULT_KEY_ROTATED" => &["old_key_id", "new_key_id"],
        "DELETION_REQUESTED" => &["artifact_ids", "requested_by"],
        "DELETION_COMPLETED" => &[
            "artifact_ids_deleted",
            "blob_delete_method",
            "sqlite_compaction_attempted",
            "result",
        ],
        _ => &[],
    }
}
