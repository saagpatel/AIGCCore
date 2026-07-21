use crate::error::CoreResult;
use crate::eval::registry::{registry_v3, GateRegistry};
use crate::policy::types::PolicyMode;
use crate::validator::{BundleValidator, ValidationSummary};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRunResult {
    pub gate_id: String,
    pub result: String, // PASS|FAIL|NOT_APPLICABLE
    pub severity: String,
    pub message: String,
    pub evidence_pointers: Vec<String>,
}

pub struct EvalRunner {
    pub registry: GateRegistry,
}

impl EvalRunner {
    pub fn new_v3() -> CoreResult<Self> {
        Ok(Self {
            registry: registry_v3()?,
        })
    }

    pub fn run_all_for_bundle(
        &self,
        bundle_zip: &std::path::Path,
        policy: PolicyMode,
    ) -> CoreResult<Vec<GateRunResult>> {
        // Phase 2: gates are currently implemented by reusing the bundle validator and mapping to gate IDs.
        // This keeps gate outputs stable and enforces the checklist semantics.
        let summary = BundleValidator::new_v3().validate_zip(bundle_zip, policy)?;
        let (allowlist_result, allowlist_msg) = evaluate_offline_allowlist_gate(bundle_zip)?;
        let (evidence_outputs_result, evidence_outputs_msg) =
            evaluate_evidenceos_outputs_gate(bundle_zip)?;
        let (mapping_review_result, mapping_review_msg) =
            evaluate_evidenceos_mapping_review_gate(bundle_zip)?;
        Ok(map_validator_to_gates(
            &summary,
            &self.registry,
            policy,
            (allowlist_result, allowlist_msg),
            (evidence_outputs_result, evidence_outputs_msg),
            (mapping_review_result, mapping_review_msg),
        ))
    }
}

fn map_validator_to_gates(
    summary: &ValidationSummary,
    registry: &GateRegistry,
    policy: PolicyMode,
    allowlist_gate: (String, String),
    evidence_outputs_gate: (String, String),
    mapping_review_gate: (String, String),
) -> Vec<GateRunResult> {
    let policy_str = match policy {
        PolicyMode::STRICT => "STRICT",
        PolicyMode::BALANCED => "BALANCED",
        PolicyMode::DRAFT_ONLY => "DRAFT_ONLY",
    };

    let mut results = Vec::new();
    for g in &registry.gates {
        if !g.applies_to_policies.iter().any(|p| p == policy_str) {
            continue;
        }
        // Minimal mapping based on category/check IDs.
        let (result, msg) = match g.gate_id.as_str() {
            "BUNDLE_FORMAT.REQUIRED_FILES_V1" => summary.result_for_checks_prefix("CHK.BUNDLE."),
            "AUDIT_HASH_CHAIN.VERIFY_V1" => {
                summary.result_for_check("CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN")
            }
            "EVIDENCE_AUTHORITY.CONTRACT_V1" => {
                summary.result_for_check("CHK.EVIDENCE.AUTHORITY_CONTRACT")
            }
            "OFFLINE_ENFORCEMENT.MODE_PROOF_V1" => {
                summary.result_for_check("CHK.NETWORK.SNAPSHOT_PRESENT")
            }
            "OFFLINE_ENFORCEMENT.ALLOWLIST_MATCH_V1" => allowlist_gate.clone(),
            "CITATIONS.STRICT_ENFORCED_V1" => summary.result_for_check("CHK.CITATIONS.STRICT"),
            "REDACTION.REQUIRED_APPLIED_V1" => {
                summary.result_for_check("CHK.REDACTION.POLICY_GATE")
            }
            "MODEL_PINNING.MIN_LEVEL_V1" => summary.result_for_check("CHK.MODEL.PINNING_LEVEL"),
            "VAULT_CRYPTO.ENCRYPTION_AT_REST_V1" => (
                summary.vault_crypto_gate_result(),
                summary.vault_crypto_message(),
            ),
            "DETERMINISM.ZIP_PACKAGING_V1" => summary.result_for_check("CHK.DETERMINISM.ZIP_RULES"),
            "DETERMINISM.PDF_CAPABLE_V1" => (
                "NOT_APPLICABLE".to_string(),
                "No PDFs in self-audit bundle".to_string(),
            ),
            "EVIDENCEOS.OUTPUTS_PRESENT_V1" => evidence_outputs_gate.clone(),
            "EVIDENCEOS.MAPPING_REVIEW_PRESENT_V1" => mapping_review_gate.clone(),
            _ => (
                "NOT_APPLICABLE".to_string(),
                "Gate not implemented in Phase 2 runner".to_string(),
            ),
        };

        results.push(GateRunResult {
            gate_id: g.gate_id.clone(),
            result,
            severity: g.severity.clone(),
            message: msg,
            evidence_pointers: g.evidence_required.clone(),
        });
    }
    results.sort_by(|a, b| a.gate_id.cmp(&b.gate_id));
    results
}

fn evaluate_offline_allowlist_gate(bundle_zip: &Path) -> CoreResult<(String, String)> {
    let file = File::open(bundle_zip)?;
    let mut zip = ZipArchive::new(file).map_err(|e| crate::error::CoreError::Zip(e.to_string()))?;
    let mut f = zip
        .by_name("audit_log.ndjson")
        .map_err(|e| crate::error::CoreError::Zip(e.to_string()))?;
    let mut ndjson = String::new();
    f.read_to_string(&mut ndjson)?;
    Ok(evaluate_offline_allowlist_from_ndjson(&ndjson))
}

fn evaluate_evidenceos_outputs_gate(bundle_zip: &Path) -> CoreResult<(String, String)> {
    let required = [
        "exports/evidenceos/deliverables/evidence_index.csv",
        "exports/evidenceos/deliverables/evidence_index.md",
        "exports/evidenceos/deliverables/evidence_index.pdf",
        "exports/evidenceos/deliverables/evidence_narrative.md",
        "exports/evidenceos/deliverables/missing_evidence_checklist.md",
    ];
    let file = File::open(bundle_zip)?;
    let mut zip = ZipArchive::new(file).map_err(|e| crate::error::CoreError::Zip(e.to_string()))?;
    if !is_evidenceos_pack(&mut zip) {
        return Ok(("NOT_APPLICABLE".to_string(), "not evidenceos pack".to_string()));
    }
    for path in required {
        if zip.by_name(path).is_err() {
            return Ok((
                "FAIL".to_string(),
                format!("missing required EvidenceOS deliverable {}", path),
            ));
        }
    }
    Ok(("PASS".to_string(), "ok".to_string()))
}

fn evaluate_evidenceos_mapping_review_gate(bundle_zip: &Path) -> CoreResult<(String, String)> {
    let path = "exports/evidenceos/deliverables/evidence_mapping_review.json";
    let file = File::open(bundle_zip)?;
    let mut zip = ZipArchive::new(file).map_err(|e| crate::error::CoreError::Zip(e.to_string()))?;
    if !is_evidenceos_pack(&mut zip) {
        return Ok(("NOT_APPLICABLE".to_string(), "not evidenceos pack".to_string()));
    }
    let mut f = match zip.by_name(path) {
        Ok(v) => v,
        Err(_) => return Ok(("FAIL".to_string(), format!("missing {}", path))),
    };
    let mut body = String::new();
    f.read_to_string(&mut body)?;
    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return Ok((
                "FAIL".to_string(),
                format!("invalid JSON in {}: {}", path, e),
            ))
        }
    };
    let schema = parsed
        .get("schema_version")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if schema != "EVIDENCE_MAPPING_REVIEW_V1" {
        return Ok((
            "FAIL".to_string(),
            format!("unexpected schema_version {} in {}", schema, path),
        ));
    }
    Ok(("PASS".to_string(), "ok".to_string()))
}

fn is_evidenceos_pack<R: Read + std::io::Seek>(zip: &mut ZipArchive<R>) -> bool {
    let mut f = match zip.by_name("BUNDLE_INFO.json") {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut body = String::new();
    if f.read_to_string(&mut body).is_err() {
        return false;
    }
    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return false,
    };
    parsed
        .get("pack_id")
        .and_then(|x| x.as_str())
        .map(|x| x == "evidenceos")
        .unwrap_or(false)
}

fn evaluate_offline_allowlist_from_ndjson(ndjson: &str) -> (String, String) {
    let mut seen_allowlist_updated = false;
    let mut simulated_blocked_count: usize = 0;
    let mut runtime_blocked_count: usize = 0;
    let mut ambiguous_origin_count: usize = 0;
    let mut blocked_invalid_reasons: Vec<String> = Vec::new();
    let mut allowed_missing_rule_count: usize = 0;
    let allowed_block_reasons = [
        "OFFLINE_MODE",
        "NOT_ALLOWLISTED",
        "UI_DIRECT_EGRESS_BLOCKED",
    ];

    for (line_no, line) in ndjson.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return (
                    "FAIL".to_string(),
                    format!("invalid audit_log.ndjson at line {}: {}", line_no + 1, e),
                )
            }
        };
        let event_type = v
            .get("event_type")
            .and_then(|x| x.as_str())
            .unwrap_or_default();

        match event_type {
            "ALLOWLIST_UPDATED" => seen_allowlist_updated = true,
            "EGRESS_REQUEST_BLOCKED" => {
                match v
                    .pointer("/details/evidence_origin")
                    .and_then(|x| x.as_str())
                {
                    Some("CONTROL_SIMULATION") => simulated_blocked_count += 1,
                    Some("RUNTIME_OBSERVATION") => runtime_blocked_count += 1,
                    _ => ambiguous_origin_count += 1,
                }
                let reason = v
                    .pointer("/details/block_reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default();
                if !allowed_block_reasons.contains(&reason) {
                    blocked_invalid_reasons.push(reason.to_string());
                }
            }
            "EGRESS_REQUEST_ALLOWED" => {
                let rule_id = v
                    .pointer("/details/allowlist_rule_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default();
                if rule_id.is_empty() {
                    allowed_missing_rule_count += 1;
                }
            }
            _ => {}
        }
    }

    if !seen_allowlist_updated {
        return (
            "FAIL".to_string(),
            "missing ALLOWLIST_UPDATED event".to_string(),
        );
    }
    if simulated_blocked_count + runtime_blocked_count + ambiguous_origin_count == 0 {
        return (
            "FAIL".to_string(),
            "no EGRESS_REQUEST_BLOCKED events recorded".to_string(),
        );
    }
    if ambiguous_origin_count > 0 {
        return (
            "FAIL".to_string(),
            format!(
                "{ambiguous_origin_count} blocked egress events have missing or ambiguous evidence_origin"
            ),
        );
    }
    if !blocked_invalid_reasons.is_empty() {
        blocked_invalid_reasons.sort();
        blocked_invalid_reasons.dedup();
        return (
            "FAIL".to_string(),
            format!(
                "invalid blocked reasons: {}",
                blocked_invalid_reasons.join(", ")
            ),
        );
    }
    if allowed_missing_rule_count > 0 {
        return (
            "FAIL".to_string(),
            format!(
                "{} EGRESS_REQUEST_ALLOWED events missing allowlist_rule_id",
                allowed_missing_rule_count
            ),
        );
    }

    if runtime_blocked_count == 0 {
        return (
            "NOT_APPLICABLE".to_string(),
            format!(
                "{simulated_blocked_count} CONTROL_SIMULATION event(s) prove the policy path only; no live egress observation occurred"
            ),
        );
    }

    (
        "PASS".to_string(),
        format!("{runtime_blocked_count} runtime-observed blocked egress event(s) verified"),
    )
}

#[cfg(test)]
mod tests {
    use super::evaluate_offline_allowlist_from_ndjson;

    #[test]
    fn allowlist_gate_passes_when_runtime_blocked_and_allowlist_events_present() {
        let ndjson = r#"{"ts_utc":"2026-01-01T00:00:00Z","event_type":"ALLOWLIST_UPDATED","run_id":"r1","vault_id":"v1","actor":"system","details":{"allowlist_hash_sha256":"abc","allowlist_count":0},"prev_event_hash":"0000000000000000000000000000000000000000000000000000000000000000","event_hash":"1111111111111111111111111111111111111111111111111111111111111111"}
{"ts_utc":"2026-01-01T00:00:01Z","event_type":"EGRESS_REQUEST_BLOCKED","run_id":"r1","vault_id":"v1","actor":"system","details":{"destination":{},"block_reason":"OFFLINE_MODE","request_hash_sha256":"abc","evidence_origin":"RUNTIME_OBSERVATION"},"prev_event_hash":"1111111111111111111111111111111111111111111111111111111111111111","event_hash":"2222222222222222222222222222222222222222222222222222222222222222"}"#;
        let (result, msg) = evaluate_offline_allowlist_from_ndjson(ndjson);
        assert_eq!(result, "PASS");
        assert!(msg.contains("runtime-observed"));
    }

    #[test]
    fn allowlist_gate_does_not_treat_control_simulation_as_live_observation() {
        let ndjson = r#"{"event_type":"ALLOWLIST_UPDATED","details":{}}
{"event_type":"EGRESS_REQUEST_BLOCKED","details":{"block_reason":"OFFLINE_MODE","evidence_origin":"CONTROL_SIMULATION"}}"#;
        let (result, msg) = evaluate_offline_allowlist_from_ndjson(ndjson);
        assert_eq!(result, "NOT_APPLICABLE");
        assert!(msg.contains("policy path only"));
        assert!(msg.contains("no live egress observation"));
    }

    #[test]
    fn allowlist_gate_fails_closed_on_missing_origin() {
        let ndjson = r#"{"event_type":"ALLOWLIST_UPDATED","details":{}}
{"event_type":"EGRESS_REQUEST_BLOCKED","details":{"block_reason":"OFFLINE_MODE"}}"#;
        let (result, msg) = evaluate_offline_allowlist_from_ndjson(ndjson);
        assert_eq!(result, "FAIL");
        assert!(msg.contains("missing or ambiguous evidence_origin"));
    }

    #[test]
    fn allowlist_gate_fails_when_no_blocked_events() {
        let ndjson = r#"{"ts_utc":"2026-01-01T00:00:00Z","event_type":"ALLOWLIST_UPDATED","run_id":"r1","vault_id":"v1","actor":"system","details":{"allowlist_hash_sha256":"abc","allowlist_count":0},"prev_event_hash":"0000000000000000000000000000000000000000000000000000000000000000","event_hash":"1111111111111111111111111111111111111111111111111111111111111111"}"#;
        let (result, msg) = evaluate_offline_allowlist_from_ndjson(ndjson);
        assert_eq!(result, "FAIL");
        assert!(msg.contains("no EGRESS_REQUEST_BLOCKED events"));
    }
}
