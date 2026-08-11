use crate::error::CoreResult;
use crate::eval::registry::{not_applicable_allowed, registry_v3, GateRegistry};
use crate::evidence_bundle::schemas::{EvalGateResult, EvalReport};
use crate::policy::types::PolicyMode;
use crate::validator::{BundleValidator, ValidationSummary};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

const UNMAPPED_GATE_MESSAGE_PREFIX: &str = "Applicable gate has no evaluator implementation: ";

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
        let summary =
            BundleValidator::new_v3().validate_zip_for_evaluation_preflight(bundle_zip, policy)?;
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

    /// Materialize the authoritative v3 eval report from one complete evaluator run.
    ///
    /// This rejects missing, duplicate, unexpected, malformed, or severity-downgraded
    /// results so callers cannot serialize a partial result set as a successful report.
    pub fn report_from_results(
        &self,
        gate_results: &[GateRunResult],
        policy: PolicyMode,
        pack_id: &str,
    ) -> CoreResult<EvalReport> {
        if pack_id.trim().is_empty() {
            return Err(crate::error::CoreError::InvalidInput(
                "pack_id is required to materialize an eval report".to_string(),
            ));
        }
        let policy_str = policy_name(policy);
        let applicable: BTreeMap<&str, _> = self
            .registry
            .gates
            .iter()
            .filter(|gate| gate.applies_to_policies.iter().any(|p| p == policy_str))
            .map(|gate| (gate.gate_id.as_str(), gate))
            .collect();
        let mut by_id: BTreeMap<&str, &GateRunResult> = BTreeMap::new();

        for result in gate_results {
            let gate = applicable.get(result.gate_id.as_str()).ok_or_else(|| {
                crate::error::CoreError::InvalidInput(format!(
                    "unexpected or inapplicable gate result {} for {}",
                    result.gate_id, policy_str
                ))
            })?;
            if by_id.insert(result.gate_id.as_str(), result).is_some() {
                return Err(crate::error::CoreError::InvalidInput(format!(
                    "duplicate gate result {}",
                    result.gate_id
                )));
            }
            if !matches!(result.result.as_str(), "PASS" | "FAIL" | "NOT_APPLICABLE") {
                return Err(crate::error::CoreError::InvalidInput(format!(
                    "invalid result {} for gate {}",
                    result.result, result.gate_id
                )));
            }
            if result.result == "NOT_APPLICABLE"
                && !not_applicable_allowed(&result.gate_id, Some(pack_id))
            {
                return Err(crate::error::CoreError::InvalidInput(format!(
                    "NOT_APPLICABLE is not allowed for gate {}",
                    result.gate_id
                )));
            }
            let reported_rank = severity_rank(&result.severity).ok_or_else(|| {
                crate::error::CoreError::InvalidInput(format!(
                    "invalid severity {} for gate {}",
                    result.severity, result.gate_id
                ))
            })?;
            let registry_rank = severity_rank(&gate.severity).ok_or_else(|| {
                crate::error::CoreError::InvalidInput(format!(
                    "invalid registry severity {} for gate {}",
                    gate.severity, gate.gate_id
                ))
            })?;
            if reported_rank < registry_rank {
                return Err(crate::error::CoreError::InvalidInput(format!(
                    "severity downgrade for gate {}: {} below {}",
                    result.gate_id, result.severity, gate.severity
                )));
            }
            let mut reported_evidence = result.evidence_pointers.clone();
            let mut registry_evidence = gate.evidence_required.clone();
            reported_evidence.sort();
            registry_evidence.sort();
            if reported_evidence != registry_evidence {
                return Err(crate::error::CoreError::InvalidInput(format!(
                    "evidence pointers do not match registry for gate {}",
                    result.gate_id
                )));
            }
        }

        let present: BTreeSet<&str> = by_id.keys().copied().collect();
        let expected: BTreeSet<&str> = applicable.keys().copied().collect();
        let missing: Vec<&str> = expected.difference(&present).copied().collect();
        if !missing.is_empty() {
            return Err(crate::error::CoreError::InvalidInput(format!(
                "missing applicable gate results: {}",
                missing.join(", ")
            )));
        }

        let gates: Vec<EvalGateResult> = applicable
            .into_iter()
            .map(|(gate_id, gate)| {
                let result = by_id
                    .get(gate_id)
                    .expect("applicable gate presence checked above");
                EvalGateResult {
                    gate_id: result.gate_id.clone(),
                    category: gate.category.clone(),
                    status: result.result.clone(),
                    severity: result.severity.clone(),
                    message: result.message.clone(),
                    evidence_pointers: result.evidence_pointers.clone(),
                }
            })
            .collect();

        Ok(EvalReport {
            overall_status: overall_status_for_gates(&gates),
            tests: Vec::new(),
            gates,
            registry_version: self.registry.registry_version.clone(),
        })
    }

    /// Resolve a policy gate without treating missing applicable evidence as success.
    pub fn gate_satisfied_for_export(
        &self,
        report: &EvalReport,
        gate_id: &str,
        policy: PolicyMode,
    ) -> bool {
        let Some(definition) = self
            .registry
            .gates
            .iter()
            .find(|gate| gate.gate_id == gate_id)
        else {
            return false;
        };
        if !definition
            .applies_to_policies
            .iter()
            .any(|p| p == policy_name(policy))
        {
            return true;
        }
        let matches: Vec<&EvalGateResult> = report
            .gates
            .iter()
            .filter(|gate| gate.gate_id == gate_id)
            .collect();
        matches.len() == 1 && matches!(matches[0].status.as_str(), "PASS" | "NOT_APPLICABLE")
    }
}

fn policy_name(policy: PolicyMode) -> &'static str {
    match policy {
        PolicyMode::STRICT => "STRICT",
        PolicyMode::BALANCED => "BALANCED",
        PolicyMode::DRAFT_ONLY => "DRAFT_ONLY",
    }
}

fn severity_rank(severity: &str) -> Option<u8> {
    match severity {
        "MINOR" => Some(1),
        "MAJOR" => Some(2),
        "BLOCKER" => Some(3),
        _ => None,
    }
}

fn overall_status_for_gates(gates: &[EvalGateResult]) -> String {
    if gates
        .iter()
        .any(|gate| gate.status == "FAIL" && gate.severity == "BLOCKER")
    {
        "FAIL".to_string()
    } else if gates.iter().any(|gate| gate.status == "FAIL") {
        "WARN".to_string()
    } else {
        "PASS".to_string()
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
        let mut severity = g.severity.clone();
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
            _ => {
                // An applicable registry entry without an evaluator is a coverage failure,
                // regardless of the severity declared by the unmapped definition.
                severity = "BLOCKER".to_string();
                (
                    "FAIL".to_string(),
                    format!("{UNMAPPED_GATE_MESSAGE_PREFIX}{}", g.gate_id),
                )
            }
        };

        let mut evidence_pointers = g.evidence_required.clone();
        evidence_pointers.sort();
        results.push(GateRunResult {
            gate_id: g.gate_id.clone(),
            result,
            severity,
            message: msg,
            evidence_pointers,
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
        return Ok((
            "NOT_APPLICABLE".to_string(),
            "not evidenceos pack".to_string(),
        ));
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
        return Ok((
            "NOT_APPLICABLE".to_string(),
            "not evidenceos pack".to_string(),
        ));
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
    use super::{
        evaluate_offline_allowlist_from_ndjson, map_validator_to_gates, EvalRunner, GateRunResult,
        UNMAPPED_GATE_MESSAGE_PREFIX,
    };
    use crate::eval::registry::{GateDef, GateRegistry};
    use crate::policy::types::PolicyMode;
    use crate::validator::ValidationSummary;

    fn map_single_gate(
        gate_id: &str,
        severity: &str,
        applies_to_policies: &[&str],
        policy: PolicyMode,
    ) -> Vec<super::GateRunResult> {
        let summary = ValidationSummary {
            checklist_version: "test".to_string(),
            policy: "test".to_string(),
            overall: "PASS".to_string(),
            checks: Vec::new(),
        };
        let registry = GateRegistry {
            registry_version: "test".to_string(),
            gates: vec![GateDef {
                gate_id: gate_id.to_string(),
                category: "TEST".to_string(),
                severity: severity.to_string(),
                applies_to_policies: applies_to_policies
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                pass_criteria: serde_json::Value::Null,
                evidence_required: Vec::new(),
            }],
            generated_at_ms: 0,
        };

        map_validator_to_gates(
            &summary,
            &registry,
            policy,
            ("PASS".to_string(), "test".to_string()),
            ("PASS".to_string(), "test".to_string()),
            ("PASS".to_string(), "test".to_string()),
        )
    }

    fn complete_results(runner: &EvalRunner, policy: PolicyMode) -> Vec<GateRunResult> {
        let policy_name = format!("{policy:?}");
        runner
            .registry
            .gates
            .iter()
            .filter(|gate| gate.applies_to_policies.contains(&policy_name))
            .map(|gate| {
                let mut evidence_pointers = gate.evidence_required.clone();
                evidence_pointers.sort();
                GateRunResult {
                    gate_id: gate.gate_id.clone(),
                    result: if gate.gate_id == "OFFLINE_ENFORCEMENT.ALLOWLIST_MATCH_V1" {
                        "NOT_APPLICABLE".to_string()
                    } else {
                        "PASS".to_string()
                    },
                    severity: gate.severity.clone(),
                    message: "test result".to_string(),
                    evidence_pointers,
                }
            })
            .collect()
    }

    #[test]
    fn complete_results_materialize_a_registry_bound_report() {
        let runner = EvalRunner::new_v3().expect("runner");
        let results = complete_results(&runner, PolicyMode::STRICT);

        let report = runner
            .report_from_results(&results, PolicyMode::STRICT, "self_audit")
            .expect("complete report");

        assert_eq!(report.registry_version, "gates_registry_v3");
        assert_eq!(report.gates.len(), results.len());
        assert_eq!(report.overall_status, "PASS");
        assert!(report.gates.iter().any(|gate| {
            gate.gate_id == "OFFLINE_ENFORCEMENT.ALLOWLIST_MATCH_V1"
                && gate.status == "NOT_APPLICABLE"
        }));
    }

    #[test]
    fn report_materialization_rejects_a_missing_applicable_gate() {
        let runner = EvalRunner::new_v3().expect("runner");
        let mut results = complete_results(&runner, PolicyMode::STRICT);
        let missing = results.pop().expect("at least one applicable gate").gate_id;

        let error = runner
            .report_from_results(&results, PolicyMode::STRICT, "self_audit")
            .expect_err("partial results must fail closed");

        assert!(error
            .to_string()
            .contains("missing applicable gate results"));
        assert!(error.to_string().contains(&missing));
    }

    #[test]
    fn report_materialization_rejects_duplicate_and_invalid_results() {
        let runner = EvalRunner::new_v3().expect("runner");
        let mut duplicate_results = complete_results(&runner, PolicyMode::STRICT);
        duplicate_results.push(duplicate_results[0].clone());
        let duplicate_error = runner
            .report_from_results(&duplicate_results, PolicyMode::STRICT, "self_audit")
            .expect_err("duplicate results must fail closed");
        assert!(duplicate_error
            .to_string()
            .contains("duplicate gate result"));

        let mut invalid_results = complete_results(&runner, PolicyMode::STRICT);
        invalid_results[0].result = "UNKNOWN".to_string();
        let invalid_error = runner
            .report_from_results(&invalid_results, PolicyMode::STRICT, "self_audit")
            .expect_err("invalid status must fail closed");
        assert!(invalid_error.to_string().contains("invalid result UNKNOWN"));

        let mut missing_evidence = complete_results(&runner, PolicyMode::STRICT);
        missing_evidence[0].evidence_pointers.clear();
        let evidence_error = runner
            .report_from_results(&missing_evidence, PolicyMode::STRICT, "self_audit")
            .expect_err("registry evidence pointers must remain bound");
        assert!(evidence_error
            .to_string()
            .contains("evidence pointers do not match registry"));

        let mut unapproved_not_applicable = complete_results(&runner, PolicyMode::STRICT);
        let audit_gate = unapproved_not_applicable
            .iter_mut()
            .find(|gate| gate.gate_id == "AUDIT_HASH_CHAIN.VERIFY_V1")
            .expect("audit gate");
        audit_gate.result = "NOT_APPLICABLE".to_string();
        let not_applicable_error = runner
            .report_from_results(
                &unapproved_not_applicable,
                PolicyMode::STRICT,
                "self_audit",
            )
            .expect_err("NOT_APPLICABLE must be gate-specific");
        assert!(not_applicable_error
            .to_string()
            .contains("NOT_APPLICABLE is not allowed"));

        let mut pack_sensitive = complete_results(&runner, PolicyMode::STRICT);
        let evidenceos_gate = pack_sensitive
            .iter_mut()
            .find(|gate| gate.gate_id == "EVIDENCEOS.OUTPUTS_PRESENT_V1")
            .expect("EvidenceOS gate");
        evidenceos_gate.result = "NOT_APPLICABLE".to_string();
        let pack_error = runner
            .report_from_results(&pack_sensitive, PolicyMode::STRICT, "evidenceos")
            .expect_err("EvidenceOS pack cannot omit its own output gate");
        assert!(pack_error
            .to_string()
            .contains("NOT_APPLICABLE is not allowed"));

        let missing_pack_error = runner
            .report_from_results(
                &complete_results(&runner, PolicyMode::STRICT),
                PolicyMode::STRICT,
                "",
            )
            .expect_err("pack identity is required");
        assert!(missing_pack_error.to_string().contains("pack_id is required"));
    }

    #[test]
    fn export_gate_lookup_fails_closed_for_missing_applicable_evidence() {
        let runner = EvalRunner::new_v3().expect("runner");
        let results = complete_results(&runner, PolicyMode::STRICT);
        let mut report = runner
            .report_from_results(&results, PolicyMode::STRICT, "self_audit")
            .expect("complete report");
        report
            .gates
            .retain(|gate| gate.gate_id != "CITATIONS.STRICT_ENFORCED_V1");

        assert!(!runner.gate_satisfied_for_export(
            &report,
            "CITATIONS.STRICT_ENFORCED_V1",
            PolicyMode::STRICT,
        ));
        assert!(runner.gate_satisfied_for_export(
            &report,
            "CITATIONS.STRICT_ENFORCED_V1",
            PolicyMode::BALANCED,
        ));
    }

    #[test]
    fn applicable_unmapped_gate_fails_as_a_blocker() {
        let results = map_single_gate(
            "FUTURE.UNMAPPED_V1",
            "MAJOR",
            &["STRICT"],
            PolicyMode::STRICT,
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].result, "FAIL");
        assert_eq!(results[0].severity, "BLOCKER");
        assert!(results[0].message.contains("FUTURE.UNMAPPED_V1"));
    }

    #[test]
    fn explicit_pdf_gate_keeps_its_not_applicable_semantics() {
        let results = map_single_gate(
            "DETERMINISM.PDF_CAPABLE_V1",
            "MAJOR",
            &["STRICT"],
            PolicyMode::STRICT,
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].result, "NOT_APPLICABLE");
        assert_eq!(results[0].severity, "MAJOR");
        assert_eq!(results[0].message, "No PDFs in self-audit bundle");
    }

    #[test]
    fn unmapped_gate_for_another_policy_is_not_executed() {
        let results = map_single_gate(
            "FUTURE.BALANCED_ONLY_V1",
            "BLOCKER",
            &["BALANCED"],
            PolicyMode::STRICT,
        );

        assert!(results.is_empty());
    }

    #[test]
    fn registry_v3_has_an_explicit_mapping_for_every_applicable_gate() {
        let summary = ValidationSummary {
            checklist_version: "test".to_string(),
            policy: "STRICT".to_string(),
            overall: "PASS".to_string(),
            checks: Vec::new(),
        };
        let registry = crate::eval::registry::registry_v3().expect("registry v3");
        let mut unmapped = Vec::new();
        for policy in [
            PolicyMode::STRICT,
            PolicyMode::BALANCED,
            PolicyMode::DRAFT_ONLY,
        ] {
            let results = map_validator_to_gates(
                &summary,
                &registry,
                policy,
                ("PASS".to_string(), "test".to_string()),
                ("PASS".to_string(), "test".to_string()),
                ("PASS".to_string(), "test".to_string()),
            );
            unmapped.extend(
                results
                    .into_iter()
                    .filter(|result| result.message.starts_with(UNMAPPED_GATE_MESSAGE_PREFIX))
                    .map(|result| result.gate_id),
            );
        }
        unmapped.sort();
        unmapped.dedup();

        assert!(
            unmapped.is_empty(),
            "registry v3 contains unmapped gates: {unmapped:?}"
        );
    }

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
