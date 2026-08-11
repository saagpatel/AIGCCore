use crate::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRegistry {
    pub registry_version: String,
    pub gates: Vec<GateDef>,
    pub generated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDef {
    pub gate_id: String,
    pub category: String,
    pub severity: String,
    pub applies_to_policies: Vec<String>,
    pub pass_criteria: serde_json::Value,
    pub evidence_required: Vec<String>,
}

pub fn registry_v3() -> CoreResult<GateRegistry> {
    // Embed the authoritative JSON from Eval_Gate_Registry_v3.md.
    let json = include_str!("registry_v3.json");
    let reg: GateRegistry = serde_json::from_str(json)?;
    if reg.registry_version != "gates_registry_v3" {
        return Err(CoreError::InvalidInput(
            "embedded registry is not gates_registry_v3".to_string(),
        ));
    }
    Ok(reg)
}

/// Gate-level exceptions whose evaluator semantics explicitly permit
/// `NOT_APPLICABLE` even when the gate applies to the selected policy.
pub fn not_applicable_allowed(gate_id: &str, pack_id: Option<&str>) -> bool {
    match gate_id {
        "OFFLINE_ENFORCEMENT.ALLOWLIST_MATCH_V1" | "DETERMINISM.PDF_CAPABLE_V1" => true,
        "EVIDENCEOS.OUTPUTS_PRESENT_V1" | "EVIDENCEOS.MAPPING_REVIEW_PRESENT_V1" => {
            pack_id.map(|id| id != "evidenceos").unwrap_or(true)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::not_applicable_allowed;

    #[test]
    fn not_applicable_exceptions_are_explicit_and_pack_bound() {
        assert!(not_applicable_allowed(
            "OFFLINE_ENFORCEMENT.ALLOWLIST_MATCH_V1",
            Some("self_audit")
        ));
        assert!(not_applicable_allowed(
            "EVIDENCEOS.OUTPUTS_PRESENT_V1",
            Some("self_audit")
        ));
        assert!(!not_applicable_allowed(
            "EVIDENCEOS.OUTPUTS_PRESENT_V1",
            Some("evidenceos")
        ));
        assert!(!not_applicable_allowed(
            "AUDIT_HASH_CHAIN.VERIFY_V1",
            Some("self_audit")
        ));
    }
}
