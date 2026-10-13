use crate::policy::allowlist::AllowlistEntry;
use crate::policy::types::{NetworkMode, ProofLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterEndpointSnapshot {
    pub endpoint: String,
    pub is_loopback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub network_mode: NetworkMode,
    pub proof_level: ProofLevel,
    pub proof_source: NetworkProofSource,
    pub allowlist: Vec<AllowlistEntry>, // canonical entries; sorted
    pub ui_remote_fetch_disabled: bool,
    pub adapter_endpoints: Vec<AdapterEndpointSnapshot>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkProofSource {
    POLICY_DECLARATION,
}

impl NetworkSnapshot {
    /// Enforced configuration in the production binary, not a traffic
    /// measurement or adapter health probe.
    pub fn offline_policy() -> Self {
        Self {
            network_mode: NetworkMode::OFFLINE,
            proof_level: ProofLevel::OFFLINE_STRICT,
            proof_source: NetworkProofSource::POLICY_DECLARATION,
            allowlist: vec![],
            ui_remote_fetch_disabled: true,
            adapter_endpoints: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_policy_does_not_claim_measurement_or_adapters() {
        let snapshot = NetworkSnapshot::offline_policy();
        assert_eq!(
            snapshot.proof_source,
            NetworkProofSource::POLICY_DECLARATION
        );
        assert_eq!(snapshot.network_mode, NetworkMode::OFFLINE);
        assert!(snapshot.adapter_endpoints.is_empty());
        assert!(snapshot.allowlist.is_empty());
        let mut value = serde_json::to_value(snapshot).unwrap();
        value["proof_source"] = serde_json::json!("RUNTIME_MEASUREMENT");
        assert!(serde_json::from_value::<NetworkSnapshot>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove("proof_source");
        assert!(serde_json::from_value::<NetworkSnapshot>(value).is_err());
    }
}
