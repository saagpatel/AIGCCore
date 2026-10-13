use crate::policy::allowlist::AllowlistEntry;
use crate::policy::types::{NetworkMode, ProofLevel};

#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub network_mode: NetworkMode,
    pub proof_level: ProofLevel,
    pub allowlist: Vec<AllowlistEntry>, // canonical + sorted
}

#[derive(Debug, Clone)]
pub enum EgressDecision {
    Allowed { allowlist_rule_id: String },
    Blocked { reason: String },
}
