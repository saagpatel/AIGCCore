use crate::adapters::pinning::PinningLevel;
use crate::policy::types::{NetworkMode, PolicyMode, ProofLevel};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExportBlockReason {
    EVAL_FAILED,
    MISSING_CITATIONS,
    MISSING_REDACTIONS,
    INSUFFICIENT_PINNING,
    OFFLINE_PROOF_INSUFFICIENT,
    DETERMINISM_FAILED,
    BUNDLE_VALIDATION_FAILED,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportGateInputs {
    pub policy_mode: PolicyMode,
    pub pinning_level: Option<PinningLevel>,
    pub citations_required_passed: bool,
    pub redactions_required_passed: bool,
    pub blocker_gate_failures: Vec<String>,
    pub determinism_passed: bool,
    pub network_mode: NetworkMode,
    pub proof_level: ProofLevel,
}

pub fn evaluate_export_gate(i: &ExportGateInputs) -> Result<(), ExportBlockReason> {
    if !i.blocker_gate_failures.is_empty() {
        return Err(ExportBlockReason::EVAL_FAILED);
    }
    if !i.determinism_passed {
        return Err(ExportBlockReason::DETERMINISM_FAILED);
    }

    // Pinning rules from lock addendum §7.
    let pin_ok = i.pinning_level.is_none()
        || match i.policy_mode {
            PolicyMode::STRICT | PolicyMode::BALANCED => {
                i.pinning_level == Some(PinningLevel::CRYPTO_PINNED)
                    || i.pinning_level == Some(PinningLevel::VERSION_PINNED)
            }
            PolicyMode::DRAFT_ONLY => true,
        };
    if !pin_ok {
        return Err(ExportBlockReason::INSUFFICIENT_PINNING);
    }

    if i.policy_mode == PolicyMode::STRICT && !i.citations_required_passed {
        return Err(ExportBlockReason::MISSING_CITATIONS);
    }
    if (i.policy_mode == PolicyMode::STRICT || i.policy_mode == PolicyMode::BALANCED)
        && !i.redactions_required_passed
    {
        return Err(ExportBlockReason::MISSING_REDACTIONS);
    }

    // Offline proof sufficiency check (strictest interpretation preserving privacy):
    // Strict requires OFFLINE mode + OFFLINE_STRICT proof level at export.
    if i.policy_mode == PolicyMode::STRICT
        && (i.network_mode != NetworkMode::OFFLINE || i.proof_level != ProofLevel::OFFLINE_STRICT)
    {
        return Err(ExportBlockReason::OFFLINE_PROOF_INSUFFICIENT);
    }

    Ok(())
}
