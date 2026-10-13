use aigc_core::adapters::pinning::PinningLevel;
use aigc_core::policy::export_gate::{evaluate_export_gate, ExportBlockReason, ExportGateInputs};
use aigc_core::policy::types::{NetworkMode, PolicyMode, ProofLevel};

#[test]
fn strict_blocks_name_only_pinning() {
    let r = evaluate_export_gate(&ExportGateInputs {
        policy_mode: PolicyMode::STRICT,
        pinning_level: Some(PinningLevel::NAME_ONLY),
        citations_required_passed: true,
        redactions_required_passed: true,
        blocker_gate_failures: vec![],
        determinism_passed: true,
        network_mode: NetworkMode::OFFLINE,
        proof_level: ProofLevel::OFFLINE_STRICT,
    });
    assert_eq!(r.err(), Some(ExportBlockReason::INSUFFICIENT_PINNING));
}

#[test]
fn strict_requires_offline_strict_proof() {
    let r = evaluate_export_gate(&ExportGateInputs {
        policy_mode: PolicyMode::STRICT,
        pinning_level: Some(PinningLevel::CRYPTO_PINNED),
        citations_required_passed: true,
        redactions_required_passed: true,
        blocker_gate_failures: vec![],
        determinism_passed: true,
        network_mode: NetworkMode::ONLINE_ALLOWLISTED,
        proof_level: ProofLevel::ONLINE_ALLOWLIST_CORE_ONLY,
    });
    assert_eq!(r.err(), Some(ExportBlockReason::OFFLINE_PROOF_INSUFFICIENT));
}

#[test]
fn balanced_passes_when_requirements_met() {
    let r = evaluate_export_gate(&ExportGateInputs {
        policy_mode: PolicyMode::BALANCED,
        pinning_level: Some(PinningLevel::VERSION_PINNED),
        citations_required_passed: true,
        redactions_required_passed: true,
        blocker_gate_failures: vec![],
        determinism_passed: true,
        network_mode: NetworkMode::ONLINE_ALLOWLISTED,
        proof_level: ProofLevel::ONLINE_ALLOWLIST_CORE_ONLY,
    });
    assert!(r.is_ok());
}

#[test]
fn unused_model_skips_pinning_but_preserves_other_gate_failures() {
    let mut input = ExportGateInputs {
        policy_mode: PolicyMode::STRICT,
        pinning_level: None,
        citations_required_passed: true,
        redactions_required_passed: true,
        blocker_gate_failures: vec![],
        determinism_passed: true,
        network_mode: NetworkMode::OFFLINE,
        proof_level: ProofLevel::OFFLINE_STRICT,
    };
    assert!(evaluate_export_gate(&input).is_ok());
    input.pinning_level = Some(PinningLevel::NAME_ONLY);
    assert_eq!(
        evaluate_export_gate(&input),
        Err(ExportBlockReason::INSUFFICIENT_PINNING)
    );
    input.pinning_level = None;
    input
        .blocker_gate_failures
        .push("CHK.MODEL.PINNING_LEVEL".into());
    assert_eq!(
        evaluate_export_gate(&input),
        Err(ExportBlockReason::EVAL_FAILED)
    );
}
