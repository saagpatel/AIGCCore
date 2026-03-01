use crate::adapters::pinning::PinningLevel;
use crate::audit::event::{Actor, AuditEvent};
use crate::audit::log::AuditLog;
use crate::error::CoreResult;
use crate::eval::runner::EvalRunner;
use crate::evidence_bundle::builder::EvidenceBundleBuilder;
use crate::evidence_bundle::schemas::EvidenceBundleInputs;
use crate::policy::export_gate::{evaluate_export_gate, ExportBlockReason, ExportGateInputs};
use crate::policy::types::{NetworkMode, PolicyMode, ProofLevel};
use crate::validator::BundleValidator;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRequest {
    pub run_id: String,
    pub vault_id: String,
    pub policy_mode: PolicyMode,
    pub network_mode: NetworkMode,
    pub proof_level: ProofLevel,
    pub pinning_level: PinningLevel,
    pub requested_by: String, // user|system
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunState {
    CREATED,
    INGESTING,
    READY,
    EXECUTING,
    EVALUATING,
    EXPORTING,
    COMPLETED,
    FAILED,
    CANCELLED,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOutcome {
    pub status: String, // COMPLETED|BLOCKED|FAILED
    pub bundle_path: Option<String>,
    pub bundle_sha256: Option<String>,
    pub block_reason: Option<ExportBlockReason>,
}

pub struct RunManager {
    pub audit: AuditLog,
    pub state: RunState,
}

impl RunManager {
    pub fn new(audit: AuditLog) -> Self {
        Self {
            audit,
            state: RunState::READY,
        }
    }

    pub fn export_run(
        &mut self,
        req: &ExportRequest,
        bundle_inputs: &EvidenceBundleInputs,
        bundle_dir: &Path,
        bundle_zip: &Path,
    ) -> CoreResult<ExportOutcome> {
        // 1) EXPORT_REQUESTED
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "EXPORT_REQUESTED".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::User,
            details: serde_json::json!({
                "requested_by": req.requested_by,
                "export_targets": [bundle_zip
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("evidence_bundle.zip")
                    .to_string()],
                "policy_mode": format!("{:?}", req.policy_mode)
            }),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;
        // 2) Run state -> EVALUATING
        self.transition(req, RunState::EVALUATING, "export requested")?;

        // 2-3) EVAL_STARTED + EVAL results
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "EVAL_STARTED".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::System,
            details: serde_json::json!({ "registry_version": "gates_registry_v3" }),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;

        // Preflight bundle for eval checks only (kept outside final export target).
        let preflight = PreflightArtifacts::create(&req.run_id)?;
        EvidenceBundleBuilder::build_dir(&preflight.root, bundle_inputs)?;
        EvidenceBundleBuilder::build_zip(&preflight.root, &preflight.zip)?;
        harden_preflight_file_permissions(&preflight.zip)?;

        let eval_runner = EvalRunner::new_v3()?;
        let gate_results = eval_runner.run_all_for_bundle(&preflight.zip, req.policy_mode)?;
        let mut blocker_fails = Vec::new();
        for g in &gate_results {
            self.audit.append(AuditEvent {
                ts_utc: now_rfc3339_utc(),
                event_type: "EVAL_GATE_RESULT".to_string(),
                run_id: req.run_id.clone(),
                vault_id: req.vault_id.clone(),
                actor: Actor::System,
                details: serde_json::json!({
                    "gate_id": g.gate_id,
                    "result": g.result,
                    "severity": g.severity,
                    "evidence_pointers": g.evidence_pointers,
                    "message": g.message
                }),
                prev_event_hash: String::new(),
                event_hash: String::new(),
            })?;
            if g.severity == "BLOCKER" && g.result == "FAIL" {
                blocker_fails.push(g.gate_id.clone());
            }
        }
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "EVAL_COMPLETED".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::System,
            details: serde_json::json!({
                "gates_executed": gate_results.len(),
                "gates_failed_blocker": blocker_fails.len(),
                "gates_failed_total": blocker_fails.len()
            }),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;

        // Policy gate checks from evaluated gates.
        let citations_ok = gate_results
            .iter()
            .find(|g| g.gate_id == "CITATIONS.STRICT_ENFORCED_V1")
            .map(|g| g.result == "PASS" || g.result == "NOT_APPLICABLE")
            .unwrap_or(true);
        let redactions_ok = gate_results
            .iter()
            .find(|g| g.gate_id == "REDACTION.REQUIRED_APPLIED_V1")
            .map(|g| g.result == "PASS" || g.result == "NOT_APPLICABLE")
            .unwrap_or(true);
        let determinism_ok = gate_results
            .iter()
            .find(|g| g.gate_id == "DETERMINISM.ZIP_PACKAGING_V1")
            .map(|g| g.result == "PASS" || g.result == "NOT_APPLICABLE")
            .unwrap_or(true);

        if let Err(reason) = evaluate_export_gate(&ExportGateInputs {
            policy_mode: req.policy_mode,
            pinning_level: req.pinning_level,
            citations_required_passed: citations_ok,
            redactions_required_passed: redactions_ok,
            blocker_gate_failures: blocker_fails.clone(),
            determinism_passed: determinism_ok,
            network_mode: req.network_mode,
            proof_level: req.proof_level,
        }) {
            self.audit.append(AuditEvent {
                ts_utc: now_rfc3339_utc(),
                event_type: "EXPORT_BLOCKED".to_string(),
                run_id: req.run_id.clone(),
                vault_id: req.vault_id.clone(),
                actor: Actor::System,
                details: serde_json::json!({
                    "block_reason": format!("{:?}", reason),
                    "failed_gate_ids": blocker_fails
                }),
                prev_event_hash: String::new(),
                event_hash: String::new(),
            })?;
            self.transition(req, RunState::FAILED, "export blocked")?;
            return Ok(ExportOutcome {
                status: "BLOCKED".to_string(),
                bundle_path: None,
                bundle_sha256: None,
                block_reason: Some(reason),
            });
        }

        self.transition(req, RunState::EXPORTING, "gates passed")?;
        // 8-10) Final bundle generation
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "BUNDLE_GENERATION_STARTED".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::System,
            details: serde_json::json!({}),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;
        let mut final_bundle_inputs = bundle_inputs.clone();
        final_bundle_inputs.audit_log_ndjson = self.audit.read_all_ndjson()?;
        EvidenceBundleBuilder::build_dir(bundle_dir, &final_bundle_inputs)?;
        let _initial_bundle_sha = EvidenceBundleBuilder::build_zip(bundle_dir, bundle_zip)?;
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "BUNDLE_GENERATION_COMPLETED".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::System,
            details: serde_json::json!({}),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;

        // 11-13) Bundle validation
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "BUNDLE_VALIDATION_STARTED".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::System,
            details: serde_json::json!({}),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;
        let validator = BundleValidator::new_v3();
        let summary = validator.validate_zip(bundle_zip, req.policy_mode)?;
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "BUNDLE_VALIDATION_RESULT".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::System,
            details: serde_json::json!({
                "result": summary.overall,
                "failed_checks": summary.checks.iter().filter(|c| c.result != "PASS").map(|c| c.check_id.clone()).collect::<Vec<_>>(),
                "validator_version": "bundle_validator_v3"
            }),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;
        if summary.overall != "PASS" {
            self.audit.append(AuditEvent {
                ts_utc: now_rfc3339_utc(),
                event_type: "EXPORT_FAILED".to_string(),
                run_id: req.run_id.clone(),
                vault_id: req.vault_id.clone(),
                actor: Actor::System,
                details: serde_json::json!({"reason":"BUNDLE_VALIDATION_FAILED"}),
                prev_event_hash: String::new(),
                event_hash: String::new(),
            })?;
            self.transition(req, RunState::FAILED, "bundle validation failed")?;
            return Ok(ExportOutcome {
                status: "FAILED".to_string(),
                bundle_path: None,
                bundle_sha256: None,
                block_reason: Some(ExportBlockReason::BUNDLE_VALIDATION_FAILED),
            });
        }

        // Refresh the bundle once after validation events are appended so bundled audit_log.ndjson
        // includes final export lifecycle evidence.
        final_bundle_inputs.audit_log_ndjson = self.audit.read_all_ndjson()?;
        EvidenceBundleBuilder::build_dir(bundle_dir, &final_bundle_inputs)?;
        let bundle_sha = EvidenceBundleBuilder::build_zip(bundle_dir, bundle_zip)?;

        // 15) EXPORT_COMPLETED
        let rel = bundle_zip.to_string_lossy().to_string();
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "EXPORT_COMPLETED".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::System,
            details: serde_json::json!({
                "bundle_path": rel,
                "bundle_sha256": bundle_sha,
                "bundle_version": "EVIDENCE_BUNDLE_V1",
                "validator_result": "PASS"
            }),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;
        self.transition(req, RunState::COMPLETED, "export completed")?;
        Ok(ExportOutcome {
            status: "COMPLETED".to_string(),
            bundle_path: Some(rel),
            bundle_sha256: Some(bundle_sha),
            block_reason: None,
        })
    }

    fn transition(&mut self, req: &ExportRequest, to: RunState, reason: &str) -> CoreResult<()> {
        if !valid_transition(self.state, to) {
            return Err(crate::error::CoreError::PolicyBlocked(format!(
                "invalid run state transition {:?} -> {:?}",
                self.state, to
            )));
        }
        self.audit.append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "RUN_STATE_CHANGED".to_string(),
            run_id: req.run_id.clone(),
            vault_id: req.vault_id.clone(),
            actor: Actor::System,
            details: serde_json::json!({
                "from_state": format!("{:?}", self.state),
                "to_state": format!("{:?}", to),
                "reason": reason
            }),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;
        self.state = to;
        Ok(())
    }
}

struct PreflightArtifacts {
    root: PathBuf,
    zip: PathBuf,
}

impl PreflightArtifacts {
    fn create(run_id: &str) -> CoreResult<Self> {
        let nonce = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let root = std::env::temp_dir().join(format!("{}_preflight_bundle_{}", run_id, nonce));
        let zip = std::env::temp_dir().join(format!("{}_preflight_bundle_{}.zip", run_id, nonce));

        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        if zip.exists() {
            std::fs::remove_file(&zip)?;
        }

        std::fs::create_dir_all(&root)?;
        harden_preflight_dir_permissions(&root)?;

        Ok(Self { root, zip })
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_file(&self.zip);
    }
}

impl Drop for PreflightArtifacts {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn harden_preflight_dir_permissions(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn harden_preflight_file_permissions(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn valid_transition(from: RunState, to: RunState) -> bool {
    use RunState::*;
    match (from, to) {
        (CREATED, INGESTING) => true,
        (CREATED, READY) => true,
        (READY, EXECUTING) => true,
        (EXECUTING, EVALUATING) => true,
        (READY, EVALUATING) => true,
        (EVALUATING, EXPORTING) => true,
        (EVALUATING, FAILED) => true,
        (EXPORTING, COMPLETED) => true,
        (EXPORTING, FAILED) => true,
        (_, CANCELLED) => true,
        _ => false,
    }
}

fn now_rfc3339_utc() -> String {
    if let Ok(fixed) = std::env::var("AIGC_AUDIT_FIXED_TS_UTC") {
        if !fixed.trim().is_empty() {
            return fixed;
        }
    }
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        harden_preflight_file_permissions, valid_transition, PreflightArtifacts, RunState,
    };

    #[test]
    fn state_machine_blocks_invalid_edges() {
        assert!(valid_transition(RunState::CREATED, RunState::READY));
        assert!(!valid_transition(RunState::CREATED, RunState::EXPORTING));
        assert!(!valid_transition(RunState::COMPLETED, RunState::EVALUATING));
    }

    #[test]
    fn preflight_artifacts_cleanup_removes_temp_paths() {
        let (root, zip) = {
            let preflight = PreflightArtifacts::create("test_run_cleanup")
                .expect("preflight artifacts should be created");
            std::fs::write(&preflight.zip, b"preflight zip")
                .expect("preflight zip fixture should be written");
            (preflight.root.clone(), preflight.zip.clone())
        };

        assert!(!root.exists(), "preflight temp directory should be removed");
        assert!(!zip.exists(), "preflight temp zip should be removed");
    }

    #[test]
    fn preflight_artifacts_permissions_hardened_when_supported() {
        let preflight =
            PreflightArtifacts::create("test_run_permissions").expect("preflight create should pass");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(&preflight.root)
                .expect("preflight root metadata should be readable")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
        }
    }

    #[test]
    fn preflight_zip_permissions_hardened_when_supported() {
        let preflight =
            PreflightArtifacts::create("test_run_zip_permissions").expect("preflight create should pass");
        std::fs::write(&preflight.zip, b"zip bytes").expect("zip fixture should be written");
        harden_preflight_file_permissions(&preflight.zip).expect("zip permission hardening should pass");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&preflight.zip)
                .expect("preflight zip metadata should be readable")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600);
        }
    }
}
