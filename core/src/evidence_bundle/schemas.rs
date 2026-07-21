use crate::adapters::pinning::ModelSnapshot;
use crate::evidence_bundle::authority::EvidenceAuthorityManifest;
use crate::policy::network_snapshot::NetworkSnapshot;
use crate::policy::types::{InputExportProfile, PolicyMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleInfo {
    pub bundle_version: String, // "1.0.0"
    pub schema_versions: SchemaVersions,
    pub pack_id: String,
    pub pack_version: String,
    pub core_build: String,
    pub run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaVersions {
    pub run_manifest: String,
    pub eval_report: String,
    pub citations_map: String,
    pub redactions_map: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub run_id: String,
    pub vault_id: String,
    pub evidence_authority: EvidenceAuthorityManifest,
    pub determinism: DeterminismManifest,
    pub inputs: Vec<ManifestArtifactRef>,
    pub outputs: Vec<ManifestOutputRef>,
    pub model_calls: Vec<ModelCallSummary>,
    pub eval: EvalSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterminismManifest {
    pub enabled: bool,
    pub manifest_inputs_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestArtifactRef {
    pub artifact_id: String,
    pub sha256: String,
    pub bytes: u64,
    pub mime_type: String,
    pub logical_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestOutputRef {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub content_type: String,
    pub logical_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCallSummary {
    pub call_id: String,
    pub model_id: String,
    pub adapter_version: String,
    pub status: String,
    pub input_hash: String,
    pub output_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalSummary {
    pub gate_status: String, // PASS|FAIL|WARN
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub policy_mode: PolicyMode,
    pub determinism: DeterminismPolicy,
    pub export_profile: ExportProfile,
    pub encryption_at_rest: bool,
    pub encryption_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterminismPolicy {
    pub enabled: bool,
    pub pdf_determinism_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportProfile {
    pub inputs: InputExportProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactListEntry {
    pub artifact_id: String,
    pub sha256: String,
    pub bytes: u64,
    pub content_type: String,
    pub logical_role: String,
    pub classification: String, // Public|Internal|Confidential|Restricted
    pub tags: Vec<String>,      // PII|PHI|PCI|SECRET|CUSTOM
    pub retention_policy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactList {
    pub artifacts: Vec<ArtifactListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub overall_status: String, // PASS|FAIL|WARN
    pub tests: Vec<EvalTest>,
    pub gates: Vec<EvalGateResult>,
    pub registry_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalTest {
    pub test_id: String,
    pub category: String,
    pub status: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalGateResult {
    pub gate_id: String,
    pub category: String,
    pub status: String, // PASS|FAIL|WARN|NOT_APPLICABLE
    pub severity: String,
    pub message: String,
    pub evidence_pointers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackAttachments {
    pub templates_used_json: serde_json::Value,
    pub citations_map_json: Option<serde_json::Value>,
    pub redactions_map_json: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct EvidenceBundleInputs {
    pub run_manifest: RunManifest,
    pub bundle_info: BundleInfo,
    pub audit_log_ndjson: String,
    pub eval_report: EvalReport,
    pub artifact_hashes_csv: String,
    pub artifact_list: ArtifactList,
    pub policy_snapshot: PolicySnapshot,
    pub network_snapshot: NetworkSnapshot,
    pub model_snapshot: ModelSnapshot,
    pub pack_id: String,
    pub pack_version: String,
    pub deliverables: Vec<(String, Vec<u8>, String)>, // rel path, bytes, content_type
    pub attachments: PackAttachments,
}
