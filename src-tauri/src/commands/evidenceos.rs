use aigc_core::evidence_bundle::authority::EvidenceAuthorityManifest;
use aigc_core::evidenceos::control_library::{controls_for_capabilities, ControlDefinition};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceOsRunResult {
    pub(crate) status: String,
    pub(crate) bundle_path: String,
    pub(crate) bundle_sha256: String,
    pub(crate) missing_control_ids: Vec<String>,
    pub(crate) evidence_authority: EvidenceAuthorityManifest,
    pub(crate) encryption_at_rest: bool,
    pub(crate) model_used: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct EvidenceOsRunInput {
    pub(crate) enabled_capabilities: Vec<String>,
    pub(crate) artifact_title: String,
    pub(crate) artifact_body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) artifact_sha256: Option<String>,
    pub(crate) artifact_tags_csv: String,
    pub(crate) control_families_csv: String,
    pub(crate) claim_text: String,
}

#[tauri::command]
pub(crate) fn list_control_library(
    enabled_capabilities: Option<Vec<String>>,
) -> Vec<ControlDefinition> {
    controls_for_capabilities(&enabled_capabilities.unwrap_or_default())
}

#[tauri::command]
pub(crate) fn generate_evidenceos_bundle(
    input: EvidenceOsRunInput,
) -> Result<EvidenceOsRunResult, String> {
    crate::export::generate_evidenceos_bundle(input)
}
