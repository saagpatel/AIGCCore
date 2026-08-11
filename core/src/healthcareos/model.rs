use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthcareArtifactRef {
    pub artifact_id: String,
    #[serde(default)]
    pub sha256: String,
    pub artifact_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthcareOsInputV1 {
    pub schema_version: String,
    pub consent_artifacts: Vec<HealthcareArtifactRef>,
    pub transcript_artifacts: Vec<HealthcareArtifactRef>,
    pub draft_template_profile: String,
    pub verifier_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthcareOsOutputManifestV1 {
    pub schema_version: String,
    pub deliverable_paths: Vec<String>,
    pub attachment_paths: Vec<String>,
}
