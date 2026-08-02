use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentArtifactRef {
    pub artifact_id: String,
    #[serde(default)]
    pub sha256: String,
    pub source_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentOsInputV1 {
    pub schema_version: String,
    pub incident_artifacts: Vec<IncidentArtifactRef>,
    pub timeline_start_hint: Option<String>,
    pub timeline_end_hint: Option<String>,
    pub customer_redaction_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentOsOutputManifestV1 {
    pub schema_version: String,
    pub deliverable_paths: Vec<String>,
    pub attachment_paths: Vec<String>,
}
