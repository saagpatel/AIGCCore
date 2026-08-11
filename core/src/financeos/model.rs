use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinanceArtifactRef {
    pub artifact_id: String,
    #[serde(default)]
    pub sha256: String,
    pub artifact_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinanceOsInputV1 {
    pub schema_version: String,
    pub finance_artifacts: Vec<FinanceArtifactRef>,
    pub period: String,
    pub exception_rules_profile: String,
    pub retention_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinanceOsOutputManifestV1 {
    pub schema_version: String,
    pub deliverable_paths: Vec<String>,
    pub attachment_paths: Vec<String>,
}
