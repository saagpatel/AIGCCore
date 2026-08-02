use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractArtifactRef {
    pub artifact_id: String,
    #[serde(default)]
    pub sha256: String,
    pub filename: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedlineOsInputV1 {
    pub schema_version: String,
    pub contract_artifacts: Vec<ContractArtifactRef>,
    pub extraction_mode: String,
    pub jurisdiction_hint: Option<String>,
    pub review_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedlineOsOutputManifestV1 {
    pub schema_version: String,
    pub deliverable_paths: Vec<String>,
    pub attachment_paths: Vec<String>,
}

// Extraction result structs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedContract {
    pub artifact_id: String,
    pub source_bytes_hash: String,
    pub extracted_text: String,
    pub page_count: usize,
    pub extraction_confidence: f32,
    pub spatial_data: Option<Vec<PageLayout>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageLayout {
    pub page_num: usize,
    pub width_points: f32,
    pub height_points: f32,
    pub text_blocks: Vec<TextBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextBlock {
    pub text: String,
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub font_size: Option<f32>,
    pub is_bold: bool,
    pub is_heading: bool,
}

// Clause and anchor structs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentedClause {
    pub clause_id: String,
    pub clause_number: Option<String>,
    pub title: Option<String>,
    pub text: String,
    pub start_page: usize,
    pub start_char_offset: usize,
    pub end_char_offset: usize,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseAnchor {
    pub anchor_id: String,
    pub clause_id: String,
    pub text_hash: String,
    pub page_hint: Option<usize>,
    pub char_offset_range: (usize, usize),
}

// Risk assessment structs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub anchor_id: String,
    pub risk_level: String,
    pub keywords_matched: Vec<String>,
    pub advisory: String,
    pub citations: Vec<CitationMarker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitationMarker {
    pub claim_id: String,
    pub anchor_id: String,
    pub locator_span: (usize, usize),
}
