use super::model::{RedlineOsInputV1, RiskAssessment};
use super::extraction;
use super::anchors;
use super::risk_analysis;
use super::render;
use crate::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedlineWorkflowStage {
    Ingested,
    Analyzed,
    Reviewed,
    Renderable,
    ExportReady,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedlineWorkflowState {
    pub stage: RedlineWorkflowStage,
    pub input: RedlineOsInputV1,
}

impl RedlineWorkflowState {
    pub fn ingest(input: RedlineOsInputV1) -> CoreResult<Self> {
        if input.schema_version != "REDLINEOS_INPUT_V1" {
            return Err(CoreError::InputSchemaError(format!(
                "expected REDLINEOS_INPUT_V1, got {}",
                input.schema_version
            )));
        }
        if input.contract_artifacts.is_empty() {
            return Err(CoreError::ArtifactMissingError(
                "at least one contract artifact is required".to_string(),
            ));
        }
        Ok(Self {
            stage: RedlineWorkflowStage::Ingested,
            input,
        })
    }

    pub fn transition(self, next: RedlineWorkflowStage) -> CoreResult<Self> {
        let allowed = matches!(
            (self.stage, next),
            (
                RedlineWorkflowStage::Ingested,
                RedlineWorkflowStage::Analyzed
            ) | (
                RedlineWorkflowStage::Analyzed,
                RedlineWorkflowStage::Reviewed
            ) | (
                RedlineWorkflowStage::Reviewed,
                RedlineWorkflowStage::Renderable
            ) | (
                RedlineWorkflowStage::Renderable,
                RedlineWorkflowStage::ExportReady
            )
        );
        if !allowed {
            return Err(CoreError::WorkflowTransitionError(format!(
                "invalid transition {:?} -> {:?}",
                self.stage, next
            )));
        }
        Ok(Self {
            stage: next,
            input: self.input,
        })
    }
}

/// Execute complete RedlineOS workflow: extract → segment → assess → render
pub fn execute_redlineos_workflow(
    input: RedlineOsInputV1,
    contract_bytes: &[u8],
) -> CoreResult<RedlineWorkflowOutput> {
    // Step 1: Ingest and validate input
    let mut state = RedlineWorkflowState::ingest(input)?;

    // Step 2: Extract text from contract
    let extracted = extraction::extract_contract_text(contract_bytes, &state.input.extraction_mode)?;
    state = state.transition(RedlineWorkflowStage::Analyzed)?;

    // Step 3: Segment into clauses
    let clauses = anchors::segment_clauses(&extracted.extracted_text, &extracted.artifact_id)?;
    let anchors = anchors::generate_anchors(&clauses, &extracted.artifact_id)?;
    state = state.transition(RedlineWorkflowStage::Reviewed)?;

    // Step 4: Assess risks
    let assessments: Vec<RiskAssessment> = clauses
        .iter()
        .zip(anchors.iter())
        .map(|(clause, anchor)| risk_analysis::assess_clause_risk(clause, anchor))
        .collect();
    state = state.transition(RedlineWorkflowStage::Renderable)?;

    // Step 5: Render deliverables
    let risk_memo = render::render_risk_memo(&assessments, &clauses)?;
    let clause_map = render::render_clause_map_csv(&assessments)?;
    let suggestions = render::render_redline_suggestions(&assessments)?;
    state = state.transition(RedlineWorkflowStage::ExportReady)?;

    Ok(RedlineWorkflowOutput {
        stage: state.stage,
        risk_memo,
        clause_map,
        suggestions,
        assessment_count: assessments.len(),
        high_risk_count: assessments.iter().filter(|a| a.risk_level == "HIGH").count(),
        extraction_confidence: extracted.extraction_confidence,
    })
}

/// Output of RedlineOS workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedlineWorkflowOutput {
    pub stage: RedlineWorkflowStage,
    pub risk_memo: String,
    pub clause_map: String,
    pub suggestions: String,
    pub assessment_count: usize,
    pub high_risk_count: usize,
    pub extraction_confidence: f32,
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::redlineos::model::ContractArtifactRef;

    /// Helper: Create minimal valid PDF with sample contract
    fn create_sample_pdf() -> Vec<u8> {
        // Minimal PDF structure with text content
        b"%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj
4 0 obj<</Length 200>>stream
BT
/F1 12 Tf
100 700 Td
(1. License Grant: Company hereby grants a perpetual, irrevocable license.) Tj
0 -20 Td
(2. Indemnification: Licensee shall indemnify Company against all claims.) Tj
0 -20 Td
(3. Limitation of Liability: In no event shall liability exceed contract value.) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000074 00000 n
0000000133 00000 n
0000000281 00000 n
trailer<</Size 5/Root 1 0 R>>
startxref
531
%%EOF".to_vec()
    }

    #[test]
    fn test_full_workflow_end_to_end() {
        let pdf_bytes = create_sample_pdf();
        let input = RedlineOsInputV1 {
            schema_version: "REDLINEOS_INPUT_V1".to_string(),
            contract_artifacts: vec![],
            extraction_mode: "NATIVE_PDF".to_string(),
            jurisdiction_hint: Some("US-CA".to_string()),
            review_profile: "default".to_string(),
        };

        // Should fail on empty artifacts
        let result = RedlineWorkflowState::ingest(input.clone());
        assert!(result.is_err());

        // Now with valid artifact
        let mut valid_input = input;
        valid_input.contract_artifacts = vec![
            ContractArtifactRef {
                artifact_id: "test_contract_001".to_string(),
                sha256: "abc123".to_string(),
                filename: "test.pdf".to_string(),
            },
        ];

        let output = execute_redlineos_workflow(valid_input, &pdf_bytes);
        assert!(output.is_ok(), "Workflow should succeed");

        let output = output.unwrap();
        assert_eq!(output.stage, RedlineWorkflowStage::ExportReady);
        assert!(output.assessment_count > 0, "Should have assessed clauses");
        assert!(output.risk_memo.contains("Risk Assessment Memo"));
        assert!(output.risk_memo.contains("<!-- CLAIM:C"));
        assert!(output.clause_map.contains("clause_id,risk_level"));
    }

    #[test]
    fn test_workflow_determinism() {
        // Run same contract twice, should produce identical output
        let pdf_bytes = create_sample_pdf();
        let input = RedlineOsInputV1 {
            schema_version: "REDLINEOS_INPUT_V1".to_string(),
            contract_artifacts: vec![ContractArtifactRef {
                artifact_id: "test_contract_001".to_string(),
                sha256: "abc123".to_string(),
                filename: "test.pdf".to_string(),
            }],
            extraction_mode: "NATIVE_PDF".to_string(),
            jurisdiction_hint: Some("US-CA".to_string()),
            review_profile: "default".to_string(),
        };

        let output1 = execute_redlineos_workflow(input.clone(), &pdf_bytes).unwrap();
        let output2 = execute_redlineos_workflow(input.clone(), &pdf_bytes).unwrap();

        // Risk memo should be identical (deterministic)
        assert_eq!(output1.risk_memo, output2.risk_memo);
        assert_eq!(output1.clause_map, output2.clause_map);
        assert_eq!(output1.assessment_count, output2.assessment_count);
        assert_eq!(output1.high_risk_count, output2.high_risk_count);
    }

    #[test]
    fn test_workflow_citation_enforcement() {
        let pdf_bytes = create_sample_pdf();
        let input = RedlineOsInputV1 {
            schema_version: "REDLINEOS_INPUT_V1".to_string(),
            contract_artifacts: vec![ContractArtifactRef {
                artifact_id: "test_contract_001".to_string(),
                sha256: "abc123".to_string(),
                filename: "test.pdf".to_string(),
            }],
            extraction_mode: "NATIVE_PDF".to_string(),
            jurisdiction_hint: Some("US-CA".to_string()),
            review_profile: "default".to_string(),
        };

        let output = execute_redlineos_workflow(input, &pdf_bytes).unwrap();

        // Every risk assessment must have a citation marker
        let claim_count = output.risk_memo.matches("<!-- CLAIM:C").count();
        assert!(claim_count > 0, "Risk memo must contain citation markers");
        assert_eq!(claim_count, output.assessment_count, "Each assessment must have one citation");
    }

    #[test]
    fn test_workflow_high_risk_detection() {
        let pdf_bytes = create_sample_pdf();
        let input = RedlineOsInputV1 {
            schema_version: "REDLINEOS_INPUT_V1".to_string(),
            contract_artifacts: vec![ContractArtifactRef {
                artifact_id: "test_contract_001".to_string(),
                sha256: "abc123".to_string(),
                filename: "test.pdf".to_string(),
            }],
            extraction_mode: "NATIVE_PDF".to_string(),
            jurisdiction_hint: Some("US-CA".to_string()),
            review_profile: "default".to_string(),
        };

        let output = execute_redlineos_workflow(input, &pdf_bytes).unwrap();

        // Sample PDF contains "indemnify" and "perpetual" (HIGH risk keywords)
        assert!(output.high_risk_count > 0, "Should detect HIGH risk clauses");
        assert!(
            output.suggestions.contains("HIGH-Risk Clauses"),
            "Should include redline suggestions"
        );
    }

    #[test]
    fn test_workflow_state_transitions() {
        let input = RedlineOsInputV1 {
            schema_version: "REDLINEOS_INPUT_V1".to_string(),
            contract_artifacts: vec![ContractArtifactRef {
                artifact_id: "test_contract_001".to_string(),
                sha256: "abc123".to_string(),
                filename: "test.pdf".to_string(),
            }],
            extraction_mode: "NATIVE_PDF".to_string(),
            jurisdiction_hint: None,
            review_profile: "default".to_string(),
        };

        let state = RedlineWorkflowState::ingest(input).unwrap();
        assert_eq!(state.stage, RedlineWorkflowStage::Ingested);

        let state = state.transition(RedlineWorkflowStage::Analyzed).unwrap();
        assert_eq!(state.stage, RedlineWorkflowStage::Analyzed);

        let state = state.transition(RedlineWorkflowStage::Reviewed).unwrap();
        assert_eq!(state.stage, RedlineWorkflowStage::Reviewed);

        let state = state.transition(RedlineWorkflowStage::Renderable).unwrap();
        assert_eq!(state.stage, RedlineWorkflowStage::Renderable);

        let state = state.transition(RedlineWorkflowStage::ExportReady).unwrap();
        assert_eq!(state.stage, RedlineWorkflowStage::ExportReady);

        // Invalid transition should fail
        let invalid = state.transition(RedlineWorkflowStage::Ingested);
        assert!(invalid.is_err());
    }

    #[test]
    fn test_workflow_invalid_schema_version() {
        let input = RedlineOsInputV1 {
            schema_version: "INVALID_V1".to_string(),
            contract_artifacts: vec![ContractArtifactRef {
                artifact_id: "test".to_string(),
                sha256: "abc".to_string(),
                filename: "test.pdf".to_string(),
            }],
            extraction_mode: "NATIVE_PDF".to_string(),
            jurisdiction_hint: None,
            review_profile: "default".to_string(),
        };

        let result = RedlineWorkflowState::ingest(input);
        assert!(result.is_err());
    }
}
