use crate::determinism::json_canonical;
use crate::error::{CoreError, CoreResult};
use crate::policy::types::PolicyMode;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::control_library::{controls_for_capabilities, ControlDefinition};
use super::model::{EvidenceItem, NarrativeClaimInput};
use super::narrative::render_narrative_markdown;
use super::render::{
    render_evidence_index_csv, render_evidence_index_markdown, render_evidence_index_pdf,
    render_missing_checklist_markdown, MappingReviewRow,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceOsRequest {
    pub pack_id: String,
    pub pack_version: String,
    pub run_id: String,
    pub policy_mode: PolicyMode,
    pub determinism_enabled: bool,
    pub enabled_capabilities: Vec<String>,
    pub evidence_items: Vec<EvidenceItem>,
    pub narrative_claims: Vec<NarrativeClaimInput>,
}

#[derive(Debug, Clone)]
pub struct EvidenceOsArtifacts {
    pub deliverables: Vec<(String, Vec<u8>, String)>,
    pub templates_used_json: serde_json::Value,
    pub citations_map_json: serde_json::Value,
    pub redactions_map_json: serde_json::Value,
    pub mapping_review_rows: Vec<MappingReviewRow>,
    pub missing_control_ids: Vec<String>,
}

pub fn generate_evidenceos_artifacts(req: &EvidenceOsRequest) -> CoreResult<EvidenceOsArtifacts> {
    if req.pack_id.trim().is_empty() {
        return Err(CoreError::EvidenceOsValidation(
            "pack_id cannot be empty".to_string(),
        ));
    }
    if req.run_id.trim().is_empty() {
        return Err(CoreError::EvidenceOsValidation(
            "run_id cannot be empty".to_string(),
        ));
    }

    let mut evidence_items: Vec<EvidenceItem> = req
        .evidence_items
        .iter()
        .cloned()
        .map(EvidenceItem::normalized)
        .collect();
    evidence_items.sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));

    let controls = controls_for_capabilities(&req.enabled_capabilities);
    if controls.is_empty() {
        return Err(CoreError::EvidenceOsValidation(
            "enabled_capabilities produced an empty control library".to_string(),
        ));
    }

    for claim in &req.narrative_claims {
        if claim.claim_id.trim().is_empty() {
            return Err(CoreError::EvidenceOsValidation(
                "claim_id cannot be empty".to_string(),
            ));
        }
        if claim.text.trim().is_empty() {
            return Err(CoreError::EvidenceOsValidation(format!(
                "claim {} has empty text",
                claim.claim_id
            )));
        }
        if req.policy_mode == PolicyMode::STRICT && claim.citations.is_empty() {
            return Err(CoreError::PolicyBlocked(format!(
                "strict mode requires citations for claim {}",
                claim.claim_id
            )));
        }
    }

    let mapping_rows = build_mapping_review_rows(&controls, &evidence_items);
    let missing_control_ids: Vec<String> = mapping_rows
        .iter()
        .filter(|r| r.status == "MISSING")
        .map(|r| r.control_id.clone())
        .collect();

    let evidence_index_csv = render_evidence_index_csv(&evidence_items)?;
    let evidence_index_md = render_evidence_index_markdown(&evidence_items);
    let evidence_index_pdf = render_evidence_index_pdf(&evidence_items);
    let missing_md = render_missing_checklist_markdown(&missing_control_ids, &mapping_rows);
    let (narrative_md, claim_ranges) = render_narrative_markdown(&req.narrative_claims);

    let evidence_index_csv_path =
        format!("exports/{}/deliverables/evidence_index.csv", req.pack_id);
    let evidence_index_md_path = format!("exports/{}/deliverables/evidence_index.md", req.pack_id);
    let evidence_index_pdf_path =
        format!("exports/{}/deliverables/evidence_index.pdf", req.pack_id);
    let missing_path = format!(
        "exports/{}/deliverables/missing_evidence_checklist.md",
        req.pack_id
    );
    let narrative_path = format!("exports/{}/deliverables/evidence_narrative.md", req.pack_id);
    let review_path = format!(
        "exports/{}/deliverables/evidence_mapping_review.json",
        req.pack_id
    );

    let mapping_review_json = json!({
        "schema_version": "EVIDENCE_MAPPING_REVIEW_V1",
        "pack_id": req.pack_id,
        "pack_version": req.pack_version,
        "run_id": req.run_id,
        "mappings": mapping_rows,
    });
    let mapping_review_bytes = json_canonical::to_canonical_bytes(&mapping_review_json)?;

    let generated_at_ms = if req.determinism_enabled {
        0
    } else {
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
            .map_err(|_| CoreError::EvidenceOsValidation("generation time before epoch".into()))?
    };
    let citations_map_json = json!({
        "schema_version": "LOCATOR_SCHEMA_V1",
        "pack_id": req.pack_id,
        "pack_version": req.pack_version,
        "run_id": req.run_id,
        "generated_at_ms": generated_at_ms,
        "claims": req.narrative_claims.iter().zip(claim_ranges.iter()).map(|(claim, range)| {
            json!({
                "claim_id": claim.claim_id,
                "output_path": narrative_path,
                "output_claim_locator": {
                    "locator_type": "TEXT_LINE_RANGE_V1",
                    "locator": {
                        "start_line": range.start_line,
                        "end_line": range.end_line,
                        "text_sha256": range.text_sha256
                    }
                },
                "citations": claim.citations.iter().enumerate().map(|(idx, c)| {
                    json!({
                        "citation_index": idx as u64,
                        "artifact_id": c.artifact_id,
                        "locator_type": c.locator_type,
                        "locator": c.locator
                    })
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    });

    let redactions_map_json = json!({
        "schema_version": "REDACTION_SCHEMA_V1",
        "pack_id": req.pack_id,
        "pack_version": req.pack_version,
        "run_id": req.run_id,
        "generated_at_ms": generated_at_ms,
        "artifacts": []
    });

    let templates_used_json = json!({
        "schema_version": "TEMPLATES_USED_V1",
        "pack_id": req.pack_id,
        "pack_version": req.pack_version,
        "run_id": req.run_id,
        "templates": [
            {
                "template_id": "evidence_index_csv",
                "template_version": "1.0.0",
                "output_paths": [evidence_index_csv_path],
                "render_engine": { "name": "core_template_renderer", "version": env!("CARGO_PKG_VERSION") }
            },
            {
                "template_id": "evidence_index_md",
                "template_version": "1.0.0",
                "output_paths": [evidence_index_md_path],
                "render_engine": { "name": "core_template_renderer", "version": env!("CARGO_PKG_VERSION") }
            },
            {
                "template_id": "evidence_index_pdf",
                "template_version": "1.0.0",
                "output_paths": [evidence_index_pdf_path],
                "render_engine": { "name": "core_template_renderer", "version": env!("CARGO_PKG_VERSION") }
            },
            {
                "template_id": "evidence_mapping_review_json",
                "template_version": "1.0.0",
                "output_paths": [review_path],
                "render_engine": { "name": "core_template_renderer", "version": env!("CARGO_PKG_VERSION") }
            },
            {
                "template_id": "missing_evidence_checklist_md",
                "template_version": "1.0.0",
                "output_paths": [missing_path],
                "render_engine": { "name": "core_template_renderer", "version": env!("CARGO_PKG_VERSION") }
            },
            {
                "template_id": "narrative_md",
                "template_version": "1.0.0",
                "output_paths": [narrative_path],
                "render_engine": { "name": "core_template_renderer", "version": env!("CARGO_PKG_VERSION") }
            }
        ]
    });

    let deliverables = vec![
        (
            format!("exports/{}/deliverables/evidence_index.csv", req.pack_id),
            evidence_index_csv.into_bytes(),
            "text/csv".to_string(),
        ),
        (
            format!("exports/{}/deliverables/evidence_index.md", req.pack_id),
            evidence_index_md.into_bytes(),
            "text/markdown".to_string(),
        ),
        (
            format!("exports/{}/deliverables/evidence_index.pdf", req.pack_id),
            evidence_index_pdf,
            "application/pdf".to_string(),
        ),
        (
            format!(
                "exports/{}/deliverables/missing_evidence_checklist.md",
                req.pack_id
            ),
            missing_md.into_bytes(),
            "text/markdown".to_string(),
        ),
        (
            format!("exports/{}/deliverables/evidence_narrative.md", req.pack_id),
            narrative_md.into_bytes(),
            "text/markdown".to_string(),
        ),
        (
            format!(
                "exports/{}/deliverables/evidence_mapping_review.json",
                req.pack_id
            ),
            mapping_review_bytes,
            "application/json".to_string(),
        ),
    ];

    Ok(EvidenceOsArtifacts {
        deliverables,
        templates_used_json,
        citations_map_json,
        redactions_map_json,
        mapping_review_rows: mapping_rows,
        missing_control_ids,
    })
}

fn build_mapping_review_rows(
    controls: &[ControlDefinition],
    evidence_items: &[EvidenceItem],
) -> Vec<MappingReviewRow> {
    let mut rows = Vec::new();
    for control in controls {
        let mut mapped_artifact_ids: Vec<String> = evidence_items
            .iter()
            .filter(|item| {
                item.control_family_labels
                    .iter()
                    .any(|label| label == &control.control_family)
            })
            .map(|item| item.artifact_id.clone())
            .collect();
        mapped_artifact_ids.sort();
        mapped_artifact_ids.dedup();
        let status = if mapped_artifact_ids.is_empty() {
            "MISSING".to_string()
        } else {
            "MAPPED".to_string()
        };
        rows.push(MappingReviewRow {
            control_id: control.control_id.clone(),
            capability: control.capability.clone(),
            control_family: control.control_family.clone(),
            status,
            mapped_artifact_ids,
            reviewer_note: String::new(),
        });
    }
    rows.sort_by(|a, b| a.control_id.cmp(&b.control_id));
    rows
}
