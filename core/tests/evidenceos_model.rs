use aigc_core::evidenceos::model::{CitationInput, EvidenceItem, NarrativeClaimInput};
use aigc_core::evidenceos::workflow::{generate_evidenceos_artifacts, EvidenceOsRequest};
use aigc_core::policy::types::PolicyMode;
use serde_json::json;

#[test]
fn evidence_item_normalization_sorts_and_dedups_labels() {
    let item = EvidenceItem {
        artifact_id: "a_1".to_string(),
        artifact_sha256: "abc".to_string(),
        title: "Artifact".to_string(),
        tags: vec!["PII".to_string(), "PII".to_string(), "DOC".to_string()],
        control_family_labels: vec![
            "Traceability".to_string(),
            "Auditability".to_string(),
            "Traceability".to_string(),
        ],
    }
    .normalized();

    assert_eq!(item.tags, vec!["DOC".to_string(), "PII".to_string()]);
    assert_eq!(
        item.control_family_labels,
        vec!["Auditability".to_string(), "Traceability".to_string()]
    );
}

#[test]
fn strict_mode_blocks_claim_without_citation() {
    let req = EvidenceOsRequest {
        determinism_enabled: true,
        pack_id: "evidenceos".to_string(),
        pack_version: "1.0.0".to_string(),
        run_id: "r_test".to_string(),
        policy_mode: PolicyMode::STRICT,
        enabled_capabilities: vec![],
        evidence_items: vec![EvidenceItem {
            artifact_id: "a_1".to_string(),
            artifact_sha256: "abc".to_string(),
            title: "Artifact".to_string(),
            tags: vec!["DOC".to_string()],
            control_family_labels: vec!["Traceability".to_string()],
        }],
        narrative_claims: vec![NarrativeClaimInput {
            claim_id: "C0001".to_string(),
            text: "Claim text".to_string(),
            citations: vec![],
        }],
    };

    let err = generate_evidenceos_artifacts(&req).unwrap_err();
    assert!(err.to_string().contains("strict mode requires citations"));
}

#[test]
fn mapping_workflow_marks_missing_controls() {
    let mut req = EvidenceOsRequest {
        determinism_enabled: true,
        pack_id: "evidenceos".to_string(),
        pack_version: "1.0.0".to_string(),
        run_id: "r_test".to_string(),
        policy_mode: PolicyMode::STRICT,
        enabled_capabilities: vec![],
        evidence_items: vec![EvidenceItem {
            artifact_id: "a_1".to_string(),
            artifact_sha256: "abc".to_string(),
            title: "Artifact".to_string(),
            tags: vec!["DOC".to_string()],
            control_family_labels: vec!["Traceability".to_string()],
        }],
        narrative_claims: vec![NarrativeClaimInput {
            claim_id: "C0001".to_string(),
            text: "Claim text".to_string(),
            citations: vec![CitationInput {
                artifact_id: "a_1".to_string(),
                locator_type: "PDF_TEXT_SPAN_V1".to_string(),
                locator: json!({"page_index": 0, "start_char": 0, "end_char": 5, "text_sha256": "abc"}),
            }],
        }],
    };

    let out = generate_evidenceos_artifacts(&req).unwrap();
    assert_eq!(out.citations_map_json["generated_at_ms"], 0);
    assert_eq!(out.redactions_map_json["generated_at_ms"], 0);
    assert!(!out.missing_control_ids.is_empty());
    assert!(out
        .mapping_review_rows
        .iter()
        .any(|row| row.status == "MISSING"));
    let pdf = out
        .deliverables
        .iter()
        .find(|(path, _, _)| path.ends_with("evidence_index.pdf"))
        .map(|(_, bytes, _)| bytes.clone())
        .expect("expected evidence_index.pdf deliverable");
    assert!(pdf.starts_with(b"%PDF-1.4"));

    req.determinism_enabled = false;
    let before = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let timed = generate_evidenceos_artifacts(&req).unwrap();
    let after = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let generated = timed.citations_map_json["generated_at_ms"]
        .as_u64()
        .unwrap() as i128;
    assert!((before..=after).contains(&generated));
    assert_eq!(
        timed.citations_map_json["generated_at_ms"],
        timed.redactions_map_json["generated_at_ms"]
    );
    req.pack_id.clear();
    assert!(generate_evidenceos_artifacts(&req)
        .unwrap_err()
        .to_string()
        .contains("pack_id cannot be empty"));
    req.pack_id = "evidenceos".into();
    req.run_id.clear();
    assert!(generate_evidenceos_artifacts(&req)
        .unwrap_err()
        .to_string()
        .contains("run_id cannot be empty"));
}
