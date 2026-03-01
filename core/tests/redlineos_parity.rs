use aigc_core::redlineos::model::{ContractArtifactRef, RedlineOsInputV1};
use aigc_core::redlineos::workflow::execute_redlineos_workflow;
use std::path::Path;

fn digital_sample_pdf() -> Vec<u8> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    std::fs::read(repo_root.join("core/corpus/contracts/digital_sample.pdf")).unwrap()
}

fn sample_input() -> RedlineOsInputV1 {
    RedlineOsInputV1 {
        schema_version: "REDLINEOS_INPUT_V1".to_string(),
        contract_artifacts: vec![ContractArtifactRef {
            artifact_id: "a_digital_sample".to_string(),
            sha256: "demo".to_string(),
            filename: "digital_sample.pdf".to_string(),
        }],
        extraction_mode: "NATIVE_PDF".to_string(),
        jurisdiction_hint: Some("US-CA".to_string()),
        review_profile: "default".to_string(),
    }
}

#[test]
fn redline_corpus_outputs_are_deterministic() {
    let pdf = digital_sample_pdf();
    let out1 = execute_redlineos_workflow(sample_input(), &pdf).expect("first run");
    let out2 = execute_redlineos_workflow(sample_input(), &pdf).expect("second run");

    assert_eq!(out1.risk_memo, out2.risk_memo);
    assert_eq!(out1.clause_map, out2.clause_map);
    assert_eq!(out1.suggestions, out2.suggestions);
    assert!(!out1.risk_memo.trim().is_empty());
    assert!(!out1.clause_map.trim().is_empty());
    assert!(out1.risk_memo.contains("<!-- CLAIM:C"));
}

#[test]
fn redline_rejects_non_pdf_input() {
    let bad_bytes = b"this is not a pdf".to_vec();
    let err = execute_redlineos_workflow(sample_input(), &bad_bytes).unwrap_err();
    assert!(err.to_string().contains("Invalid PDF format"));
}
