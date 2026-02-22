use aigc_core::adapters::pinning::PinningLevel;
use aigc_core::audit::event::{Actor, AuditEvent};
use aigc_core::audit::log::AuditLog;
use aigc_core::determinism::json_canonical;
use aigc_core::determinism::run_id::sha256_hex;
use aigc_core::evidence_bundle::artifact_hashes::{render_artifact_hashes_csv, ArtifactHashRow};
use aigc_core::evidence_bundle::schemas::*;
use aigc_core::financeos::model::{FinanceArtifactRef, FinanceOsInputV1};
use aigc_core::financeos::workflow::execute_financeos_workflow;
use aigc_core::healthcareos::model::{HealthcareArtifactRef, HealthcareOsInputV1};
use aigc_core::healthcareos::workflow::execute_healthcareos_workflow;
use aigc_core::incidentos::model::{IncidentArtifactRef, IncidentOsInputV1};
use aigc_core::incidentos::workflow::execute_incidentos_workflow;
use aigc_core::policy::network_snapshot::{AdapterEndpointSnapshot, NetworkSnapshot};
use aigc_core::policy::types::{InputExportProfile, NetworkMode, PolicyMode, ProofLevel};
use aigc_core::run::manager::{ExportRequest, RunManager};
use aigc_core::validator::BundleValidator;
use serde_json::json;
use std::path::Path;

fn extract_claim_markers(markdown: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut idx = 0;
    while let Some(pos) = markdown[idx..].find("<!-- CLAIM:") {
        let start = idx + pos + "<!-- CLAIM:".len();
        if let Some(end) = markdown[start..].find("-->") {
            let claim = markdown[start..start + end].trim().to_string();
            if claim.starts_with('C') {
                out.push(claim);
            }
            idx = start + end + 3;
        } else {
            break;
        }
    }
    out.sort();
    out.dedup();
    out
}

fn append_required_events(
    audit: &mut AuditLog,
    run_id: &str,
    vault_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let events = vec![
        (
            "VAULT_ENCRYPTION_STATUS",
            Actor::System,
            json!({"encryption_at_rest":true,"algorithm":"XCHACHA20_POLY1305","key_storage":"FILE_FALLBACK"}),
        ),
        (
            "NETWORK_MODE_SET",
            Actor::User,
            json!({"network_mode":"OFFLINE","proof_level":"OFFLINE_STRICT","ui_remote_fetch_disabled":true}),
        ),
        (
            "ALLOWLIST_UPDATED",
            Actor::System,
            json!({"allowlist_hash_sha256":sha256_hex(b""),"allowlist_count":0}),
        ),
        (
            "EGRESS_REQUEST_BLOCKED",
            Actor::System,
            json!({"destination":{"scheme":"https","host":"example.invalid","port":443,"path":"/"},"block_reason":"OFFLINE_MODE","request_hash_sha256":sha256_hex(b"blocked")}),
        ),
    ];
    for (event_type, actor, details) in events {
        audit.append(AuditEvent {
            ts_utc: "2026-02-10T00:00:00Z".to_string(),
            event_type: event_type.to_string(),
            run_id: run_id.to_string(),
            vault_id: vault_id.to_string(),
            actor,
            details,
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;
    }
    Ok(())
}

fn make_bundle_inputs(
    pack_id: &str,
    run_id: &str,
    vault_id: &str,
    input_artifact_id: &str,
    input_bytes: &[u8],
    input_content_type: &str,
    input_tags: Vec<String>,
    deliverables: Vec<(String, Vec<u8>, String)>,
    templates_used_json: serde_json::Value,
    citations_map_json: serde_json::Value,
    redactions_map_json: serde_json::Value,
    audit_path: &Path,
) -> Result<EvidenceBundleInputs, Box<dyn std::error::Error>> {
    let input_sha = sha256_hex(input_bytes);
    let manifest_inputs_fingerprint = sha256_hex(format!("{}:{}", input_artifact_id, input_sha).as_bytes());
    let templates_rel = format!("exports/{}/attachments/templates_used.json", pack_id);
    let citations_rel = format!("exports/{}/attachments/citations_map.json", pack_id);
    let redactions_rel = format!("exports/{}/attachments/redactions_map.json", pack_id);

    let templates_bytes = json_canonical::to_canonical_bytes(&templates_used_json)?;
    let citations_bytes = json_canonical::to_canonical_bytes(&citations_map_json)?;
    let redactions_bytes = json_canonical::to_canonical_bytes(&redactions_map_json)?;

    let mut hash_rows = vec![ArtifactHashRow {
        artifact_id: input_artifact_id.to_string(),
        bundle_rel_path: String::new(),
        sha256: input_sha.clone(),
        bytes: input_bytes.len() as u64,
        content_type: input_content_type.to_string(),
        logical_role: "INPUT".to_string(),
    }];
    for (path, bytes, content_type) in &deliverables {
        hash_rows.push(ArtifactHashRow {
            artifact_id: format!("o:{}", path),
            bundle_rel_path: path.clone(),
            sha256: sha256_hex(bytes),
            bytes: bytes.len() as u64,
            content_type: content_type.clone(),
            logical_role: "DELIVERABLE".to_string(),
        });
    }
    hash_rows.push(ArtifactHashRow {
        artifact_id: format!("o:{}", templates_rel),
        bundle_rel_path: templates_rel.clone(),
        sha256: sha256_hex(&templates_bytes),
        bytes: templates_bytes.len() as u64,
        content_type: "application/json".to_string(),
        logical_role: "ATTACHMENT".to_string(),
    });
    hash_rows.push(ArtifactHashRow {
        artifact_id: format!("o:{}", citations_rel),
        bundle_rel_path: citations_rel.clone(),
        sha256: sha256_hex(&citations_bytes),
        bytes: citations_bytes.len() as u64,
        content_type: "application/json".to_string(),
        logical_role: "ATTACHMENT".to_string(),
    });
    hash_rows.push(ArtifactHashRow {
        artifact_id: format!("o:{}", redactions_rel),
        bundle_rel_path: redactions_rel.clone(),
        sha256: sha256_hex(&redactions_bytes),
        bytes: redactions_bytes.len() as u64,
        content_type: "application/json".to_string(),
        logical_role: "ATTACHMENT".to_string(),
    });
    let artifact_hashes_csv = render_artifact_hashes_csv(hash_rows)?;

    let outputs: Vec<ManifestOutputRef> = deliverables
        .iter()
        .map(|(path, bytes, content_type)| ManifestOutputRef {
            path: path.clone(),
            sha256: sha256_hex(bytes),
            bytes: bytes.len() as u64,
            content_type: content_type.clone(),
            logical_role: "DELIVERABLE".to_string(),
        })
        .collect();

    Ok(EvidenceBundleInputs {
        run_manifest: RunManifest {
            run_id: run_id.to_string(),
            vault_id: vault_id.to_string(),
            determinism: DeterminismManifest {
                enabled: true,
                manifest_inputs_fingerprint,
            },
            inputs: vec![ManifestArtifactRef {
                artifact_id: input_artifact_id.to_string(),
                sha256: input_sha.clone(),
                bytes: input_bytes.len() as u64,
                mime_type: input_content_type.to_string(),
                logical_role: "INPUT".to_string(),
            }],
            outputs,
            model_calls: vec![],
            eval: EvalSummary {
                gate_status: "PASS".to_string(),
            },
        },
        bundle_info: BundleInfo {
            bundle_version: "1.0.0".to_string(),
            schema_versions: SchemaVersions {
                run_manifest: "RUN_MANIFEST_V1".to_string(),
                eval_report: "EVAL_REPORT_V1".to_string(),
                citations_map: "LOCATOR_SCHEMA_V1".to_string(),
                redactions_map: "REDACTION_SCHEMA_V1".to_string(),
            },
            pack_id: pack_id.to_string(),
            pack_version: "1.0.0".to_string(),
            core_build: "test".to_string(),
            run_id: run_id.to_string(),
        },
        audit_log_ndjson: std::fs::read_to_string(audit_path)?,
        eval_report: EvalReport {
            overall_status: "PASS".to_string(),
            tests: vec![],
            gates: vec![],
            registry_version: "gates_registry_v3".to_string(),
        },
        artifact_hashes_csv,
        artifact_list: ArtifactList {
            artifacts: vec![ArtifactListEntry {
                artifact_id: input_artifact_id.to_string(),
                sha256: input_sha,
                bytes: input_bytes.len() as u64,
                content_type: input_content_type.to_string(),
                logical_role: "INPUT".to_string(),
                classification: "Internal".to_string(),
                tags: input_tags,
                retention_policy_id: "ret_default".to_string(),
            }],
        },
        policy_snapshot: PolicySnapshot {
            policy_mode: PolicyMode::STRICT,
            determinism: DeterminismPolicy {
                enabled: true,
                pdf_determinism_enabled: false,
            },
            export_profile: ExportProfile {
                inputs: InputExportProfile::HASH_ONLY,
            },
            encryption_at_rest: true,
            encryption_algorithm: "XCHACHA20_POLY1305".to_string(),
        },
        network_snapshot: NetworkSnapshot {
            network_mode: NetworkMode::OFFLINE,
            proof_level: ProofLevel::OFFLINE_STRICT,
            allowlist: vec![],
            ui_remote_fetch_disabled: true,
            adapter_endpoints: vec![AdapterEndpointSnapshot {
                endpoint: "http://127.0.0.1:11434".to_string(),
                is_loopback: true,
                validation_error: None,
            }],
        },
        model_snapshot: aigc_core::adapters::pinning::ModelSnapshot {
            adapter_id: "local_adapter".to_string(),
            adapter_version: "1.0.0".to_string(),
            adapter_endpoint: "http://127.0.0.1:11434".to_string(),
            model_id: "model-a".to_string(),
            model_sha256: Some(sha256_hex(b"model-a")),
            pinning_level: PinningLevel::CRYPTO_PINNED,
        },
        pack_id: pack_id.to_string(),
        pack_version: "1.0.0".to_string(),
        deliverables,
        attachments: PackAttachments {
            templates_used_json,
            citations_map_json: Some(citations_map_json),
            redactions_map_json: Some(redactions_map_json),
        },
    })
}

fn export_bundle(
    run_id: &str,
    vault_id: &str,
    inputs: &EvidenceBundleInputs,
    bundle_root: &Path,
    bundle_zip: &Path,
    audit: AuditLog,
) -> Result<String, Box<dyn std::error::Error>> {
    let req = ExportRequest {
        run_id: run_id.to_string(),
        vault_id: vault_id.to_string(),
        policy_mode: PolicyMode::STRICT,
        network_mode: NetworkMode::OFFLINE,
        proof_level: ProofLevel::OFFLINE_STRICT,
        pinning_level: PinningLevel::CRYPTO_PINNED,
        requested_by: "test".to_string(),
    };
    let mut manager = RunManager::new(audit);
    let outcome = manager.export_run(&req, inputs, bundle_root, bundle_zip)?;
    assert_eq!(outcome.status, "COMPLETED");
    assert!(outcome.bundle_path.is_some());
    assert!(outcome.bundle_sha256.is_some());
    let bundle_sha = outcome.bundle_sha256.unwrap_or_default();
    assert!(!bundle_sha.is_empty());

    let validator = BundleValidator::new_v3();
    let summary = validator.validate_zip(bundle_zip, PolicyMode::STRICT)?;
    assert_eq!(summary.overall, "PASS");
    Ok(bundle_sha)
}

#[test]
fn incidentos_deterministic_export_bundle_via_run_manager() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let log_content = std::fs::read_to_string(repo_root.join("core/corpus/incidents/sample_incident.ndjson")).unwrap();
    let input = IncidentOsInputV1 {
        schema_version: "INCIDENTOS_INPUT_V1".to_string(),
        incident_artifacts: vec![IncidentArtifactRef {
            artifact_id: "incident_001".to_string(),
            sha256: "demo".to_string(),
            source_type: "syslog".to_string(),
        }],
        timeline_start_hint: None,
        timeline_end_hint: None,
        customer_redaction_profile: "STRICT".to_string(),
    };
    let workflow = execute_incidentos_workflow(input, &log_content).unwrap();
    let artifact_id = "incident_001";
    let input_sha = sha256_hex(log_content.as_bytes());
    let run_id = format!("r_{}", &sha256_hex(format!("{}:{}", artifact_id, input_sha).as_bytes())[..32]);
    let vault_id = "v_incident_test";

    let customer_path = "exports/incidentos/deliverables/customer_packet.md".to_string();
    let internal_path = "exports/incidentos/deliverables/internal_packet.md".to_string();
    let deliverables = vec![
        (customer_path.clone(), workflow.customer_packet.as_bytes().to_vec(), "text/markdown".to_string()),
        (internal_path.clone(), workflow.internal_packet.as_bytes().to_vec(), "text/markdown".to_string()),
        ("exports/incidentos/deliverables/timeline.csv".to_string(), workflow.timeline_csv.as_bytes().to_vec(), "text/csv".to_string()),
    ];

    let mut claims = Vec::new();
    for (output_path, content) in [(customer_path.as_str(), workflow.customer_packet.as_str()), (internal_path.as_str(), workflow.internal_packet.as_str())] {
        for claim_id in extract_claim_markers(content) {
            claims.push(json!({
                "claim_id": claim_id,
                "output_path": output_path,
                "citations": [{
                    "citation_index": 0,
                    "artifact_id": artifact_id,
                    "locator_type": "TEXT_LINE_RANGE_V1",
                    "locator": {"start_line": 1, "end_line": 1, "text_sha256": input_sha}
                }]
            }));
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let audit_path = temp.path().join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).unwrap();
    append_required_events(&mut audit, &run_id, vault_id).unwrap();
    let inputs = make_bundle_inputs(
        "incidentos",
        &run_id,
        vault_id,
        artifact_id,
        log_content.as_bytes(),
        "application/x-ndjson",
        vec!["INCIDENT".to_string()],
        deliverables.clone(),
        json!({"schema_version":"TEMPLATES_USED_V1","pack_id":"incidentos","pack_version":"1.0.0","run_id":run_id.clone(),"templates":[{"template_id":"incidentos_v1","template_version":"1.0.0","output_paths":["exports/incidentos/deliverables/customer_packet.md","exports/incidentos/deliverables/internal_packet.md","exports/incidentos/deliverables/timeline.csv"],"render_engine":{"name":"core_template_renderer","version":"1.0.0"}}]}),
        json!({"schema_version":"LOCATOR_SCHEMA_V1","pack_id":"incidentos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"claims":claims.clone()}),
        json!({"schema_version":"REDACTION_SCHEMA_V1","pack_id":"incidentos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"artifacts":[]}),
        &audit_path,
    )
    .unwrap();
    let first_hash = export_bundle(
        &run_id,
        vault_id,
        &inputs,
        &temp.path().join("bundle_root"),
        &temp.path().join("bundle.zip"),
        audit,
    )
    .unwrap();

    let temp_second = tempfile::tempdir().unwrap();
    let audit_path_second = temp_second.path().join("audit.ndjson");
    let mut audit_second = AuditLog::open_or_create(&audit_path_second).unwrap();
    append_required_events(&mut audit_second, &run_id, vault_id).unwrap();
    let inputs_second = make_bundle_inputs(
        "incidentos",
        &run_id,
        vault_id,
        artifact_id,
        log_content.as_bytes(),
        "application/x-ndjson",
        vec!["INCIDENT".to_string()],
        deliverables,
        json!({"schema_version":"TEMPLATES_USED_V1","pack_id":"incidentos","pack_version":"1.0.0","run_id":run_id.clone(),"templates":[{"template_id":"incidentos_v1","template_version":"1.0.0","output_paths":["exports/incidentos/deliverables/customer_packet.md","exports/incidentos/deliverables/internal_packet.md","exports/incidentos/deliverables/timeline.csv"],"render_engine":{"name":"core_template_renderer","version":"1.0.0"}}]}),
        json!({"schema_version":"LOCATOR_SCHEMA_V1","pack_id":"incidentos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"claims":claims}),
        json!({"schema_version":"REDACTION_SCHEMA_V1","pack_id":"incidentos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"artifacts":[]}),
        &audit_path_second,
    )
    .unwrap();
    let second_hash = export_bundle(
        &run_id,
        vault_id,
        &inputs_second,
        &temp_second.path().join("bundle_root"),
        &temp_second.path().join("bundle.zip"),
        audit_second,
    )
    .unwrap();

    assert_eq!(first_hash, second_hash);
}

#[test]
fn financeos_deterministic_export_bundle_via_run_manager() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let statement_content = std::fs::read_to_string(repo_root.join("core/corpus/financials/sample_statement.json")).unwrap();
    let input = FinanceOsInputV1 {
        schema_version: "FINANCEOS_INPUT_V1".to_string(),
        finance_artifacts: vec![FinanceArtifactRef {
            artifact_id: "stmt_001".to_string(),
            sha256: "demo".to_string(),
            artifact_kind: "statement".to_string(),
        }],
        period: "2026-01".to_string(),
        exception_rules_profile: "standard".to_string(),
        retention_profile: "standard".to_string(),
    };
    let workflow = execute_financeos_workflow(input, &statement_content).unwrap();
    let artifact_id = "stmt_001";
    let input_sha = sha256_hex(statement_content.as_bytes());
    let run_id = format!("r_{}", &sha256_hex(format!("{}:{}", artifact_id, input_sha).as_bytes())[..32]);
    let vault_id = "v_finance_test";

    let audit_path_md = "exports/financeos/deliverables/exceptions_audit.md".to_string();
    let compliance_path_md = "exports/financeos/deliverables/compliance_internal.md".to_string();
    let deliverables = vec![
        (audit_path_md.clone(), workflow.exceptions_audit.as_bytes().to_vec(), "text/markdown".to_string()),
        (compliance_path_md.clone(), workflow.compliance_internal.as_bytes().to_vec(), "text/markdown".to_string()),
        ("exports/financeos/deliverables/exceptions.csv".to_string(), workflow.exceptions_csv.as_bytes().to_vec(), "text/csv".to_string()),
    ];
    let mut claims = Vec::new();
    for (output_path, content) in [(audit_path_md.as_str(), workflow.exceptions_audit.as_str()), (compliance_path_md.as_str(), workflow.compliance_internal.as_str())] {
        for claim_id in extract_claim_markers(content) {
            claims.push(json!({
                "claim_id": claim_id,
                "output_path": output_path,
                "citations": [{
                    "citation_index": 0,
                    "artifact_id": artifact_id,
                    "locator_type": "TEXT_LINE_RANGE_V1",
                    "locator": {"start_line": 1, "end_line": 1, "text_sha256": input_sha}
                }]
            }));
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let audit_path = temp.path().join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).unwrap();
    append_required_events(&mut audit, &run_id, vault_id).unwrap();
    let inputs = make_bundle_inputs(
        "financeos",
        &run_id,
        vault_id,
        artifact_id,
        statement_content.as_bytes(),
        "application/json",
        vec!["FINANCE".to_string()],
        deliverables.clone(),
        json!({"schema_version":"TEMPLATES_USED_V1","pack_id":"financeos","pack_version":"1.0.0","run_id":run_id.clone(),"templates":[{"template_id":"financeos_v1","template_version":"1.0.0","output_paths":["exports/financeos/deliverables/exceptions_audit.md","exports/financeos/deliverables/compliance_internal.md","exports/financeos/deliverables/exceptions.csv"],"render_engine":{"name":"core_template_renderer","version":"1.0.0"}}]}),
        json!({"schema_version":"LOCATOR_SCHEMA_V1","pack_id":"financeos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"claims":claims.clone()}),
        json!({"schema_version":"REDACTION_SCHEMA_V1","pack_id":"financeos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"artifacts":[]}),
        &audit_path,
    )
    .unwrap();
    let first_hash = export_bundle(
        &run_id,
        vault_id,
        &inputs,
        &temp.path().join("bundle_root"),
        &temp.path().join("bundle.zip"),
        audit,
    )
    .unwrap();

    let temp_second = tempfile::tempdir().unwrap();
    let audit_path_second = temp_second.path().join("audit.ndjson");
    let mut audit_second = AuditLog::open_or_create(&audit_path_second).unwrap();
    append_required_events(&mut audit_second, &run_id, vault_id).unwrap();
    let inputs_second = make_bundle_inputs(
        "financeos",
        &run_id,
        vault_id,
        artifact_id,
        statement_content.as_bytes(),
        "application/json",
        vec!["FINANCE".to_string()],
        deliverables,
        json!({"schema_version":"TEMPLATES_USED_V1","pack_id":"financeos","pack_version":"1.0.0","run_id":run_id.clone(),"templates":[{"template_id":"financeos_v1","template_version":"1.0.0","output_paths":["exports/financeos/deliverables/exceptions_audit.md","exports/financeos/deliverables/compliance_internal.md","exports/financeos/deliverables/exceptions.csv"],"render_engine":{"name":"core_template_renderer","version":"1.0.0"}}]}),
        json!({"schema_version":"LOCATOR_SCHEMA_V1","pack_id":"financeos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"claims":claims}),
        json!({"schema_version":"REDACTION_SCHEMA_V1","pack_id":"financeos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"artifacts":[]}),
        &audit_path_second,
    )
    .unwrap();
    let second_hash = export_bundle(
        &run_id,
        vault_id,
        &inputs_second,
        &temp_second.path().join("bundle_root"),
        &temp_second.path().join("bundle.zip"),
        audit_second,
    )
    .unwrap();

    assert_eq!(first_hash, second_hash);
}

#[test]
fn healthcareos_deterministic_export_bundle_via_run_manager() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let transcript_content =
        std::fs::read_to_string(repo_root.join("core/corpus/clinical/sample_transcript.json")).unwrap();
    let consent_content =
        std::fs::read_to_string(repo_root.join("core/corpus/clinical/sample_consent.json")).unwrap();
    let input = HealthcareOsInputV1 {
        schema_version: "HEALTHCAREOS_INPUT_V1".to_string(),
        consent_artifacts: vec![HealthcareArtifactRef {
            artifact_id: "consent_001".to_string(),
            sha256: "demo".to_string(),
            artifact_kind: "consent".to_string(),
        }],
        transcript_artifacts: vec![HealthcareArtifactRef {
            artifact_id: "tx_001".to_string(),
            sha256: "demo".to_string(),
            artifact_kind: "transcript".to_string(),
        }],
        draft_template_profile: "standard".to_string(),
        verifier_identity: "clinician_1".to_string(),
    };
    let workflow = execute_healthcareos_workflow(input, &transcript_content, Some(&consent_content)).unwrap();
    let artifact_id = "tx_001";
    let input_sha = sha256_hex(transcript_content.as_bytes());
    let run_id = format!("r_{}", &sha256_hex(format!("{}:{}", artifact_id, input_sha).as_bytes())[..32]);
    let vault_id = "v_healthcare_test";
    let draft_path = "exports/healthcareos/deliverables/draft_note.md".to_string();
    let checklist_path = "exports/healthcareos/deliverables/verification_checklist.md".to_string();
    let deliverables = vec![
        (draft_path.clone(), workflow.draft_note.as_bytes().to_vec(), "text/markdown".to_string()),
        (checklist_path, workflow.verification_checklist.as_bytes().to_vec(), "text/markdown".to_string()),
        ("exports/healthcareos/attachments/consent_record.json".to_string(), consent_content.as_bytes().to_vec(), "application/json".to_string()),
        ("exports/healthcareos/attachments/uncertainty_map.json".to_string(), workflow.uncertainty_map.as_bytes().to_vec(), "application/json".to_string()),
    ];
    let claims: Vec<serde_json::Value> = extract_claim_markers(&workflow.draft_note)
        .iter()
        .map(|claim_id| {
            json!({
                "claim_id": claim_id,
                "output_path": draft_path,
                "citations": [{
                    "citation_index": 0,
                    "artifact_id": artifact_id,
                    "locator_type": "TEXT_LINE_RANGE_V1",
                    "locator": {"start_line": 1, "end_line": 1, "text_sha256": input_sha}
                }]
            })
        })
        .collect();

    let temp = tempfile::tempdir().unwrap();
    let audit_path = temp.path().join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).unwrap();
    append_required_events(&mut audit, &run_id, vault_id).unwrap();
    let inputs = make_bundle_inputs(
        "healthcareos",
        &run_id,
        vault_id,
        artifact_id,
        transcript_content.as_bytes(),
        "application/json",
        vec!["HEALTHCARE".to_string()],
        deliverables.clone(),
        json!({"schema_version":"TEMPLATES_USED_V1","pack_id":"healthcareos","pack_version":"1.0.0","run_id":run_id.clone(),"templates":[{"template_id":"healthcareos_v1","template_version":"1.0.0","output_paths":["exports/healthcareos/deliverables/draft_note.md","exports/healthcareos/deliverables/verification_checklist.md"],"render_engine":{"name":"core_template_renderer","version":"1.0.0"}}]}),
        json!({"schema_version":"LOCATOR_SCHEMA_V1","pack_id":"healthcareos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"claims":claims.clone()}),
        json!({"schema_version":"REDACTION_SCHEMA_V1","pack_id":"healthcareos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"artifacts":[]}),
        &audit_path,
    )
    .unwrap();
    let first_hash = export_bundle(
        &run_id,
        vault_id,
        &inputs,
        &temp.path().join("bundle_root"),
        &temp.path().join("bundle.zip"),
        audit,
    )
    .unwrap();

    let temp_second = tempfile::tempdir().unwrap();
    let audit_path_second = temp_second.path().join("audit.ndjson");
    let mut audit_second = AuditLog::open_or_create(&audit_path_second).unwrap();
    append_required_events(&mut audit_second, &run_id, vault_id).unwrap();
    let inputs_second = make_bundle_inputs(
        "healthcareos",
        &run_id,
        vault_id,
        artifact_id,
        transcript_content.as_bytes(),
        "application/json",
        vec!["HEALTHCARE".to_string()],
        deliverables,
        json!({"schema_version":"TEMPLATES_USED_V1","pack_id":"healthcareos","pack_version":"1.0.0","run_id":run_id.clone(),"templates":[{"template_id":"healthcareos_v1","template_version":"1.0.0","output_paths":["exports/healthcareos/deliverables/draft_note.md","exports/healthcareos/deliverables/verification_checklist.md"],"render_engine":{"name":"core_template_renderer","version":"1.0.0"}}]}),
        json!({"schema_version":"LOCATOR_SCHEMA_V1","pack_id":"healthcareos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"claims":claims}),
        json!({"schema_version":"REDACTION_SCHEMA_V1","pack_id":"healthcareos","pack_version":"1.0.0","run_id":run_id.clone(),"generated_at_ms":0,"artifacts":[]}),
        &audit_path_second,
    )
    .unwrap();
    let second_hash = export_bundle(
        &run_id,
        vault_id,
        &inputs_second,
        &temp_second.path().join("bundle_root"),
        &temp_second.path().join("bundle.zip"),
        audit_second,
    )
    .unwrap();

    assert_eq!(first_hash, second_hash);
}

#[test]
fn incidentos_invalid_log_fails() {
    let input = IncidentOsInputV1 {
        schema_version: "INCIDENTOS_INPUT_V1".to_string(),
        incident_artifacts: vec![IncidentArtifactRef {
            artifact_id: "incident_001".to_string(),
            sha256: "demo".to_string(),
            source_type: "syslog".to_string(),
        }],
        timeline_start_hint: None,
        timeline_end_hint: None,
        customer_redaction_profile: "STRICT".to_string(),
    };
    let err = execute_incidentos_workflow(input, "{not-json}")
        .unwrap_err()
        .to_string()
        .to_lowercase();
    assert!(err.contains("parse") || err.contains("json"));
}

#[test]
fn financeos_invalid_statement_fails() {
    let input = FinanceOsInputV1 {
        schema_version: "FINANCEOS_INPUT_V1".to_string(),
        finance_artifacts: vec![FinanceArtifactRef {
            artifact_id: "stmt_001".to_string(),
            sha256: "demo".to_string(),
            artifact_kind: "statement".to_string(),
        }],
        period: "2026-01".to_string(),
        exception_rules_profile: "standard".to_string(),
        retention_profile: "standard".to_string(),
    };
    let err = execute_financeos_workflow(input, "{\"statement_id\":\"x\"}")
        .unwrap_err()
        .to_string()
        .to_lowercase();
    assert!(err.contains("missing") || err.contains("required") || err.contains("invalid"));
}

#[test]
fn healthcareos_revoked_consent_fails() {
    let transcript = r#"{"patient_id":"PT-001","date":"2026-02-01","provider":"Dr X","specialty":"Cardiology","content":"Possible chest pain.","confidence":0.95}"#;
    let revoked_consent = r#"{"patient_id":"PT-001","date_given":"2024-01-01","scope":"general","status":"REVOKED"}"#;
    let input = HealthcareOsInputV1 {
        schema_version: "HEALTHCAREOS_INPUT_V1".to_string(),
        consent_artifacts: vec![HealthcareArtifactRef {
            artifact_id: "consent_001".to_string(),
            sha256: "demo".to_string(),
            artifact_kind: "consent".to_string(),
        }],
        transcript_artifacts: vec![HealthcareArtifactRef {
            artifact_id: "tx_001".to_string(),
            sha256: "demo".to_string(),
            artifact_kind: "transcript".to_string(),
        }],
        draft_template_profile: "standard".to_string(),
        verifier_identity: "clinician_1".to_string(),
    };
    let err = execute_healthcareos_workflow(input, transcript, Some(revoked_consent))
        .unwrap_err()
        .to_string()
        .to_lowercase();
    assert!(err.contains("revoked") || err.contains("consent"));
}
