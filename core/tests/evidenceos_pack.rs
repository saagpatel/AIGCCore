use aigc_core::adapters::pinning::{ModelSnapshot, PinningLevel};
use aigc_core::audit::event::{Actor, AuditEvent};
use aigc_core::audit::log::AuditLog;
use aigc_core::determinism::json_canonical;
use aigc_core::determinism::run_id::sha256_hex;
use aigc_core::eval::runner::EvalRunner;
use aigc_core::evidence_bundle::artifact_hashes::{render_artifact_hashes_csv, ArtifactHashRow};
use aigc_core::evidence_bundle::authority::EvidenceAuthorityManifest;
use aigc_core::evidence_bundle::builder::EvidenceBundleBuilder;
use aigc_core::evidence_bundle::schemas::*;
use aigc_core::evidenceos::model::{CitationInput, EvidenceItem, NarrativeClaimInput};
use aigc_core::evidenceos::workflow::{generate_evidenceos_artifacts, EvidenceOsRequest};
use aigc_core::policy::network_snapshot::{AdapterEndpointSnapshot, NetworkSnapshot};
use aigc_core::policy::types::{InputExportProfile, NetworkMode, PolicyMode, ProofLevel};
use aigc_core::validator::BundleValidator;
use serde_json::json;
use std::path::Path;

fn test_authority(run_id: &str) -> EvidenceAuthorityManifest {
    EvidenceAuthorityManifest::controlled_simulation(
        run_id,
        "aigccore-test:evidenceos_pack",
        "test-revision",
        "test-executable",
        sha256_hex(b"test-executable"),
        sha256_hex(b"test-arguments"),
        sha256_hex(b"test-environment"),
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
    )
}

#[test]
fn evidenceos_bundle_validates_and_is_deterministic() {
    let temp = tempfile::tempdir().unwrap();
    let bundle_root_1 = temp.path().join("bundle_1");
    let bundle_root_2 = temp.path().join("bundle_2");
    let zip_1 = temp.path().join("bundle_1.zip");
    let zip_2 = temp.path().join("bundle_2.zip");

    let inputs_1 = make_inputs(&bundle_root_1).unwrap();
    let mut inputs_2 = make_inputs(&bundle_root_2).unwrap();
    inputs_2.audit_log_ndjson = inputs_2.audit_log_ndjson.replace('\n', "\r\n");

    EvidenceBundleBuilder::build_dir(&bundle_root_1, &inputs_1).unwrap();
    EvidenceBundleBuilder::build_dir(&bundle_root_2, &inputs_2).unwrap();

    let hash_1 = EvidenceBundleBuilder::build_zip(&bundle_root_1, &zip_1).unwrap();
    let hash_2 = EvidenceBundleBuilder::build_zip(&bundle_root_2, &zip_2).unwrap();
    assert_eq!(hash_1, hash_2);

    let validator = BundleValidator::new_v3();
    let summary = validator.validate_zip(&zip_1, PolicyMode::STRICT).unwrap();
    assert_eq!(summary.overall, "PASS");

    let eval = EvalRunner::new_v3().unwrap();
    let gates = eval.run_all_for_bundle(&zip_1, PolicyMode::STRICT).unwrap();
    assert!(gates
        .iter()
        .any(|g| g.gate_id == "EVIDENCEOS.OUTPUTS_PRESENT_V1" && g.result == "PASS"));
    assert!(gates
        .iter()
        .any(|g| g.gate_id == "EVIDENCEOS.MAPPING_REVIEW_PRESENT_V1" && g.result == "PASS"));
}

fn make_inputs(bundle_root: &Path) -> Result<EvidenceBundleInputs, Box<dyn std::error::Error>> {
    let input_bytes = b"evidence-input-bytes";
    let input_sha = sha256_hex(input_bytes);
    let artifact_id = "a_ev_0001".to_string();
    let run_fingerprint = sha256_hex(format!("{}:{}", artifact_id, input_sha).as_bytes());
    let run_id = format!("r_{}", &run_fingerprint[..32]);
    let vault_id = "v_0001".to_string();
    let pack_id = "evidenceos".to_string();
    let pack_version = "1.0.0".to_string();

    let evidence_req = EvidenceOsRequest {
        pack_id: pack_id.clone(),
        pack_version: pack_version.clone(),
        run_id: run_id.clone(),
        policy_mode: PolicyMode::STRICT,
        enabled_capabilities: vec![],
        evidence_items: vec![EvidenceItem {
            artifact_id: artifact_id.clone(),
            artifact_sha256: input_sha.clone(),
            title: "Network posture report".to_string(),
            tags: vec!["OPS".to_string()],
            control_family_labels: vec![
                "Auditability".to_string(),
                "NetworkGovernance".to_string(),
                "Traceability".to_string(),
            ],
        }],
        narrative_claims: vec![NarrativeClaimInput {
            claim_id: "C0001".to_string(),
            text: "The control simulation exercised the offline block path without live traffic."
                .to_string(),
            citations: vec![CitationInput {
                artifact_id: artifact_id.clone(),
                locator_type: "PDF_TEXT_SPAN_V1".to_string(),
                locator: json!({
                    "page_index": 0,
                    "start_char": 0,
                    "end_char": 30,
                    "text_sha256": input_sha
                }),
            }],
        }],
    };
    let pack_artifacts = generate_evidenceos_artifacts(&evidence_req)?;

    let audit_path = bundle_root.join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path)?;
    let base_events = vec![
        (
            "NETWORK_MODE_SET",
            Actor::User,
            json!({"network_mode":"OFFLINE","proof_level":"OFFLINE_STRICT","ui_remote_fetch_disabled":true}),
        ),
        (
            "ALLOWLIST_UPDATED",
            Actor::System,
            json!({"allowlist_hash_sha256": sha256_hex(b""), "allowlist_count":0}),
        ),
        (
            "EGRESS_REQUEST_BLOCKED",
            Actor::System,
            json!({
                "destination":{"scheme":"https","host":"example.invalid","port":443,"path":"/"},
                "block_reason":"OFFLINE_MODE",
                "request_hash_sha256": sha256_hex(b"blocked"),
                "evidence_origin":"CONTROL_SIMULATION"
            }),
        ),
        (
            "VAULT_ENCRYPTION_STATUS",
            Actor::System,
            json!({
                "encryption_at_rest": true,
                "algorithm": "XCHACHA20_POLY1305",
                "key_storage": "FILE_FALLBACK"
            }),
        ),
    ];
    for (event_type, actor, details) in base_events {
        audit.append(AuditEvent {
            ts_utc: "2026-02-10T00:00:00Z".to_string(),
            event_type: event_type.to_string(),
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            actor,
            details,
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })?;
    }
    let audit_log_ndjson = std::fs::read_to_string(&audit_path)?;

    let templates_rel = format!("exports/{}/attachments/templates_used.json", pack_id);
    let citations_rel = format!("exports/{}/attachments/citations_map.json", pack_id);
    let redactions_rel = format!("exports/{}/attachments/redactions_map.json", pack_id);
    let templates_bytes = json_canonical::to_canonical_bytes(&pack_artifacts.templates_used_json)?;
    let citations_bytes = json_canonical::to_canonical_bytes(&pack_artifacts.citations_map_json)?;
    let redactions_bytes = json_canonical::to_canonical_bytes(&pack_artifacts.redactions_map_json)?;

    let mut hash_rows = vec![ArtifactHashRow {
        artifact_id: artifact_id.clone(),
        bundle_rel_path: String::new(),
        sha256: input_sha.clone(),
        bytes: input_bytes.len() as u64,
        content_type: "text/plain".to_string(),
        logical_role: "INPUT".to_string(),
    }];
    for (path, bytes, content_type) in &pack_artifacts.deliverables {
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
        bundle_rel_path: templates_rel,
        sha256: sha256_hex(&templates_bytes),
        bytes: templates_bytes.len() as u64,
        content_type: "application/json".to_string(),
        logical_role: "ATTACHMENT".to_string(),
    });
    hash_rows.push(ArtifactHashRow {
        artifact_id: format!("o:{}", citations_rel),
        bundle_rel_path: citations_rel,
        sha256: sha256_hex(&citations_bytes),
        bytes: citations_bytes.len() as u64,
        content_type: "application/json".to_string(),
        logical_role: "ATTACHMENT".to_string(),
    });
    hash_rows.push(ArtifactHashRow {
        artifact_id: format!("o:{}", redactions_rel),
        bundle_rel_path: redactions_rel,
        sha256: sha256_hex(&redactions_bytes),
        bytes: redactions_bytes.len() as u64,
        content_type: "application/json".to_string(),
        logical_role: "ATTACHMENT".to_string(),
    });
    let artifact_hashes_csv = render_artifact_hashes_csv(hash_rows)?;

    let outputs: Vec<ManifestOutputRef> = pack_artifacts
        .deliverables
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
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            evidence_authority: test_authority(&run_id),
            determinism: DeterminismManifest {
                enabled: true,
                manifest_inputs_fingerprint: run_fingerprint,
            },
            inputs: vec![ManifestArtifactRef {
                artifact_id: artifact_id.clone(),
                sha256: input_sha.clone(),
                bytes: input_bytes.len() as u64,
                mime_type: "text/plain".to_string(),
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
                run_manifest: "RUN_MANIFEST_V2".to_string(),
                eval_report: "EVAL_REPORT_V1".to_string(),
                citations_map: "LOCATOR_SCHEMA_V1".to_string(),
                redactions_map: "REDACTION_SCHEMA_V1".to_string(),
            },
            pack_id: pack_id.clone(),
            pack_version: pack_version.clone(),
            core_build: "dev".to_string(),
            run_id: run_id.clone(),
        },
        audit_log_ndjson,
        eval_report: EvalReport {
            overall_status: "PASS".to_string(),
            tests: vec![],
            gates: vec![],
            registry_version: "gates_registry_v3".to_string(),
        },
        artifact_hashes_csv,
        artifact_list: ArtifactList {
            artifacts: vec![ArtifactListEntry {
                artifact_id,
                sha256: input_sha,
                bytes: input_bytes.len() as u64,
                content_type: "text/plain".to_string(),
                logical_role: "INPUT".to_string(),
                classification: "Internal".to_string(),
                tags: vec!["OPS".to_string()],
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
        model_snapshot: ModelSnapshot {
            adapter_id: "local_adapter".to_string(),
            adapter_version: "1.0.0".to_string(),
            adapter_endpoint: "http://127.0.0.1:11434".to_string(),
            model_id: "model-a".to_string(),
            model_sha256: Some(sha256_hex(b"model-a")),
            pinning_level: PinningLevel::CRYPTO_PINNED,
        },
        pack_id,
        pack_version,
        deliverables: pack_artifacts.deliverables,
        attachments: PackAttachments {
            templates_used_json: pack_artifacts.templates_used_json,
            citations_map_json: Some(pack_artifacts.citations_map_json),
            redactions_map_json: Some(pack_artifacts.redactions_map_json),
        },
    })
}
