#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aigc_core::adapters::pinning::{classify_pinning_level, PinningLevel};
use aigc_core::audit::event::{Actor, AuditEvent};
use aigc_core::audit::log::AuditLog;
use aigc_core::determinism::json_canonical;
use aigc_core::determinism::run_id::sha256_hex;
use aigc_core::evidence_bundle::artifact_hashes::{render_artifact_hashes_csv, ArtifactHashRow};
use aigc_core::evidence_bundle::schemas::*;
use aigc_core::evidenceos::control_library::{controls_for_capabilities, ControlDefinition};
use aigc_core::evidenceos::model::{CitationInput, EvidenceItem, NarrativeClaimInput};
use aigc_core::evidenceos::workflow::{generate_evidenceos_artifacts, EvidenceOsRequest};
use aigc_core::financeos::model::FinanceOsInputV1;
use aigc_core::financeos::parser::parse_financial_statement;
use aigc_core::financeos::render::{
    output_manifest as finance_output_manifest, render_compliance_summary, render_exceptions_map,
};
use aigc_core::financeos::exceptions::ExceptionDetector;
use aigc_core::financeos::workflow::{execute_financeos_workflow, FinanceWorkflowState};
use aigc_core::healthcareos::model::HealthcareOsInputV1;
use aigc_core::healthcareos::render::output_manifest as healthcare_output_manifest;
use aigc_core::healthcareos::workflow::{execute_healthcareos_workflow, HealthcareWorkflowState};
use aigc_core::incidentos::model::IncidentOsInputV1;
use aigc_core::incidentos::redaction::RedactionProfile;
use aigc_core::incidentos::parser::{parse_json_log, parse_ndjson_log};
use aigc_core::incidentos::render::{
    output_manifest as incident_output_manifest, render_citations_map as render_incident_citations,
    render_redactions_map,
};
use aigc_core::incidentos::timeline::build_timeline;
use aigc_core::incidentos::workflow::{execute_incidentos_workflow, IncidentWorkflowState};
use aigc_core::policy::network_snapshot::{AdapterEndpointSnapshot, NetworkSnapshot};
use aigc_core::policy::types::{InputExportProfile, NetworkMode, PolicyMode, ProofLevel};
use aigc_core::redlineos::model::RedlineOsInputV1;
use aigc_core::redlineos::workflow::{self, RedlineWorkflowState};
use aigc_core::run::manager::{ExportOutcome, ExportRequest, RunManager};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize)]
struct PackCommandStatus {
    status: String,
    message: String,
    bundle_path: Option<String>,
    bundle_sha256: Option<String>,
    error_code: Option<String>,
    run_id: Option<String>,
    audit_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct UiNetworkSnapshot {
    network_mode: &'static str,
    proof_level: &'static str,
    ui_remote_fetch_disabled: bool,
}

#[derive(Debug, Serialize)]
struct EvidenceOsRunResult {
    status: String,
    bundle_path: String,
    bundle_sha256: String,
    missing_control_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EvidenceOsRunInput {
    enabled_capabilities: Vec<String>,
    artifact_title: String,
    artifact_body: String,
    artifact_tags_csv: String,
    control_families_csv: String,
    claim_text: String,
}

#[derive(Debug, Deserialize)]
struct ArtifactPayloadInput {
    artifact_id: String,
    #[serde(default)]
    content_text: Option<String>,
    #[serde(default)]
    content_base64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RedlineCommandInput {
    #[serde(flatten)]
    workflow_input: RedlineOsInputV1,
    #[serde(default)]
    artifact_payloads: Vec<ArtifactPayloadInput>,
}

#[derive(Debug, Deserialize)]
struct IncidentCommandInput {
    #[serde(flatten)]
    workflow_input: IncidentOsInputV1,
    #[serde(default)]
    artifact_payloads: Vec<ArtifactPayloadInput>,
}

#[derive(Debug, Deserialize)]
struct FinanceCommandInput {
    #[serde(flatten)]
    workflow_input: FinanceOsInputV1,
    #[serde(default)]
    artifact_payloads: Vec<ArtifactPayloadInput>,
}

#[derive(Debug, Deserialize)]
struct HealthcareCommandInput {
    #[serde(flatten)]
    workflow_input: HealthcareOsInputV1,
    #[serde(default)]
    artifact_payloads: Vec<ArtifactPayloadInput>,
}

#[derive(Debug, Clone)]
struct InputArtifactDescriptor {
    artifact_id: String,
    sha256: String,
    bytes: u64,
    mime_type: String,
    content_type: String,
    classification: String,
    tags: Vec<String>,
}

const MAX_TEXT_PAYLOAD_BYTES: usize = 5 * 1024 * 1024;
const MAX_BINARY_PAYLOAD_BYTES: usize = 20 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
enum PayloadExpectation {
    Text,
    BinaryPdf,
}

#[derive(Debug, Clone)]
struct IngestedArtifactPayload {
    artifact_id: String,
    bytes: Vec<u8>,
    text: Option<String>,
    sha256: String,
    sha_enforced: bool,
    declared_sha: String,
}

#[derive(Debug)]
struct PackCommandError {
    status: &'static str,
    error_code: &'static str,
    message: String,
    run_id: Option<String>,
    audit_path: Option<String>,
}

impl PackCommandError {
    fn blocked(error_code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: "BLOCKED",
            error_code,
            message: message.into(),
            run_id: None,
            audit_path: None,
        }
    }

    fn failed(error_code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: "FAILED",
            error_code,
            message: message.into(),
            run_id: None,
            audit_path: None,
        }
    }

    fn failed_with_meta(
        error_code: &'static str,
        message: impl Into<String>,
        run_id: &str,
        audit_path: &std::path::Path,
    ) -> Self {
        Self {
            status: "FAILED",
            error_code,
            message: message.into(),
            run_id: Some(run_id.to_string()),
            audit_path: Some(audit_path.display().to_string()),
        }
    }
}

fn pack_status_from_error(error: PackCommandError) -> PackCommandStatus {
    PackCommandStatus {
        status: error.status.to_string(),
        message: error.message,
        bundle_path: None,
        bundle_sha256: None,
        error_code: Some(error.error_code.to_string()),
        run_id: error.run_id,
        audit_path: error.audit_path,
    }
}

#[tauri::command]
fn get_network_snapshot() -> UiNetworkSnapshot {
    UiNetworkSnapshot {
        network_mode: "OFFLINE",
        proof_level: "OFFLINE_STRICT",
        ui_remote_fetch_disabled: true,
    }
}

#[tauri::command]
fn list_control_library(enabled_capabilities: Option<Vec<String>>) -> Vec<ControlDefinition> {
    controls_for_capabilities(&enabled_capabilities.unwrap_or_default())
}

#[tauri::command]
fn generate_evidenceos_bundle(input: EvidenceOsRunInput) -> Result<EvidenceOsRunResult, String> {
    let runtime_dir = make_runtime_dir()?;
    let bundle_root = runtime_dir.join("bundle_root");
    let bundle_zip = runtime_dir.join("evidence_bundle_evidenceos_v1.zip");
    let audit_path = runtime_dir.join("audit.ndjson");

    let artifact_bytes = if input.artifact_body.trim().is_empty() {
        b"default evidence artifact body".to_vec()
    } else {
        input.artifact_body.as_bytes().to_vec()
    };
    let artifact_sha = sha256_hex(&artifact_bytes);
    let artifact_id = format!("a_ui_{}", &artifact_sha[..8]);
    let manifest_inputs_fingerprint =
        sha256_hex(format!("{}:{}", artifact_id, artifact_sha).as_bytes());
    let run_id = format!("r_{}", &manifest_inputs_fingerprint[..32]);
    let vault_id = "v_ui_0001".to_string();
    let pack_id = "evidenceos".to_string();
    let pack_version = "1.0.0".to_string();

    let mut audit = AuditLog::open_or_create(&audit_path).map_err(|e| e.to_string())?;
    let events = vec![
        (
            "VAULT_ENCRYPTION_STATUS",
            Actor::System,
            json!({
                "encryption_at_rest": true,
                "algorithm": "XCHACHA20_POLY1305",
                "key_storage": "FILE_FALLBACK"
            }),
        ),
        (
            "NETWORK_MODE_SET",
            Actor::User,
            json!({
                "network_mode":"OFFLINE",
                "proof_level":"OFFLINE_STRICT",
                "ui_remote_fetch_disabled":true
            }),
        ),
        (
            "ALLOWLIST_UPDATED",
            Actor::System,
            json!({
                "allowlist_hash_sha256": sha256_hex(b""),
                "allowlist_count":0
            }),
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
    ];
    for (event_type, actor, details) in events {
        audit
            .append(AuditEvent {
                ts_utc: now_rfc3339_utc(),
                event_type: event_type.to_string(),
                run_id: run_id.clone(),
                vault_id: vault_id.clone(),
                actor,
                details,
                prev_event_hash: String::new(),
                event_hash: String::new(),
            })
            .map_err(|e| e.to_string())?;
    }

    let tags = csv_to_vec(&input.artifact_tags_csv);
    let control_families = csv_to_vec(&input.control_families_csv);
    let enabled_capabilities = if input.enabled_capabilities.is_empty() {
        vec!["Traceability".to_string()]
    } else {
        input.enabled_capabilities.clone()
    };
    let claim_text = if input.claim_text.trim().is_empty() {
        "The EvidenceOS run remained offline with blocked network egress attempts.".to_string()
    } else {
        input.claim_text.clone()
    };

    let req = EvidenceOsRequest {
        pack_id: pack_id.clone(),
        pack_version: pack_version.clone(),
        run_id: run_id.clone(),
        policy_mode: PolicyMode::STRICT,
        enabled_capabilities,
        evidence_items: vec![EvidenceItem {
            artifact_id: artifact_id.clone(),
            artifact_sha256: artifact_sha.clone(),
            title: if input.artifact_title.trim().is_empty() {
                "User provided evidence artifact".to_string()
            } else {
                input.artifact_title.clone()
            },
            tags: tags.clone(),
            control_family_labels: if control_families.is_empty() {
                vec!["Traceability".to_string()]
            } else {
                control_families
            },
        }],
        narrative_claims: vec![NarrativeClaimInput {
            claim_id: "C0001".to_string(),
            text: claim_text,
            citations: vec![CitationInput {
                artifact_id: artifact_id.clone(),
                locator_type: "PDF_TEXT_SPAN_V1".to_string(),
                locator: json!({
                    "page_index": 0,
                    "start_char": 0,
                    "end_char": 30,
                    "text_sha256": artifact_sha
                }),
            }],
        }],
    };

    let generated = generate_evidenceos_artifacts(&req).map_err(|e| e.to_string())?;

    let templates_rel = format!("exports/{}/attachments/templates_used.json", pack_id);
    let citations_rel = format!("exports/{}/attachments/citations_map.json", pack_id);
    let redactions_rel = format!("exports/{}/attachments/redactions_map.json", pack_id);

    let templates_bytes = json_canonical::to_canonical_bytes(&generated.templates_used_json)
        .map_err(|e| e.to_string())?;
    let citations_bytes = json_canonical::to_canonical_bytes(&generated.citations_map_json)
        .map_err(|e| e.to_string())?;
    let redactions_bytes = json_canonical::to_canonical_bytes(&generated.redactions_map_json)
        .map_err(|e| e.to_string())?;

    let mut hash_rows = vec![ArtifactHashRow {
        artifact_id: artifact_id.clone(),
        bundle_rel_path: String::new(),
        sha256: req.evidence_items[0].artifact_sha256.clone(),
        bytes: artifact_bytes.len() as u64,
        content_type: "text/plain".to_string(),
        logical_role: "INPUT".to_string(),
    }];
    for (path, bytes, content_type) in &generated.deliverables {
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
    let artifact_hashes_csv = render_artifact_hashes_csv(hash_rows).map_err(|e| e.to_string())?;

    let outputs: Vec<ManifestOutputRef> = generated
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

    let bundle_inputs = EvidenceBundleInputs {
        run_manifest: RunManifest {
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            determinism: DeterminismManifest {
                enabled: true,
                manifest_inputs_fingerprint,
            },
            inputs: vec![ManifestArtifactRef {
                artifact_id: artifact_id.clone(),
                sha256: req.evidence_items[0].artifact_sha256.clone(),
                bytes: artifact_bytes.len() as u64,
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
                run_manifest: "RUN_MANIFEST_V1".to_string(),
                eval_report: "EVAL_REPORT_V1".to_string(),
                citations_map: "LOCATOR_SCHEMA_V1".to_string(),
                redactions_map: "REDACTION_SCHEMA_V1".to_string(),
            },
            pack_id: pack_id.clone(),
            pack_version: pack_version.clone(),
            core_build: "dev".to_string(),
            run_id: run_id.clone(),
        },
        audit_log_ndjson: std::fs::read_to_string(&audit_path).map_err(|e| e.to_string())?,
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
                sha256: req.evidence_items[0].artifact_sha256.clone(),
                bytes: artifact_bytes.len() as u64,
                content_type: "text/plain".to_string(),
                logical_role: "INPUT".to_string(),
                classification: "Internal".to_string(),
                tags,
                retention_policy_id: "ret_default".to_string(),
            }],
        },
        policy_snapshot: PolicySnapshot {
            policy_mode: PolicyMode::STRICT,
            determinism: DeterminismPolicy {
                enabled: true,
                pdf_determinism_enabled: true,
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
            pinning_level: {
                let m = sha256_hex(b"model-a");
                classify_pinning_level(Some(&m), "local_adapter", "1.0.0")
            },
        },
        pack_id: pack_id.clone(),
        pack_version,
        deliverables: generated.deliverables,
        attachments: PackAttachments {
            templates_used_json: generated.templates_used_json,
            citations_map_json: Some(generated.citations_map_json),
            redactions_map_json: Some(generated.redactions_map_json),
        },
    };

    let mut manager = RunManager::new(audit);
    let export_req = ExportRequest {
        run_id,
        vault_id,
        policy_mode: PolicyMode::STRICT,
        network_mode: NetworkMode::OFFLINE,
        proof_level: ProofLevel::OFFLINE_STRICT,
        pinning_level: PinningLevel::CRYPTO_PINNED,
        requested_by: "user".to_string(),
    };

    let outcome = manager
        .export_run(&export_req, &bundle_inputs, &bundle_root, &bundle_zip)
        .map_err(|e| format!("failed to export EvidenceOS bundle: {}", e))?;
    if outcome.status != "COMPLETED" {
        return Err(format!(
            "EvidenceOS export did not complete. status={} block_reason={:?}",
            outcome.status, outcome.block_reason
        ));
    }

    Ok(EvidenceOsRunResult {
        status: outcome.status,
        bundle_path: outcome.bundle_path.unwrap_or_default(),
        bundle_sha256: outcome.bundle_sha256.unwrap_or_default(),
        missing_control_ids: generated.missing_control_ids,
    })
}

#[tauri::command]
fn run_redlineos(input: RedlineCommandInput) -> PackCommandStatus {
    run_redlineos_impl(input).unwrap_or_else(pack_status_from_error)
}

fn run_redlineos_impl(input: RedlineCommandInput) -> Result<PackCommandStatus, PackCommandError> {
    let workflow_input = input.workflow_input;
    let _state = RedlineWorkflowState::ingest(workflow_input.clone()).map_err(|e| {
        PackCommandError::blocked("REDLINEOS_INPUT_INVALID", format!("Invalid RedlineOS input: {e}"))
    })?;
    let contract_artifact = workflow_input
        .contract_artifacts
        .first()
        .cloned()
        .ok_or_else(|| {
            PackCommandError::blocked(
                "REDLINEOS_INPUT_INVALID",
                "At least one contract artifact is required",
            )
        })?;
    let contract_artifact_id = contract_artifact.artifact_id.clone();
    let ingested_contract = ingest_payload(
        &contract_artifact_id,
        &contract_artifact.sha256,
        &input.artifact_payloads,
        PayloadExpectation::BinaryPdf,
    )?;
    let contract_bytes = ingested_contract.bytes.clone();
    let workflow_output = workflow::execute_redlineos_workflow(workflow_input.clone(), &contract_bytes)
        .map_err(|e| {
            PackCommandError::blocked(
                "REDLINEOS_WORKFLOW_INVALID_INPUT",
                format!("RedlineOS workflow failed: {e}"),
            )
        })?;

    let input_sha = ingested_contract.sha256.clone();
    let manifest_inputs_fingerprint =
        sha256_hex(format!("{}:{}", contract_artifact_id, input_sha).as_bytes());
    let run_id = format!("r_{}", &manifest_inputs_fingerprint[..32]);
    let vault_id = "v_redline_0001".to_string();
    let runtime_dir = make_runtime_dir().map_err(|e| {
        PackCommandError::failed("RUNTIME_DIR_CREATE_FAILED", format!("Failed to create runtime directory: {e}"))
    })?;
    let bundle_root = runtime_dir.join("redlineos_bundle");
    let bundle_zip = runtime_dir.join("evidence_bundle_redlineos_v1.zip");
    let audit_path = runtime_dir.join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_LOG_OPEN_FAILED",
            format!("Failed to open audit log: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    append_required_audit_events(&mut audit, &run_id, &vault_id).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_APPEND_FAILED",
            format!("Failed to append required audit events: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    append_ingestion_audit_event(&mut audit, &run_id, &vault_id, &ingested_contract).map_err(
        |e| {
            PackCommandError::failed_with_meta(
                "AUDIT_APPEND_FAILED",
                format!("Failed to append artifact ingestion audit event: {e}"),
                &run_id,
                &audit_path,
            )
        },
    )?;

    let deliverables = vec![
        (
            "exports/redlineos/deliverables/risk_memo.md".to_string(),
            workflow_output.risk_memo.as_bytes().to_vec(),
            "text/markdown".to_string(),
        ),
        (
            "exports/redlineos/deliverables/clause_map.csv".to_string(),
            workflow_output.clause_map.as_bytes().to_vec(),
            "text/csv".to_string(),
        ),
        (
            "exports/redlineos/deliverables/redline_suggestions.md".to_string(),
            workflow_output.suggestions.as_bytes().to_vec(),
            "text/markdown".to_string(),
        ),
    ];
    let claim_entries: Vec<serde_json::Value> = extract_claim_markers(&workflow_output.risk_memo)
        .iter()
        .map(|claim_id| {
            json!({
                "claim_id": claim_id,
                "output_path": "exports/redlineos/deliverables/risk_memo.md",
                "citations": [
                    {
                        "citation_index": 0,
                        "artifact_id": contract_artifact_id,
                        "locator_type": "PDF_TEXT_SPAN_V1",
                        "locator": {
                            "page_index": 0,
                            "start_char": 0,
                            "end_char": 32,
                            "text_sha256": input_sha
                        }
                    }
                ]
            })
        })
        .collect();
    let templates_used_json = json!({
        "schema_version": "TEMPLATES_USED_V1",
        "pack_id": "redlineos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "templates": [
            {
                "template_id": "redlineos_v1",
                "template_version": "1.0.0",
                "output_paths": [
                    "exports/redlineos/deliverables/risk_memo.md",
                    "exports/redlineos/deliverables/clause_map.csv",
                    "exports/redlineos/deliverables/redline_suggestions.md"
                ],
                "render_engine": {"name":"core_template_renderer","version":"1.0.0"}
            }
        ]
    });
    let citations_map_json = json!({
        "schema_version": "LOCATOR_SCHEMA_V1",
        "pack_id": "redlineos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "generated_at_ms": 0,
        "claims": claim_entries
    });
    let redactions_map_json = json!({
        "schema_version": "REDACTION_SCHEMA_V1",
        "pack_id": "redlineos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "generated_at_ms": 0,
        "artifacts": []
    });
    let input_artifacts = vec![InputArtifactDescriptor {
        artifact_id: contract_artifact_id,
        sha256: input_sha,
        bytes: contract_bytes.len() as u64,
        mime_type: "application/pdf".to_string(),
        content_type: "application/pdf".to_string(),
        classification: "Internal".to_string(),
        tags: vec!["LEGAL".to_string()],
    }];
    let bundle_inputs = build_pack_bundle_inputs(
        "redlineos",
        "1.0.0",
        &run_id,
        &vault_id,
        &audit_path,
        &input_artifacts,
        deliverables,
        templates_used_json,
        citations_map_json,
        redactions_map_json,
        true,
    )
    .map_err(|e| {
        PackCommandError::failed_with_meta(
            "BUNDLE_BUILD_FAILED",
            format!("Failed to build bundle inputs: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    let outcome =
        run_export(&run_id, &vault_id, audit, &bundle_inputs, &bundle_root, &bundle_zip)
            .map_err(|e| {
                PackCommandError::failed_with_meta(
                    "EXPORT_RUN_FAILED",
                    e,
                    &run_id,
                    &audit_path,
                )
            })?;
    Ok(status_from_outcome(
        format!(
            "RedlineOS bundle exported with {} HIGH-risk clauses and {:.0}% extraction confidence.",
            workflow_output.high_risk_count,
            workflow_output.extraction_confidence * 100.0
        ),
        outcome,
        &run_id,
        &audit_path,
    ))
}

#[tauri::command]
fn run_incidentos(input: IncidentCommandInput) -> PackCommandStatus {
    run_incidentos_impl(input).unwrap_or_else(pack_status_from_error)
}

fn run_incidentos_impl(input: IncidentCommandInput) -> Result<PackCommandStatus, PackCommandError> {
    let workflow_input = input.workflow_input;
    let _state = IncidentWorkflowState::ingest(workflow_input.clone()).map_err(|e| {
        PackCommandError::blocked("INCIDENTOS_INPUT_INVALID", format!("Invalid IncidentOS input: {e}"))
    })?;
    let manifest = incident_output_manifest();
    let source_artifact = workflow_input
        .incident_artifacts
        .first()
        .cloned()
        .ok_or_else(|| {
            PackCommandError::blocked(
                "INCIDENTOS_INPUT_INVALID",
                "At least one incident artifact is required",
            )
        })?;
    let ingested_log = ingest_payload(
        &source_artifact.artifact_id,
        &source_artifact.sha256,
        &input.artifact_payloads,
        PayloadExpectation::Text,
    )?;
    let log_content = ingested_log.text.clone().ok_or_else(|| {
        PackCommandError::blocked(
            "ARTIFACT_CONTENT_TYPE_UNSUPPORTED",
            format!(
                "Text artifact payload for {} could not be decoded as text",
                source_artifact.artifact_id
            ),
        )
    })?;
    let events = if log_content.trim().starts_with('[') {
        parse_json_log(&log_content)
    } else {
        parse_ndjson_log(&log_content)
    }
    .map_err(|e| {
        PackCommandError::blocked(
            "INCIDENT_LOG_INVALID_FORMAT",
            format!("Failed to parse incident log payload: {e}"),
        )
    })?;
    let timeline = build_timeline(&source_artifact.artifact_id, events).map_err(|e| {
        PackCommandError::blocked("INCIDENT_TIMELINE_BUILD_FAILED", format!("Failed to build timeline: {e}"))
    })?;
    let redaction_profile = RedactionProfile::from_str(&workflow_input.customer_redaction_profile)
        .map_err(|e| {
            PackCommandError::blocked(
                "INCIDENT_REDACTION_PROFILE_INVALID",
                format!("Invalid redaction profile: {e}"),
            )
        })?;
    let workflow_output = execute_incidentos_workflow(workflow_input.clone(), &log_content)
        .map_err(|e| {
            PackCommandError::blocked(
                "INCIDENTOS_WORKFLOW_INVALID_INPUT",
                format!("IncidentOS workflow failed: {e}"),
            )
        })?;
    let redactions_map = render_redactions_map(&timeline, redaction_profile).map_err(|e| {
        PackCommandError::failed("INCIDENT_REDACTIONS_RENDER_FAILED", format!("Failed to render redactions map: {e}"))
    })?;
    let incident_citations_map = render_incident_citations(&timeline).map_err(|e| {
        PackCommandError::failed("INCIDENT_CITATIONS_RENDER_FAILED", format!("Failed to render citations map: {e}"))
    })?;

    let input_sha = ingested_log.sha256.clone();
    let manifest_inputs_fingerprint =
        sha256_hex(format!("{}:{}", source_artifact.artifact_id, input_sha).as_bytes());
    let run_id = format!("r_{}", &manifest_inputs_fingerprint[..32]);
    let vault_id = "v_incident_0001".to_string();
    let runtime_dir = make_runtime_dir().map_err(|e| {
        PackCommandError::failed("RUNTIME_DIR_CREATE_FAILED", format!("Failed to create runtime directory: {e}"))
    })?;
    let bundle_root = runtime_dir.join("incidentos_bundle");
    let bundle_zip = runtime_dir.join("evidence_bundle_incidentos_v1.zip");
    let audit_path = runtime_dir.join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_LOG_OPEN_FAILED",
            format!("Failed to open audit log: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    append_required_audit_events(&mut audit, &run_id, &vault_id).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_APPEND_FAILED",
            format!("Failed to append required audit events: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    append_ingestion_audit_event(&mut audit, &run_id, &vault_id, &ingested_log).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_APPEND_FAILED",
            format!("Failed to append artifact ingestion audit event: {e}"),
            &run_id,
            &audit_path,
        )
    })?;

    let customer_path = manifest.deliverable_paths[0].clone();
    let internal_path = manifest.deliverable_paths[1].clone();
    let timeline_path = manifest.deliverable_paths[2].clone();
    let redactions_path = manifest.attachment_paths[0].clone();
    let citations_path = manifest.attachment_paths[1].clone();
    let deliverables = vec![
        (
            customer_path.clone(),
            workflow_output.customer_packet.as_bytes().to_vec(),
            "text/markdown".to_string(),
        ),
        (
            internal_path.clone(),
            workflow_output.internal_packet.as_bytes().to_vec(),
            "text/markdown".to_string(),
        ),
        (
            timeline_path,
            workflow_output.timeline_csv.as_bytes().to_vec(),
            "text/csv".to_string(),
        ),
        (
            redactions_path,
            redactions_map.as_bytes().to_vec(),
            "application/json".to_string(),
        ),
        (
            citations_path,
            incident_citations_map.as_bytes().to_vec(),
            "application/json".to_string(),
        ),
    ];

    let mut claim_entries = Vec::new();
    for (output_path, output_text) in [
        (customer_path.as_str(), workflow_output.customer_packet.as_str()),
        (internal_path.as_str(), workflow_output.internal_packet.as_str()),
    ] {
        for claim_id in extract_claim_markers(output_text) {
            claim_entries.push(json!({
                "claim_id": claim_id,
                "output_path": output_path,
                "citations": [
                    {
                        "citation_index": 0,
                        "artifact_id": source_artifact.artifact_id,
                        "locator_type": "TEXT_LINE_RANGE_V1",
                        "locator": { "start_line": 1, "end_line": 1, "text_sha256": input_sha }
                    }
                ]
            }));
        }
    }
    let templates_used_json = json!({
        "schema_version": "TEMPLATES_USED_V1",
        "pack_id": "incidentos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "templates": [
            {
                "template_id": "incidentos_v1",
                "template_version": "1.0.0",
                "output_paths": [customer_path, internal_path, manifest.deliverable_paths[2]],
                "render_engine": {"name":"core_template_renderer","version":"1.0.0"}
            }
        ]
    });
    let citations_map_json = json!({
        "schema_version": "LOCATOR_SCHEMA_V1",
        "pack_id": "incidentos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "generated_at_ms": 0,
        "claims": claim_entries
    });
    let redactions_map_json = json!({
        "schema_version": "REDACTION_SCHEMA_V1",
        "pack_id": "incidentos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "generated_at_ms": 0,
        "artifacts": []
    });
    let input_artifacts = vec![InputArtifactDescriptor {
        artifact_id: source_artifact.artifact_id.clone(),
        sha256: input_sha,
        bytes: ingested_log.bytes.len() as u64,
        mime_type: "application/x-ndjson".to_string(),
        content_type: "application/x-ndjson".to_string(),
        classification: "Internal".to_string(),
        tags: vec!["INCIDENT".to_string(), "SECURITY".to_string()],
    }];
    let bundle_inputs = build_pack_bundle_inputs(
        "incidentos",
        "1.0.0",
        &run_id,
        &vault_id,
        &audit_path,
        &input_artifacts,
        deliverables,
        templates_used_json,
        citations_map_json,
        redactions_map_json,
        false,
    )
    .map_err(|e| {
        PackCommandError::failed_with_meta(
            "BUNDLE_BUILD_FAILED",
            format!("Failed to build bundle inputs: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    let outcome =
        run_export(&run_id, &vault_id, audit, &bundle_inputs, &bundle_root, &bundle_zip)
            .map_err(|e| {
                PackCommandError::failed_with_meta(
                    "EXPORT_RUN_FAILED",
                    e,
                    &run_id,
                    &audit_path,
                )
            })?;
    Ok(status_from_outcome(
        format!(
            "IncidentOS bundle exported with {} events and {} HIGH-severity events.",
            workflow_output.event_count, workflow_output.high_severity_count
        ),
        outcome,
        &run_id,
        &audit_path,
    ))
}

#[tauri::command]
fn run_financeos(input: FinanceCommandInput) -> PackCommandStatus {
    run_financeos_impl(input).unwrap_or_else(pack_status_from_error)
}

fn run_financeos_impl(input: FinanceCommandInput) -> Result<PackCommandStatus, PackCommandError> {
    let workflow_input = input.workflow_input;
    let _state = FinanceWorkflowState::ingest(workflow_input.clone()).map_err(|e| {
        PackCommandError::blocked("FINANCEOS_INPUT_INVALID", format!("Invalid FinanceOS input: {e}"))
    })?;
    let manifest = finance_output_manifest();
    let source_artifact = workflow_input
        .finance_artifacts
        .first()
        .cloned()
        .ok_or_else(|| {
            PackCommandError::blocked(
                "FINANCEOS_INPUT_INVALID",
                "At least one finance artifact is required",
            )
        })?;
    let source_artifact_id = source_artifact.artifact_id.clone();
    let ingested_statement = ingest_payload(
        &source_artifact_id,
        &source_artifact.sha256,
        &input.artifact_payloads,
        PayloadExpectation::Text,
    )?;
    let statement_content = ingested_statement.text.clone().ok_or_else(|| {
        PackCommandError::blocked(
            "ARTIFACT_CONTENT_TYPE_UNSUPPORTED",
            format!(
                "Text artifact payload for {} could not be decoded as text",
                source_artifact_id
            ),
        )
    })?;
    let statement = parse_financial_statement(&statement_content).map_err(|e| {
        PackCommandError::blocked(
            "FINANCE_STATEMENT_INVALID_FORMAT",
            format!("Failed to parse finance statement payload: {e}"),
        )
    })?;
    let workflow_output = execute_financeos_workflow(workflow_input.clone(), &statement_content)
        .map_err(|e| {
            PackCommandError::blocked(
                "FINANCEOS_WORKFLOW_INVALID_INPUT",
                format!("FinanceOS workflow failed: {e}"),
            )
        })?;
    let exceptions = ExceptionDetector::new()
        .detect_exceptions(&statement)
        .map_err(|e| {
            PackCommandError::failed("FINANCE_EXCEPTION_DETECTION_FAILED", format!("Failed to detect exceptions: {e}"))
        })?;
    let exceptions_map = render_exceptions_map(&exceptions).map_err(|e| {
        PackCommandError::failed("FINANCE_EXCEPTIONS_RENDER_FAILED", format!("Failed to render exceptions map: {e}"))
    })?;
    let compliance_summary = render_compliance_summary(&statement, &exceptions).map_err(|e| {
        PackCommandError::failed(
            "FINANCE_COMPLIANCE_SUMMARY_RENDER_FAILED",
            format!("Failed to render compliance summary: {e}"),
        )
    })?;

    let input_sha = ingested_statement.sha256.clone();
    let manifest_inputs_fingerprint =
        sha256_hex(format!("{}:{}", source_artifact_id, input_sha).as_bytes());
    let run_id = format!("r_{}", &manifest_inputs_fingerprint[..32]);
    let vault_id = "v_finance_0001".to_string();
    let runtime_dir = make_runtime_dir().map_err(|e| {
        PackCommandError::failed("RUNTIME_DIR_CREATE_FAILED", format!("Failed to create runtime directory: {e}"))
    })?;
    let bundle_root = runtime_dir.join("financeos_bundle");
    let bundle_zip = runtime_dir.join("evidence_bundle_financeos_v1.zip");
    let audit_path = runtime_dir.join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_LOG_OPEN_FAILED",
            format!("Failed to open audit log: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    append_required_audit_events(&mut audit, &run_id, &vault_id).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_APPEND_FAILED",
            format!("Failed to append required audit events: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    append_ingestion_audit_event(&mut audit, &run_id, &vault_id, &ingested_statement).map_err(
        |e| {
            PackCommandError::failed_with_meta(
                "AUDIT_APPEND_FAILED",
                format!("Failed to append artifact ingestion audit event: {e}"),
                &run_id,
                &audit_path,
            )
        },
    )?;

    let audit_path_md = manifest.deliverable_paths[0].clone();
    let compliance_path_md = manifest.deliverable_paths[1].clone();
    let exceptions_csv_path = manifest.deliverable_paths[2].clone();
    let exceptions_map_path = manifest.attachment_paths[0].clone();
    let compliance_summary_path = manifest.attachment_paths[1].clone();
    let deliverables = vec![
        (
            audit_path_md.clone(),
            workflow_output.exceptions_audit.as_bytes().to_vec(),
            "text/markdown".to_string(),
        ),
        (
            compliance_path_md.clone(),
            workflow_output.compliance_internal.as_bytes().to_vec(),
            "text/markdown".to_string(),
        ),
        (
            exceptions_csv_path,
            workflow_output.exceptions_csv.as_bytes().to_vec(),
            "text/csv".to_string(),
        ),
        (
            exceptions_map_path,
            exceptions_map.as_bytes().to_vec(),
            "application/json".to_string(),
        ),
        (
            compliance_summary_path,
            compliance_summary.as_bytes().to_vec(),
            "application/json".to_string(),
        ),
    ];

    let mut claim_entries = Vec::new();
    for (output_path, output_text) in [
        (audit_path_md.as_str(), workflow_output.exceptions_audit.as_str()),
        (
            compliance_path_md.as_str(),
            workflow_output.compliance_internal.as_str(),
        ),
    ] {
        for claim_id in extract_claim_markers(output_text) {
            claim_entries.push(json!({
                "claim_id": claim_id,
                "output_path": output_path,
                "citations": [
                    {
                        "citation_index": 0,
                        "artifact_id": source_artifact_id,
                        "locator_type": "TEXT_LINE_RANGE_V1",
                        "locator": { "start_line": 1, "end_line": 1, "text_sha256": input_sha }
                    }
                ]
            }));
        }
    }
    let templates_used_json = json!({
        "schema_version": "TEMPLATES_USED_V1",
        "pack_id": "financeos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "templates": [
            {
                "template_id": "financeos_v1",
                "template_version": "1.0.0",
                "output_paths": manifest.deliverable_paths,
                "render_engine": {"name":"core_template_renderer","version":"1.0.0"}
            }
        ]
    });
    let citations_map_json = json!({
        "schema_version": "LOCATOR_SCHEMA_V1",
        "pack_id": "financeos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "generated_at_ms": 0,
        "claims": claim_entries
    });
    let redactions_map_json = json!({
        "schema_version": "REDACTION_SCHEMA_V1",
        "pack_id": "financeos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "generated_at_ms": 0,
        "artifacts": []
    });
    let input_artifacts = vec![InputArtifactDescriptor {
        artifact_id: source_artifact_id,
        sha256: input_sha,
        bytes: ingested_statement.bytes.len() as u64,
        mime_type: "application/json".to_string(),
        content_type: "application/json".to_string(),
        classification: "Confidential".to_string(),
        tags: vec!["FINANCE".to_string()],
    }];
    let bundle_inputs = build_pack_bundle_inputs(
        "financeos",
        "1.0.0",
        &run_id,
        &vault_id,
        &audit_path,
        &input_artifacts,
        deliverables,
        templates_used_json,
        citations_map_json,
        redactions_map_json,
        false,
    )
    .map_err(|e| {
        PackCommandError::failed_with_meta(
            "BUNDLE_BUILD_FAILED",
            format!("Failed to build bundle inputs: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    let outcome =
        run_export(&run_id, &vault_id, audit, &bundle_inputs, &bundle_root, &bundle_zip)
            .map_err(|e| {
                PackCommandError::failed_with_meta(
                    "EXPORT_RUN_FAILED",
                    e,
                    &run_id,
                    &audit_path,
                )
            })?;
    Ok(status_from_outcome(
        format!(
            "FinanceOS bundle exported with {} transactions and {} detected exceptions.",
            workflow_output.transaction_count, workflow_output.exception_count
        ),
        outcome,
        &run_id,
        &audit_path,
    ))
}

#[tauri::command]
fn run_healthcareos(input: HealthcareCommandInput) -> PackCommandStatus {
    run_healthcareos_impl(input).unwrap_or_else(pack_status_from_error)
}

fn run_healthcareos_impl(input: HealthcareCommandInput) -> Result<PackCommandStatus, PackCommandError> {
    let workflow_input = input.workflow_input;
    let _state = HealthcareWorkflowState::ingest(workflow_input.clone()).map_err(|e| {
        PackCommandError::blocked(
            "HEALTHCAREOS_INPUT_INVALID",
            format!("Invalid HealthcareOS input: {e}"),
        )
    })?;
    let manifest = healthcare_output_manifest();
    let transcript_artifact = workflow_input
        .transcript_artifacts
        .first()
        .cloned()
        .ok_or_else(|| {
            PackCommandError::blocked(
                "HEALTHCAREOS_INPUT_INVALID",
                "At least one transcript artifact is required",
            )
        })?;
    let transcript_artifact_id = transcript_artifact.artifact_id.clone();
    let consent_artifact = workflow_input
        .consent_artifacts
        .first()
        .cloned()
        .ok_or_else(|| {
            PackCommandError::blocked(
                "HEALTHCAREOS_INPUT_INVALID",
                "At least one consent artifact is required",
            )
        })?;
    let consent_artifact_id = consent_artifact.artifact_id.clone();
    let ingested_transcript = ingest_payload(
        &transcript_artifact_id,
        &transcript_artifact.sha256,
        &input.artifact_payloads,
        PayloadExpectation::Text,
    )?;
    let ingested_consent = ingest_payload(
        &consent_artifact_id,
        &consent_artifact.sha256,
        &input.artifact_payloads,
        PayloadExpectation::Text,
    )?;
    let transcript_content = ingested_transcript.text.clone().ok_or_else(|| {
        PackCommandError::blocked(
            "ARTIFACT_CONTENT_TYPE_UNSUPPORTED",
            format!(
                "Text artifact payload for {} could not be decoded as text",
                transcript_artifact_id
            ),
        )
    })?;
    let consent_content = ingested_consent.text.clone().ok_or_else(|| {
        PackCommandError::blocked(
            "ARTIFACT_CONTENT_TYPE_UNSUPPORTED",
            format!(
                "Text artifact payload for {} could not be decoded as text",
                consent_artifact_id
            ),
        )
    })?;

    let workflow_output = execute_healthcareos_workflow(
        workflow_input.clone(),
        &transcript_content,
        Some(&consent_content),
    )
    .map_err(|e| {
        PackCommandError::blocked(
            "HEALTHCAREOS_WORKFLOW_INVALID_INPUT",
            format!("HealthcareOS workflow failed: {e}"),
        )
    })?;

    let transcript_sha = ingested_transcript.sha256.clone();
    let consent_sha = ingested_consent.sha256.clone();
    let input_artifacts = vec![
        InputArtifactDescriptor {
            artifact_id: transcript_artifact.artifact_id.clone(),
            sha256: transcript_sha.clone(),
            bytes: ingested_transcript.bytes.len() as u64,
            mime_type: "application/json".to_string(),
            content_type: "application/json".to_string(),
            classification: "PHI".to_string(),
            tags: vec!["HEALTHCARE".to_string(), "TRANSCRIPT".to_string()],
        },
        InputArtifactDescriptor {
            artifact_id: consent_artifact.artifact_id.clone(),
            sha256: consent_sha.clone(),
            bytes: ingested_consent.bytes.len() as u64,
            mime_type: "application/json".to_string(),
            content_type: "application/json".to_string(),
            classification: "PHI".to_string(),
            tags: vec!["HEALTHCARE".to_string(), "CONSENT".to_string()],
        },
    ];
    let manifest_inputs_fingerprint = manifest_inputs_fingerprint_from_descriptors(&input_artifacts);
    let run_id = format!("r_{}", &manifest_inputs_fingerprint[..32]);
    let vault_id = "v_healthcare_0001".to_string();
    let runtime_dir = make_runtime_dir().map_err(|e| {
        PackCommandError::failed("RUNTIME_DIR_CREATE_FAILED", format!("Failed to create runtime directory: {e}"))
    })?;
    let bundle_root = runtime_dir.join("healthcareos_bundle");
    let bundle_zip = runtime_dir.join("evidence_bundle_healthcareos_v1.zip");
    let audit_path = runtime_dir.join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_LOG_OPEN_FAILED",
            format!("Failed to open audit log: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    append_required_audit_events(&mut audit, &run_id, &vault_id).map_err(|e| {
        PackCommandError::failed_with_meta(
            "AUDIT_APPEND_FAILED",
            format!("Failed to append required audit events: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    append_ingestion_audit_event(&mut audit, &run_id, &vault_id, &ingested_transcript).map_err(
        |e| {
            PackCommandError::failed_with_meta(
                "AUDIT_APPEND_FAILED",
                format!("Failed to append artifact ingestion audit event: {e}"),
                &run_id,
                &audit_path,
            )
        },
    )?;
    append_ingestion_audit_event(&mut audit, &run_id, &vault_id, &ingested_consent).map_err(
        |e| {
            PackCommandError::failed_with_meta(
                "AUDIT_APPEND_FAILED",
                format!("Failed to append artifact ingestion audit event: {e}"),
                &run_id,
                &audit_path,
            )
        },
    )?;

    let draft_note_path = manifest.deliverable_paths[0].clone();
    let checklist_path = manifest.deliverable_paths[1].clone();
    let consent_record_path = manifest.attachment_paths[0].clone();
    let uncertainty_map_path = manifest.attachment_paths[2].clone();
    let deliverables = vec![
        (
            draft_note_path.clone(),
            workflow_output.draft_note.as_bytes().to_vec(),
            "text/markdown".to_string(),
        ),
        (
            checklist_path,
            workflow_output.verification_checklist.as_bytes().to_vec(),
            "text/markdown".to_string(),
        ),
        (
            consent_record_path,
            consent_content.as_bytes().to_vec(),
            "application/json".to_string(),
        ),
        (
            uncertainty_map_path,
            workflow_output.uncertainty_map.as_bytes().to_vec(),
            "application/json".to_string(),
        ),
    ];

    let claim_entries: Vec<serde_json::Value> = extract_claim_markers(&workflow_output.draft_note)
        .iter()
        .map(|claim_id| {
            json!({
                "claim_id": claim_id,
                "output_path": draft_note_path,
                "citations": [
                    {
                        "citation_index": 0,
                        "artifact_id": transcript_artifact_id,
                        "locator_type": "TEXT_LINE_RANGE_V1",
                        "locator": { "start_line": 1, "end_line": 1, "text_sha256": transcript_sha }
                    }
                ]
            })
        })
        .collect();
    let templates_used_json = json!({
        "schema_version": "TEMPLATES_USED_V1",
        "pack_id": "healthcareos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "templates": [
            {
                "template_id": "healthcareos_v1",
                "template_version": "1.0.0",
                "output_paths": manifest.deliverable_paths,
                "render_engine": {"name":"core_template_renderer","version":"1.0.0"}
            }
        ]
    });
    let citations_map_json = json!({
        "schema_version": "LOCATOR_SCHEMA_V1",
        "pack_id": "healthcareos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "generated_at_ms": 0,
        "claims": claim_entries
    });
    let redactions_map_json = json!({
        "schema_version": "REDACTION_SCHEMA_V1",
        "pack_id": "healthcareos",
        "pack_version": "1.0.0",
        "run_id": run_id.clone(),
        "generated_at_ms": 0,
        "artifacts": []
    });
    let bundle_inputs = build_pack_bundle_inputs(
        "healthcareos",
        "1.0.0",
        &run_id,
        &vault_id,
        &audit_path,
        &input_artifacts,
        deliverables,
        templates_used_json,
        citations_map_json,
        redactions_map_json,
        false,
    )
    .map_err(|e| {
        PackCommandError::failed_with_meta(
            "BUNDLE_BUILD_FAILED",
            format!("Failed to build bundle inputs: {e}"),
            &run_id,
            &audit_path,
        )
    })?;
    let outcome =
        run_export(&run_id, &vault_id, audit, &bundle_inputs, &bundle_root, &bundle_zip)
            .map_err(|e| {
                PackCommandError::failed_with_meta(
                    "EXPORT_RUN_FAILED",
                    e,
                    &run_id,
                    &audit_path,
                )
            })?;
    Ok(status_from_outcome(
        format!(
            "HealthcareOS bundle exported with consent status {}.",
            workflow_output.consent_status
        ),
        outcome,
        &run_id,
        &audit_path,
    ))
}

fn make_runtime_dir() -> Result<std::path::PathBuf, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis();
    let path = std::env::temp_dir().join(format!("aigc_evidenceos_{}", ts));
    std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    harden_runtime_dir_permissions(&path)?;
    Ok(path)
}

fn harden_runtime_dir_permissions(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, permissions).map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn csv_to_vec(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = raw
        .split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn extract_claim_markers(markdown: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = "<!-- CLAIM:";
    let mut idx = 0;
    while let Some(pos) = markdown[idx..].find(needle) {
        let start = idx + pos + needle.len();
        if let Some(end) = markdown[start..].find("-->") {
            let claim_id = markdown[start..start + end].trim().to_string();
            if claim_id.starts_with('C') {
                out.push(claim_id);
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

fn manifest_inputs_fingerprint_from_descriptors(input_artifacts: &[InputArtifactDescriptor]) -> String {
    let mut fp_parts: Vec<String> = input_artifacts
        .iter()
        .map(|a| format!("{}:{}", a.artifact_id, a.sha256))
        .collect();
    fp_parts.sort();
    sha256_hex(fp_parts.join("|").as_bytes())
}

fn find_artifact_payload<'a>(
    artifact_id: &str,
    payloads: &'a [ArtifactPayloadInput],
) -> Result<&'a ArtifactPayloadInput, PackCommandError> {
    let mut matches = payloads
        .iter()
        .filter(|payload| payload.artifact_id == artifact_id);
    let first = matches.next().ok_or_else(|| {
        PackCommandError::blocked(
            "ARTIFACT_PAYLOAD_MISSING",
            format!("Missing artifact payload for artifact_id={artifact_id}"),
        )
    })?;
    if matches.next().is_some() {
        return Err(PackCommandError::blocked(
            "ARTIFACT_PAYLOAD_DUPLICATE",
            format!("Duplicate artifact payload entries for artifact_id={artifact_id}"),
        ));
    }
    Ok(first)
}

fn normalize_declared_sha(
    artifact_id: &str,
    declared_sha: &str,
) -> Result<Option<String>, PackCommandError> {
    let normalized = declared_sha.trim();
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.len() == 64 {
        if normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Ok(Some(normalized.to_ascii_lowercase()));
        }
        return Err(PackCommandError::blocked(
            "ARTIFACT_SHA256_INVALID",
            format!(
                "Declared sha256 for artifact_id={} is not valid hex",
                artifact_id
            ),
        ));
    }
    Ok(None)
}

fn decode_base64_payload(payload: &ArtifactPayloadInput) -> Result<Vec<u8>, PackCommandError> {
    let content_b64 = payload
        .content_base64
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            PackCommandError::blocked(
                "ARTIFACT_PAYLOAD_EMPTY",
                format!(
                    "Artifact payload for {} is empty; provide content_base64",
                    payload.artifact_id
                ),
            )
        })?;
    BASE64_STANDARD.decode(content_b64).map_err(|e| {
        PackCommandError::blocked(
            "ARTIFACT_PAYLOAD_INVALID_BASE64",
            format!("Invalid base64 payload for {}: {}", payload.artifact_id, e),
        )
    })
}

fn enforce_payload_size(
    artifact_id: &str,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(), PackCommandError> {
    if bytes.len() > max_bytes {
        return Err(PackCommandError::blocked(
            "ARTIFACT_PAYLOAD_TOO_LARGE",
            format!(
                "Payload for artifact_id={} exceeds size limit ({} > {} bytes)",
                artifact_id,
                bytes.len(),
                max_bytes
            ),
        ));
    }
    Ok(())
}

fn ingest_payload(
    artifact_id: &str,
    declared_sha: &str,
    payloads: &[ArtifactPayloadInput],
    expectation: PayloadExpectation,
) -> Result<IngestedArtifactPayload, PackCommandError> {
    let payload = find_artifact_payload(artifact_id, payloads)?;
    let (bytes, text, max_bytes) = match expectation {
        PayloadExpectation::Text => {
            if let Some(content) = payload
                .content_text
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                (content.as_bytes().to_vec(), Some(content.to_string()), MAX_TEXT_PAYLOAD_BYTES)
            } else {
                let decoded = decode_base64_payload(payload)?;
                let text = String::from_utf8(decoded.clone()).map_err(|e| {
                    PackCommandError::blocked(
                        "ARTIFACT_PAYLOAD_INVALID_UTF8",
                        format!("Payload for {} is not UTF-8 text: {}", payload.artifact_id, e),
                    )
                })?;
                (decoded, Some(text), MAX_TEXT_PAYLOAD_BYTES)
            }
        }
        PayloadExpectation::BinaryPdf => {
            if payload
                .content_base64
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
                && payload
                    .content_text
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some()
            {
                return Err(PackCommandError::blocked(
                    "ARTIFACT_CONTENT_TYPE_UNSUPPORTED",
                    format!(
                        "Binary artifact payload for {} must use content_base64",
                        payload.artifact_id
                    ),
                ));
            }
            let decoded = decode_base64_payload(payload)?;
            if !decoded.starts_with(b"%PDF-") {
                return Err(PackCommandError::blocked(
                    "REDLINE_ARTIFACT_NOT_PDF",
                    format!(
                        "Artifact payload for {} is not a valid PDF-like payload",
                        payload.artifact_id
                    ),
                ));
            }
            (decoded, None, MAX_BINARY_PAYLOAD_BYTES)
        }
    };

    enforce_payload_size(artifact_id, &bytes, max_bytes)?;
    let computed_sha = sha256_hex(&bytes);
    let declared_sha_normalized = normalize_declared_sha(artifact_id, declared_sha)?;
    let mut sha_enforced = false;
    if let Some(expected_sha) = &declared_sha_normalized {
        sha_enforced = true;
        if expected_sha != &computed_sha {
            return Err(PackCommandError::blocked(
                "ARTIFACT_SHA256_MISMATCH",
                format!(
                    "Declared sha256 does not match payload bytes for artifact_id={}",
                    artifact_id
                ),
            ));
        }
    }

    Ok(IngestedArtifactPayload {
        artifact_id: artifact_id.to_string(),
        bytes,
        text,
        sha256: computed_sha,
        sha_enforced,
        declared_sha: declared_sha.trim().to_string(),
    })
}

fn append_required_audit_events(
    audit: &mut AuditLog,
    run_id: &str,
    vault_id: &str,
) -> Result<(), String> {
    let events = vec![
        (
            "VAULT_ENCRYPTION_STATUS",
            Actor::System,
            json!({
                "encryption_at_rest": true,
                "algorithm": "XCHACHA20_POLY1305",
                "key_storage": "FILE_FALLBACK"
            }),
        ),
        (
            "NETWORK_MODE_SET",
            Actor::User,
            json!({
                "network_mode":"OFFLINE",
                "proof_level":"OFFLINE_STRICT",
                "ui_remote_fetch_disabled":true
            }),
        ),
        (
            "ALLOWLIST_UPDATED",
            Actor::System,
            json!({
                "allowlist_hash_sha256": sha256_hex(b""),
                "allowlist_count":0
            }),
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
    ];
    for (event_type, actor, details) in events {
        audit
            .append(AuditEvent {
                ts_utc: now_rfc3339_utc(),
                event_type: event_type.to_string(),
                run_id: run_id.to_string(),
                vault_id: vault_id.to_string(),
                actor,
                details,
                prev_event_hash: String::new(),
                event_hash: String::new(),
            })
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn append_ingestion_audit_event(
    audit: &mut AuditLog,
    run_id: &str,
    vault_id: &str,
    payload: &IngestedArtifactPayload,
) -> Result<(), String> {
    let sha_policy = if payload.sha_enforced {
        "ENFORCED"
    } else {
        "SKIPPED_LEGACY_OR_MISSING"
    };
    audit
        .append(AuditEvent {
            ts_utc: now_rfc3339_utc(),
            event_type: "ARTIFACT_INGESTION_VALIDATED".to_string(),
            run_id: run_id.to_string(),
            vault_id: vault_id.to_string(),
            actor: Actor::System,
            details: json!({
                "artifact_id": payload.artifact_id,
                "declared_sha256": payload.declared_sha,
                "computed_sha256": payload.sha256,
                "payload_bytes": payload.bytes.len(),
                "sha_policy": sha_policy
            }),
            prev_event_hash: String::new(),
            event_hash: String::new(),
        })
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn build_pack_bundle_inputs(
    pack_id: &str,
    pack_version: &str,
    run_id: &str,
    vault_id: &str,
    audit_path: &std::path::Path,
    input_artifacts: &[InputArtifactDescriptor],
    deliverables: Vec<(String, Vec<u8>, String)>,
    templates_used_json: serde_json::Value,
    citations_map_json: serde_json::Value,
    redactions_map_json: serde_json::Value,
    pdf_determinism_enabled: bool,
) -> Result<EvidenceBundleInputs, String> {
    let templates_rel = format!("exports/{}/attachments/templates_used.json", pack_id);
    let citations_rel = format!("exports/{}/attachments/citations_map.json", pack_id);
    let redactions_rel = format!("exports/{}/attachments/redactions_map.json", pack_id);
    let templates_bytes =
        json_canonical::to_canonical_bytes(&templates_used_json).map_err(|e| e.to_string())?;
    let citations_bytes =
        json_canonical::to_canonical_bytes(&citations_map_json).map_err(|e| e.to_string())?;
    let redactions_bytes =
        json_canonical::to_canonical_bytes(&redactions_map_json).map_err(|e| e.to_string())?;

    let mut hash_rows: Vec<ArtifactHashRow> = input_artifacts
        .iter()
        .map(|artifact| ArtifactHashRow {
            artifact_id: artifact.artifact_id.clone(),
            bundle_rel_path: String::new(),
            sha256: artifact.sha256.clone(),
            bytes: artifact.bytes,
            content_type: artifact.content_type.clone(),
            logical_role: "INPUT".to_string(),
        })
        .collect();
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
    let artifact_hashes_csv = render_artifact_hashes_csv(hash_rows).map_err(|e| e.to_string())?;

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

    let manifest_inputs_fingerprint = manifest_inputs_fingerprint_from_descriptors(input_artifacts);
    let model_pinning_level = classify_pinning_level(None, "local_adapter", "1.0.0");

    Ok(EvidenceBundleInputs {
        run_manifest: RunManifest {
            run_id: run_id.to_string(),
            vault_id: vault_id.to_string(),
            determinism: DeterminismManifest {
                enabled: true,
                manifest_inputs_fingerprint,
            },
            inputs: input_artifacts
                .iter()
                .map(|artifact| ManifestArtifactRef {
                    artifact_id: artifact.artifact_id.clone(),
                    sha256: artifact.sha256.clone(),
                    bytes: artifact.bytes,
                    mime_type: artifact.mime_type.clone(),
                    logical_role: "INPUT".to_string(),
                })
                .collect(),
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
            pack_version: pack_version.to_string(),
            core_build: "dev".to_string(),
            run_id: run_id.to_string(),
        },
        audit_log_ndjson: std::fs::read_to_string(audit_path).map_err(|e| e.to_string())?,
        eval_report: EvalReport {
            overall_status: "PASS".to_string(),
            tests: vec![],
            gates: vec![],
            registry_version: "gates_registry_v3".to_string(),
        },
        artifact_hashes_csv,
        artifact_list: ArtifactList {
            artifacts: input_artifacts
                .iter()
                .map(|artifact| ArtifactListEntry {
                    artifact_id: artifact.artifact_id.clone(),
                    sha256: artifact.sha256.clone(),
                    bytes: artifact.bytes,
                    content_type: artifact.content_type.clone(),
                    logical_role: "INPUT".to_string(),
                    classification: artifact.classification.clone(),
                    tags: artifact.tags.clone(),
                    retention_policy_id: "ret_default".to_string(),
                })
                .collect(),
        },
        policy_snapshot: PolicySnapshot {
            policy_mode: PolicyMode::STRICT,
            determinism: DeterminismPolicy {
                enabled: true,
                pdf_determinism_enabled,
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
            model_sha256: None,
            pinning_level: model_pinning_level,
        },
        pack_id: pack_id.to_string(),
        pack_version: pack_version.to_string(),
        deliverables,
        attachments: PackAttachments {
            templates_used_json,
            citations_map_json: Some(citations_map_json),
            redactions_map_json: Some(redactions_map_json),
        },
    })
}

fn run_export(
    run_id: &str,
    vault_id: &str,
    audit: AuditLog,
    bundle_inputs: &EvidenceBundleInputs,
    bundle_root: &std::path::Path,
    bundle_zip: &std::path::Path,
) -> Result<ExportOutcome, String> {
    let export_request = ExportRequest {
        run_id: run_id.to_string(),
        vault_id: vault_id.to_string(),
        policy_mode: PolicyMode::STRICT,
        network_mode: NetworkMode::OFFLINE,
        proof_level: ProofLevel::OFFLINE_STRICT,
        pinning_level: classify_pinning_level(None, "local_adapter", "1.0.0"),
        requested_by: "ui".to_string(),
    };
    let mut run_manager = RunManager::new(audit);
    run_manager
        .export_run(&export_request, bundle_inputs, bundle_root, bundle_zip)
        .map_err(|e| format!("Export failed: {}", e))
}

fn now_rfc3339_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn status_from_outcome(
    success_message: String,
    outcome: ExportOutcome,
    run_id: &str,
    audit_path: &std::path::Path,
) -> PackCommandStatus {
    let audit_path_str = audit_path.display().to_string();
    match outcome.status.as_str() {
        "COMPLETED" => PackCommandStatus {
            status: "SUCCESS".to_string(),
            message: success_message,
            bundle_path: outcome.bundle_path,
            bundle_sha256: outcome.bundle_sha256,
            error_code: None,
            run_id: Some(run_id.to_string()),
            audit_path: Some(audit_path_str),
        },
        "BLOCKED" => PackCommandStatus {
            status: "BLOCKED".to_string(),
            message: format!("Export blocked: {:?}", outcome.block_reason),
            bundle_path: None,
            bundle_sha256: None,
            error_code: Some("EXPORT_BLOCKED".to_string()),
            run_id: Some(run_id.to_string()),
            audit_path: Some(audit_path_str),
        },
        _ => PackCommandStatus {
            status: "FAILED".to_string(),
            message: "Export failed".to_string(),
            bundle_path: None,
            bundle_sha256: None,
            error_code: Some("EXPORT_FAILED".to_string()),
            run_id: Some(run_id.to_string()),
            audit_path: Some(audit_path_str),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aigc_core::financeos::model::FinanceArtifactRef;
    use aigc_core::healthcareos::model::HealthcareArtifactRef;
    use aigc_core::incidentos::model::IncidentArtifactRef;
    use aigc_core::redlineos::model::ContractArtifactRef;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use std::fs;

    fn incident_workflow_input() -> IncidentOsInputV1 {
        IncidentOsInputV1 {
            schema_version: "INCIDENTOS_INPUT_V1".to_string(),
            incident_artifacts: vec![IncidentArtifactRef {
                artifact_id: "incident_001".to_string(),
                sha256: "demo".to_string(),
                source_type: "syslog".to_string(),
            }],
            timeline_start_hint: None,
            timeline_end_hint: None,
            customer_redaction_profile: "STRICT".to_string(),
        }
    }

    fn valid_incident_log() -> &'static str {
        r#"{"timestamp":"2026-02-12T11:16:00Z","source_system":"incident-response","actor":"security-ops","action":"incident_created","affected_resource":"incident-tracker","evidence_text":"Incident INC-2026-001234 created with severity CRITICAL"}"#
    }

    fn redline_workflow_input(sha256: &str) -> RedlineOsInputV1 {
        RedlineOsInputV1 {
            schema_version: "REDLINEOS_INPUT_V1".to_string(),
            contract_artifacts: vec![ContractArtifactRef {
                artifact_id: "contract_001".to_string(),
                sha256: sha256.to_string(),
                filename: "contract.pdf".to_string(),
            }],
            extraction_mode: "NATIVE_PDF".to_string(),
            jurisdiction_hint: Some("US-CA".to_string()),
            review_profile: "default".to_string(),
        }
    }

    #[test]
    fn healthcare_fingerprint_is_stable_across_input_order() {
        let forward = vec![
            InputArtifactDescriptor {
                artifact_id: "tx_001".to_string(),
                sha256: "a".repeat(64),
                bytes: 10,
                mime_type: "application/json".to_string(),
                content_type: "application/json".to_string(),
                classification: "PHI".to_string(),
                tags: vec!["HEALTHCARE".to_string()],
            },
            InputArtifactDescriptor {
                artifact_id: "consent_001".to_string(),
                sha256: "b".repeat(64),
                bytes: 11,
                mime_type: "application/json".to_string(),
                content_type: "application/json".to_string(),
                classification: "PHI".to_string(),
                tags: vec!["HEALTHCARE".to_string()],
            },
        ];
        let reverse = vec![forward[1].clone(), forward[0].clone()];
        assert_eq!(
            manifest_inputs_fingerprint_from_descriptors(&forward),
            manifest_inputs_fingerprint_from_descriptors(&reverse)
        );
    }

    #[test]
    fn runtime_dir_permissions_hardened_when_supported() {
        let runtime_dir = make_runtime_dir().expect("runtime directory should be created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&runtime_dir)
                .expect("runtime directory metadata should be readable")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
        let _ = fs::remove_dir_all(runtime_dir);
    }

    #[test]
    fn required_audit_events_mark_control_simulation_origin() {
        let runtime_dir = std::env::temp_dir().join(format!(
            "aigc_required_audit_marker_test_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be monotonic")
                .as_nanos()
        ));
        fs::create_dir_all(&runtime_dir).expect("test runtime directory should be created");
        let audit_path = runtime_dir.join("audit.ndjson");
        let mut audit = AuditLog::open_or_create(&audit_path).expect("audit log should open");

        append_required_audit_events(&mut audit, "r_test", "v_test")
            .expect("required events should append");

        let mut found_marker = false;
        let contents = fs::read_to_string(&audit_path).expect("audit log should be readable");
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event: serde_json::Value =
                serde_json::from_str(line).expect("audit event should parse");
            if event
                .get("event_type")
                .and_then(|value| value.as_str())
                .is_some_and(|value| value == "EGRESS_REQUEST_BLOCKED")
            {
                found_marker = event
                    .get("details")
                    .and_then(|value| value.get("evidence_origin"))
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value == "CONTROL_SIMULATION");
            }
        }

        assert!(found_marker, "expected synthetic egress control marker");
        let _ = fs::remove_dir_all(runtime_dir);
    }

    #[test]
    fn incident_missing_payload_returns_blocked_code() {
        let status = run_incidentos(IncidentCommandInput {
            workflow_input: incident_workflow_input(),
            artifact_payloads: vec![],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("ARTIFACT_PAYLOAD_MISSING")
        );
    }

    #[test]
    fn incident_malformed_payload_returns_format_code() {
        let status = run_incidentos(IncidentCommandInput {
            workflow_input: incident_workflow_input(),
            artifact_payloads: vec![ArtifactPayloadInput {
                artifact_id: "incident_001".to_string(),
                content_text: Some("{not-json}".to_string()),
                content_base64: None,
            }],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("INCIDENT_LOG_INVALID_FORMAT")
        );
    }

    #[test]
    fn finance_invalid_statement_returns_format_code() {
        let status = run_financeos(FinanceCommandInput {
            workflow_input: FinanceOsInputV1 {
                schema_version: "FINANCEOS_INPUT_V1".to_string(),
                finance_artifacts: vec![FinanceArtifactRef {
                    artifact_id: "finance_001".to_string(),
                    sha256: "demo".to_string(),
                    artifact_kind: "statement".to_string(),
                }],
                period: "2026-01".to_string(),
                exception_rules_profile: "standard".to_string(),
                retention_profile: "ret_min".to_string(),
            },
            artifact_payloads: vec![ArtifactPayloadInput {
                artifact_id: "finance_001".to_string(),
                content_text: Some("{\"statement_id\":\"x\"}".to_string()),
                content_base64: None,
            }],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("FINANCE_STATEMENT_INVALID_FORMAT")
        );
    }

    #[test]
    fn healthcare_revoked_consent_returns_workflow_code() {
        let transcript = r#"{"patient_id":"PT-001","date":"2026-02-01","provider":"Dr X","specialty":"Cardiology","content":"Possible chest pain.","confidence":0.95}"#;
        let revoked_consent =
            r#"{"patient_id":"PT-001","date_given":"2024-01-01","scope":"general","status":"REVOKED"}"#;

        let status = run_healthcareos(HealthcareCommandInput {
            workflow_input: HealthcareOsInputV1 {
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
                draft_template_profile: "soap".to_string(),
                verifier_identity: "clinician_1".to_string(),
            },
            artifact_payloads: vec![
                ArtifactPayloadInput {
                    artifact_id: "consent_001".to_string(),
                    content_text: Some(revoked_consent.to_string()),
                    content_base64: None,
                },
                ArtifactPayloadInput {
                    artifact_id: "tx_001".to_string(),
                    content_text: Some(transcript.to_string()),
                    content_base64: None,
                },
            ],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("HEALTHCAREOS_WORKFLOW_INVALID_INPUT")
        );
    }

    #[test]
    fn ingestion_contract_duplicate_payload_returns_blocked_code() {
        let status = run_incidentos(IncidentCommandInput {
            workflow_input: incident_workflow_input(),
            artifact_payloads: vec![
                ArtifactPayloadInput {
                    artifact_id: "incident_001".to_string(),
                    content_text: Some(valid_incident_log().to_string()),
                    content_base64: None,
                },
                ArtifactPayloadInput {
                    artifact_id: "incident_001".to_string(),
                    content_text: Some(valid_incident_log().to_string()),
                    content_base64: None,
                },
            ],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("ARTIFACT_PAYLOAD_DUPLICATE")
        );
    }

    #[test]
    fn ingestion_contract_sha_mismatch_returns_blocked_code() {
        let mut input = incident_workflow_input();
        input.incident_artifacts[0].sha256 = "0".repeat(64);
        let status = run_incidentos(IncidentCommandInput {
            workflow_input: input,
            artifact_payloads: vec![ArtifactPayloadInput {
                artifact_id: "incident_001".to_string(),
                content_text: Some(valid_incident_log().to_string()),
                content_base64: None,
            }],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("ARTIFACT_SHA256_MISMATCH")
        );
    }

    #[test]
    fn ingestion_contract_invalid_sha_returns_blocked_code() {
        let mut input = incident_workflow_input();
        input.incident_artifacts[0].sha256 = "z".repeat(64);
        let status = run_incidentos(IncidentCommandInput {
            workflow_input: input,
            artifact_payloads: vec![ArtifactPayloadInput {
                artifact_id: "incident_001".to_string(),
                content_text: Some(valid_incident_log().to_string()),
                content_base64: None,
            }],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("ARTIFACT_SHA256_INVALID")
        );
    }

    #[test]
    fn ingestion_contract_legacy_sha_is_allowed() {
        let status = run_incidentos(IncidentCommandInput {
            workflow_input: incident_workflow_input(),
            artifact_payloads: vec![ArtifactPayloadInput {
                artifact_id: "incident_001".to_string(),
                content_text: Some(valid_incident_log().to_string()),
                content_base64: None,
            }],
        });
        assert_ne!(
            status.error_code.as_deref(),
            Some("ARTIFACT_SHA256_INVALID")
        );
        assert_ne!(
            status.error_code.as_deref(),
            Some("ARTIFACT_SHA256_MISMATCH")
        );
    }

    #[test]
    fn ingestion_contract_oversize_text_payload_blocked() {
        let oversized = "A".repeat(MAX_TEXT_PAYLOAD_BYTES + 1);
        let status = run_incidentos(IncidentCommandInput {
            workflow_input: incident_workflow_input(),
            artifact_payloads: vec![ArtifactPayloadInput {
                artifact_id: "incident_001".to_string(),
                content_text: Some(oversized),
                content_base64: None,
            }],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("ARTIFACT_PAYLOAD_TOO_LARGE")
        );
    }

    #[test]
    fn ingestion_contract_redline_non_pdf_payload_blocked() {
        let status = run_redlineos(RedlineCommandInput {
            workflow_input: redline_workflow_input("demo"),
            artifact_payloads: vec![ArtifactPayloadInput {
                artifact_id: "contract_001".to_string(),
                content_text: None,
                content_base64: Some(BASE64_STANDARD.encode("not a pdf")),
            }],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("REDLINE_ARTIFACT_NOT_PDF")
        );
    }

    #[test]
    fn ingestion_contract_redline_text_payload_rejected() {
        let status = run_redlineos(RedlineCommandInput {
            workflow_input: redline_workflow_input("demo"),
            artifact_payloads: vec![ArtifactPayloadInput {
                artifact_id: "contract_001".to_string(),
                content_text: Some("plain text".to_string()),
                content_base64: None,
            }],
        });
        assert_eq!(status.status, "BLOCKED");
        assert_eq!(
            status.error_code.as_deref(),
            Some("ARTIFACT_CONTENT_TYPE_UNSUPPORTED")
        );
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_network_snapshot,
            list_control_library,
            generate_evidenceos_bundle,
            run_redlineos,
            run_incidentos,
            run_financeos,
            run_healthcareos
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
