use aigc_core::adapters::pinning::{classify_pinning_level, ModelSnapshot};
use aigc_core::audit::event::{Actor, AuditEvent};
use aigc_core::audit::log::AuditLog;
use aigc_core::determinism::run_id::sha256_hex;
use aigc_core::eval::runner::EvalRunner;
use aigc_core::evidence_bundle::artifact_hashes::{render_artifact_hashes_csv, ArtifactHashRow};
use aigc_core::evidence_bundle::authority::EvidenceAuthorityManifest;
use aigc_core::evidence_bundle::builder::EvidenceBundleBuilder;
use aigc_core::evidence_bundle::schemas::*;
use aigc_core::evidenceos::model::{CitationInput, EvidenceItem, NarrativeClaimInput};
use aigc_core::evidenceos::workflow::{generate_evidenceos_artifacts, EvidenceOsRequest};
use aigc_core::policy::allowlist::AllowlistEntry;
use aigc_core::policy::network_snapshot::{AdapterEndpointSnapshot, NetworkSnapshot};
use aigc_core::policy::types::{InputExportProfile, NetworkMode, PolicyMode, ProofLevel};
use aigc_core::run::lifecycle::{emit_vault_encryption_status, emit_vault_key_rotated};
use aigc_core::storage::crypto::EncryptionAlgorithm;
use aigc_core::storage::vault::{VaultConfig, VaultStorage};
use aigc_core::validator::BundleValidator;
use serde_json::json;
use std::path::PathBuf;

fn controlled_gate_authority(run_id: &str, producer: &str) -> EvidenceAuthorityManifest {
    EvidenceAuthorityManifest::controlled_simulation(
        run_id,
        producer,
        "gate-runner-revision",
        "gate-runner",
        sha256_hex(b"gate-runner"),
        sha256_hex(b"gate-runner-arguments"),
        sha256_hex(b"gate-runner-environment"),
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
    )
}

fn main() {
    // Phase 2: gate_runner generates a deterministic self-audit Evidence Bundle and runs:
    // 1) bundle validator checklist v3
    // 2) eval runner gate mapping (stable IDs)
    //
    // It prints stable gate IDs with PASS/FAIL and exits non-zero on any BLOCKER fail.
    let policy = PolicyMode::STRICT;

    let tmp = tempfile::tempdir().expect("tempdir");
    let self_audit_ok = run_pack_validation_cycle(
        "SELF_AUDIT",
        &tmp.path().join("bundle_root"),
        &tmp.path().join("bundle_root_2"),
        &tmp.path().join("evidence_bundle_self_audit_v1.zip"),
        &tmp.path().join("evidence_bundle_self_audit_v1_2.zip"),
        make_self_audit_inputs(&tmp.path().join("bundle_root"), policy),
        make_self_audit_inputs(&tmp.path().join("bundle_root_2"), policy),
        policy,
    );

    let evidenceos_ok = run_pack_validation_cycle(
        "EVIDENCEOS",
        &tmp.path().join("evidenceos_bundle_root"),
        &tmp.path().join("evidenceos_bundle_root_2"),
        &tmp.path().join("evidence_bundle_evidenceos_v1.zip"),
        &tmp.path().join("evidence_bundle_evidenceos_v1_2.zip"),
        make_evidenceos_inputs(policy),
        make_evidenceos_inputs(policy),
        policy,
    );

    if !self_audit_ok || !evidenceos_ok {
        std::process::exit(1);
    }
}

fn run_pack_validation_cycle(
    label: &str,
    bundle_root: &PathBuf,
    bundle_root_2: &PathBuf,
    bundle_zip: &PathBuf,
    bundle_zip_2: &PathBuf,
    inputs: EvidenceBundleInputs,
    inputs_2: EvidenceBundleInputs,
    policy: PolicyMode,
) -> bool {
    EvidenceBundleBuilder::build_dir(bundle_root, &inputs).expect("build bundle dir");
    let zip_sha256 = EvidenceBundleBuilder::build_zip(bundle_root, bundle_zip).expect("zip bundle");
    EvidenceBundleBuilder::build_dir(bundle_root_2, &inputs_2).expect("build bundle dir 2");
    let zip_sha256_2 =
        EvidenceBundleBuilder::build_zip(bundle_root_2, bundle_zip_2).expect("zip bundle 2");
    if zip_sha256 != zip_sha256_2 {
        eprintln!(
            "{} DETERMINISM_EXPORT_BYTE_STABILITY FAIL (sha256 {} != {})",
            label, zip_sha256, zip_sha256_2
        );
        return false;
    }

    let validator = BundleValidator::new_v3();
    let summary = validator
        .validate_zip(bundle_zip, policy)
        .expect("validate zip");
    println!(
        "{} BUNDLE_VALIDATOR overall={} sha256={}",
        label, summary.overall, zip_sha256
    );
    for c in &summary.checks {
        println!("{} CHECK {} {} {}", label, c.check_id, c.result, c.message);
    }

    let eval = EvalRunner::new_v3().expect("registry v3");
    let gate_results = eval
        .run_all_for_bundle(bundle_zip, policy)
        .expect("run gates");
    let mut any_blocker_fail = false;
    for g in &gate_results {
        println!("{} GATE {} {} {}", label, g.gate_id, g.result, g.message);
        if g.severity == "BLOCKER" && g.result != "PASS" && g.result != "NOT_APPLICABLE" {
            any_blocker_fail = true;
        }
    }
    !any_blocker_fail && summary.overall == "PASS"
}

fn make_self_audit_inputs(bundle_root: &PathBuf, policy_mode: PolicyMode) -> EvidenceBundleInputs {
    // Determinism enabled self-audit.
    let determinism_enabled = true;

    // One fake input artifact (HASH_ONLY export profile, so no bytes included)
    let input_bytes = b"hello evidence";
    let input_sha = sha256_hex(input_bytes);
    let artifact_id = "a_0001".to_string();

    let manifest_inputs_fingerprint =
        sha256_hex(format!("{}:{}", artifact_id, input_sha).as_bytes());
    let run_id = aigc_core::determinism::run_id::run_id_from_manifest_inputs_fingerprint_hex32(
        &manifest_inputs_fingerprint,
    )
    .expect("run_id from fingerprint");

    let vault_id = "v_0001".to_string();
    let pack_id = "self_audit".to_string();
    let pack_version = "0.0.0".to_string();

    // Create encrypted vault to anchor crypto status + key rotation events.
    let mut vault = VaultStorage::create(
        bundle_root
            .parent()
            .unwrap_or(bundle_root)
            .join("runtime_vault"),
        VaultConfig {
            vault_id: vault_id.clone(),
            encryption_algorithm: EncryptionAlgorithm::XCHACHA20_POLY1305,
            encryption_at_rest: true,
        },
    )
    .expect("create vault");
    vault
        .write_blob("in_1", input_bytes)
        .expect("write encrypted blob");
    vault
        .write_sqlite_bytes(b"sqlite-db")
        .expect("write encrypted sqlite bytes");

    // Audit log with required events.
    let audit_path = bundle_root.join("audit_log.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).expect("audit log open");
    emit_vault_encryption_status(&mut audit, &run_id, &vault_id, &vault, &fixed_ts())
        .expect("emit vault encryption status");
    let rotation = vault.rotate_dek("kek_v2").expect("rotate dek");
    emit_vault_key_rotated(
        &mut audit,
        &run_id,
        &vault_id,
        rotation
            .get("old_key_id")
            .and_then(|x| x.as_str())
            .unwrap_or("kek_v1"),
        rotation
            .get("new_key_id")
            .and_then(|x| x.as_str())
            .unwrap_or("kek_v2"),
        &fixed_ts(),
    )
    .expect("emit key rotated");

    let _ = audit
        .append(AuditEvent {
            ts_utc: fixed_ts(),
            event_type: "NETWORK_MODE_SET".to_string(),
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            actor: Actor::User,
            details: json!({
                "network_mode": "OFFLINE",
                "proof_level": "OFFLINE_STRICT",
                "ui_remote_fetch_disabled": true
            }),
            prev_event_hash: "".to_string(),
            event_hash: "".to_string(),
        })
        .unwrap();
    let _ = audit
        .append(AuditEvent {
            ts_utc: fixed_ts(),
            event_type: "ALLOWLIST_UPDATED".to_string(),
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            actor: Actor::System,
            details: json!({
                "allowlist_hash_sha256": sha256_hex(b""),
                "allowlist_count": 0
            }),
            prev_event_hash: "".to_string(),
            event_hash: "".to_string(),
        })
        .unwrap();
    let _ = audit
        .append(AuditEvent {
            ts_utc: fixed_ts(),
            event_type: "EGRESS_REQUEST_BLOCKED".to_string(),
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            actor: Actor::System,
            details: json!({
                "destination": {
                    "scheme": "https",
                    "host": "example.invalid",
                    "port": 443,
                    "path": "/blocked"
                },
                "block_reason": "OFFLINE_MODE",
                "request_hash_sha256": sha256_hex(b"blocked_request"),
                "evidence_origin": "CONTROL_SIMULATION"
            }),
            prev_event_hash: "".to_string(),
            event_hash: "".to_string(),
        })
        .unwrap();

    let audit_log_ndjson = std::fs::read_to_string(&audit_path).unwrap();

    // Network snapshot required fields
    let allowlist: Vec<AllowlistEntry> = Vec::new();
    let network_snapshot = NetworkSnapshot {
        network_mode: NetworkMode::OFFLINE,
        proof_level: ProofLevel::OFFLINE_STRICT,
        allowlist,
        ui_remote_fetch_disabled: true,
        adapter_endpoints: vec![AdapterEndpointSnapshot {
            endpoint: "http://127.0.0.1:1234".to_string(),
            is_loopback: true,
            validation_error: None,
        }],
    };

    let model_sha256 = Some(sha256_hex(b"dummy_model_snapshot"));
    let pin = classify_pinning_level(model_sha256.as_deref(), "local_adapter", "1.0.0");
    let model_snapshot = ModelSnapshot {
        adapter_id: "local_adapter".to_string(),
        adapter_version: "1.0.0".to_string(),
        adapter_endpoint: "http://127.0.0.1:1234".to_string(),
        model_id: "dummy-model".to_string(),
        model_sha256,
        pinning_level: pin,
    };

    let policy_snapshot = PolicySnapshot {
        policy_mode,
        determinism: DeterminismPolicy {
            enabled: determinism_enabled,
            pdf_determinism_enabled: false,
        },
        export_profile: ExportProfile {
            inputs: InputExportProfile::HASH_ONLY,
        },
        encryption_at_rest: true,
        encryption_algorithm: "XCHACHA20_POLY1305".to_string(),
    };

    let artifact_list = ArtifactList {
        artifacts: vec![ArtifactListEntry {
            artifact_id: artifact_id.clone(),
            sha256: input_sha.clone(),
            bytes: input_bytes.len() as u64,
            content_type: "text/plain".to_string(),
            logical_role: "INPUT".to_string(),
            classification: "Restricted".to_string(),
            tags: vec!["PII".to_string()],
            retention_policy_id: "ret_default".to_string(),
        }],
    };

    // One deliverable markdown with claim marker + citations map for strict.
    let deliverable_rel = format!("exports/{}/deliverables/report.md", pack_id);
    let deliverable_md = "<!-- CLAIM:C0001 -->\nThis is a claim.\n"
        .as_bytes()
        .to_vec();
    let deliverable_sha = sha256_hex(&deliverable_md);

    let citations_map = json!({
    "schema_version": "LOCATOR_SCHEMA_V1",
    "pack_id": pack_id,
    "pack_version": pack_version,
    "run_id": run_id,
    "generated_at_ms": 0,
    "claims": [
        {
                "claim_id": "C0001",
                "output_path": deliverable_rel,
                "output_claim_locator": {
                    "locator_type": "TEXT_LINE_RANGE_V1",
                    "locator": { "start_line": 1, "end_line": 2, "text_sha256": sha256_hex(b"This is a claim.\n") }
                },
                "citations": [
                    { "citation_index": 0, "artifact_id": artifact_id, "locator_type": "PDF_TEXT_SPAN_V1", "locator": { "page_index": 0, "start_char": 0, "end_char": 12, "text_sha256": sha256_hex(b"hello evidence") } }
                ]
            }
        ]
    });

    let redactions_map = json!({
        "schema_version": "REDACTION_SCHEMA_V1",
        "pack_id": pack_id,
        "pack_version": pack_version,
        "run_id": run_id,
        "generated_at_ms": 0,
        "artifacts": [
            {
                "artifact_id": artifact_id,
                "redactions": [
                    { "redaction_id": "R0001", "redaction_type": "TEXT_SPAN", "region": { "start_char": 0, "end_char": 12, "text_sha256": input_sha }, "method": "MASK", "reason": "PII", "policy_rule_id": "rule_1" }
                ]
            }
        ]
    });

    let templates_used = json!({
        "schema_version": "TEMPLATES_USED_V1",
        "pack_id": pack_id,
        "pack_version": pack_version,
        "run_id": run_id,
        "templates": [
            {
                "template_id": "report_md",
                "template_version": "1.0.0",
                "output_paths": [deliverable_rel],
                "render_engine": { "name": "core_template_renderer", "version": "0.0.0" }
            }
        ]
    });

    // artifact_hashes.csv must include INPUT entries even in HASH_ONLY (bundle_rel_path can be empty for inputs)
    // plus output entries with paths inside the zip.
    let templates_rel = format!("exports/{}/attachments/templates_used.json", pack_id);
    let citations_rel = format!("exports/{}/attachments/citations_map.json", pack_id);
    let redactions_rel = format!("exports/{}/attachments/redactions_map.json", pack_id);
    let templates_bytes =
        aigc_core::determinism::json_canonical::to_canonical_bytes(&templates_used).unwrap();
    let citations_bytes =
        aigc_core::determinism::json_canonical::to_canonical_bytes(&citations_map).unwrap();
    let redactions_bytes =
        aigc_core::determinism::json_canonical::to_canonical_bytes(&redactions_map).unwrap();
    let csv_sorted = render_artifact_hashes_csv(vec![
        ArtifactHashRow {
            artifact_id: "a_0001".to_string(),
            bundle_rel_path: "".to_string(),
            sha256: input_sha.clone(),
            bytes: input_bytes.len() as u64,
            content_type: "text/plain".to_string(),
            logical_role: "INPUT".to_string(),
        },
        ArtifactHashRow {
            artifact_id: format!("o:{}", deliverable_rel),
            bundle_rel_path: deliverable_rel.clone(),
            sha256: deliverable_sha.clone(),
            bytes: deliverable_md.len() as u64,
            content_type: "text/markdown".to_string(),
            logical_role: "DELIVERABLE".to_string(),
        },
        ArtifactHashRow {
            artifact_id: format!("o:{}", citations_rel),
            bundle_rel_path: citations_rel.clone(),
            sha256: sha256_hex(&citations_bytes),
            bytes: citations_bytes.len() as u64,
            content_type: "application/json".to_string(),
            logical_role: "ATTACHMENT".to_string(),
        },
        ArtifactHashRow {
            artifact_id: format!("o:{}", redactions_rel),
            bundle_rel_path: redactions_rel.clone(),
            sha256: sha256_hex(&redactions_bytes),
            bytes: redactions_bytes.len() as u64,
            content_type: "application/json".to_string(),
            logical_role: "ATTACHMENT".to_string(),
        },
        ArtifactHashRow {
            artifact_id: format!("o:{}", templates_rel),
            bundle_rel_path: templates_rel.clone(),
            sha256: sha256_hex(&templates_bytes),
            bytes: templates_bytes.len() as u64,
            content_type: "application/json".to_string(),
            logical_role: "ATTACHMENT".to_string(),
        },
    ])
    .unwrap();

    let bundle_info = BundleInfo {
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
    };

    let run_manifest = RunManifest {
        run_id: run_id.clone(),
        vault_id: vault_id.clone(),
        evidence_authority: controlled_gate_authority(&run_id, "gate-runner:self-audit"),
        determinism: DeterminismManifest {
            enabled: determinism_enabled,
            manifest_inputs_fingerprint: manifest_inputs_fingerprint.clone(),
        },
        inputs: vec![ManifestArtifactRef {
            artifact_id: "a_0001".to_string(),
            sha256: input_sha.clone(),
            bytes: input_bytes.len() as u64,
            mime_type: "text/plain".to_string(),
            logical_role: "INPUT".to_string(),
        }],
        outputs: vec![ManifestOutputRef {
            path: deliverable_rel.clone(),
            sha256: deliverable_sha,
            bytes: deliverable_md.len() as u64,
            content_type: "text/markdown".to_string(),
            logical_role: "DELIVERABLE".to_string(),
        }],
        model_calls: vec![],
        eval: EvalSummary {
            gate_status: "PASS".to_string(),
        },
    };

    let eval_report = EvalReport {
        overall_status: "PASS".to_string(),
        tests: vec![],
        gates: vec![],
        registry_version: "gates_registry_v3".to_string(),
    };

    EvidenceBundleInputs {
        run_manifest,
        bundle_info,
        audit_log_ndjson,
        eval_report,
        artifact_hashes_csv: csv_sorted,
        artifact_list,
        policy_snapshot,
        network_snapshot,
        model_snapshot,
        pack_id: "self_audit".to_string(),
        pack_version: "0.0.0".to_string(),
        deliverables: vec![(
            deliverable_rel.clone(),
            deliverable_md,
            "text/markdown".to_string(),
        )],
        attachments: PackAttachments {
            templates_used_json: templates_used,
            citations_map_json: Some(citations_map),
            redactions_map_json: Some(redactions_map),
        },
    }
}

fn make_evidenceos_inputs(policy_mode: PolicyMode) -> EvidenceBundleInputs {
    let determinism_enabled = true;
    let input_bytes = b"evidenceos-phase3-input";
    let input_sha = sha256_hex(input_bytes);
    let artifact_id = "a_ev_0001".to_string();

    let manifest_inputs_fingerprint = sha256_hex(format!("{}:{}", artifact_id, input_sha).as_bytes());
    let run_id = aigc_core::determinism::run_id::run_id_from_manifest_inputs_fingerprint_hex32(
        &manifest_inputs_fingerprint,
    )
    .expect("run_id from fingerprint");
    let vault_id = "v_0001".to_string();
    let pack_id = "evidenceos".to_string();
    let pack_version = "1.0.0".to_string();

    let evidence_req = EvidenceOsRequest {
        pack_id: pack_id.clone(),
        pack_version: pack_version.clone(),
        run_id: run_id.clone(),
        policy_mode,
        enabled_capabilities: vec![],
        evidence_items: vec![EvidenceItem {
            artifact_id: artifact_id.clone(),
            artifact_sha256: input_sha.clone(),
            title: "Offline network evidence".to_string(),
            tags: vec!["OPS".to_string()],
            control_family_labels: vec![
                "Auditability".to_string(),
                "NetworkGovernance".to_string(),
                "Traceability".to_string(),
            ],
        }],
        narrative_claims: vec![NarrativeClaimInput {
            claim_id: "C0001".to_string(),
            text: "The run remained offline with blocked egress attempts.".to_string(),
            citations: vec![CitationInput {
                artifact_id: artifact_id.clone(),
                locator_type: "PDF_TEXT_SPAN_V1".to_string(),
                locator: json!({
                    "page_index": 0,
                    "start_char": 0,
                    "end_char": 20,
                    "text_sha256": input_sha
                }),
            }],
        }],
    };
    let generated = generate_evidenceos_artifacts(&evidence_req).expect("generate evidenceos outputs");

    let audit_path = std::env::temp_dir().join(format!("audit_{}.ndjson", run_id));
    let mut audit = AuditLog::open_or_create(&audit_path).expect("open audit");
    let _ = audit
        .append(AuditEvent {
            ts_utc: fixed_ts(),
            event_type: "VAULT_ENCRYPTION_STATUS".to_string(),
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            actor: Actor::System,
            details: json!({
                "encryption_at_rest": true,
                "algorithm": "XCHACHA20_POLY1305",
                "key_storage": "FILE_FALLBACK"
            }),
            prev_event_hash: "".to_string(),
            event_hash: "".to_string(),
        })
        .unwrap();
    let _ = audit
        .append(AuditEvent {
            ts_utc: fixed_ts(),
            event_type: "NETWORK_MODE_SET".to_string(),
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            actor: Actor::User,
            details: json!({
                "network_mode": "OFFLINE",
                "proof_level": "OFFLINE_STRICT",
                "ui_remote_fetch_disabled": true
            }),
            prev_event_hash: "".to_string(),
            event_hash: "".to_string(),
        })
        .unwrap();
    let _ = audit
        .append(AuditEvent {
            ts_utc: fixed_ts(),
            event_type: "ALLOWLIST_UPDATED".to_string(),
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            actor: Actor::System,
            details: json!({
                "allowlist_hash_sha256": sha256_hex(b""),
                "allowlist_count": 0
            }),
            prev_event_hash: "".to_string(),
            event_hash: "".to_string(),
        })
        .unwrap();
    let _ = audit
        .append(AuditEvent {
            ts_utc: fixed_ts(),
            event_type: "EGRESS_REQUEST_BLOCKED".to_string(),
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            actor: Actor::System,
            details: json!({
                "destination": {
                    "scheme": "https",
                    "host": "example.invalid",
                    "port": 443,
                    "path": "/blocked"
                },
                "block_reason": "OFFLINE_MODE",
                "request_hash_sha256": sha256_hex(b"blocked_request"),
                "evidence_origin": "CONTROL_SIMULATION"
            }),
            prev_event_hash: "".to_string(),
            event_hash: "".to_string(),
        })
        .unwrap();
    let audit_log_ndjson = std::fs::read_to_string(&audit_path).expect("read audit");
    let _ = std::fs::remove_file(&audit_path);

    let templates_rel = format!("exports/{}/attachments/templates_used.json", pack_id);
    let citations_rel = format!("exports/{}/attachments/citations_map.json", pack_id);
    let redactions_rel = format!("exports/{}/attachments/redactions_map.json", pack_id);
    let templates_bytes = aigc_core::determinism::json_canonical::to_canonical_bytes(
        &generated.templates_used_json,
    )
    .expect("templates bytes");
    let citations_bytes = aigc_core::determinism::json_canonical::to_canonical_bytes(
        &generated.citations_map_json,
    )
    .expect("citations bytes");
    let redactions_bytes = aigc_core::determinism::json_canonical::to_canonical_bytes(
        &generated.redactions_map_json,
    )
    .expect("redactions bytes");

    let mut hash_rows = vec![ArtifactHashRow {
        artifact_id: artifact_id.clone(),
        bundle_rel_path: String::new(),
        sha256: input_sha.clone(),
        bytes: input_bytes.len() as u64,
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
    let artifact_hashes_csv = render_artifact_hashes_csv(hash_rows).unwrap();

    let mut outputs: Vec<ManifestOutputRef> = generated
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
    outputs.sort_by(|a, b| a.path.cmp(&b.path));

    EvidenceBundleInputs {
        run_manifest: RunManifest {
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            evidence_authority: controlled_gate_authority(&run_id, "gate-runner:evidenceos"),
            determinism: DeterminismManifest {
                enabled: determinism_enabled,
                manifest_inputs_fingerprint: manifest_inputs_fingerprint.clone(),
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
            policy_mode,
            determinism: DeterminismPolicy {
                enabled: determinism_enabled,
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
                endpoint: "http://127.0.0.1:1234".to_string(),
                is_loopback: true,
                validation_error: None,
            }],
        },
        model_snapshot: ModelSnapshot {
            adapter_id: "local_adapter".to_string(),
            adapter_version: "1.0.0".to_string(),
            adapter_endpoint: "http://127.0.0.1:1234".to_string(),
            model_id: "dummy-model".to_string(),
            model_sha256: Some(sha256_hex(b"dummy-model")),
            pinning_level: classify_pinning_level(Some(&sha256_hex(b"dummy-model")), "local_adapter", "1.0.0"),
        },
        pack_id,
        pack_version,
        deliverables: generated.deliverables,
        attachments: PackAttachments {
            templates_used_json: generated.templates_used_json,
            citations_map_json: Some(generated.citations_map_json),
            redactions_map_json: Some(generated.redactions_map_json),
        },
    }
}

fn fixed_ts() -> String {
    // For deterministic self-audit, use a fixed timestamp.
    "2026-02-10T00:00:00Z".to_string()
}
