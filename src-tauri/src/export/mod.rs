use crate::commands::evidenceos::{EvidenceOsRunInput, EvidenceOsRunResult};
use aigc_core::audit::event::{Actor, AuditEvent};
use aigc_core::audit::log::AuditLog;
use aigc_core::determinism::json_canonical;
use aigc_core::determinism::run_id::sha256_hex;
use aigc_core::evidence_bundle::artifact_hashes::{render_artifact_hashes_csv, ArtifactHashRow};
use aigc_core::evidence_bundle::authority::EvidenceAuthorityManifest;
use aigc_core::evidence_bundle::schemas::*;
use aigc_core::evidenceos::model::{CitationInput, EvidenceItem, NarrativeClaimInput};
use aigc_core::evidenceos::workflow::{generate_evidenceos_artifacts, EvidenceOsRequest};
use aigc_core::policy::network_snapshot::NetworkSnapshot;
use aigc_core::policy::types::{InputExportProfile, PolicyMode};
use aigc_core::run::manager::{ExportRequest, RunManager};
use serde::Serialize;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_TARGET: &str = "aigc_core_tauri::export::cleanup";
static RUNTIME_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static EXECUTABLE_SHA256: OnceLock<String> = OnceLock::new();

pub(crate) fn generate_evidenceos_bundle(
    input: EvidenceOsRunInput,
) -> Result<EvidenceOsRunResult, String> {
    let invocation_arguments_sha256 = command_arguments_sha256(&input)?;

    let artifact_bytes = input.artifact_body.as_bytes().to_vec();
    let artifact_sha = sha256_hex(&artifact_bytes);
    verify_declared_input_hash(input.artifact_sha256.as_deref(), &artifact_sha)?;
    let network_policy = NetworkSnapshot::offline_policy();
    let artifact_id = format!("a_ui_{}", &artifact_sha[..8]);
    let manifest_inputs_fingerprint =
        sha256_hex(format!("{}:{}", artifact_id, artifact_sha).as_bytes());
    let run_id = format!("r_{}", &manifest_inputs_fingerprint[..32]);
    let vault_id = format!("v_local_{}", &manifest_inputs_fingerprint[..32]);
    let pack_id = "evidenceos".to_string();
    let pack_version = "1.0.0".to_string();

    let runtime_guard = RuntimeDirGuard::create()?;
    let runtime_dir = runtime_guard.path().to_path_buf();
    let bundle_root = runtime_dir.join("bundle_root");
    let output_sequence = RUNTIME_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let bundle_zip = std::env::temp_dir().join(format!(
        "aigc_evidenceos_export_{}_{}_{}.zip",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos(),
        output_sequence
    ));
    reserve_private_output(&bundle_zip)?;
    let mut output_guard = ExportOutputGuard {
        path: bundle_zip.clone(),
        keep: false,
    };
    let audit_path = runtime_dir.join("audit.ndjson");
    let mut audit = AuditLog::open_or_create(&audit_path).map_err(|e| e.to_string())?;
    let events = vec![
        (
            "NETWORK_MODE_SET",
            Actor::System,
            json!({
                "network_mode":network_policy.network_mode,
                "proof_level":network_policy.proof_level,
                "proof_source":network_policy.proof_source,
                "ui_remote_fetch_disabled":network_policy.ui_remote_fetch_disabled
            }),
        ),
        (
            "ALLOWLIST_UPDATED",
            Actor::System,
            json!({
                "allowlist_hash_sha256": sha256_hex(&json_canonical::to_canonical_bytes(&network_policy.allowlist).map_err(|e| e.to_string())?),
                "allowlist_count":network_policy.allowlist.len()
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
        "EvidenceOS generated local artifacts under the declared offline policy; no model, adapter, vault encryption, or network traffic measurement was used."
            .to_string()
    } else {
        input.claim_text.clone()
    };

    let req = EvidenceOsRequest {
        determinism_enabled: true,
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

    let evidence_authority = local_export_authority(
        &run_id,
        "generate_evidenceos_bundle",
        &invocation_arguments_sha256,
    )?;
    let bundle_inputs = EvidenceBundleInputs {
        run_manifest: RunManifest {
            run_id: run_id.clone(),
            vault_id: vault_id.clone(),
            evidence_authority: evidence_authority.clone(),
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
            bundle_version: "1.1.0".to_string(),
            schema_versions: SchemaVersions {
                run_manifest: "RUN_MANIFEST_V2".to_string(),
                eval_report: "EVAL_REPORT_V1".to_string(),
                citations_map: "LOCATOR_SCHEMA_V1".to_string(),
                redactions_map: "REDACTION_SCHEMA_V1".to_string(),
            },
            pack_id: pack_id.clone(),
            pack_version: pack_version.clone(),
            core_build: format!(
                "{}+{}",
                env!("CARGO_PKG_VERSION"),
                env!("AIGC_SOURCE_REVISION")
            ),
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
            encryption_at_rest: false,
            encryption_algorithm: None,
        },
        network_snapshot: network_policy.clone(),
        model_snapshot: None,
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
        network_mode: network_policy.network_mode,
        proof_level: network_policy.proof_level,
        pinning_level: None,
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
    let evidence_authority = read_bound_evidence_authority(&bundle_root)?;

    output_guard.keep = true;
    Ok(EvidenceOsRunResult {
        status: outcome.status,
        bundle_path: outcome.bundle_path.unwrap_or_default(),
        bundle_sha256: outcome.bundle_sha256.unwrap_or_default(),
        missing_control_ids: generated.missing_control_ids,
        evidence_authority,
        encryption_at_rest: bundle_inputs.policy_snapshot.encryption_at_rest,
        model_used: bundle_inputs.model_snapshot.is_some(),
    })
}

fn verify_declared_input_hash(declared: Option<&str>, actual: &str) -> Result<(), String> {
    if let Some(hash) = declared {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("artifact_sha256 must be 64 lowercase hexadecimal characters".into());
        }
        if hash != actual {
            return Err("artifact_sha256 does not match payload bytes".into());
        }
    }
    Ok(())
}

fn make_runtime_dir() -> Result<std::path::PathBuf, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let sequence = RUNTIME_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "aigc_evidenceos_{}_{}_{}",
        std::process::id(),
        ts,
        sequence
    ));
    std::fs::create_dir(&path).map_err(|e| e.to_string())?;
    if let Err(error) = harden_runtime_dir_permissions(&path) {
        if let Err(cleanup_error) = std::fs::remove_dir_all(&path) {
            log::warn!(
                target: LOG_TARGET,
                "clean export working directory after permission error failed: {:?}",
                cleanup_error.kind()
            );
        }
        return Err(error);
    }
    Ok(path)
}

struct RuntimeDirGuard(std::path::PathBuf);

impl RuntimeDirGuard {
    fn create() -> Result<Self, String> {
        make_runtime_dir().map(Self)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for RuntimeDirGuard {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            log::warn!(
                target: LOG_TARGET,
                "clean export working directory failed: {:?}",
                error.kind()
            );
        }
    }
}

struct ExportOutputGuard {
    path: std::path::PathBuf,
    keep: bool,
}

impl Drop for ExportOutputGuard {
    fn drop(&mut self) {
        if !self.keep {
            if let Err(error) = std::fs::remove_file(&self.path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    log::warn!(
                        target: LOG_TARGET,
                        "clean incomplete export failed: {:?}",
                        error.kind()
                    );
                }
            }
        }
    }
}

/// Reserve the export path with `create_new` (so a pre-planted file or symlink
/// is refused) and, on unix, mode 0600 before any data is written to it.
fn reserve_private_output(path: &std::path::Path) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map(drop)
        .map_err(|error| format!("cannot reserve export archive: {}", error.kind()))
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

fn command_arguments_sha256<T: Serialize>(input: &T) -> Result<String, String> {
    let bytes = json_canonical::to_canonical_bytes(input).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

fn local_export_authority(
    run_id: &str,
    entrypoint: &str,
    arguments_sha256: &str,
) -> Result<EvidenceAuthorityManifest, String> {
    let executable_path = std::env::current_exe()
        .map_err(|error| format!("current executable unavailable: {error}"))?;
    let executable_hash = cached_success(&EXECUTABLE_SHA256, || hash_file(&executable_path))?;
    let environment = json!({
        "network_mode": "OFFLINE",
        "proof_level": "OFFLINE_STRICT",
        "credential_availability": "NOT_REQUESTED",
        "external_mutation_tools": [],
        "model_execution": "NOT_USED"
    });
    let environment_bytes =
        json_canonical::to_canonical_bytes(&environment).map_err(|error| error.to_string())?;
    let generated_at = time::OffsetDateTime::now_utc();
    let valid_until = generated_at + time::Duration::hours(24);
    let format = &time::format_description::well_known::Rfc3339;

    Ok(EvidenceAuthorityManifest::controlled_local_export(
        run_id,
        format!("aigccore-tauri:{entrypoint}"),
        option_env!("AIGC_SOURCE_REVISION")
            .unwrap_or(concat!("aigccore-package-", env!("CARGO_PKG_VERSION"))),
        executable_path.display().to_string(),
        executable_hash,
        arguments_sha256,
        sha256_hex(&environment_bytes),
        generated_at
            .format(format)
            .map_err(|error| error.to_string())?,
        valid_until
            .format(format)
            .map_err(|error| error.to_string())?,
    ))
}

/// Return the cached value, or compute it. Only a success is cached, so a
/// transient failure (for example the file briefly unreadable) is retried.
fn cached_success(
    cell: &OnceLock<String>,
    compute: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    if let Some(value) = cell.get() {
        return Ok(value.clone());
    }
    let value = compute()?;
    Ok(cell.get_or_init(|| value).clone())
}

fn hash_file(path: &std::path::Path) -> Result<String, String> {
    use sha2::Digest;
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("current executable unreadable: {error}"))?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("current executable unreadable: {error}"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn read_bound_evidence_authority(
    bundle_root: &std::path::Path,
) -> Result<EvidenceAuthorityManifest, String> {
    let bytes = std::fs::read(bundle_root.join("run_manifest.json"))
        .map_err(|error| format!("bound run manifest unavailable: {error}"))?;
    let manifest: RunManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("bound run manifest invalid: {error}"))?;
    Ok(manifest.evidence_authority)
}

fn now_rfc3339_utc() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aigc_core::evidence_bundle::authority::{
        EvidenceClaimContext, EvidenceClaimDecision, CLAIM_LIVE_EXECUTION,
        CLAIM_LOCAL_CONTROLLED_EXECUTION,
    };
    use std::fs;

    #[test]
    fn declared_input_hash_checks_exact_payload_and_rejects_malformed_or_mismatched_hash() {
        let actual = sha256_hex("payload 🧭".as_bytes());
        assert!(verify_declared_input_hash(Some(&actual), &actual).is_ok());
        assert!(verify_declared_input_hash(None, &actual).is_ok());
        for malformed in [
            "",
            "demo_sha256",
            &"a".repeat(63),
            &"A".repeat(64),
            &"g".repeat(64),
        ] {
            assert!(verify_declared_input_hash(Some(malformed), &actual)
                .unwrap_err()
                .contains("64 lowercase"));
        }
        assert!(
            verify_declared_input_hash(Some(&sha256_hex(b"different")), &actual)
                .unwrap_err()
                .contains("does not match payload")
        );
        let empty = sha256_hex(b"");
        assert!(verify_declared_input_hash(Some(&empty), &empty).is_ok());
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
    fn runtime_dirs_are_unique_for_concurrent_pack_commands() {
        let first = make_runtime_dir().expect("first runtime directory should be created");
        let second = make_runtime_dir().expect("second runtime directory should be created");

        assert_ne!(first, second);
        assert!(first.is_dir());
        assert!(second.is_dir());

        fs::remove_dir_all(first).expect("first runtime directory should be removed");
        fs::remove_dir_all(second).expect("second runtime directory should be removed");
    }

    #[test]
    fn runtime_guard_removes_work_directory_when_scope_exits() {
        let guard = RuntimeDirGuard::create().unwrap();
        let path = guard.path().to_path_buf();
        assert!(path.is_dir());
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn executable_file_hash_is_streamed_and_matches_sha256() {
        let path = std::env::temp_dir().join(format!(
            "aigc-hash-test-{}",
            RUNTIME_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, vec![0x5a; 150_000]).unwrap();
        let expected = sha256_hex(&fs::read(&path).unwrap());
        assert_eq!(hash_file(&path).unwrap(), expected);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn executable_hash_cache_keeps_successes_and_retries_failures() {
        let cell = OnceLock::new();
        assert_eq!(
            cached_success(&cell, || Err("unreadable".into())).unwrap_err(),
            "unreadable"
        );
        assert!(cell.get().is_none(), "a failure must not be cached");
        assert_eq!(cached_success(&cell, || Ok("abc".into())).unwrap(), "abc");
        assert_eq!(
            cached_success(&cell, || Err("must not run".into())).unwrap(),
            "abc"
        );
    }

    #[test]
    fn export_output_reservation_refuses_an_existing_path() {
        let path = std::env::temp_dir().join(format!(
            "aigc-reserve-test-{}-{}",
            std::process::id(),
            RUNTIME_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        reserve_private_output(&path).unwrap();
        let error = reserve_private_output(&path).unwrap_err();
        fs::remove_file(&path).unwrap();
        assert!(error.contains("already exists"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn exported_archive_is_private_to_the_current_user() {
        use std::os::unix::fs::PermissionsExt;
        let result = generate_evidenceos_bundle(EvidenceOsRunInput {
            enabled_capabilities: vec!["Traceability".to_string()],
            artifact_title: "Private export fixture".to_string(),
            artifact_body: "Mode check".to_string(),
            artifact_sha256: None,
            artifact_tags_csv: "TEST".to_string(),
            control_families_csv: "Traceability".to_string(),
            claim_text: "Mode check.".to_string(),
        })
        .expect("export completes");
        let mode = fs::metadata(&result.bundle_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        fs::remove_file(&result.bundle_path).unwrap();
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn evidenceos_command_returns_bound_non_live_authority() {
        let result = generate_evidenceos_bundle(EvidenceOsRunInput {
            enabled_capabilities: vec!["Traceability".to_string()],
            artifact_title: "Controlled authority fixture".to_string(),
            artifact_body: "Bounded local evidence".to_string(),
            artifact_sha256: Some(sha256_hex(b"Bounded local evidence")),
            artifact_tags_csv: "TEST".to_string(),
            control_families_csv: "Traceability".to_string(),
            claim_text: "The controlled bundle path was exercised.".to_string(),
        })
        .expect("controlled EvidenceOS export should complete");
        assert!(std::path::Path::new(&result.bundle_path).is_file());

        let authority = &result.evidence_authority;
        let context = EvidenceClaimContext {
            as_of_utc: authority.generated_at_utc.clone(),
            expected_case_id: authority.case_id.clone(),
            expected_source_revision: authority.source.source_revision.clone(),
            expected_executable_sha256: authority.source.executable_sha256.clone(),
            expected_arguments_sha256: authority.source.arguments_sha256.clone(),
            expected_environment_sha256: authority.source.environment_sha256.clone(),
            expected_audit_log_sha256: authority.source.audit_log_sha256.clone(),
            required_tool_id: Some("LOCAL_EVIDENCE_BUNDLE_EXPORT".to_string()),
            credentials_required: false,
        };
        assert_eq!(
            authority.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &context),
            EvidenceClaimDecision::Authorized
        );
        assert_eq!(
            authority.evaluate_claim(CLAIM_LIVE_EXECUTION, &context),
            EvidenceClaimDecision::Denied
        );
        assert!(!authority.production_equivalent);
        assert!(!authority.source.audit_log_sha256.is_empty());
        assert!(!result.encryption_at_rest);
        assert!(!result.model_used);

        let summary = aigc_core::validator::BundleValidator::new_v3()
            .validate_zip(
                std::path::Path::new(&result.bundle_path),
                PolicyMode::STRICT,
            )
            .expect("exported bundle should be inspectable");
        assert_eq!(summary.overall, "PASS", "{:?}", summary.checks);

        let read_json = |path: &str| -> serde_json::Value {
            let file = fs::File::open(&result.bundle_path).unwrap();
            let mut archive = zip::ZipArchive::new(file).unwrap();
            let mut entry = archive.by_name(path).unwrap();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        };
        let policy = read_json("inputs_snapshot/policy_snapshot.json");
        assert_eq!(policy["encryption_at_rest"], false);
        assert!(policy.get("encryption_algorithm").is_none());
        assert!(read_json("inputs_snapshot/model_snapshot.json").is_null());
        assert_eq!(
            read_json("inputs_snapshot/network_snapshot.json")["adapter_endpoints"],
            json!([])
        );
        assert_eq!(
            read_json("inputs_snapshot/network_snapshot.json")["proof_source"],
            "POLICY_DECLARATION"
        );
        assert_eq!(read_json("run_manifest.json")["model_calls"], json!([]));
        assert_eq!(
            read_json("BUNDLE_INFO.json")["core_build"],
            format!(
                "{}+{}",
                env!("CARGO_PKG_VERSION"),
                env!("AIGC_SOURCE_REVISION")
            )
        );
        let audit_bytes = {
            let file = fs::File::open(&result.bundle_path).unwrap();
            let mut archive = zip::ZipArchive::new(file).unwrap();
            let mut entry = archive.by_name("audit_log.ndjson").unwrap();
            let mut bytes = String::new();
            std::io::Read::read_to_string(&mut entry, &mut bytes).unwrap();
            bytes
        };
        assert!(!audit_bytes.contains("VAULT_ENCRYPTION_STATUS"));
        assert!(!audit_bytes.contains("EGRESS_REQUEST_BLOCKED"));

        assert!(std::path::Path::new(&result.bundle_path).is_file());
        fs::remove_file(&result.bundle_path).unwrap();
    }
}
