pub mod checklist;

use crate::error::{CoreError, CoreResult};
use crate::evidence_bundle::schemas::{BundleInfo, EvalGateResult, EvalReport, RunManifest};
use crate::policy::types::PolicyMode;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use zip::ZipArchive;

/// Validator resource limits. Keep these aligned with the published checklist.
pub const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRIES: usize = 4096;
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_COMPRESSION_RATIO: u64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check_id: String,
    pub severity: String,
    pub result: String, // PASS|FAIL
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSummary {
    pub checklist_version: String,
    pub policy: String,
    pub overall: String, // PASS|FAIL
    pub checks: Vec<CheckResult>,
}

impl ValidationSummary {
    pub fn result_for_check(&self, check_id: &str) -> (String, String) {
        for c in &self.checks {
            if c.check_id == check_id {
                return (c.result.clone(), c.message.clone());
            }
        }
        (
            "FAIL".to_string(),
            format!("missing check result for {}", check_id),
        )
    }

    pub fn result_for_checks_prefix(&self, prefix: &str) -> (String, String) {
        let mut any_match = false;
        let mut any_fail = false;
        for c in &self.checks {
            if c.check_id.starts_with(prefix) {
                any_match = true;
                if c.result != "PASS" {
                    any_fail = true;
                }
            }
        }
        if !any_match {
            (
                "FAIL".to_string(),
                format!("missing check results for prefix {}", prefix),
            )
        } else if any_fail {
            (
                "FAIL".to_string(),
                format!("one or more {} checks failed", prefix),
            )
        } else {
            ("PASS".to_string(), "ok".to_string())
        }
    }

    pub fn vault_crypto_gate_result(&self) -> String {
        // This gate passes when the bundle truthfully records that encryption was unused.
        self.result_for_check("CHK.VAULT_CRYPTO.POLICY_SNAPSHOT").0
    }

    pub fn vault_crypto_message(&self) -> String {
        self.result_for_check("CHK.VAULT_CRYPTO.POLICY_SNAPSHOT").1
    }
}

pub struct BundleValidator {
    checklist: checklist::Checklist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationMode {
    Final,
    EvaluationPreflight,
}

impl BundleValidator {
    pub fn new_v3() -> Self {
        let checklist = checklist::checklist_v3();
        Self { checklist }
    }

    pub fn validate_zip(
        &self,
        bundle_zip: &Path,
        policy: PolicyMode,
    ) -> CoreResult<ValidationSummary> {
        self.validate_zip_with_mode(bundle_zip, policy, ValidationMode::Final)
    }

    /// Internal, non-authorizing validation used only to compute gate results before
    /// an eval report exists. Every exported bundle must subsequently pass `validate_zip`.
    pub(crate) fn validate_zip_for_evaluation_preflight(
        &self,
        bundle_zip: &Path,
        policy: PolicyMode,
    ) -> CoreResult<ValidationSummary> {
        self.validate_zip_with_mode(bundle_zip, policy, ValidationMode::EvaluationPreflight)
    }

    fn validate_zip_with_mode(
        &self,
        bundle_zip: &Path,
        policy: PolicyMode,
        mode: ValidationMode,
    ) -> CoreResult<ValidationSummary> {
        let policy_s = match policy {
            PolicyMode::STRICT => "STRICT",
            PolicyMode::BALANCED => "BALANCED",
            PolicyMode::DRAFT_ONLY => "DRAFT_ONLY",
        };

        let file = File::open(bundle_zip)?;
        let archive_bytes = file.metadata()?.len();
        if archive_bytes > MAX_ARCHIVE_BYTES {
            return Err(CoreError::Zip(format!(
                "ARCHIVE_SIZE_LIMIT: {archive_bytes} exceeds {MAX_ARCHIVE_BYTES} bytes"
            )));
        }
        let mut zip = ZipArchive::new(file).map_err(|e| CoreError::Zip(e.to_string()))?;
        let mut entry_limits = Vec::with_capacity(zip.len());
        for index in 0..zip.len() {
            let entry = zip
                .by_index(index)
                .map_err(|error| CoreError::Zip(error.to_string()))?;
            entry_limits.push((
                entry.name().to_string(),
                entry.size(),
                entry.compressed_size(),
            ));
        }
        validate_archive_limits(archive_bytes, &entry_limits)?;

        // Build entry set for existence checks.
        let mut paths: BTreeSet<String> = BTreeSet::new();
        for i in 0..zip.len() {
            let f = zip.by_index(i).map_err(|e| CoreError::Zip(e.to_string()))?;
            paths.insert(f.name().to_string());
        }

        let legacy_bundle = match read_zip_entry_json(&mut zip, "BUNDLE_INFO.json") {
            Ok(info) => info
                .get("bundle_version")
                .and_then(|v| v.as_str())
                .map(is_legacy_bundle_version)
                .unwrap_or(true),
            Err(_) => false,
        };

        let mut checks_out: Vec<CheckResult> = Vec::new();

        // CHK.BUNDLE.REQUIRED_FILES
        checks_out.push(check_required_files(&paths));

        // CHK.EXPORTS.ATTACHMENTS_LAYOUT
        checks_out.push(check_exports_layout(&paths));

        // CHK.NETWORK.SNAPSHOT_PRESENT
        checks_out.push(check_json_required_fields(
            &mut zip,
            "inputs_snapshot/network_snapshot.json",
            &[
                "network_mode",
                "proof_level",
                "allowlist",
                "ui_remote_fetch_disabled",
                "adapter_endpoints",
            ],
            legacy_bundle,
        ));

        // CHK.BUNDLE.VERSION_TRUTHFULNESS
        checks_out.push(if legacy_bundle {
            CheckResult {
                check_id: "CHK.BUNDLE.VERSION_TRUTHFULNESS".to_string(),
                severity: "INFO".to_string(),
                result: "PASS".to_string(),
                message:
                    "legacy bundle inspected; its snapshot claims cannot be treated as truthful"
                        .to_string(),
            }
        } else {
            pass("CHK.BUNDLE.VERSION_TRUTHFULNESS")
        });

        // CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN
        checks_out.push(check_audit_chain(&mut zip));

        // CHK.EVIDENCE.AUTHORITY_CONTRACT
        checks_out.push(check_evidence_authority_contract(&mut zip));

        // CHK.ARTIFACT_HASHES.VERIFY
        checks_out.push(check_artifact_hashes(&mut zip, &paths));

        // CHK.MODEL.PINNING_LEVEL
        checks_out.push(check_model_pinning(&mut zip, policy));

        // CHK.CITATIONS.STRICT (conditional)
        checks_out.push(check_citations_strict(&mut zip, &paths, policy));

        // CHK.REDACTION.POLICY_GATE (conditional)
        checks_out.push(check_redaction_policy_gate(&mut zip, &paths, policy));

        // CHK.EVAL.REPORT_AND_GATES
        checks_out.push(match mode {
            ValidationMode::Final => check_eval_report(&mut zip, policy),
            ValidationMode::EvaluationPreflight => check_eval_report_preflight(&mut zip),
        });

        // CHK.DETERMINISM.ZIP_RULES (major, conditional)
        checks_out.push(check_zip_determinism(&mut zip));

        // Vault crypto minimal policy snapshot check (gate expects it)
        checks_out.push(check_vault_crypto_policy_snapshot(&mut zip));

        checks_out.push(check_run_snapshot_consistency(&mut zip));
        checks_out.push(check_network_proof_source(&mut zip, legacy_bundle));

        let overall = overall_validation_status(&checks_out, legacy_bundle);

        Ok(ValidationSummary {
            checklist_version: self.checklist.checklist_version.clone(),
            policy: policy_s.to_string(),
            overall: overall.to_string(),
            checks: checks_out,
        })
    }
}

fn validate_archive_limits(archive_bytes: u64, entries: &[(String, u64, u64)]) -> CoreResult<()> {
    if archive_bytes > MAX_ARCHIVE_BYTES {
        return Err(CoreError::Zip(format!(
            "ARCHIVE_SIZE_LIMIT: {archive_bytes} exceeds {MAX_ARCHIVE_BYTES} bytes"
        )));
    }
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        return Err(CoreError::Zip(format!(
            "ENTRY_COUNT_LIMIT: {} exceeds {MAX_ARCHIVE_ENTRIES}",
            entries.len()
        )));
    }
    let mut total_uncompressed = 0u64;
    for (name, size, compressed_size) in entries {
        if *size > MAX_ENTRY_BYTES {
            return Err(CoreError::Zip(format!(
                "ENTRY_SIZE_LIMIT: {name} exceeds {MAX_ENTRY_BYTES} bytes"
            )));
        }
        total_uncompressed = total_uncompressed
            .checked_add(*size)
            .ok_or_else(|| CoreError::Zip("TOTAL_SIZE_LIMIT: uncompressed size overflow".into()))?;
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(CoreError::Zip(format!(
                "TOTAL_SIZE_LIMIT: exceeds {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
            )));
        }
        if *size > 1024
            && u128::from(*size)
                > u128::from((*compressed_size).max(1)) * u128::from(MAX_COMPRESSION_RATIO)
        {
            return Err(CoreError::Zip(format!(
                "COMPRESSION_RATIO_LIMIT: {name} exceeds {MAX_COMPRESSION_RATIO}:1"
            )));
        }
    }
    Ok(())
}

fn check_required_files(paths: &BTreeSet<String>) -> CheckResult {
    let must = [
        "BUNDLE_INFO.json",
        "run_manifest.json",
        "audit_log.ndjson",
        "eval_report.json",
        "artifact_hashes.csv",
        "inputs_snapshot/artifact_list.json",
        "inputs_snapshot/policy_snapshot.json",
        "inputs_snapshot/network_snapshot.json",
        "inputs_snapshot/model_snapshot.json",
        "exports/",
    ];

    let mut missing = Vec::new();
    for m in must {
        if m.ends_with('/') {
            // any path with this prefix counts
            if !paths.iter().any(|p| p.starts_with(m)) {
                missing.push(m.to_string());
            }
        } else if !paths.contains(m) {
            missing.push(m.to_string());
        }
    }

    if missing.is_empty() {
        CheckResult {
            check_id: "CHK.BUNDLE.REQUIRED_FILES".to_string(),
            severity: "BLOCKER".to_string(),
            result: "PASS".to_string(),
            message: "ok".to_string(),
        }
    } else {
        CheckResult {
            check_id: "CHK.BUNDLE.REQUIRED_FILES".to_string(),
            severity: "BLOCKER".to_string(),
            result: "FAIL".to_string(),
            message: format!("missing: {}", missing.join(", ")),
        }
    }
}

fn check_exports_layout(paths: &BTreeSet<String>) -> CheckResult {
    // At least one pack export must contain deliverables/ and attachments/ and templates_used.json.
    let mut ok = false;
    for p in paths {
        if p.ends_with("attachments/templates_used.json") && p.starts_with("exports/") {
            ok = true;
            break;
        }
    }
    if ok {
        CheckResult {
            check_id: "CHK.EXPORTS.ATTACHMENTS_LAYOUT".to_string(),
            severity: "BLOCKER".to_string(),
            result: "PASS".to_string(),
            message: "ok".to_string(),
        }
    } else {
        CheckResult {
            check_id: "CHK.EXPORTS.ATTACHMENTS_LAYOUT".to_string(),
            severity: "BLOCKER".to_string(),
            result: "FAIL".to_string(),
            message: "missing templates_used.json under exports/**/attachments/".to_string(),
        }
    }
}

fn read_zip_entry_bytes<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    path: &str,
) -> CoreResult<Vec<u8>> {
    let f = zip
        .by_name(path)
        .map_err(|e| CoreError::Zip(e.to_string()))?;
    if f.size() > MAX_ENTRY_BYTES {
        return Err(CoreError::Zip(format!(
            "ENTRY_SIZE_LIMIT: {} exceeds {MAX_ENTRY_BYTES} bytes",
            f.name()
        )));
    }
    let mut out = Vec::new();
    f.take(MAX_ENTRY_BYTES + 1).read_to_end(&mut out)?;
    if out.len() as u64 > MAX_ENTRY_BYTES {
        return Err(CoreError::Zip(format!(
            "ENTRY_SIZE_LIMIT: exceeds {MAX_ENTRY_BYTES} bytes"
        )));
    }
    Ok(out)
}

fn read_zip_entry_json<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    path: &str,
) -> CoreResult<serde_json::Value> {
    let bytes = read_zip_entry_bytes(zip, path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn check_evidence_authority_contract<R: Read + Seek>(zip: &mut ZipArchive<R>) -> CheckResult {
    let fail = |message: String| CheckResult {
        check_id: "CHK.EVIDENCE.AUTHORITY_CONTRACT".to_string(),
        severity: "BLOCKER".to_string(),
        result: "FAIL".to_string(),
        message,
    };

    let bundle_info: BundleInfo = match read_zip_entry_json(zip, "BUNDLE_INFO.json")
        .and_then(|value| Ok(serde_json::from_value(value)?))
    {
        Ok(value) => value,
        Err(error) => return fail(format!("failed to read BUNDLE_INFO.json: {error}")),
    };
    if bundle_info.schema_versions.run_manifest == "RUN_MANIFEST_V1" {
        return fail(
            "legacy RUN_MANIFEST_V1 is inspectable but non-authorizing; migrate to RUN_MANIFEST_V2 with explicit evidence authority"
                .to_string(),
        );
    }
    if bundle_info.schema_versions.run_manifest != "RUN_MANIFEST_V2" {
        return fail(format!(
            "unsupported run manifest schema {}; RUN_MANIFEST_V2 is required for evidence authority",
            bundle_info.schema_versions.run_manifest
        ));
    }
    let run_manifest: RunManifest = match read_zip_entry_json(zip, "run_manifest.json")
        .and_then(|value| Ok(serde_json::from_value(value)?))
    {
        Ok(value) => value,
        Err(error) => return fail(format!("failed to read run_manifest.json: {error}")),
    };
    if bundle_info.run_id != run_manifest.run_id {
        return fail("BUNDLE_INFO run_id does not match run_manifest run_id".to_string());
    }
    let audit_log = match read_zip_entry_bytes(zip, "audit_log.ndjson").and_then(|bytes| {
        String::from_utf8(bytes).map_err(|error| CoreError::InvalidInput(error.to_string()))
    }) {
        Ok(value) => value,
        Err(error) => return fail(format!("failed to read audit_log.ndjson: {error}")),
    };
    if let Err(error) = run_manifest
        .evidence_authority
        .validate_internal(&run_manifest.run_id, &audit_log)
    {
        return fail(error);
    }
    CheckResult {
        check_id: "CHK.EVIDENCE.AUTHORITY_CONTRACT".to_string(),
        severity: "BLOCKER".to_string(),
        result: "PASS".to_string(),
        message:
            "evidence authority is hash-bound, internally coherent, and carries a valid freshness interval"
                .to_string(),
    }
}

fn check_json_required_fields<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    path: &str,
    required: &[&str],
    legacy_bundle: bool,
) -> CheckResult {
    let v = match read_zip_entry_json(zip, path) {
        Ok(v) => v,
        Err(e) => {
            return CheckResult {
                check_id: "CHK.NETWORK.SNAPSHOT_PRESENT".to_string(),
                severity: "BLOCKER".to_string(),
                result: "FAIL".to_string(),
                message: format!("failed to read {}: {}", path, e),
            };
        }
    };
    let mut missing = Vec::new();
    for k in required {
        if v.get(*k).is_none() {
            missing.push((*k).to_string());
        }
    }
    if !legacy_bundle && v.get("proof_source").is_none() {
        missing.push("proof_source".to_string());
    }
    // Lock addendum: ui_remote_fetch_disabled_must_be_true and adapter loopback validation results present.
    if v.get("ui_remote_fetch_disabled").and_then(|x| x.as_bool()) != Some(true) {
        missing.push("ui_remote_fetch_disabled=true".to_string());
    }
    if let Some(arr) = v.get("adapter_endpoints").and_then(|x| x.as_array()) {
        for (idx, ep) in arr.iter().enumerate() {
            if ep.get("is_loopback").and_then(|x| x.as_bool()) != Some(true) {
                missing.push(format!("adapter_endpoints[{}].is_loopback=true", idx));
            }
        }
    }
    if missing.is_empty() {
        CheckResult {
            check_id: "CHK.NETWORK.SNAPSHOT_PRESENT".to_string(),
            severity: "BLOCKER".to_string(),
            result: "PASS".to_string(),
            message: "ok".to_string(),
        }
    } else {
        CheckResult {
            check_id: "CHK.NETWORK.SNAPSHOT_PRESENT".to_string(),
            severity: "BLOCKER".to_string(),
            result: "FAIL".to_string(),
            message: format!("missing fields: {}", missing.join(", ")),
        }
    }
}

fn check_audit_chain<R: Read + Seek>(zip: &mut ZipArchive<R>) -> CheckResult {
    // Recompute per lock addendum: hash canonical JSON with event_hash forced to zeros.
    let bytes = match read_zip_entry_bytes(zip, "audit_log.ndjson") {
        Ok(b) => b,
        Err(e) => {
            return CheckResult {
                check_id: "CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN".to_string(),
                severity: "BLOCKER".to_string(),
                result: "FAIL".to_string(),
                message: format!("failed to read audit_log.ndjson: {}", e),
            };
        }
    };
    let s = String::from_utf8_lossy(&bytes);
    let mut prev = crate::audit::event::ZERO_HASH_64.to_string();
    let required = [
        "ts_utc",
        "event_type",
        "run_id",
        "vault_id",
        "actor",
        "details",
        "prev_event_hash",
        "event_hash",
    ];

    for (idx, line) in s.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return fail(
                    "CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN",
                    format!("invalid json at line {}: {}", idx + 1, e),
                );
            }
        };

        for k in required {
            if v.get(k).is_none() {
                return fail(
                    "CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN",
                    format!("missing key {} at line {}", k, idx + 1),
                );
            }
        }

        let prev_hash = v
            .get("prev_event_hash")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if prev_hash != prev {
            return fail(
                "CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN",
                format!(
                    "prev_event_hash mismatch at line {} (expected {})",
                    idx + 1,
                    prev
                ),
            );
        }

        let stored_hash = v
            .get("event_hash")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        // Force event_hash to zeros before hashing (matches core implementation).
        v.as_object_mut().unwrap().insert(
            "event_hash".to_string(),
            serde_json::Value::String(crate::audit::event::ZERO_HASH_64.to_string()),
        );
        let canonical = match crate::determinism::json_canonical::to_canonical_bytes(&v) {
            Ok(b) => b,
            Err(e) => {
                return fail(
                    "CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN",
                    format!("canonicalize error: {}", e),
                );
            }
        };
        let mut h = sha2::Sha256::new();
        h.update(canonical);
        let computed = hex::encode(h.finalize());
        if computed != stored_hash {
            return fail(
                "CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN",
                format!(
                    "event_hash mismatch at line {} (computed {})",
                    idx + 1,
                    computed
                ),
            );
        }
        prev = stored_hash;
    }

    pass("CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN")
}

fn check_artifact_hashes<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    paths: &BTreeSet<String>,
) -> CheckResult {
    let bytes = match read_zip_entry_bytes(zip, "artifact_hashes.csv") {
        Ok(b) => b,
        Err(e) => {
            return fail(
                "CHK.ARTIFACT_HASHES.VERIFY",
                format!("failed to read artifact_hashes.csv: {}", e),
            );
        }
    };
    let s = String::from_utf8_lossy(&bytes).to_string();

    // Read export profile from policy_snapshot
    let policy = match read_zip_entry_json(zip, "inputs_snapshot/policy_snapshot.json") {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.ARTIFACT_HASHES.VERIFY",
                format!("failed to read policy_snapshot: {}", e),
            );
        }
    };
    let profile = policy
        .pointer("/export_profile/inputs")
        .and_then(|x| x.as_str())
        .unwrap_or("");

    // Parse CSV
    let mut rdr = csv::Reader::from_reader(s.as_bytes());
    let mut rows: Vec<(String, String, String, u64)> = Vec::new(); // artifact_id, bundle_rel_path, sha256, bytes
    for rec in rdr.records() {
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                return fail(
                    "CHK.ARTIFACT_HASHES.VERIFY",
                    format!("csv parse error: {}", e),
                );
            }
        };
        let artifact_id = rec.get(0).unwrap_or("").to_string();
        let bundle_rel_path = rec.get(1).unwrap_or("").to_string();
        let sha256 = rec.get(2).unwrap_or("").to_string();
        if !is_sha256_hex(&sha256) {
            return fail(
                "CHK.ARTIFACT_HASHES.VERIFY",
                format!("malformed declared sha256 for {}", bundle_rel_path),
            );
        }
        let bytes_s = rec.get(3).unwrap_or("0");
        let bytes_v: u64 = bytes_s.parse().unwrap_or(0);
        rows.push((artifact_id, bundle_rel_path, sha256, bytes_v));
    }

    // Verify ordering
    let mut sorted = rows.clone();
    sorted.sort_by_key(|a| (a.0.clone(), a.1.clone()));
    if sorted != rows {
        return fail(
            "CHK.ARTIFACT_HASHES.VERIFY",
            "rows not sorted by artifact_id then path".to_string(),
        );
    }

    // Every declared digest uses the same format check; absent optional digests
    // (including a null model snapshot) make no hash claim.
    for (path, collection, hash_fields) in [
        ("run_manifest.json", Some("inputs"), &["sha256"][..]),
        ("run_manifest.json", Some("outputs"), &["sha256"][..]),
        (
            "run_manifest.json",
            Some("model_calls"),
            &["input_hash", "output_hash"][..],
        ),
        (
            "inputs_snapshot/artifact_list.json",
            Some("artifacts"),
            &["sha256"][..],
        ),
        (
            "inputs_snapshot/model_snapshot.json",
            None,
            &["model_sha256"][..],
        ),
    ] {
        let index = match read_zip_entry_json(zip, path) {
            Ok(value) => value,
            Err(error) => {
                return fail(
                    "CHK.ARTIFACT_HASHES.VERIFY",
                    format!("failed to read {path}: {error}"),
                );
            }
        };
        let entries = match collection {
            Some(name) => index
                .get(name)
                .and_then(|value| value.as_array())
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            None => std::slice::from_ref(&index),
        };
        for entry in entries {
            for field in hash_fields {
                if let Some(hash_value) = entry.get(*field) {
                    let Some(hash) = hash_value.as_str() else {
                        return fail(
                            "CHK.ARTIFACT_HASHES.VERIFY",
                            format!("declared {field} is not a string in {path}"),
                        );
                    };
                    if !is_sha256_hex(hash) {
                        return fail(
                            "CHK.ARTIFACT_HASHES.VERIFY",
                            format!("malformed declared {field} in {path}"),
                        );
                    }
                }
            }
        }
    }

    // Verify each path present and hash matches when path is non-empty.
    for (artifact_id, p, sha, bytes_expected) in &rows {
        if p.is_empty() {
            continue;
        }
        if !paths.contains(p) {
            return fail(
                "CHK.ARTIFACT_HASHES.VERIFY",
                format!("missing path listed in csv: {}", p),
            );
        }
        let entry_bytes = match read_zip_entry_bytes(zip, p) {
            Ok(b) => b,
            Err(e) => {
                return fail(
                    "CHK.ARTIFACT_HASHES.VERIFY",
                    format!("failed to read {}: {}", p, e),
                );
            }
        };
        if entry_bytes.len() as u64 != *bytes_expected {
            return fail(
                "CHK.ARTIFACT_HASHES.VERIFY",
                format!("bytes mismatch for {} (expected {})", p, bytes_expected),
            );
        }
        let mut h = sha2::Sha256::new();
        h.update(&entry_bytes);
        let computed = hex::encode(h.finalize());
        if computed != *sha {
            return fail(
                "CHK.ARTIFACT_HASHES.VERIFY",
                format!("sha256 mismatch for {}", p),
            );
        }

        // If INCLUDE_INPUT_BYTES, enforce presence of inputs_snapshot/artifacts/<artifact_id>/bytes for input artifacts.
        if profile == "INCLUDE_INPUT_BYTES" && !artifact_id.starts_with("o:") {
            let in_path = format!("inputs_snapshot/artifacts/{}/bytes", artifact_id);
            if !paths.contains(&in_path) {
                return fail(
                    "CHK.ARTIFACT_HASHES.VERIFY",
                    format!("missing input bytes at {}", in_path),
                );
            }
        }
    }

    pass("CHK.ARTIFACT_HASHES.VERIFY")
}

fn check_model_pinning<R: Read + Seek>(zip: &mut ZipArchive<R>, policy: PolicyMode) -> CheckResult {
    let v = match read_zip_entry_json(zip, "inputs_snapshot/model_snapshot.json") {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.MODEL.PINNING_LEVEL",
                format!("failed to read model_snapshot: {}", e),
            );
        }
    };
    if v.is_null() {
        return pass("CHK.MODEL.PINNING_LEVEL");
    }
    let lvl = v
        .get("pinning_level")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let ok = match policy {
        PolicyMode::STRICT | PolicyMode::BALANCED => {
            lvl == "CRYPTO_PINNED" || lvl == "VERSION_PINNED"
        }
        PolicyMode::DRAFT_ONLY => {
            lvl == "CRYPTO_PINNED" || lvl == "VERSION_PINNED" || lvl == "NAME_ONLY"
        }
    };
    if ok {
        pass("CHK.MODEL.PINNING_LEVEL")
    } else {
        fail(
            "CHK.MODEL.PINNING_LEVEL",
            format!("pinning_level {} insufficient for policy", lvl),
        )
    }
}

fn check_run_snapshot_consistency<R: Read + Seek>(zip: &mut ZipArchive<R>) -> CheckResult {
    let model = match read_zip_entry_json(zip, "inputs_snapshot/model_snapshot.json") {
        Ok(value) => value,
        Err(error) => {
            return fail(
                "CHK.RUN.SNAPSHOT_CONSISTENCY",
                format!("failed to read model snapshot: {error}"),
            );
        }
    };
    let network = match read_zip_entry_json(zip, "inputs_snapshot/network_snapshot.json") {
        Ok(value) => value,
        Err(error) => {
            return fail(
                "CHK.RUN.SNAPSHOT_CONSISTENCY",
                format!("failed to read network snapshot: {error}"),
            );
        }
    };
    let manifest = match read_zip_entry_json(zip, "run_manifest.json") {
        Ok(value) => value,
        Err(error) => {
            return fail(
                "CHK.RUN.SNAPSHOT_CONSISTENCY",
                format!("failed to read run manifest: {error}"),
            );
        }
    };
    let Some(endpoints) = network.get("adapter_endpoints").and_then(|v| v.as_array()) else {
        return fail(
            "CHK.RUN.SNAPSHOT_CONSISTENCY",
            "adapter_endpoints must be an array".to_string(),
        );
    };
    let Some(calls) = manifest.get("model_calls").and_then(|v| v.as_array()) else {
        return fail(
            "CHK.RUN.SNAPSHOT_CONSISTENCY",
            "model_calls must be an array".to_string(),
        );
    };
    if model.is_null() {
        if !endpoints.is_empty() || !calls.is_empty() {
            return fail(
                "CHK.RUN.SNAPSHOT_CONSISTENCY",
                "model is absent but adapter endpoints or model calls were recorded".to_string(),
            );
        }
        return pass("CHK.RUN.SNAPSHOT_CONSISTENCY");
    }
    let endpoint = model
        .get("adapter_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let model_id = model.get("model_id").and_then(|v| v.as_str()).unwrap_or("");
    let adapter_version = model
        .get("adapter_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if endpoint.is_empty() || model_id.is_empty() || adapter_version.is_empty() {
        return fail(
            "CHK.RUN.SNAPSHOT_CONSISTENCY",
            "model snapshot is missing endpoint, model_id, or adapter_version".to_string(),
        );
    }
    if endpoints.len() != 1
        || endpoints[0].get("endpoint").and_then(|v| v.as_str()) != Some(endpoint)
    {
        return fail(
            "CHK.RUN.SNAPSHOT_CONSISTENCY",
            "model endpoint and adapter_endpoints must match exactly".to_string(),
        );
    }
    if crate::adapters::interface::enforce_loopback_endpoint(endpoint).is_err() {
        return fail(
            "CHK.RUN.SNAPSHOT_CONSISTENCY",
            "model adapter endpoint is not loopback".to_string(),
        );
    }
    if calls.is_empty()
        || calls.iter().any(|call| {
            call.get("model_id").and_then(|v| v.as_str()) != Some(model_id)
                || call.get("adapter_version").and_then(|v| v.as_str()) != Some(adapter_version)
        })
    {
        return fail(
            "CHK.RUN.SNAPSHOT_CONSISTENCY",
            "model calls are absent or disagree with model/version snapshot".to_string(),
        );
    }
    pass("CHK.RUN.SNAPSHOT_CONSISTENCY")
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_legacy_bundle_version(version: &str) -> bool {
    let mut parts = version.split('.').map(str::parse::<u64>);
    let (Some(Ok(major)), Some(Ok(minor)), Some(Ok(patch)), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return true;
    };
    (major, minor, patch) < (1, 1, 0)
}

fn overall_validation_status(checks: &[CheckResult], legacy_bundle: bool) -> &'static str {
    let has_blocker_failure = checks.iter().any(|check| {
        check.severity == "BLOCKER"
            && check.result != "PASS"
            && !(legacy_bundle
                && matches!(
                    check.check_id.as_str(),
                    "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT"
                        | "CHK.RUN.SNAPSHOT_CONSISTENCY"
                        | "CHK.NETWORK.PROOF_SOURCE"
                ))
    });
    if has_blocker_failure {
        "FAIL"
    } else if legacy_bundle {
        "LEGACY_UNVERIFIABLE"
    } else {
        "PASS"
    }
}

fn check_citations_strict<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    paths: &BTreeSet<String>,
    policy: PolicyMode,
) -> CheckResult {
    if policy != PolicyMode::STRICT {
        return CheckResult {
            check_id: "CHK.CITATIONS.STRICT".to_string(),
            severity: "BLOCKER".to_string(),
            result: "PASS".to_string(),
            message: "not applicable".to_string(),
        };
    }
    let citations_path = paths
        .iter()
        .find(|p| p.ends_with("attachments/citations_map.json"))
        .cloned();
    let citations_path = match citations_path {
        Some(p) => p,
        None => {
            return fail(
                "CHK.CITATIONS.STRICT",
                "missing citations_map.json".to_string(),
            );
        }
    };
    let v = match read_zip_entry_json(zip, &citations_path) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.CITATIONS.STRICT",
                format!("failed to read citations_map: {}", e),
            );
        }
    };
    let schema = v
        .get("schema_version")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if schema != "LOCATOR_SCHEMA_V1" {
        return fail(
            "CHK.CITATIONS.STRICT",
            format!("wrong schema_version {}", schema),
        );
    }
    // Minimal enforcement: ensure every claim marker in deliverable md has >=1 citation entry.
    // We'll parse deliverables md for <!-- CLAIM:C#### -->, and compare to claims list.
    let mut markers: BTreeSet<String> = BTreeSet::new();
    for p in paths {
        if p.starts_with("exports/") && p.contains("/deliverables/") && p.ends_with(".md") {
            if let Ok(b) = read_zip_entry_bytes(zip, p) {
                let s = String::from_utf8_lossy(&b);
                for cap in regex_find_claim_markers(&s) {
                    markers.insert(cap);
                }
            }
        }
    }
    let claims = v
        .get("claims")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut cited: BTreeSet<String> = BTreeSet::new();
    for c in claims {
        if let Some(cid) = c.get("claim_id").and_then(|x| x.as_str()) {
            let citations = c
                .get("citations")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            if !citations.is_empty() {
                cited.insert(cid.to_string());
            }
        }
    }
    let missing: Vec<String> = markers.difference(&cited).cloned().collect();
    if missing.is_empty() {
        pass("CHK.CITATIONS.STRICT")
    } else {
        fail(
            "CHK.CITATIONS.STRICT",
            format!("claims missing citations: {}", missing.join(", ")),
        )
    }
}

fn regex_find_claim_markers(s: &str) -> Vec<String> {
    // Strict marker format is locked: <!-- CLAIM:C#### -->
    // We'll do a minimal scan without pulling regex crate.
    let mut out = Vec::new();
    let needle = "<!-- CLAIM:";
    let mut idx = 0;
    while let Some(pos) = s[idx..].find(needle) {
        let start = idx + pos + needle.len();
        if let Some(end) = s[start..].find("-->") {
            let id = s[start..start + end].trim().to_string();
            if id.starts_with('C') {
                out.push(id);
            }
            idx = start + end + 3;
        } else {
            break;
        }
    }
    out
}

fn check_redaction_policy_gate<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    paths: &BTreeSet<String>,
    policy: PolicyMode,
) -> CheckResult {
    if policy == PolicyMode::DRAFT_ONLY {
        return CheckResult {
            check_id: "CHK.REDACTION.POLICY_GATE".to_string(),
            severity: "BLOCKER".to_string(),
            result: "PASS".to_string(),
            message: "not applicable".to_string(),
        };
    }
    let redactions_path = paths
        .iter()
        .find(|p| p.ends_with("attachments/redactions_map.json"))
        .cloned();
    if redactions_path.is_none() {
        return fail(
            "CHK.REDACTION.POLICY_GATE",
            "missing redactions_map.json".to_string(),
        );
    }
    let v = match read_zip_entry_json(zip, redactions_path.as_ref().unwrap()) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.REDACTION.POLICY_GATE",
                format!("failed to read redactions_map: {}", e),
            );
        }
    };
    let schema = v
        .get("schema_version")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if schema != "REDACTION_SCHEMA_V1" {
        return fail(
            "CHK.REDACTION.POLICY_GATE",
            format!("wrong schema_version {}", schema),
        );
    }

    let citations_path = match paths
        .iter()
        .find(|p| p.ends_with("attachments/citations_map.json"))
    {
        Some(p) => p.clone(),
        None => {
            return fail(
                "CHK.REDACTION.POLICY_GATE",
                "missing citations_map.json".to_string(),
            );
        }
    };
    let citations = match read_zip_entry_json(zip, &citations_path) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.REDACTION.POLICY_GATE",
                format!("failed to read citations_map: {}", e),
            );
        }
    };
    let artifact_list = match read_zip_entry_json(zip, "inputs_snapshot/artifact_list.json") {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.REDACTION.POLICY_GATE",
                format!("failed to read artifact_list.json: {}", e),
            );
        }
    };

    let mut sensitive_artifacts: BTreeSet<String> = BTreeSet::new();
    if let Some(arr) = artifact_list.get("artifacts").and_then(|x| x.as_array()) {
        for a in arr {
            let aid = a
                .get("artifact_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if aid.is_empty() {
                continue;
            }
            let classif = a
                .get("classification")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let mut tagged_sensitive = false;
            if let Some(tags) = a.get("tags").and_then(|x| x.as_array()) {
                for t in tags {
                    let ts = t.as_str().unwrap_or("");
                    if ts == "PII" || ts == "PHI" || ts == "PCI" || ts == "SECRET" {
                        tagged_sensitive = true;
                        break;
                    }
                }
            }
            if classif == "Restricted" || tagged_sensitive {
                sensitive_artifacts.insert(aid);
            }
        }
    }

    let mut redaction_index: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();
    if let Some(arts) = v.get("artifacts").and_then(|x| x.as_array()) {
        for a in arts {
            let aid = a
                .get("artifact_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let reds = a
                .get("redactions")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            redaction_index.entry(aid).or_default().extend(reds);
        }
    }

    let mut missing: Vec<String> = Vec::new();
    if let Some(claims) = citations.get("claims").and_then(|x| x.as_array()) {
        for claim in claims {
            let claim_id = claim
                .get("claim_id")
                .and_then(|x| x.as_str())
                .unwrap_or("UNKNOWN");
            let cits = claim
                .get("citations")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            for c in cits {
                let aid = c.get("artifact_id").and_then(|x| x.as_str()).unwrap_or("");
                if aid.is_empty() || !sensitive_artifacts.contains(aid) {
                    continue;
                }
                let c_locator_type = c.get("locator_type").and_then(|x| x.as_str()).unwrap_or("");
                let c_locator = c.get("locator").cloned().unwrap_or(serde_json::Value::Null);
                let reds = redaction_index.get(aid).cloned().unwrap_or_default();
                let covered = reds
                    .iter()
                    .any(|r| redaction_covers_citation(r, c_locator_type, &c_locator));
                if !covered {
                    missing.push(format!("{}:{}", claim_id, aid));
                }
            }
        }
    }

    if missing.is_empty() {
        pass("CHK.REDACTION.POLICY_GATE")
    } else {
        fail(
            "CHK.REDACTION.POLICY_GATE",
            format!(
                "missing required redaction coverage for {}",
                missing.join(", ")
            ),
        )
    }
}

fn redaction_covers_citation(
    redaction: &serde_json::Value,
    c_locator_type: &str,
    c_locator: &serde_json::Value,
) -> bool {
    let r_type = redaction
        .get("redaction_type")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let r_region = redaction
        .get("region")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    match (r_type, c_locator_type) {
        ("TEXT_SPAN", "PDF_TEXT_SPAN_V1") => {
            let rs = r_region
                .get("start_char")
                .and_then(|x| x.as_i64())
                .unwrap_or(-1);
            let re = r_region
                .get("end_char")
                .and_then(|x| x.as_i64())
                .unwrap_or(-1);
            let cs = c_locator
                .get("start_char")
                .and_then(|x| x.as_i64())
                .unwrap_or(-1);
            let ce = c_locator
                .get("end_char")
                .and_then(|x| x.as_i64())
                .unwrap_or(-1);
            rs >= 0 && re >= 0 && cs >= 0 && ce >= 0 && rs <= cs && re >= ce
        }
        ("IMAGE_BBOX", "IMAGE_BBOX_V1") | ("IMAGE_BBOX", "PDF_BBOX_V1") => {
            let rb = r_region
                .get("bbox")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let cb = c_locator
                .get("bbox")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            bbox_contains(&rb, &cb)
        }
        _ => false,
    }
}

fn bbox_contains(outer: &serde_json::Value, inner: &serde_json::Value) -> bool {
    let ox = outer.get("x").and_then(|x| x.as_f64()).unwrap_or(-1.0);
    let oy = outer.get("y").and_then(|x| x.as_f64()).unwrap_or(-1.0);
    let ow = outer.get("w").and_then(|x| x.as_f64()).unwrap_or(-1.0);
    let oh = outer.get("h").and_then(|x| x.as_f64()).unwrap_or(-1.0);
    let ix = inner.get("x").and_then(|x| x.as_f64()).unwrap_or(-1.0);
    let iy = inner.get("y").and_then(|x| x.as_f64()).unwrap_or(-1.0);
    let iw = inner.get("w").and_then(|x| x.as_f64()).unwrap_or(-1.0);
    let ih = inner.get("h").and_then(|x| x.as_f64()).unwrap_or(-1.0);
    if ox < 0.0 || oy < 0.0 || ow < 0.0 || oh < 0.0 || ix < 0.0 || iy < 0.0 || iw < 0.0 || ih < 0.0
    {
        return false;
    }
    let orx = ox + ow;
    let ory = oy + oh;
    let irx = ix + iw;
    let iry = iy + ih;
    ox <= ix && oy <= iy && orx >= irx && ory >= iry
}

fn check_eval_report<R: Read + Seek>(zip: &mut ZipArchive<R>, policy: PolicyMode) -> CheckResult {
    let report: EvalReport = match read_zip_entry_json(zip, "eval_report.json")
        .and_then(|value| serde_json::from_value(value).map_err(CoreError::from))
    {
        Ok(report) => report,
        Err(error) => {
            return fail(
                "CHK.EVAL.REPORT_AND_GATES",
                format!("failed to read eval_report.json: {}", error),
            );
        }
    };
    let manifest = match read_zip_entry_json(zip, "run_manifest.json") {
        Ok(manifest) => manifest,
        Err(error) => {
            return fail(
                "CHK.EVAL.REPORT_AND_GATES",
                format!("failed to read run_manifest.json: {}", error),
            );
        }
    };
    let manifest_gate_status = match manifest
        .pointer("/eval/gate_status")
        .and_then(|v| v.as_str())
    {
        Some(status) => status,
        None => {
            return fail(
                "CHK.EVAL.REPORT_AND_GATES",
                "run_manifest.json is missing string eval.gate_status".to_string(),
            );
        }
    };
    let bundle_info = match read_zip_entry_json(zip, "BUNDLE_INFO.json") {
        Ok(bundle_info) => bundle_info,
        Err(error) => {
            return fail(
                "CHK.EVAL.REPORT_AND_GATES",
                format!("failed to read BUNDLE_INFO.json: {}", error),
            );
        }
    };
    let pack_id = match bundle_info.get("pack_id").and_then(|v| v.as_str()) {
        Some(pack_id) if !pack_id.is_empty() => pack_id,
        _ => {
            return fail(
                "CHK.EVAL.REPORT_AND_GATES",
                "BUNDLE_INFO.json is missing string pack_id".to_string(),
            );
        }
    };

    match validate_eval_report(&report, manifest_gate_status, policy, pack_id) {
        Ok(()) => pass("CHK.EVAL.REPORT_AND_GATES"),
        Err(message) => fail("CHK.EVAL.REPORT_AND_GATES", message),
    }
}

fn check_eval_report_preflight<R: Read + Seek>(zip: &mut ZipArchive<R>) -> CheckResult {
    let report: EvalReport = match read_zip_entry_json(zip, "eval_report.json")
        .and_then(|value| serde_json::from_value(value).map_err(CoreError::from))
    {
        Ok(report) => report,
        Err(error) => {
            return fail(
                "CHK.EVAL.REPORT_AND_GATES",
                format!("failed to read preflight eval_report.json: {}", error),
            );
        }
    };
    if report.registry_version != "gates_registry_v3" {
        return fail(
            "CHK.EVAL.REPORT_AND_GATES",
            format!(
                "evaluation preflight requires gates_registry_v3, found {}",
                report.registry_version
            ),
        );
    }
    CheckResult {
        check_id: "CHK.EVAL.REPORT_AND_GATES".to_string(),
        severity: "BLOCKER".to_string(),
        result: "PASS".to_string(),
        message: "deferred during non-authorizing evaluation preflight".to_string(),
    }
}

fn validate_eval_report(
    report: &EvalReport,
    manifest_gate_status: &str,
    policy: PolicyMode,
    pack_id: &str,
) -> Result<(), String> {
    match report.registry_version.as_str() {
        "gates_registry_v3" => {}
        "gates_registry_v1" | "gates_registry_v2" => {
            return Err(format!(
                "legacy {} is inspectable but non-authorizing; re-evaluate with gates_registry_v3",
                report.registry_version
            ));
        }
        other => return Err(format!("unsupported registry_version {}", other)),
    }
    if !matches!(report.overall_status.as_str(), "PASS" | "FAIL" | "WARN") {
        return Err(format!("invalid overall_status {}", report.overall_status));
    }
    if report.gates.is_empty() {
        return Err("missing applicable gates: eval report gate set is empty".to_string());
    }

    let registry = crate::eval::registry::registry_v3()
        .map_err(|error| format!("failed to load gate registry: {}", error))?;
    let known: BTreeMap<&str, _> = registry
        .gates
        .iter()
        .map(|gate| (gate.gate_id.as_str(), gate))
        .collect();
    let mut actual = BTreeSet::new();

    for gate in &report.gates {
        if gate.gate_id.trim().is_empty() {
            return Err("eval report contains an empty gate_id".to_string());
        }
        if !actual.insert(gate.gate_id.as_str()) {
            return Err(format!(
                "duplicate gate_id in eval report: {}",
                gate.gate_id
            ));
        }
        let definition = known
            .get(gate.gate_id.as_str())
            .ok_or_else(|| format!("unknown gate_id in eval_report: {}", gate.gate_id))?;
        let valid_status = matches!(gate.status.as_str(), "PASS" | "FAIL" | "NOT_APPLICABLE");
        if !valid_status {
            return Err(format!(
                "invalid status {} for gate {}",
                gate.status, gate.gate_id
            ));
        }
        if gate.status == "NOT_APPLICABLE"
            && !crate::eval::registry::not_applicable_allowed(&gate.gate_id, Some(pack_id))
        {
            return Err(format!(
                "NOT_APPLICABLE is not allowed for gate {} in pack {}",
                gate.gate_id, pack_id
            ));
        }
        let reported_rank = eval_severity_rank(&gate.severity).ok_or_else(|| {
            format!(
                "invalid severity {} for gate {}",
                gate.severity, gate.gate_id
            )
        })?;

        let registry_rank = eval_severity_rank(&definition.severity).ok_or_else(|| {
            format!(
                "invalid registry severity {} for gate {}",
                definition.severity, definition.gate_id
            )
        })?;
        if gate.category != definition.category {
            return Err(format!(
                "category mismatch for gate {}: {} != {}",
                gate.gate_id, gate.category, definition.category
            ));
        }
        if reported_rank < registry_rank {
            return Err(format!(
                "severity downgrade for gate {}: {} below {}",
                gate.gate_id, gate.severity, definition.severity
            ));
        }
        let mut reported_evidence = gate.evidence_pointers.clone();
        let mut registry_evidence = definition.evidence_required.clone();
        reported_evidence.sort();
        registry_evidence.sort();
        if reported_evidence != registry_evidence {
            return Err(format!(
                "evidence pointers do not match registry for gate {}",
                gate.gate_id
            ));
        }
    }

    let policy_name = format!("{policy:?}");
    let expected: BTreeSet<&str> = registry
        .gates
        .iter()
        .filter(|gate| gate.applies_to_policies.contains(&policy_name))
        .map(|gate| gate.gate_id.as_str())
        .collect();
    let missing: Vec<&str> = expected.difference(&actual).copied().collect();
    if !missing.is_empty() {
        return Err(format!("missing applicable gates: {}", missing.join(", ")));
    }
    let unexpected: Vec<&str> = actual.difference(&expected).copied().collect();
    if !unexpected.is_empty() {
        return Err(format!(
            "gates not applicable to {}: {}",
            policy_name,
            unexpected.join(", ")
        ));
    }

    let expected_overall = eval_overall_status(&report.gates);
    if report.overall_status != expected_overall {
        return Err(format!(
            "overall_status {} does not match gate results {}",
            report.overall_status, expected_overall
        ));
    }
    if manifest_gate_status != report.overall_status {
        return Err(format!(
            "run_manifest eval.gate_status {} does not match eval report {}",
            manifest_gate_status, report.overall_status
        ));
    }
    if report.overall_status == "FAIL" {
        return Err("eval report contains blocker gate failures".to_string());
    }
    Ok(())
}

fn eval_severity_rank(severity: &str) -> Option<u8> {
    match severity {
        "MINOR" => Some(1),
        "MAJOR" => Some(2),
        "BLOCKER" => Some(3),
        _ => None,
    }
}

fn eval_overall_status(gates: &[EvalGateResult]) -> &'static str {
    if gates
        .iter()
        .any(|gate| gate.status == "FAIL" && gate.severity == "BLOCKER")
    {
        "FAIL"
    } else if gates
        .iter()
        .any(|gate| matches!(gate.status.as_str(), "FAIL" | "WARN"))
    {
        "WARN"
    } else {
        "PASS"
    }
}

fn check_zip_determinism<R: Read + Seek>(zip: &mut ZipArchive<R>) -> CheckResult {
    let policy = match read_zip_entry_json(zip, "inputs_snapshot/policy_snapshot.json") {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.DETERMINISM.ZIP_RULES",
                format!("failed to read policy_snapshot: {}", e),
            );
        }
    };
    let determinism_enabled = policy
        .pointer("/determinism/enabled")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    if !determinism_enabled {
        return CheckResult {
            check_id: "CHK.DETERMINISM.ZIP_RULES".to_string(),
            severity: "MAJOR".to_string(),
            result: "PASS".to_string(),
            message: "not applicable".to_string(),
        };
    }

    // Enforce lock addendum + determinism matrix for zip packaging:
    // sorted entry names, fixed timestamp, fixed compression, normalized modes, empty comment.
    if !zip.comment().is_empty() {
        return fail(
            "CHK.DETERMINISM.ZIP_RULES",
            "zip comment must be empty".to_string(),
        );
    }

    let fixed_time = match zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0) {
        Ok(t) => t,
        Err(_) => {
            return fail(
                "CHK.DETERMINISM.ZIP_RULES",
                "failed to construct fixed timestamp for comparison".to_string(),
            );
        }
    };

    let mut names: Vec<String> = Vec::new();
    for i in 0..zip.len() {
        let f = match zip.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                return fail(
                    "CHK.DETERMINISM.ZIP_RULES",
                    format!("zip read error: {}", e),
                );
            }
        };
        names.push(f.name().to_string());

        if f.is_file() && f.compression() != zip::CompressionMethod::Deflated {
            return fail(
                "CHK.DETERMINISM.ZIP_RULES",
                format!("entry {} is not DEFLATE-compressed", f.name()),
            );
        }
        let lm = match f.last_modified() {
            Some(v) => v,
            None => {
                return fail(
                    "CHK.DETERMINISM.ZIP_RULES",
                    format!("entry {} missing last_modified timestamp", f.name()),
                );
            }
        };
        if lm != fixed_time {
            return fail(
                "CHK.DETERMINISM.ZIP_RULES",
                format!("entry {} has non-fixed timestamp", f.name()),
            );
        }

        if let Some(mode) = f.unix_mode() {
            let perm_bits = mode & 0o777;
            let expected = if f.is_dir() { 0o755 } else { 0o644 };
            if perm_bits != expected {
                return fail(
                    "CHK.DETERMINISM.ZIP_RULES",
                    format!(
                        "entry {} has mode {:o}, expected {:o}",
                        f.name(),
                        perm_bits,
                        expected
                    ),
                );
            }
        }
    }
    let mut sorted = names.clone();
    sorted.sort();
    if sorted != names {
        return fail(
            "CHK.DETERMINISM.ZIP_RULES",
            "zip entries not lexicographically sorted".to_string(),
        );
    }
    pass("CHK.DETERMINISM.ZIP_RULES")
}

fn check_vault_crypto_policy_snapshot<R: Read + Seek>(zip: &mut ZipArchive<R>) -> CheckResult {
    let v = match read_zip_entry_json(zip, "inputs_snapshot/policy_snapshot.json") {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
                format!("failed to read policy_snapshot: {}", e),
            );
        }
    };
    let Some(enc) = v.get("encryption_at_rest").and_then(|x| x.as_bool()) else {
        return fail(
            "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
            "encryption_at_rest must be present and boolean".to_string(),
        );
    };
    let alg_value = v.get("encryption_algorithm");
    if let Some(value) = alg_value {
        if !value.is_null() && !value.is_string() {
            return fail(
                "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
                "encryption_algorithm must be a string or null".to_string(),
            );
        }
    }
    let alg = alg_value.and_then(|x| x.as_str());
    let accepted_alg = alg
        .map(|value| value == "XCHACHA20_POLY1305" || value == "AES_256_GCM")
        .unwrap_or(false);
    if !enc && alg.is_some() {
        fail(
            "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
            "encryption algorithm is present while encryption_at_rest is false".to_string(),
        )
    } else if !enc {
        let events = vault_status_events(zip);
        if events.iter().any(|event| {
            event
                .get("details")
                .and_then(|d| d.get("encryption_at_rest"))
                .and_then(|x| x.as_bool())
                == Some(true)
        }) {
            fail(
                "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
                "vault status claims encryption while snapshot says it was unused".to_string(),
            )
        } else {
            pass("CHK.VAULT_CRYPTO.POLICY_SNAPSHOT")
        }
    } else if !accepted_alg {
        fail(
            "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
            "encryption_at_rest requires an accepted encryption algorithm".to_string(),
        )
    } else {
        let manifest = match read_zip_entry_json(zip, "run_manifest.json") {
            Ok(value) => value,
            Err(error) => {
                return fail(
                    "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
                    format!("failed to read run_manifest.json: {error}"),
                );
            }
        };
        let run_id = manifest
            .get("run_id")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let vault_id = manifest
            .get("vault_id")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if run_id.is_empty() || vault_id.is_empty() {
            return fail(
                "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
                "encrypted vault evidence requires manifest run_id and vault_id".to_string(),
            );
        }
        // Ensure audit has VAULT_ENCRYPTION_STATUS and accepted key_storage values.
        let bytes = match read_zip_entry_bytes(zip, "audit_log.ndjson") {
            Ok(b) => b,
            Err(e) => {
                return fail(
                    "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
                    format!("failed to read audit_log.ndjson: {}", e),
                );
            }
        };
        let s = String::from_utf8_lossy(&bytes);
        let mut found = false;
        for line in s.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("event_type").and_then(|x| x.as_str()) == Some("VAULT_ENCRYPTION_STATUS") {
                let ks = v
                    .get("details")
                    .and_then(|d| d.get("key_storage"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                let event_alg = v
                    .get("details")
                    .and_then(|d| d.get("algorithm"))
                    .and_then(|x| x.as_str());
                let event_encrypted = v
                    .get("details")
                    .and_then(|d| d.get("encryption_at_rest"))
                    .and_then(|x| x.as_bool());
                let ids_match = v.get("run_id").and_then(|x| x.as_str()) == Some(run_id)
                    && v.get("vault_id").and_then(|x| x.as_str()) == Some(vault_id);
                if (ks == "MACOS_KEYCHAIN" || ks == "WINDOWS_DPAPI" || ks == "FILE_FALLBACK")
                    && event_encrypted == Some(true)
                    && event_alg == alg
                    && ids_match
                {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return fail(
                "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
                "missing VAULT_ENCRYPTION_STATUS with key_storage".to_string(),
            );
        }
        pass("CHK.VAULT_CRYPTO.POLICY_SNAPSHOT")
    }
}

fn vault_status_events<R: Read + Seek>(zip: &mut ZipArchive<R>) -> Vec<serde_json::Value> {
    let Ok(manifest) = read_zip_entry_json(zip, "run_manifest.json") else {
        return Vec::new();
    };
    let run_id = manifest.get("run_id").and_then(|value| value.as_str());
    let vault_id = manifest.get("vault_id").and_then(|value| value.as_str());
    if run_id.is_none_or(str::is_empty) || vault_id.is_none_or(str::is_empty) {
        return Vec::new();
    }
    let Ok(bytes) = read_zip_entry_bytes(zip, "audit_log.ndjson") else {
        return Vec::new();
    };
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| {
            event.get("event_type").and_then(|value| value.as_str())
                == Some("VAULT_ENCRYPTION_STATUS")
                && event.get("run_id").and_then(|value| value.as_str()) == run_id
                && event.get("vault_id").and_then(|value| value.as_str()) == vault_id
        })
        .collect()
}

fn check_network_proof_source<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    legacy_bundle: bool,
) -> CheckResult {
    let network = match read_zip_entry_json(zip, "inputs_snapshot/network_snapshot.json") {
        Ok(value) => value,
        Err(error) => {
            return fail(
                "CHK.NETWORK.PROOF_SOURCE",
                format!("failed to read network snapshot: {error}"),
            );
        }
    };
    let Some(source) = network.get("proof_source").and_then(|value| value.as_str()) else {
        return if legacy_bundle {
            CheckResult {
                check_id: "CHK.NETWORK.PROOF_SOURCE".to_string(),
                severity: "INFO".to_string(),
                result: "PASS".to_string(),
                message:
                    "legacy network snapshot has no proof_source; its claims remain unverifiable"
                        .to_string(),
            }
        } else {
            fail(
                "CHK.NETWORK.PROOF_SOURCE",
                "proof_source must be POLICY_DECLARATION".to_string(),
            )
        };
    };
    if source != "POLICY_DECLARATION" {
        return fail(
            "CHK.NETWORK.PROOF_SOURCE",
            format!("unsupported proof_source {source}"),
        );
    }
    let offline = network.get("network_mode").and_then(|value| value.as_str()) == Some("OFFLINE")
        && network.get("proof_level").and_then(|value| value.as_str()) == Some("OFFLINE_STRICT")
        && network
            .get("allowlist")
            .and_then(|value| value.as_array())
            .is_some_and(Vec::is_empty)
        && network
            .get("ui_remote_fetch_disabled")
            .and_then(|value| value.as_bool())
            == Some(true)
        && network
            .get("adapter_endpoints")
            .and_then(|value| value.as_array())
            .is_some_and(|endpoints| {
                endpoints.iter().all(|endpoint| {
                    endpoint
                        .get("is_loopback")
                        .and_then(|value| value.as_bool())
                        == Some(true)
                        && endpoint
                            .get("endpoint")
                            .and_then(|value| value.as_str())
                            .is_some_and(|value| {
                                crate::adapters::interface::enforce_loopback_endpoint(value).is_ok()
                            })
                })
            });
    if offline {
        pass("CHK.NETWORK.PROOF_SOURCE")
    } else {
        fail("CHK.NETWORK.PROOF_SOURCE", "POLICY_DECLARATION requires OFFLINE/OFFLINE_STRICT, an empty allowlist, and disabled UI remote fetch".to_string())
    }
}

fn pass(check_id: &str) -> CheckResult {
    CheckResult {
        check_id: check_id.to_string(),
        severity: "BLOCKER".to_string(),
        result: "PASS".to_string(),
        message: "ok".to_string(),
    }
}

fn fail(check_id: &str, msg: String) -> CheckResult {
    CheckResult {
        check_id: check_id.to_string(),
        severity: "BLOCKER".to_string(),
        result: "FAIL".to_string(),
        message: msg,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_model_pinning, check_network_proof_source, check_run_snapshot_consistency,
        check_vault_crypto_policy_snapshot, is_legacy_bundle_version, is_sha256_hex,
        overall_validation_status, validate_archive_limits, validate_eval_report,
        ValidationSummary, MAX_ARCHIVE_ENTRIES, MAX_ENTRY_BYTES,
    };
    use crate::evidence_bundle::schemas::{EvalGateResult, EvalReport};
    use crate::policy::types::PolicyMode;
    use std::io::{Cursor, Write};
    use zip::{write::FileOptions, ZipArchive, ZipWriter};

    fn archive(entries: &[(&str, &str)]) -> ZipArchive<Cursor<Vec<u8>>> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (path, contents) in entries {
            writer
                .start_file(path, FileOptions::<()>::default())
                .unwrap();
            writer.write_all(contents.as_bytes()).unwrap();
        }
        ZipArchive::new(writer.finish().unwrap()).unwrap()
    }

    #[test]
    fn truthful_unused_crypto_and_no_model_are_accepted() {
        let mut zip = archive(&[
            (
                "inputs_snapshot/policy_snapshot.json",
                r#"{"encryption_at_rest":false,"encryption_algorithm":null}"#,
            ),
            ("audit_log.ndjson", ""),
            ("inputs_snapshot/model_snapshot.json", "null"),
            (
                "inputs_snapshot/network_snapshot.json",
                r#"{"adapter_endpoints":[]}"#,
            ),
            ("run_manifest.json", r#"{"model_calls":[]}"#),
        ]);
        assert_eq!(check_vault_crypto_policy_snapshot(&mut zip).result, "PASS");
        assert_eq!(check_run_snapshot_consistency(&mut zip).result, "PASS");
        assert_eq!(
            check_model_pinning(&mut zip, PolicyMode::STRICT).result,
            "PASS"
        );
    }

    #[test]
    fn zip_resource_limits_reject_count_entry_ratio_total_and_archive_size() {
        let too_many = vec![("entry".to_string(), 1, 1); MAX_ARCHIVE_ENTRIES + 1];
        assert!(validate_archive_limits(1, &too_many)
            .unwrap_err()
            .to_string()
            .contains("ENTRY_COUNT_LIMIT"));

        assert!(
            validate_archive_limits(1, &[("large".into(), MAX_ENTRY_BYTES + 1, 1)])
                .unwrap_err()
                .to_string()
                .contains("ENTRY_SIZE_LIMIT")
        );
        assert!(validate_archive_limits(1, &[("bomb".into(), 2_000, 1)])
            .unwrap_err()
            .to_string()
            .contains("COMPRESSION_RATIO_LIMIT"));
        assert!(
            validate_archive_limits(1, &vec![("a".into(), MAX_ENTRY_BYTES, 100_000); 5])
                .unwrap_err()
                .to_string()
                .contains("TOTAL_SIZE_LIMIT")
        );
        assert!(validate_archive_limits(super::MAX_ARCHIVE_BYTES + 1, &[])
            .unwrap_err()
            .to_string()
            .contains("ARCHIVE_SIZE_LIMIT"));
    }

    #[test]
    fn crypto_claim_requires_matching_encrypted_vault_status() {
        let mut zip = archive(&[
            (
                "inputs_snapshot/policy_snapshot.json",
                r#"{"encryption_at_rest":true,"encryption_algorithm":"AES_256_GCM"}"#,
            ),
            (
                "audit_log.ndjson",
                r#"{"event_type":"VAULT_ENCRYPTION_STATUS","run_id":"run-1","vault_id":"vault-1","details":{"encryption_at_rest":true,"algorithm":"XCHACHA20_POLY1305","key_storage":"MACOS_KEYCHAIN"}}"#,
            ),
            (
                "run_manifest.json",
                r#"{"run_id":"run-1","vault_id":"vault-1"}"#,
            ),
        ]);
        let result = check_vault_crypto_policy_snapshot(&mut zip);
        assert_eq!(result.result, "FAIL");
        assert!(result.message.contains("missing VAULT_ENCRYPTION_STATUS"));

        let mut contradictory_unused = archive(&[
            (
                "inputs_snapshot/policy_snapshot.json",
                r#"{"encryption_at_rest":false,"encryption_algorithm":null}"#,
            ),
            (
                "audit_log.ndjson",
                r#"{"event_type":"VAULT_ENCRYPTION_STATUS","run_id":"run-1","vault_id":"vault-1","details":{"encryption_at_rest":true,"algorithm":"AES_256_GCM","key_storage":"MACOS_KEYCHAIN"}}"#,
            ),
            (
                "run_manifest.json",
                r#"{"run_id":"run-1","vault_id":"vault-1"}"#,
            ),
        ]);
        let contradictory = check_vault_crypto_policy_snapshot(&mut contradictory_unused);
        assert_eq!(contradictory.result, "FAIL");
        assert!(contradictory
            .message
            .contains("snapshot says it was unused"));
    }

    #[test]
    fn crypto_event_must_match_run_and_vault_identity() {
        let policy = r#"{"encryption_at_rest":true,"encryption_algorithm":"AES_256_GCM"}"#;
        let event = r#"{"event_type":"VAULT_ENCRYPTION_STATUS","run_id":"run-1","vault_id":"vault-1","details":{"encryption_at_rest":true,"algorithm":"AES_256_GCM","key_storage":"MACOS_KEYCHAIN"}}"#;
        let manifest = r#"{"run_id":"run-1","vault_id":"vault-1"}"#;
        let mut matching = archive(&[
            ("inputs_snapshot/policy_snapshot.json", policy),
            ("run_manifest.json", manifest),
            ("audit_log.ndjson", event),
        ]);
        assert_eq!(
            check_vault_crypto_policy_snapshot(&mut matching).result,
            "PASS"
        );

        let wrong_run = event.replace("run-1", "run-other");
        let mut wrong_run_archive = archive(&[
            ("inputs_snapshot/policy_snapshot.json", policy),
            ("run_manifest.json", manifest),
            ("audit_log.ndjson", &wrong_run),
        ]);
        assert_eq!(
            check_vault_crypto_policy_snapshot(&mut wrong_run_archive).result,
            "FAIL"
        );

        let wrong_vault = event.replace("vault-1", "vault-other");
        let mut wrong_vault_archive = archive(&[
            ("inputs_snapshot/policy_snapshot.json", policy),
            ("run_manifest.json", manifest),
            ("audit_log.ndjson", &wrong_vault),
        ]);
        assert_eq!(
            check_vault_crypto_policy_snapshot(&mut wrong_vault_archive).result,
            "FAIL"
        );
    }

    #[test]
    fn encryption_fields_must_have_explicit_types() {
        for snapshot in [
            r#"{"encryption_algorithm":null}"#,
            r#"{"encryption_at_rest":"false","encryption_algorithm":null}"#,
            r#"{"encryption_at_rest":false,"encryption_algorithm":5}"#,
        ] {
            let mut zip = archive(&[("inputs_snapshot/policy_snapshot.json", snapshot)]);
            assert_eq!(check_vault_crypto_policy_snapshot(&mut zip).result, "FAIL");
        }
    }

    #[test]
    fn model_endpoint_must_match_the_single_recorded_adapter_and_call() {
        let snapshot = r#"{"adapter_endpoint":"http://127.0.0.1:11434","adapter_version":"1.0","model_id":"model-a","pinning_level":"VERSION_PINNED"}"#;
        let call = r#"{"model_id":"model-a","adapter_version":"1.0"}"#;
        let mut missing = archive(&[
            ("inputs_snapshot/model_snapshot.json", snapshot),
            (
                "inputs_snapshot/network_snapshot.json",
                r#"{"adapter_endpoints":[]}"#,
            ),
            (
                "run_manifest.json",
                r#"{"model_calls":[{"model_id":"model-a","adapter_version":"1.0"}]}"#,
            ),
        ]);
        assert_eq!(check_run_snapshot_consistency(&mut missing).result, "FAIL");

        let mut extra = archive(&[
            ("inputs_snapshot/model_snapshot.json", snapshot),
            (
                "inputs_snapshot/network_snapshot.json",
                r#"{"adapter_endpoints":[{"endpoint":"http://127.0.0.1:11434"},{"endpoint":"http://127.0.0.1:11435"}]}"#,
            ),
            (
                "run_manifest.json",
                r#"{"model_calls":[{"model_id":"model-a","adapter_version":"1.0"}]}"#,
            ),
        ]);
        assert_eq!(check_run_snapshot_consistency(&mut extra).result, "FAIL");

        let mut matching = archive(&[
            ("inputs_snapshot/model_snapshot.json", snapshot),
            (
                "inputs_snapshot/network_snapshot.json",
                r#"{"adapter_endpoints":[{"endpoint":"http://127.0.0.1:11434"}]}"#,
            ),
            (
                "run_manifest.json",
                &format!(r#"{{"model_calls":[{}]}}"#, call),
            ),
        ]);
        assert_eq!(check_run_snapshot_consistency(&mut matching).result, "PASS");
    }

    #[test]
    fn model_endpoint_uses_shared_literal_loopback_validation() {
        for (endpoint, expected) in [
            ("http://127.2.3.4:11434", "PASS"),
            ("http://192.168.1.2:11434", "FAIL"),
            ("http://127.0.0.1.evil:11434", "FAIL"),
        ] {
            let model = format!(
                r#"{{"adapter_endpoint":"{endpoint}","adapter_version":"1.0","model_id":"model-a","pinning_level":"VERSION_PINNED"}}"#
            );
            let network = format!(
                r#"{{"adapter_endpoints":[{{"endpoint":"{endpoint}","is_loopback":true}}]}}"#
            );
            let mut zip = archive(&[
                ("inputs_snapshot/model_snapshot.json", &model),
                ("inputs_snapshot/network_snapshot.json", &network),
                (
                    "run_manifest.json",
                    r#"{"model_calls":[{"model_id":"model-a","adapter_version":"1.0"}]}"#,
                ),
            ]);
            assert_eq!(check_run_snapshot_consistency(&mut zip).result, expected);
        }
    }

    #[test]
    fn unused_model_requires_explicit_model_and_adapter_arrays() {
        let cases = [
            (r#"{"adapter_endpoints":[]}"#, r#"{"model_calls":{}}"#),
            (r#"{"adapter_endpoints":[]}"#, r#"{}"#),
            (r#"{}"#, r#"{"model_calls":[]}"#),
        ];
        for (network, manifest) in cases {
            let mut zip = archive(&[
                ("inputs_snapshot/model_snapshot.json", "null"),
                ("inputs_snapshot/network_snapshot.json", network),
                ("run_manifest.json", manifest),
            ]);
            assert_eq!(check_run_snapshot_consistency(&mut zip).result, "FAIL");
        }
    }

    #[test]
    fn declared_sha256_and_legacy_version_are_explicitly_classified() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex("demo_sha256"));
        assert!(is_legacy_bundle_version("1.0.0"));
        assert!(!is_legacy_bundle_version("1.1.0"));
        assert!(!is_legacy_bundle_version("1.2.0"));
    }

    #[test]
    fn malformed_declared_hash_is_rejected_from_artifact_hash_csv() {
        let mut zip = archive(&[
            (
                "artifact_hashes.csv",
                "artifact_id,bundle_rel_path,sha256,bytes\na,,demo_sha256,0\n",
            ),
            (
                "inputs_snapshot/policy_snapshot.json",
                r#"{"export_profile":{"inputs":"OMIT_INPUT_BYTES"}}"#,
            ),
            ("run_manifest.json", r#"{"inputs":[]}"#),
            ("inputs_snapshot/artifact_list.json", r#"{"artifacts":[]}"#),
        ]);
        let result = super::check_artifact_hashes(&mut zip, &std::collections::BTreeSet::new());
        assert_eq!(result.result, "FAIL");
        assert!(result.message.contains("malformed declared sha256"));

        let mut empty = archive(&[
            (
                "artifact_hashes.csv",
                "artifact_id,bundle_rel_path,sha256,bytes\na,, ,0\n",
            ),
            (
                "inputs_snapshot/policy_snapshot.json",
                r#"{"export_profile":{"inputs":"OMIT_INPUT_BYTES"}}"#,
            ),
            ("run_manifest.json", r#"{"inputs":[]}"#),
            ("inputs_snapshot/artifact_list.json", r#"{"artifacts":[]}"#),
        ]);
        assert_eq!(
            super::check_artifact_hashes(&mut empty, &std::collections::BTreeSet::new()).result,
            "FAIL"
        );
    }

    #[test]
    fn legacy_old_model_stamp_is_inspectable_but_never_truthful() {
        let mut old_bundle = archive(&[
            ("BUNDLE_INFO.json", r#"{"bundle_version":"1.0.0"}"#),
            (
                "inputs_snapshot/model_snapshot.json",
                r#"{"adapter_endpoint":"http://127.0.0.1:11434","adapter_version":"1.0.0","model_id":"model-a","pinning_level":"VERSION_PINNED"}"#,
            ),
            (
                "inputs_snapshot/network_snapshot.json",
                r#"{"adapter_endpoints":[]}"#,
            ),
            ("run_manifest.json", r#"{"model_calls":[]}"#),
        ]);
        let info = super::read_zip_entry_json(&mut old_bundle, "BUNDLE_INFO.json").unwrap();
        let legacy = info
            .get("bundle_version")
            .and_then(|value| value.as_str())
            .map(is_legacy_bundle_version)
            .unwrap();
        let model_check = check_run_snapshot_consistency(&mut old_bundle);
        assert_eq!(model_check.result, "FAIL");
        let summary = ValidationSummary {
            checklist_version: "test".to_string(),
            policy: "STRICT".to_string(),
            overall: overall_validation_status(&[model_check], legacy).to_string(),
            checks: Vec::new(),
        };
        assert_eq!(summary.overall, "LEGACY_UNVERIFIABLE");
        let unrelated_blocker =
            super::fail("CHK.AUDIT.REQUIRED_KEYS_AND_CHAIN", "bad chain".to_string());
        assert_eq!(
            overall_validation_status(&[unrelated_blocker], legacy),
            "FAIL"
        );
    }

    #[test]
    fn current_network_snapshot_must_declare_policy_source_consistently() {
        let offline = r#"{"proof_source":"POLICY_DECLARATION","network_mode":"OFFLINE","proof_level":"OFFLINE_STRICT","allowlist":[],"ui_remote_fetch_disabled":true,"adapter_endpoints":[]}"#;
        let mut current = archive(&[("inputs_snapshot/network_snapshot.json", offline)]);
        assert_eq!(
            check_network_proof_source(&mut current, false).result,
            "PASS"
        );

        let ungrounded = r#"{"proof_source":"POLICY_DECLARATION","network_mode":"ONLINE_ALLOWLISTED","proof_level":"OFFLINE_STRICT","allowlist":[{}],"ui_remote_fetch_disabled":true,"adapter_endpoints":[]}"#;
        let mut inconsistent = archive(&[("inputs_snapshot/network_snapshot.json", ungrounded)]);
        assert_eq!(
            check_network_proof_source(&mut inconsistent, false).result,
            "FAIL"
        );

        let mut old = archive(&[(
            "inputs_snapshot/network_snapshot.json",
            r#"{"network_mode":"OFFLINE"}"#,
        )]);
        assert_eq!(check_network_proof_source(&mut old, true).result, "PASS");
    }

    fn complete_v3_report(policy: PolicyMode) -> EvalReport {
        let policy_name = format!("{policy:?}");
        let registry = crate::eval::registry::registry_v3().expect("registry");
        let gates = registry
            .gates
            .into_iter()
            .filter(|gate| gate.applies_to_policies.contains(&policy_name))
            .map(|gate| EvalGateResult {
                gate_id: gate.gate_id,
                category: gate.category,
                status: "PASS".to_string(),
                severity: gate.severity,
                message: "test result".to_string(),
                evidence_pointers: gate.evidence_required,
            })
            .collect();
        EvalReport {
            overall_status: "PASS".to_string(),
            tests: Vec::new(),
            gates,
            registry_version: "gates_registry_v3".to_string(),
        }
    }

    #[test]
    fn checks_prefix_fails_when_no_check_results_match() {
        let summary = ValidationSummary {
            checklist_version: "test".to_string(),
            policy: "STRICT".to_string(),
            overall: "PASS".to_string(),
            checks: Vec::new(),
        };

        let (result, message) = summary.result_for_checks_prefix("CHK.BUNDLE.");

        assert_eq!(result, "FAIL");
        assert!(message.contains("missing check results"));
    }

    #[test]
    fn complete_v3_eval_report_matches_policy_and_manifest() {
        let report = complete_v3_report(PolicyMode::STRICT);

        validate_eval_report(&report, "PASS", PolicyMode::STRICT, "evidenceos")
            .expect("complete registry-bound report");
    }

    #[test]
    fn v3_eval_report_rejects_missing_and_duplicate_gates() {
        let mut missing = complete_v3_report(PolicyMode::STRICT);
        let missing_id = missing.gates.pop().expect("applicable gate").gate_id;
        let missing_error =
            validate_eval_report(&missing, "PASS", PolicyMode::STRICT, "evidenceos")
                .expect_err("missing gate must fail");
        assert!(missing_error.contains("missing applicable gates"));
        assert!(missing_error.contains(&missing_id));

        let mut duplicate = complete_v3_report(PolicyMode::STRICT);
        duplicate.gates.push(duplicate.gates[0].clone());
        let duplicate_error =
            validate_eval_report(&duplicate, "PASS", PolicyMode::STRICT, "evidenceos")
                .expect_err("duplicate gate must fail");
        assert!(duplicate_error.contains("duplicate gate_id"));
    }

    #[test]
    fn v3_eval_report_rejects_invalid_status_and_summary_mismatches() {
        let mut invalid = complete_v3_report(PolicyMode::STRICT);
        invalid.gates[0].status = "UNKNOWN".to_string();
        let invalid_error =
            validate_eval_report(&invalid, "PASS", PolicyMode::STRICT, "evidenceos")
                .expect_err("invalid gate status must fail");
        assert!(invalid_error.contains("invalid status UNKNOWN"));

        let mut overall_mismatch = complete_v3_report(PolicyMode::STRICT);
        overall_mismatch.overall_status = "WARN".to_string();
        let overall_error =
            validate_eval_report(&overall_mismatch, "WARN", PolicyMode::STRICT, "evidenceos")
                .expect_err("derived overall mismatch must fail");
        assert!(overall_error.contains("does not match gate results"));

        let report = complete_v3_report(PolicyMode::STRICT);
        let manifest_error =
            validate_eval_report(&report, "WARN", PolicyMode::STRICT, "evidenceos")
                .expect_err("manifest/report mismatch must fail");
        assert!(manifest_error.contains("run_manifest eval.gate_status"));
    }

    #[test]
    fn v3_eval_report_rejects_registry_metadata_drift() {
        let mut category_drift = complete_v3_report(PolicyMode::STRICT);
        category_drift.gates[0].category = "OTHER".to_string();
        let category_error =
            validate_eval_report(&category_drift, "PASS", PolicyMode::STRICT, "evidenceos")
                .expect_err("category drift must fail");
        assert!(category_error.contains("category mismatch"));

        let mut severity_drift = complete_v3_report(PolicyMode::STRICT);
        severity_drift.gates[0].severity = "MAJOR".to_string();
        let severity_error =
            validate_eval_report(&severity_drift, "PASS", PolicyMode::STRICT, "evidenceos")
                .expect_err("severity downgrade must fail");
        assert!(severity_error.contains("severity downgrade"));

        let mut evidence_drift = complete_v3_report(PolicyMode::STRICT);
        evidence_drift.gates[0].evidence_pointers.clear();
        let evidence_error =
            validate_eval_report(&evidence_drift, "PASS", PolicyMode::STRICT, "evidenceos")
                .expect_err("evidence pointer drift must fail");
        assert!(evidence_error.contains("evidence pointers do not match registry"));
    }

    #[test]
    fn legacy_registry_label_cannot_bypass_v3_completeness() {
        let mut report = complete_v3_report(PolicyMode::STRICT);
        report.registry_version = "gates_registry_v2".to_string();
        report.gates.truncate(1);

        let error = validate_eval_report(&report, "PASS", PolicyMode::STRICT, "evidenceos")
            .expect_err("legacy reports are diagnostic-only");

        assert!(error.contains("inspectable but non-authorizing"));
        assert!(error.contains("gates_registry_v3"));
    }

    #[test]
    fn final_report_rejects_unapproved_not_applicable_and_blocker_failures() {
        let mut not_applicable = complete_v3_report(PolicyMode::STRICT);
        let audit_gate = not_applicable
            .gates
            .iter_mut()
            .find(|gate| gate.gate_id == "AUDIT_HASH_CHAIN.VERIFY_V1")
            .expect("audit gate");
        audit_gate.status = "NOT_APPLICABLE".to_string();
        let not_applicable_error =
            validate_eval_report(&not_applicable, "PASS", PolicyMode::STRICT, "evidenceos")
                .expect_err("unapproved NOT_APPLICABLE must fail");
        assert!(not_applicable_error.contains("NOT_APPLICABLE is not allowed"));

        let mut blocker_failure = complete_v3_report(PolicyMode::STRICT);
        blocker_failure.gates[0].status = "FAIL".to_string();
        blocker_failure.overall_status = "FAIL".to_string();
        let blocker_error =
            validate_eval_report(&blocker_failure, "FAIL", PolicyMode::STRICT, "evidenceos")
                .expect_err("blocker failure cannot validate final bytes");
        assert!(blocker_error.contains("blocker gate failures"));
    }
}
