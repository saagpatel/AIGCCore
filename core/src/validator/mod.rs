pub mod checklist;

use crate::error::{CoreError, CoreResult};
use crate::evidence_bundle::schemas::{BundleInfo, RunManifest};
use crate::policy::types::PolicyMode;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use zip::ZipArchive;

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
        let mut any_fail = false;
        for c in &self.checks {
            if c.check_id.starts_with(prefix) && c.result != "PASS" {
                any_fail = true;
            }
        }
        if any_fail {
            (
                "FAIL".to_string(),
                format!("one or more {} checks failed", prefix),
            )
        } else {
            ("PASS".to_string(), "ok".to_string())
        }
    }

    pub fn vault_crypto_gate_result(&self) -> String {
        // Phase 2: we validate policy_snapshot says encryption_at_rest=true and algorithm allowed.
        self.result_for_check("CHK.VAULT_CRYPTO.POLICY_SNAPSHOT").0
    }

    pub fn vault_crypto_message(&self) -> String {
        self.result_for_check("CHK.VAULT_CRYPTO.POLICY_SNAPSHOT").1
    }
}

pub struct BundleValidator {
    checklist: checklist::Checklist,
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
        let policy_s = match policy {
            PolicyMode::STRICT => "STRICT",
            PolicyMode::BALANCED => "BALANCED",
            PolicyMode::DRAFT_ONLY => "DRAFT_ONLY",
        };

        let file = File::open(bundle_zip)?;
        let mut zip = ZipArchive::new(file).map_err(|e| CoreError::Zip(e.to_string()))?;

        // Build entry set for existence checks.
        let mut paths: BTreeSet<String> = BTreeSet::new();
        for i in 0..zip.len() {
            let f = zip.by_index(i).map_err(|e| CoreError::Zip(e.to_string()))?;
            paths.insert(f.name().to_string());
        }

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
        ));

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
        checks_out.push(check_eval_report(&mut zip));

        // CHK.DETERMINISM.ZIP_RULES (major, conditional)
        checks_out.push(check_zip_determinism(&mut zip));

        // Vault crypto minimal policy snapshot check (gate expects it)
        checks_out.push(check_vault_crypto_policy_snapshot(&mut zip));

        let overall = if checks_out
            .iter()
            .any(|c| c.severity == "BLOCKER" && c.result != "PASS")
        {
            "FAIL"
        } else {
            "PASS"
        };

        Ok(ValidationSummary {
            checklist_version: self.checklist.checklist_version.clone(),
            policy: policy_s.to_string(),
            overall: overall.to_string(),
            checks: checks_out,
        })
    }
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
    let mut f = zip
        .by_name(path)
        .map_err(|e| CoreError::Zip(e.to_string()))?;
    let mut out = Vec::new();
    f.read_to_end(&mut out)?;
    Ok(out)
}

fn read_zip_entry_json<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    path: &str,
) -> CoreResult<serde_json::Value> {
    let bytes = read_zip_entry_bytes(zip, path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn check_evidence_authority_contract<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
) -> CheckResult {
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
    if bundle_info.schema_versions.run_manifest != "RUN_MANIFEST_V2" {
        return fail(
            "run manifest schema must be RUN_MANIFEST_V2 for evidence authority".to_string(),
        );
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
    let audit_log = match read_zip_entry_bytes(zip, "audit_log.ndjson")
        .and_then(|bytes| String::from_utf8(bytes).map_err(|error| CoreError::InvalidInput(error.to_string())))
    {
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
                )
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
            )
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
            )
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
                )
            }
        };
        let artifact_id = rec.get(0).unwrap_or("").to_string();
        let bundle_rel_path = rec.get(1).unwrap_or("").to_string();
        let sha256 = rec.get(2).unwrap_or("").to_string();
        let bytes_s = rec.get(3).unwrap_or("0");
        let bytes_v: u64 = bytes_s.parse().unwrap_or(0);
        rows.push((artifact_id, bundle_rel_path, sha256, bytes_v));
    }

    // Verify ordering
    let mut sorted = rows.clone();
    sorted.sort_by(|a, b| (a.0.clone(), a.1.clone()).cmp(&(b.0.clone(), b.1.clone())));
    if sorted != rows {
        return fail(
            "CHK.ARTIFACT_HASHES.VERIFY",
            "rows not sorted by artifact_id then path".to_string(),
        );
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
                )
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
            )
        }
    };
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
            )
        }
    };
    let v = match read_zip_entry_json(zip, &citations_path) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.CITATIONS.STRICT",
                format!("failed to read citations_map: {}", e),
            )
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
            )
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
            )
        }
    };
    let citations = match read_zip_entry_json(zip, &citations_path) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.REDACTION.POLICY_GATE",
                format!("failed to read citations_map: {}", e),
            )
        }
    };
    let artifact_list = match read_zip_entry_json(zip, "inputs_snapshot/artifact_list.json") {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.REDACTION.POLICY_GATE",
                format!("failed to read artifact_list.json: {}", e),
            )
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

fn check_eval_report<R: Read + Seek>(zip: &mut ZipArchive<R>) -> CheckResult {
    let v = match read_zip_entry_json(zip, "eval_report.json") {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.EVAL.REPORT_AND_GATES",
                format!("failed to read eval_report.json: {}", e),
            )
        }
    };
    if v.get("overall_status").is_none() || v.get("gates").is_none() {
        return fail(
            "CHK.EVAL.REPORT_AND_GATES",
            "missing required fields".to_string(),
        );
    }
    let reg = v
        .get("registry_version")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    // Packet precedence: accept v3 (and v1/v2 for backwards compatibility).
    if reg != "gates_registry_v3" && reg != "gates_registry_v2" && reg != "gates_registry_v1" {
        return fail(
            "CHK.EVAL.REPORT_AND_GATES",
            format!("unsupported registry_version {}", reg),
        );
    }
    // Validate gate IDs are present in registry v3.
    let gates = v
        .get("gates")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let reg_v3 = crate::eval::registry::registry_v3();
    if let Ok(registry) = reg_v3 {
        let known: std::collections::BTreeSet<String> =
            registry.gates.iter().map(|g| g.gate_id.clone()).collect();
        for g in gates {
            let gid = g.get("gate_id").and_then(|x| x.as_str()).unwrap_or("");
            if !gid.is_empty() && !known.contains(gid) {
                return fail(
                    "CHK.EVAL.REPORT_AND_GATES",
                    format!("unknown gate_id in eval_report: {}", gid),
                );
            }
        }
    }
    pass("CHK.EVAL.REPORT_AND_GATES")
}

fn check_zip_determinism<R: Read + Seek>(zip: &mut ZipArchive<R>) -> CheckResult {
    let policy = match read_zip_entry_json(zip, "inputs_snapshot/policy_snapshot.json") {
        Ok(v) => v,
        Err(e) => {
            return fail(
                "CHK.DETERMINISM.ZIP_RULES",
                format!("failed to read policy_snapshot: {}", e),
            )
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
            )
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
                )
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
                )
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
            )
        }
    };
    let enc = v
        .get("encryption_at_rest")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let alg = v
        .get("encryption_algorithm")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let ok_alg = alg == "XCHACHA20_POLY1305" || alg == "AES_256_GCM";
    if !(enc && ok_alg) {
        fail(
            "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
            "encryption_at_rest or algorithm invalid".to_string(),
        )
    } else {
        // Ensure audit has VAULT_ENCRYPTION_STATUS and accepted key_storage values.
        let bytes = match read_zip_entry_bytes(zip, "audit_log.ndjson") {
            Ok(b) => b,
            Err(e) => {
                return fail(
                    "CHK.VAULT_CRYPTO.POLICY_SNAPSHOT",
                    format!("failed to read audit_log.ndjson: {}", e),
                )
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
                if ks == "MACOS_KEYCHAIN" || ks == "WINDOWS_DPAPI" || ks == "FILE_FALLBACK" {
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
