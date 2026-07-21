use crate::determinism::json_canonical;
use crate::determinism::zip::zip_dir_deterministic;
use crate::error::CoreResult;
use crate::evidence_bundle::schemas::EvidenceBundleInputs;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct EvidenceBundleBuilder;

impl EvidenceBundleBuilder {
    pub fn build_dir(bundle_root: &Path, inputs: &EvidenceBundleInputs) -> CoreResult<()> {
        fs::create_dir_all(bundle_root)?;

        // Required files (Annex A §A.3 / A.4)
        write_json(bundle_root.join("BUNDLE_INFO.json"), &inputs.bundle_info)?;
        let mut run_manifest = inputs.run_manifest.clone();
        run_manifest
            .evidence_authority
            .bind_audit_log(&inputs.audit_log_ndjson);
        write_json(bundle_root.join("run_manifest.json"), &run_manifest)?;

        write_text(
            bundle_root.join("audit_log.ndjson"),
            normalize_newlines(&inputs.audit_log_ndjson),
        )?;
        write_json(bundle_root.join("eval_report.json"), &inputs.eval_report)?;
        write_text(
            bundle_root.join("artifact_hashes.csv"),
            normalize_newlines(&inputs.artifact_hashes_csv),
        )?;

        // Exports layout (lock addendum §4)
        let exports_root = bundle_root.join("exports").join(&inputs.pack_id);
        let deliverables_dir = exports_root.join("deliverables");
        let attachments_dir = exports_root.join("attachments");
        fs::create_dir_all(&deliverables_dir)?;
        fs::create_dir_all(&attachments_dir)?;

        // deliverables
        for (rel, bytes, _content_type) in &inputs.deliverables {
            let p = bundle_root.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(p, bytes)?;
        }

        // attachments
        write_json_value(
            attachments_dir.join("templates_used.json"),
            &inputs.attachments.templates_used_json,
        )?;
        if let Some(v) = &inputs.attachments.citations_map_json {
            write_json_value(attachments_dir.join("citations_map.json"), v)?;
        }
        if let Some(v) = &inputs.attachments.redactions_map_json {
            write_json_value(attachments_dir.join("redactions_map.json"), v)?;
        }

        // inputs_snapshot
        let inputs_snap = bundle_root.join("inputs_snapshot");
        fs::create_dir_all(&inputs_snap)?;
        write_json(
            bundle_root
                .join("inputs_snapshot")
                .join("artifact_list.json"),
            &inputs.artifact_list,
        )?;
        write_json(
            bundle_root
                .join("inputs_snapshot")
                .join("policy_snapshot.json"),
            &inputs.policy_snapshot,
        )?;
        write_json(
            bundle_root
                .join("inputs_snapshot")
                .join("network_snapshot.json"),
            &inputs.network_snapshot,
        )?;
        write_json(
            bundle_root
                .join("inputs_snapshot")
                .join("model_snapshot.json"),
            &inputs.model_snapshot,
        )?;

        Ok(())
    }

    pub fn build_zip(bundle_root_dir: &Path, out_zip: &Path) -> CoreResult<String> {
        zip_dir_deterministic(bundle_root_dir, out_zip)
    }
}

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn write_text(path: PathBuf, content: String) -> CoreResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

fn write_json<T: serde::Serialize>(path: PathBuf, value: &T) -> CoreResult<()> {
    let bytes = json_canonical::to_canonical_bytes(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn write_json_value(path: PathBuf, value: &serde_json::Value) -> CoreResult<()> {
    let bytes = json_canonical::to_canonical_bytes(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}
