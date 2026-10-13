use crate::determinism::json_canonical;
use crate::determinism::zip::zip_dir_deterministic;
use crate::error::CoreResult;
use crate::evidence_bundle::schemas::EvidenceBundleInputs;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub struct EvidenceBundleBuilder;

impl EvidenceBundleBuilder {
    pub fn build_dir(bundle_root: &Path, inputs: &EvidenceBundleInputs) -> CoreResult<()> {
        if fs::symlink_metadata(bundle_root).is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(crate::error::CoreError::InvalidInput(
                "SYMLINKED_BUNDLE_ROOT: symlinked bundle root rejected".into(),
            ));
        }
        fs::create_dir_all(bundle_root)?;
        reject_existing_symlinks(bundle_root)?;
        let pack_id = PackId::try_from(inputs.pack_id.as_str())?;

        // Required files (Annex A §A.3 / A.4)
        write_json(bundle_root.join("BUNDLE_INFO.json"), &inputs.bundle_info)?;
        let normalized_audit_log = normalize_newlines(&inputs.audit_log_ndjson);
        let mut run_manifest = inputs.run_manifest.clone();
        run_manifest
            .evidence_authority
            .bind_audit_log(&normalized_audit_log);
        write_json(bundle_root.join("run_manifest.json"), &run_manifest)?;

        write_text(bundle_root.join("audit_log.ndjson"), normalized_audit_log)?;
        write_json(bundle_root.join("eval_report.json"), &inputs.eval_report)?;
        write_text(
            bundle_root.join("artifact_hashes.csv"),
            normalize_newlines(&inputs.artifact_hashes_csv),
        )?;

        // Exports layout (lock addendum §4)
        let exports_root = bundle_root.join("exports").join(pack_id.0);
        let attachments_dir = exports_root.join("attachments");
        create_contained_dirs(bundle_root, &attachments_dir)?;

        // deliverables
        for (rel, bytes, _content_type) in &inputs.deliverables {
            let p = contained_deliverable_path(bundle_root, pack_id, rel)?;
            if let Some(parent) = p.parent() {
                create_contained_dirs(bundle_root, parent)?;
            }
            write_create_new_or_identical(&p, bytes)?;
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
        create_contained_dirs(bundle_root, &inputs_snap)?;
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

fn write_create_new_or_identical(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => file.write_all(bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(crate::error::CoreError::InvalidInput(
                    "DELIVERABLE_OVERWRITE_REJECTED: existing deliverable is not a regular file"
                        .into(),
                ));
            }
            if fs::read(path)? != bytes {
                return Err(crate::error::CoreError::InvalidInput("DELIVERABLE_OVERWRITE_REJECTED: refusing to replace existing deliverable bytes".into()));
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct PackId<'a>(&'a str);

impl<'a> TryFrom<&'a str> for PackId<'a> {
    type Error = crate::error::CoreError;

    fn try_from(pack_id: &'a str) -> Result<Self, Self::Error> {
        if pack_id.is_empty()
            || !pack_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(crate::error::CoreError::InvalidInput(
                "INVALID_PACK_ID: expected non-empty ASCII letters, digits, underscore, or hyphen"
                    .into(),
            ));
        }
        Ok(Self(pack_id))
    }
}

struct RelativeDeliverablePath(PathBuf);

impl TryFrom<(&PackId<'_>, &str)> for RelativeDeliverablePath {
    type Error = crate::error::CoreError;

    fn try_from((pack_id, rel): (&PackId<'_>, &str)) -> Result<Self, Self::Error> {
        let relative = Path::new(rel);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(crate::error::CoreError::InvalidInput(
                "INVALID_DELIVERABLE_PATH: expected a normalized relative path".into(),
            ));
        }
        let expected = format!("exports/{}/deliverables/", pack_id.0);
        if !rel.starts_with(&expected) || rel.len() == expected.len() {
            return Err(crate::error::CoreError::InvalidInput(
                "INVALID_DELIVERABLE_PATH: path must be under this pack's deliverables directory"
                    .into(),
            ));
        }
        Ok(Self(relative.to_path_buf()))
    }
}

fn contained_deliverable_path(root: &Path, pack_id: PackId<'_>, rel: &str) -> CoreResult<PathBuf> {
    let relative = RelativeDeliverablePath::try_from((&pack_id, rel))?;
    Ok(root.join(relative.0))
}

fn create_contained_dirs(root: &Path, parent: &Path) -> CoreResult<()> {
    let relative = parent.strip_prefix(root).map_err(|_| {
        crate::error::CoreError::InvalidInput(
            "INVALID_DELIVERABLE_PATH: escaped bundle root".into(),
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(crate::error::CoreError::InvalidInput(
                    "SYMLINKED_DELIVERABLE_PARENT: symlinked path component rejected".into(),
                ))
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(crate::error::CoreError::InvalidInput(
                    "INVALID_DELIVERABLE_PARENT: path component is not a directory".into(),
                ))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn reject_existing_symlinks(root: &Path) -> CoreResult<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(crate::error::CoreError::InvalidInput(
                "SYMLINKED_BUNDLE_PATH: symlinked path component rejected".into(),
            ));
        }
        if metadata.is_dir() {
            reject_existing_symlinks(&path)?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn deliverable_paths_reject_absolute_traversal_and_wrong_pack() {
        let root = Path::new("/tmp/bundle");
        for invalid in [
            "/tmp/escape",
            "exports/pack/deliverables/../../escape",
            "exports/other/deliverables/file.txt",
            "exports/pack/deliverables/",
        ] {
            assert!(
                contained_deliverable_path(root, PackId::try_from("pack").unwrap(), invalid)
                    .is_err(),
                "{invalid}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn deliverable_write_rejects_symlinked_parent_and_existing_file() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("bundle");
        fs::create_dir(&root).unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::create_dir(root.join("exports")).unwrap();
        symlink(&outside, root.join("exports/pack")).unwrap();
        let pack_id = PackId::try_from("pack").unwrap();
        let path = contained_deliverable_path(&root, pack_id, "exports/pack/deliverables/file.txt")
            .unwrap();
        assert!(create_contained_dirs(&root, path.parent().unwrap()).is_err());
        assert!(!outside.join("deliverables/file.txt").exists());

        fs::remove_file(root.join("exports/pack")).unwrap();
        fs::create_dir_all(root.join("exports/pack/deliverables")).unwrap();
        let path = contained_deliverable_path(&root, pack_id, "exports/pack/deliverables/file.txt")
            .unwrap();
        create_contained_dirs(&root, path.parent().unwrap()).unwrap();
        fs::write(&path, b"preexisting").unwrap();
        assert!(write_create_new_or_identical(&path, b"replacement").is_err());
        assert!(write_create_new_or_identical(&path, b"preexisting").is_ok());
    }
}
