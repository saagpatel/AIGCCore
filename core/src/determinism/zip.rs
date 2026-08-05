use crate::error::{CoreError, CoreResult};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;

// Addendum_A_Determinism_Matrix_v2.md §4 + Phase_2_5_Lock_Addendum_v2.5-lock-4.md §3.1
// Deterministic zip builder:
// - entries sorted lexicographically by bundle_rel_path
// - fixed timestamps (DOS epoch equivalent)
// - fixed compression method/level
// - fixed permissions
// - empty zip comment
pub fn zip_dir_deterministic(root_dir: &Path, out_zip: &Path) -> CoreResult<String> {
    let mut entries: Vec<(PathBuf, String)> = Vec::new();

    for e in WalkDir::new(root_dir) {
        let e =
            e.map_err(|err| CoreError::Io(std::io::Error::new(std::io::ErrorKind::Other, err)))?;
        let p = e.path();
        if p == root_dir {
            continue;
        }
        if p.is_dir() {
            // zip crate doesn't require explicit directory entries, but determinism matrix wants dirs mode pinned.
            // We'll include directory entries for stability.
            let rel = p.strip_prefix(root_dir).unwrap();
            let mut rel_s = rel.to_string_lossy().replace('\\', "/");
            if !rel_s.ends_with('/') {
                rel_s.push('/');
            }
            entries.push((p.to_path_buf(), rel_s));
        } else if p.is_file() {
            let rel = p.strip_prefix(root_dir).unwrap();
            let rel_s = rel.to_string_lossy().replace('\\', "/");
            entries.push((p.to_path_buf(), rel_s));
        }
    }
    entries.sort_by(|a, b| a.1.cmp(&b.1));

    let f = File::create(out_zip)?;
    let mut zw = ZipWriter::new(f);

    // DOS epoch (zip format): earliest representable time is 1980-01-01.
    let fixed_time = zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).map_err(|_| {
        CoreError::DeterminismViolationError("failed to create fixed zip datetime".to_string())
    })?;

    // zip::write::FileOptions provides unix_permissions and last_modified_time.
    let base_opts = FileOptions::<()>::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(9))
        .last_modified_time(fixed_time);

    for (abs_path, rel) in entries {
        if rel.ends_with('/') {
            let opts = base_opts.unix_permissions(0o755);
            zw.add_directory(rel, opts)
                .map_err(|e| CoreError::Zip(e.to_string()))?;
            continue;
        }

        let opts = base_opts.unix_permissions(0o644);
        zw.start_file(rel, opts)
            .map_err(|e| CoreError::Zip(e.to_string()))?;

        let mut rf = File::open(abs_path)?;
        std::io::copy(&mut rf, &mut zw)?;
    }

    zw.set_comment("")
        .map_err(|e| CoreError::Zip(e.to_string()))?;
    zw.finish().map_err(|e| CoreError::Zip(e.to_string()))?;

    // Compute sha256 of zip bytes (used by export completed + validator outputs)
    let mut zf = File::open(out_zip)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = zf.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
