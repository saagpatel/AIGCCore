use crate::error::CoreResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactHashRow {
    pub artifact_id: String,
    pub bundle_rel_path: String,
    pub sha256: String,
    pub bytes: u64,
    pub content_type: String,
    pub logical_role: String, // INPUT|DELIVERABLE|ATTACHMENT
}

pub fn render_artifact_hashes_csv(mut rows: Vec<ArtifactHashRow>) -> CoreResult<String> {
    rows.sort_by(|a, b| {
        (a.artifact_id.clone(), a.bundle_rel_path.clone())
            .cmp(&(b.artifact_id.clone(), b.bundle_rel_path.clone()))
    });

    let mut wtr = csv::WriterBuilder::new().from_writer(vec![]);
    wtr.write_record([
        "artifact_id",
        "bundle_rel_path",
        "sha256",
        "bytes",
        "content_type",
        "logical_role",
    ])?;
    for r in rows {
        wtr.write_record(&[
            r.artifact_id,
            r.bundle_rel_path,
            r.sha256,
            r.bytes.to_string(),
            r.content_type,
            r.logical_role,
        ])?;
    }
    let bytes = wtr.into_inner().map_err(|e| e.into_error())?;
    Ok(String::from_utf8_lossy(&bytes).replace("\r\n", "\n"))
}
