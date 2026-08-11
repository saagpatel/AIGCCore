#[path = "../build_provenance.rs"]
mod build_provenance;

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn explicit_revision_supports_source_tree_without_git_metadata() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "aigccore-build-provenance-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("temporary source tree");

    build_provenance::emit_source_revision_rerun_inputs(&root);
    let revision = build_provenance::source_revision_with_candidates(
        &root,
        ["archive-revision-123".to_string()],
    );

    assert_eq!(revision, "archive-revision-123");
    fs::remove_dir_all(root).expect("remove temporary source tree");
}
