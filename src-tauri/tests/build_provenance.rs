#[path = "../build_provenance.rs"]
mod build_provenance;

use std::fs;
use std::path::Path;
use std::process::Command;
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

#[test]
fn rerun_inputs_exclude_documentation_and_include_source_directories() {
    assert!(!build_provenance::should_rerun_for_tracked_path(Path::new(
        "docs/guide.md"
    )));
    assert!(!build_provenance::should_rerun_for_tracked_path(Path::new(
        "README.md"
    )));
    assert!(build_provenance::should_rerun_for_tracked_path(Path::new(
        "core/src/storage/vault.rs"
    )));
    assert!(build_provenance::should_rerun_for_tracked_path(Path::new(
        "src-tauri/src/lib.rs"
    )));
}

#[test]
fn environment_revision_takes_priority_without_git_metadata() {
    // A child process isolates environment overrides from concurrently running tests.
    if std::env::var("AIGC_TEST_REVISION_CHILD").as_deref() == Ok("1") {
        assert_eq!(
            build_provenance::source_revision(Path::new("missing-source-tree")),
            "archive-revision-123"
        );
        return;
    }
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "environment_revision_takes_priority_without_git_metadata",
        ])
        .env("AIGC_TEST_REVISION_CHILD", "1")
        .env("AIGC_SOURCE_REVISION", "  archive-revision-123  ")
        .env("GITHUB_SHA", "lower-priority-revision")
        .output()
        .expect("isolated revision test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[should_panic(expected = "source revision contains unsupported characters")]
fn revision_rejects_directive_delimiters() {
    build_provenance::source_revision_with_candidates(
        Path::new("missing-source-tree"),
        ["revision\ncargo:rustc-env=INJECTED=value".to_string()],
    );
}

#[test]
#[should_panic(expected = "source revision contains unsupported characters")]
fn revision_rejects_oversized_values() {
    build_provenance::source_revision_with_candidates(
        Path::new("missing-source-tree"),
        ["x".repeat(129)],
    );
}
