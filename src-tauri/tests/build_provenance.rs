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

#[test]
fn rerun_inputs_include_manifests_lockfile_and_build_configuration() {
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "core/Cargo.toml",
        "tools/gate_runner/Cargo.toml",
        "src-tauri/Cargo.toml",
        "src-tauri/build.rs",
        "src-tauri/build_provenance.rs",
        "src-tauri/tauri.conf.json",
        "src-tauri/capabilities/default.json",
        "rust-toolchain.toml",
    ] {
        assert!(
            build_provenance::should_rerun_for_tracked_path(Path::new(path)),
            "{path} must trigger a rebuild"
        );
    }
    assert!(!build_provenance::should_rerun_for_tracked_path(Path::new(
        "CHANGELOG.md"
    )));
    assert!(!build_provenance::should_rerun_for_tracked_path(Path::new(
        "package.json"
    )));
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.test"])
        .args(args)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?}");
}

#[test]
fn dirty_stamp_follows_the_same_paths_as_the_rebuild_triggers() {
    let root = std::env::temp_dir().join(format!(
        "aigccore-dirty-stamp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(root.join("src-tauri")).expect("tree");
    git(&root, &["init", "-q"]);
    fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("manifest");
    fs::write(root.join("README.md"), "docs\n").expect("docs");
    git(&root, &["add", "Cargo.toml", "README.md"]);
    git(&root, &["commit", "-q", "-m", "init"]);

    let clean = build_provenance::source_revision_with_candidates(&root, []);
    assert!(!clean.ends_with("+DIRTY"), "{clean}");

    fs::write(root.join("README.md"), "edited docs\n").expect("docs edit");
    let docs_only = build_provenance::source_revision_with_candidates(&root, []);
    assert_eq!(docs_only, clean, "documentation edits must not stamp DIRTY");

    fs::write(root.join("Cargo.toml"), "[workspace]\nresolver = \"2\"\n").expect("edit");
    let manifest_edit = build_provenance::source_revision_with_candidates(&root, []);
    assert_eq!(manifest_edit, format!("{clean}+DIRTY"));

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn changed_path_scan_treats_invalid_utf8_as_dirty() {
    assert!(build_provenance::any_changed_path_affects_build(
        b"\xff\xfe\0"
    ));
    assert!(!build_provenance::any_changed_path_affects_build(
        b"docs/a.md\0README.md\0"
    ));
    assert!(!build_provenance::any_changed_path_affects_build(b""));
}
