use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=AIGC_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required");
    let repository_root = Path::new(&manifest_dir)
        .parent()
        .expect("src-tauri must be inside the repository");
    let source_revision = source_revision(repository_root);
    println!("cargo:rustc-env=AIGC_SOURCE_REVISION={source_revision}");
    tauri_build::build()
}

fn source_revision(repository_root: &Path) -> String {
    if let Some(value) = ["AIGC_SOURCE_REVISION", "GITHUB_SHA"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
    {
        return validate_revision(value);
    }

    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git is required to bind the AIGCCore source revision");
    assert!(
        output.status.success(),
        "unable to resolve the AIGCCore source revision"
    );
    let revision = String::from_utf8(output.stdout)
        .expect("git revision must be UTF-8")
        .trim()
        .to_string();
    assert!(!revision.is_empty(), "git revision must not be empty");

    let worktree_clean = git_quiet(
        repository_root,
        &["diff", "--quiet", "--ignore-submodules", "--"],
    );
    let index_clean = git_quiet(
        repository_root,
        &["diff", "--cached", "--quiet", "--ignore-submodules", "--"],
    );
    if worktree_clean && index_clean {
        validate_revision(revision)
    } else {
        validate_revision(format!("{revision}+DIRTY"))
    }
}

fn git_quiet(repository_root: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(args)
        .status()
        .is_ok_and(|status| status.success())
}

fn validate_revision(value: String) -> String {
    assert!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._+-".contains(character)),
        "source revision contains unsupported characters"
    );
    value
}
