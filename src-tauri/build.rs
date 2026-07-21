use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=AIGC_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required");
    let repository_root = Path::new(&manifest_dir)
        .parent()
        .expect("src-tauri must be inside the repository");
    emit_source_revision_rerun_inputs(repository_root);
    let source_revision = source_revision(repository_root);
    println!("cargo:rustc-env=AIGC_SOURCE_REVISION={source_revision}");
    tauri_build::build()
}

fn emit_source_revision_rerun_inputs(repository_root: &Path) {
    let tracked = git_output(repository_root, &["ls-files", "-z"]);
    for path in tracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = String::from_utf8(path.to_vec()).expect("tracked paths must be UTF-8");
        assert!(
            !path.contains(['\n', '\r']),
            "tracked path contains a Cargo directive delimiter"
        );
        println!(
            "cargo:rerun-if-changed={}",
            repository_root.join(path).display()
        );
    }

    let mut git_metadata = vec![
        "HEAD".to_string(),
        "index".to_string(),
        "packed-refs".to_string(),
    ];
    if let Some(symbolic_ref) =
        git_optional_stdout(repository_root, &["symbolic-ref", "-q", "HEAD"])
    {
        git_metadata.push(symbolic_ref);
    }
    for git_path in git_metadata {
        let absolute_path = git_stdout(
            repository_root,
            &[
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                &git_path,
            ],
        );
        assert!(
            !absolute_path.contains(['\n', '\r']),
            "Git metadata path contains a Cargo directive delimiter"
        );
        println!("cargo:rerun-if-changed={absolute_path}");
    }
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

fn git_output(repository_root: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(args)
        .output()
        .expect("git is required to bind AIGCCore provenance");
    assert!(
        output.status.success(),
        "unable to read AIGCCore Git provenance inputs"
    );
    output.stdout
}

fn git_stdout(repository_root: &Path, args: &[&str]) -> String {
    String::from_utf8(git_output(repository_root, args))
        .expect("Git provenance output must be UTF-8")
        .trim()
        .to_string()
}

fn git_optional_stdout(repository_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
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
