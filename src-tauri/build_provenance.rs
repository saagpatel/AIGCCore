use std::path::Path;
use std::process::Command;

pub fn emit_source_revision_rerun_inputs(repository_root: &Path) {
    let Some(tracked) = git_optional_output(repository_root, &["ls-files", "-z"]) else {
        // Source archives and vendored checkouts may intentionally have no Git
        // metadata. The revision remains bound through AIGC_SOURCE_REVISION or
        // GITHUB_SHA; only Git-backed rebuild invalidation is unavailable.
        return;
    };
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
        let Some(absolute_path) = git_optional_stdout(
            repository_root,
            &[
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                &git_path,
            ],
        ) else {
            continue;
        };
        assert!(
            !absolute_path.contains(['\n', '\r']),
            "Git metadata path contains a Cargo directive delimiter"
        );
        println!("cargo:rerun-if-changed={absolute_path}");
    }
}

pub fn source_revision(repository_root: &Path) -> String {
    let candidates = ["AIGC_SOURCE_REVISION", "GITHUB_SHA"]
        .iter()
        .filter_map(|name| std::env::var(name).ok());
    source_revision_with_candidates(repository_root, candidates)
}

pub fn source_revision_with_candidates(
    repository_root: &Path,
    candidates: impl IntoIterator<Item = String>,
) -> String {
    if let Some(value) = candidates
        .into_iter()
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
        .expect("git is required when no explicit AIGCCore source revision is provided");
    assert!(
        output.status.success(),
        "unable to resolve the AIGCCore source revision; set AIGC_SOURCE_REVISION"
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

fn git_optional_output(repository_root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root)
        .args(args)
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout)
}

fn git_optional_stdout(repository_root: &Path, args: &[&str]) -> Option<String> {
    let value = String::from_utf8(git_optional_output(repository_root, args)?)
        .ok()?
        .trim()
        .to_string();
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
