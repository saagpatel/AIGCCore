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
        let Ok(path) = std::str::from_utf8(path) else {
            continue;
        };
        if !should_rerun_for_tracked_path(Path::new(path)) {
            continue;
        }
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

/// Paths whose contents can change the compiled binary. The rebuild triggers
/// and the `+DIRTY` stamp both use this one predicate so they always agree.
pub fn should_rerun_for_tracked_path(path: &Path) -> bool {
    const SOURCE_DIRECTORIES: [&str; 5] = [
        "core/src",
        "src-tauri/src",
        "tools",
        "src",
        "src-tauri/capabilities",
    ];
    const BUILD_INPUT_FILES: [&str; 5] = [
        "Cargo.lock",
        "rust-toolchain.toml",
        "src-tauri/build.rs",
        "src-tauri/build_provenance.rs",
        "src-tauri/tauri.conf.json",
    ];
    SOURCE_DIRECTORIES
        .iter()
        .any(|directory| path.starts_with(directory))
        || BUILD_INPUT_FILES.iter().any(|file| path == Path::new(file))
        || path.file_name().is_some_and(|name| name == "Cargo.toml")
}

/// True when any path that can affect the binary differs from `HEAD`
/// (staged or unstaged). Changes to documentation do not count.
pub fn tree_is_dirty_for_build(repository_root: &Path) -> bool {
    let Some(changed) = git_optional_output(
        repository_root,
        &[
            "diff",
            "--name-only",
            "-z",
            "--ignore-submodules",
            "HEAD",
            "--",
        ],
    ) else {
        // Cannot prove the tree is clean; stamp conservatively.
        return true;
    };
    any_changed_path_affects_build(&changed)
}

pub fn any_changed_path_affects_build(nul_separated_paths: &[u8]) -> bool {
    nul_separated_paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .any(|path| match std::str::from_utf8(path) {
            Ok(path) => should_rerun_for_tracked_path(Path::new(path)),
            Err(_) => true,
        })
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

    if tree_is_dirty_for_build(repository_root) {
        validate_revision(format!("{revision}+DIRTY"))
    } else {
        validate_revision(revision)
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
