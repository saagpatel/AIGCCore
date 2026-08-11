mod build_provenance;

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=AIGC_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required");
    let repository_root = Path::new(&manifest_dir)
        .parent()
        .expect("src-tauri must be inside the repository");
    build_provenance::emit_source_revision_rerun_inputs(repository_root);
    let source_revision = build_provenance::source_revision(repository_root);
    println!("cargo:rustc-env=AIGC_SOURCE_REVISION={source_revision}");
    tauri_build::build()
}
