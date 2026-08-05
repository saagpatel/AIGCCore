#[cfg(not(feature = "local-execution-backend-v1"))]
fn main() {
    eprintln!("aigc_local_execution_qualify requires --features local-execution-backend-v1");
    std::process::exit(2);
}

#[cfg(feature = "local-execution-backend-v1")]
fn main() {
    let mut args = std::env::args().skip(1);
    if args
        .next()
        .as_deref()
        .is_some_and(|value| value == "--controller-death-child")
    {
        let id = args.next().unwrap_or_default();
        let token = args.next().unwrap_or_default();
        let root = args.next().unwrap_or_default();
        let engine_endpoint = args.next().unwrap_or_default();
        if args.next().is_some() {
            std::process::exit(64);
        }
        let code = aigc_core_tauri::local_execution::run_controller_death_child(
            &id,
            &token,
            &root,
            &engine_endpoint,
        );
        std::process::exit(code);
    }
    let mut args = std::env::args().skip(1);
    let output = args.next().unwrap_or_else(|| {
        eprintln!("usage: aigc_local_execution_qualify <output-receipt.json>");
        std::process::exit(2);
    });
    if args.next().is_some() {
        eprintln!("usage: aigc_local_execution_qualify <output-receipt.json>");
        std::process::exit(2);
    }
    let output = std::path::PathBuf::from(output);
    match aigc_core_tauri::local_execution::qualify_to_path(&output) {
        Ok(receipt) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt)
                    .expect("qualification receipt should serialize")
            );
        }
        Err(error) => {
            eprintln!("qualification ERROR: {error}");
            std::process::exit(1);
        }
    }
}
