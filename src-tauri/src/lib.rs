mod commands;
mod export;
pub mod logging;

#[cfg(not(feature = "authority-integrity-test-hooks"))]
pub fn app_builder<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder.invoke_handler(tauri::generate_handler![
        commands::network::get_network_snapshot,
        commands::evidenceos::list_control_library,
        commands::evidenceos::generate_evidenceos_bundle,
    ])
}

#[cfg(feature = "authority-integrity-test-hooks")]
pub fn app_builder<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder.invoke_handler(tauri::generate_handler![
        commands::network::get_network_snapshot,
        commands::evidenceos::list_control_library,
        commands::evidenceos::generate_evidenceos_bundle,
        commands::authority_integrity::authority_integrity_probe_adapter
    ])
}

pub fn run() {
    app_builder(tauri::Builder::default())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
