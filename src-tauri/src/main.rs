#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(error) = aigc_core_tauri::logging::init() {
        eprintln!("operational logging initialization failed: {error}");
    }
    aigc_core_tauri::run();
}
