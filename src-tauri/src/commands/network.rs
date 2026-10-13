use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct UiNetworkSnapshot {
    pub(crate) network_mode: &'static str,
    pub(crate) proof_level: &'static str,
    pub(crate) ui_remote_fetch_disabled: bool,
}

#[tauri::command]
pub(crate) fn get_network_snapshot() -> UiNetworkSnapshot {
    UiNetworkSnapshot {
        network_mode: "OFFLINE",
        proof_level: "OFFLINE_STRICT",
        ui_remote_fetch_disabled: true,
    }
}
