use aigc_core::policy::network_snapshot::{NetworkProofSource, NetworkSnapshot};
use aigc_core::policy::types::{NetworkMode, ProofLevel};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct UiNetworkSnapshot {
    pub(crate) network_mode: NetworkMode,
    pub(crate) proof_level: ProofLevel,
    pub(crate) proof_source: NetworkProofSource,
    pub(crate) ui_remote_fetch_disabled: bool,
}

#[tauri::command]
pub(crate) fn get_network_snapshot() -> UiNetworkSnapshot {
    let policy = NetworkSnapshot::offline_policy();
    UiNetworkSnapshot {
        network_mode: policy.network_mode,
        proof_level: policy.proof_level,
        proof_source: policy.proof_source,
        ui_remote_fetch_disabled: policy.ui_remote_fetch_disabled,
    }
}
