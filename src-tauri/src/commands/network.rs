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

#[cfg(test)]
mod tests {
    use super::*;
    use aigc_core::policy::allowlist::AllowlistEntry;
    use aigc_core::policy::network_snapshot::AdapterEndpointSnapshot;
    use serde_json::json;
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn serialized_network_dtos_match_openapi_schemas() {
        let ui = serde_json::to_value(get_network_snapshot()).unwrap();
        let mut network = NetworkSnapshot::offline_policy();
        let endpoint = AdapterEndpointSnapshot {
            endpoint: "http://127.0.0.1:11434".into(),
            is_loopback: true,
            validation_error: None,
        };
        let mut cases = vec![
            json!({"schema":"UiNetworkSnapshot", "value":ui}),
            json!({"schema":"TruthfulNetworkSnapshot", "value":network}),
            json!({"schema":"AdapterEndpointSnapshot", "value":endpoint}),
        ];
        network.adapter_endpoints.push(endpoint);
        network.allowlist.push(AllowlistEntry {
            scheme: "https".into(),
            host: "example.invalid".into(),
            port: 443,
            path_prefix: None,
            purpose: "test".into(),
            policy_pack_id: "test".into(),
            policy_pack_version: "1".into(),
        });
        cases.push(json!({"schema":"TruthfulNetworkSnapshot", "value":network}));
        network.adapter_endpoints[0].validation_error = Some("test error".into());
        network.allowlist[0].path_prefix = Some("/test".into());
        network.network_mode = NetworkMode::ONLINE_ALLOWLISTED;
        for level in [
            ProofLevel::ONLINE_ALLOWLIST_CORE_ONLY,
            ProofLevel::ONLINE_ALLOWLIST_WITH_OS_FIREWALL_PROFILE,
        ] {
            network.proof_level = level;
            cases.push(json!({"schema":"TruthfulNetworkSnapshot", "value":network}));
        }

        let contract: serde_json::Value =
            serde_json::from_str(include_str!("../../../openapi/openapi.generated.json")).unwrap();
        assert_eq!(
            ui,
            contract["components"]["schemas"]["UiNetworkSnapshot"]["example"]
        );
        for (schema, value) in [
            ("UiNetworkSnapshot", ui),
            (
                "TruthfulNetworkSnapshot",
                serde_json::to_value(network).unwrap(),
            ),
        ] {
            let mut measured = value.clone();
            measured["proof_source"] = json!("MEASURED");
            cases.push(json!({"schema":schema, "value":measured, "valid":false}));
            let mut missing = value;
            missing.as_object_mut().unwrap().remove("proof_source");
            cases.push(json!({"schema":schema, "value":missing, "valid":false}));
        }
        let mut strings = serde_json::to_value(NetworkSnapshot::offline_policy()).unwrap();
        strings["adapter_endpoints"] = json!(["http://127.0.0.1:11434"]);
        cases.push(json!({"schema":"TruthfulNetworkSnapshot", "value":strings, "valid":false}));
        cases.push(json!({"schema":"AdapterEndpointSnapshot", "value":{"endpoint":"http://127.0.0.1:11434"}, "valid":false}));

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let mut child = Command::new("node")
            .arg(root.join("scripts/test-network-openapi.mjs"))
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Node and pnpm dependencies are required for OpenAPI contract validation");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&cases).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
