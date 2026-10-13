//! Authority probes preserve caller input for core validation and report only observed local results.

use aigc_core::adapters::interface::{
    AdapterCapabilitiesResponse, AdapterClient, AdapterHealthResponse, AdapterModel,
    ResolveModelRequest, ResolveModelResponse,
};
use aigc_core::adapters::loopback::loopback_endpoint_socket_addr;
use aigc_core::adapters::runtime::AdapterRuntime;
use aigc_core::error::CoreResult;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

#[cfg(feature = "authority-integrity-test-hooks")]
#[derive(Debug, Deserialize)]
pub(crate) struct AuthorityIntegrityProbeInput {
    endpoint: String,
}

#[cfg(feature = "authority-integrity-test-hooks")]
#[derive(Debug, Serialize)]
pub(crate) struct AuthorityIntegrityProbeResult {
    adapter_id: String,
    endpoint: String,
    dependency_path_reached: bool,
}

#[cfg(feature = "authority-integrity-test-hooks")]
#[derive(Clone)]
struct SocketAttemptProbe {
    endpoint: String,
}

#[cfg(feature = "authority-integrity-test-hooks")]
impl SocketAttemptProbe {
    fn socket_address(&self) -> CoreResult<std::net::SocketAddr> {
        loopback_endpoint_socket_addr(&self.endpoint)
    }

    fn record_attempt(&self) -> CoreResult<()> {
        let Ok(path) = std::env::var("AIGC_AUTHORITY_INTEGRITY_ATTEMPT_LOG") else {
            return Ok(());
        };
        let mut output = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(output, "{}", self.endpoint)?;
        output.flush()?;
        Ok(())
    }
}

#[cfg(feature = "authority-integrity-test-hooks")]
impl AdapterClient for SocketAttemptProbe {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn health(&self) -> CoreResult<AdapterHealthResponse> {
        self.record_attempt()?;
        TcpStream::connect_timeout(&self.socket_address()?, Duration::from_millis(250))?;
        Ok(AdapterHealthResponse {
            status: "ok".to_string(),
            adapter_id: "authority-integrity-probe".to_string(),
            adapter_version: "1".to_string(),
            uptime_ms: 0,
        })
    }

    fn capabilities(&self) -> CoreResult<AdapterCapabilitiesResponse> {
        Ok(AdapterCapabilitiesResponse {
            adapter_type: "TEST".to_string(),
            features: Vec::new(),
            limits: json!({}),
            models: Vec::new(),
        })
    }

    fn resolve_model(&self, _req: ResolveModelRequest) -> CoreResult<ResolveModelResponse> {
        Ok(ResolveModelResponse {
            resolved_model: AdapterModel {
                model_id: "authority-integrity-probe".to_string(),
                model_sha256: None,
                quantization: None,
                context_window: None,
                notes: None,
            },
            rationale: "authority-integrity probe".to_string(),
        })
    }
}

#[cfg(feature = "authority-integrity-test-hooks")]
#[tauri::command]
pub(crate) fn authority_integrity_probe_adapter(
    input: AuthorityIntegrityProbeInput,
) -> Result<AuthorityIntegrityProbeResult, String> {
    let endpoint = input.endpoint;
    let runtime = AdapterRuntime::new(vec![SocketAttemptProbe {
        endpoint: endpoint.clone(),
    }]);
    runtime
        .validate_loopback_only()
        .map_err(|error| error.to_string())?;
    let health = runtime.health_all().map_err(|error| error.to_string())?;
    let adapter_id = health
        .first()
        .map(|value| value.adapter_id.clone())
        .ok_or_else(|| "probe adapter returned no health record".to_string())?;
    Ok(AuthorityIntegrityProbeResult {
        adapter_id,
        endpoint,
        dependency_path_reached: true,
    })
}

#[cfg(all(test, feature = "authority-integrity-test-hooks"))]
mod authority_integrity_tests {
    use crate::app_builder;
    use serde_json::json;
    use std::fs;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tauri::ipc::{CallbackFn, InvokeBody};
    use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, INVOKE_KEY};
    use tauri::webview::InvokeRequest;

    fn temp_test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aigc_authority_integrity_{label}_{}_{}",
            std::process::id(),
            nonce
        ))
    }

    fn environment_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("environment test lock")
    }

    fn request(endpoint: &str) -> InvokeRequest {
        InvokeRequest {
            cmd: "authority_integrity_probe_adapter".into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: "tauri://localhost".parse().expect("valid test URL"),
            body: InvokeBody::Json(json!({"input": {"endpoint": endpoint}})),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        }
    }

    #[test]
    fn tauri_ipc_adapter_dependency_path_reaches_loopback_sensor() {
        let _environment_guard = environment_lock();
        let root = temp_test_dir("positive");
        fs::create_dir_all(&root).expect("create temp root");
        let attempts = root.join("attempts.log");
        std::env::set_var("AIGC_AUTHORITY_INTEGRITY_ATTEMPT_LOG", &attempts);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback sensor");
        let endpoint = format!("http://{}", listener.local_addr().expect("sensor address"));
        let accept = std::thread::spawn(move || listener.accept().expect("accept probe"));
        let app = app_builder(mock_builder())
            .build(mock_context(noop_assets()))
            .expect("build target app");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("build test webview");

        let response = get_ipc_response(&webview, request(&endpoint))
            .expect("loopback probe should succeed")
            .deserialize::<serde_json::Value>()
            .expect("probe response should be JSON");
        accept.join().expect("join sensor");

        assert_eq!(response["dependency_path_reached"], true);
        assert_eq!(response["endpoint"], endpoint);
        assert_eq!(
            fs::read_to_string(&attempts).expect("read attempt log"),
            format!("{endpoint}\n")
        );
        println!("MHAI_LP007_POSITIVE_ATTEMPT_SENSOR=PASS");
        println!("MHAI_LP007_TAURI_IPC_TO_DEPENDENCY_PATH=PASS");
        std::env::remove_var("AIGC_AUTHORITY_INTEGRITY_ATTEMPT_LOG");
        fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn non_loopback_endpoint_is_rejected_before_dependency_attempt() {
        let _environment_guard = environment_lock();
        let root = temp_test_dir("non_loopback");
        fs::create_dir_all(&root).expect("create temp root");
        let attempts = root.join("attempts.log");
        std::env::set_var("AIGC_AUTHORITY_INTEGRITY_ATTEMPT_LOG", &attempts);
        let app = app_builder(mock_builder())
            .build(mock_context(noop_assets()))
            .expect("build target app");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("build test webview");

        let error = get_ipc_response(&webview, request("http://203.0.113.1:9"))
            .expect_err("non-loopback endpoint must fail");

        assert!(error.to_string().contains("adapter endpoint rejected"));
        assert!(!attempts.exists());
        println!("MHAI_LP007_NON_LOOPBACK_REJECTED_BEFORE_ATTEMPT=PASS");
        std::env::remove_var("AIGC_AUTHORITY_INTEGRITY_ATTEMPT_LOG");
        fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn malformed_endpoint_is_rejected_without_attempt() {
        let _environment_guard = environment_lock();
        let root = temp_test_dir("malformed");
        fs::create_dir_all(&root).expect("create temp root");
        let attempts = root.join("attempts.log");
        std::env::set_var("AIGC_AUTHORITY_INTEGRITY_ATTEMPT_LOG", &attempts);
        let app = app_builder(mock_builder())
            .build(mock_context(noop_assets()))
            .expect("build target app");
        let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("build test webview");

        let error = get_ipc_response(&webview, request("not-a-url"))
            .expect_err("malformed endpoint must fail");

        assert!(error.to_string().contains("invalid adapter endpoint URL"));
        assert!(!attempts.exists());
        println!("MHAI_LP007_MALFORMED_REJECTED_BEFORE_ATTEMPT=PASS");
        std::env::remove_var("AIGC_AUTHORITY_INTEGRITY_ATTEMPT_LOG");
        fs::remove_dir_all(root).expect("remove temp root");
    }
}
