#![no_main]

use aigc_core::adapters::interface::{
    AdapterCapabilitiesResponse, AdapterClient, AdapterHealthResponse, AdapterModel,
    ResolveModelRequest, ResolveModelResponse,
};
use aigc_core::adapters::loopback::loopback_endpoint_socket_addr;
use aigc_core::adapters::runtime::AdapterRuntime;
use aigc_core::error::CoreResult;
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

struct FuzzAdapter<'a> {
    endpoint: &'a str,
}

impl AdapterClient for FuzzAdapter<'_> {
    fn endpoint(&self) -> &str {
        self.endpoint
    }

    fn health(&self) -> CoreResult<AdapterHealthResponse> {
        Ok(AdapterHealthResponse {
            status: "ok".to_string(),
            adapter_id: "authority-integrity-fuzz".to_string(),
            adapter_version: "fuzz".to_string(),
            uptime_ms: 0,
        })
    }

    fn capabilities(&self) -> CoreResult<AdapterCapabilitiesResponse> {
        Ok(AdapterCapabilitiesResponse {
            adapter_type: "LLM".to_string(),
            features: Vec::new(),
            limits: serde_json::json!({}),
            models: vec![AdapterModel {
                model_id: "fuzz-model".to_string(),
                model_sha256: None,
                quantization: None,
                context_window: None,
                notes: None,
            }],
        })
    }

    fn resolve_model(&self, _req: ResolveModelRequest) -> CoreResult<ResolveModelResponse> {
        Ok(ResolveModelResponse {
            resolved_model: AdapterModel {
                model_id: "fuzz-model".to_string(),
                model_sha256: None,
                quantization: None,
                context_window: None,
                notes: None,
            },
            rationale: "fuzz target".to_string(),
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(endpoint) = std::str::from_utf8(data) else {
        return;
    };

    let runtime = AdapterRuntime::new(vec![FuzzAdapter { endpoint }]);
    let accepted = runtime.validate_loopback_only().is_ok();
    let oracle_loopback_ip_endpoint = strict_raw_ip_host(endpoint)
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);

    assert_eq!(
        accepted, oracle_loopback_ip_endpoint,
        "authority integrity adapter policy must accept only URL endpoints with loopback IP hosts"
    );

    if accepted {
        let socket_addr =
            loopback_endpoint_socket_addr(endpoint).expect("accepted endpoint must resolve safely");
        assert!(
            socket_addr.ip().is_loopback(),
            "accepted authority integrity endpoint must connect only to a loopback socket address"
        );
    }
});

fn strict_raw_ip_host(endpoint: &str) -> Option<IpAddr> {
    let url = url::Url::parse(endpoint).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }

    let scheme_end = endpoint.find(':')?;
    let after_scheme = endpoint[scheme_end + 1..].strip_prefix("//")?;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }

    let host = if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, suffix) = after_bracket.split_once(']')?;
        if !suffix.is_empty()
            && !suffix.strip_prefix(':').is_some_and(|port| {
                !port.is_empty() && port.bytes().all(|value| value.is_ascii_digit())
            })
        {
            return None;
        }
        host
    } else {
        if authority.matches(':').count() > 1 {
            return None;
        }
        match authority.rsplit_once(':') {
            Some((host, port))
                if !port.is_empty() && port.bytes().all(|value| value.is_ascii_digit()) =>
            {
                host
            }
            Some(_) => return None,
            None => authority,
        }
    };

    host.parse().ok()
}
