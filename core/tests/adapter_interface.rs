use aigc_core::adapters::interface::{classify_adapter_error, enforce_loopback_endpoint};
use aigc_core::adapters::loopback::loopback_endpoint_socket_addr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn loopback_endpoint_is_enforced() {
    assert!(enforce_loopback_endpoint("http://127.0.0.1:11434").is_ok());
    assert!(enforce_loopback_endpoint("http://[::1]:11434").is_ok());
    assert!(enforce_loopback_endpoint("http://192.168.1.8:11434").is_err());
}

#[test]
fn obfuscated_numeric_loopback_hosts_are_rejected() {
    for endpoint in [
        "http://0177.0.0.1:11434",
        "http://0x7f.0.0.1:11434",
        "http://2130706433:11434",
        "http://127.1:11434",
        "http://user@127.0.0.1:11434",
    ] {
        assert!(
            enforce_loopback_endpoint(endpoint).is_err(),
            "{endpoint} must not pass authority-integrity loopback policy"
        );
    }
}

#[test]
fn loopback_socket_addr_uses_strict_literal_ip_parse() {
    assert_eq!(
        loopback_endpoint_socket_addr("http://127.0.0.1:11434").unwrap(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 11434)
    );
    assert_eq!(
        loopback_endpoint_socket_addr("http://[::1]:11434").unwrap(),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 11434)
    );
    assert!(loopback_endpoint_socket_addr("http://0177.0.0.1:11434").is_err());
    assert!(loopback_endpoint_socket_addr("http://203.0.113.1:11434").is_err());
}

#[test]
fn adapter_error_envelope_categories_are_stable() {
    let t = classify_adapter_error("timeout while waiting");
    assert_eq!(t.error.category, "TIMEOUT");
    let nf = classify_adapter_error("model not found");
    assert_eq!(nf.error.category, "MODEL_NOT_FOUND");
    let ns = classify_adapter_error("unsupported feature");
    assert_eq!(ns.error.category, "NOT_SUPPORTED");
}
