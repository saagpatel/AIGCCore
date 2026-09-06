use crate::error::{CoreError, CoreResult};
use std::net::{IpAddr, SocketAddr};

pub fn is_loopback_endpoint(endpoint: &str) -> CoreResult<bool> {
    let ip = strict_endpoint_ip(endpoint)?;
    Ok(ip.is_loopback())
}

pub fn loopback_endpoint_socket_addr(endpoint: &str) -> CoreResult<SocketAddr> {
    let url = parse_http_endpoint(endpoint)?;
    let ip = strict_endpoint_ip(endpoint)?;
    if !ip.is_loopback() {
        return Err(CoreError::PolicyBlocked(
            "adapter endpoint rejected: not loopback (127.0.0.1/::1)".to_string(),
        ));
    }
    let port = url.port_or_known_default().ok_or_else(|| {
        CoreError::InvalidInput("adapter endpoint missing socket port".to_string())
    })?;
    Ok(SocketAddr::new(ip, port))
}

fn strict_endpoint_ip(endpoint: &str) -> CoreResult<IpAddr> {
    parse_http_endpoint(endpoint)?;
    let host = raw_host_literal(endpoint)?;
    host.parse().map_err(|_| {
        CoreError::InvalidInput("adapter endpoint host must be a literal IP address".to_string())
    })
}

fn parse_http_endpoint(endpoint: &str) -> CoreResult<url::Url> {
    let url = url::Url::parse(endpoint)
        .map_err(|_| CoreError::InvalidInput("invalid adapter endpoint URL".to_string()))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        _ => Err(CoreError::InvalidInput(
            "adapter endpoint scheme must be http or https".to_string(),
        )),
    }
}

fn raw_host_literal(endpoint: &str) -> CoreResult<&str> {
    let scheme_end = endpoint
        .find(':')
        .ok_or_else(|| CoreError::InvalidInput("invalid adapter endpoint URL".to_string()))?;
    let after_scheme = endpoint[scheme_end + 1..]
        .strip_prefix("//")
        .ok_or_else(|| CoreError::InvalidInput("invalid adapter endpoint URL".to_string()))?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err(CoreError::InvalidInput(
            "adapter endpoint missing host".to_string(),
        ));
    }
    if authority.contains('@') {
        return Err(CoreError::InvalidInput(
            "adapter endpoint userinfo is not allowed".to_string(),
        ));
    }

    if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, suffix) = after_bracket.split_once(']').ok_or_else(|| {
            CoreError::InvalidInput("adapter endpoint has invalid IPv6 host".to_string())
        })?;
        validate_port_suffix(suffix)?;
        return Ok(host);
    }

    if authority.matches(':').count() > 1 {
        return Err(CoreError::InvalidInput(
            "adapter endpoint IPv6 host must be bracketed".to_string(),
        ));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) => {
            validate_port(port)?;
            Ok(host)
        }
        None => Ok(authority),
    }
}

fn validate_port_suffix(suffix: &str) -> CoreResult<()> {
    if suffix.is_empty() {
        return Ok(());
    }
    let port = suffix.strip_prefix(':').ok_or_else(|| {
        CoreError::InvalidInput("adapter endpoint has invalid socket port".to_string())
    })?;
    validate_port(port)
}

fn validate_port(port: &str) -> CoreResult<()> {
    if port.is_empty() || !port.bytes().all(|value| value.is_ascii_digit()) {
        return Err(CoreError::InvalidInput(
            "adapter endpoint has invalid socket port".to_string(),
        ));
    }
    Ok(())
}
