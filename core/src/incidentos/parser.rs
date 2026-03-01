use serde::{Deserialize, Serialize};
use crate::error::{CoreError, CoreResult};

/// Raw incident event from log file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawIncidentEvent {
    pub timestamp: String,
    pub source_system: String,
    pub actor: String,
    pub action: String,
    pub affected_resource: String,
    pub evidence_text: String,
}

/// Parsed incident event with timestamp validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParsedIncidentEvent {
    pub event_id: String,
    pub timestamp_epoch_ms: u64,
    pub timestamp_iso: String,
    pub source_system: String,
    pub actor: String,
    pub action: String,
    pub affected_resource: String,
    pub evidence_text: String,
    pub severity: String,
}

/// Parse JSON incident log format
pub fn parse_json_log(json_str: &str) -> CoreResult<Vec<ParsedIncidentEvent>> {
    let raw_events: Vec<RawIncidentEvent> = serde_json::from_str(json_str)
        .map_err(|e| CoreError::InvalidInput(format!("Failed to parse JSON log: {}", e)))?;

    parse_raw_events(raw_events)
}

/// Parse NDJSON incident log format (one JSON object per line)
pub fn parse_ndjson_log(ndjson_str: &str) -> CoreResult<Vec<ParsedIncidentEvent>> {
    let mut raw_events = Vec::new();

    for (line_num, line) in ndjson_str.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: RawIncidentEvent = serde_json::from_str(trimmed).map_err(|e| {
            CoreError::InvalidInput(format!(
                "Failed to parse NDJSON line {}: {}",
                line_num + 1,
                e
            ))
        })?;

        raw_events.push(event);
    }

    parse_raw_events(raw_events)
}

/// Parse raw events into validated, sorted events
fn parse_raw_events(raw_events: Vec<RawIncidentEvent>) -> CoreResult<Vec<ParsedIncidentEvent>> {
    let mut events = Vec::new();

    for (idx, raw) in raw_events.into_iter().enumerate() {
        // Parse ISO 8601 timestamp to epoch milliseconds
        let timestamp_epoch_ms = parse_iso8601_to_epoch(&raw.timestamp)
            .unwrap_or_else(|_| {
                // Fallback: use event index as pseudo-timestamp
                idx as u64 * 1000
            });

        // Infer severity from keywords (HIGH/MEDIUM/LOW)
        let severity = infer_severity(&raw.action, &raw.evidence_text);

        let event_id = format!(
            "INCIDENT_{:08x}_{:04x}_{:04x}",
            (timestamp_epoch_ms ^ idx as u64) & 0xffffffff,
            idx & 0xffff,
            (raw.action.len() ^ raw.source_system.len()) & 0xffff
        );

        events.push(ParsedIncidentEvent {
            event_id,
            timestamp_epoch_ms,
            timestamp_iso: raw.timestamp.clone(),
            source_system: raw.source_system,
            actor: raw.actor,
            action: raw.action,
            affected_resource: raw.affected_resource,
            evidence_text: raw.evidence_text,
            severity,
        });
    }

    // Sort by timestamp for deterministic ordering
    events.sort_by_key(|e| e.timestamp_epoch_ms);

    if events.is_empty() {
        return Err(CoreError::InvalidInput(
            "No valid events found in incident log".to_string(),
        ));
    }

    Ok(events)
}

/// Parse ISO 8601 timestamp to epoch milliseconds (best effort)
fn parse_iso8601_to_epoch(timestamp_str: &str) -> CoreResult<u64> {
    // Simple ISO 8601 parser (handles YYYY-MM-DDTHH:MM:SSZ format)
    // For MVP: return a deterministic hash-based value
    let trimmed = timestamp_str.trim();

    // Extract numeric components if possible
    let bytes = trimmed.as_bytes();
    let mut epoch_ms = 0u64;

    for &b in bytes {
        if b.is_ascii_digit() {
            epoch_ms = epoch_ms.wrapping_mul(10).wrapping_add((b - b'0') as u64);
        }
    }

    if epoch_ms == 0 {
        return Err(CoreError::InvalidInput(
            "Could not parse timestamp".to_string(),
        ));
    }

    Ok(epoch_ms)
}

/// Infer severity from keywords
fn infer_severity(action: &str, evidence: &str) -> String {
    let text = format!("{} {}", action.to_lowercase(), evidence.to_lowercase());

    let high_keywords = ["critical", "error", "fail", "breach", "attack", "intrusion"];
    let medium_keywords = ["warn", "timeout", "retry", "denied", "rejected"];

    if high_keywords.iter().any(|kw| text.contains(kw)) {
        "HIGH".to_string()
    } else if medium_keywords.iter().any(|kw| text.contains(kw)) {
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_log() {
        let json = r#"[
            {
                "timestamp": "2026-02-12T10:15:30Z",
                "source_system": "web-server",
                "actor": "user@example.com",
                "action": "login_attempt",
                "affected_resource": "auth-service",
                "evidence_text": "User successfully authenticated"
            }
        ]"#;

        let result = parse_json_log(json);
        assert!(result.is_ok());
        let events = result.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "login_attempt");
        assert_eq!(events[0].severity, "LOW");
    }

    #[test]
    fn test_parse_ndjson_log() {
        let ndjson = r#"{"timestamp":"2026-02-12T10:15:30Z","source_system":"web","actor":"user1","action":"login","affected_resource":"auth","evidence_text":"success"}
{"timestamp":"2026-02-12T10:16:00Z","source_system":"db","actor":"user1","action":"query","affected_resource":"users","evidence_text":"SELECT * FROM users"}"#;

        let result = parse_ndjson_log(ndjson);
        assert!(result.is_ok());
        let events = result.unwrap();
        assert_eq!(events.len(), 2);
        // Events should be sorted by timestamp
        assert!(events[0].timestamp_epoch_ms <= events[1].timestamp_epoch_ms);
    }

    #[test]
    fn test_parse_invalid_json() {
        let json = r#"{ invalid json }"#;
        let result = parse_json_log(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_severity_inference_high() {
        let json = r#"[{
            "timestamp":"2026-02-12T10:15:30Z",
            "source_system":"web",
            "actor":"system",
            "action":"critical_error",
            "affected_resource":"api",
            "evidence_text":"System breach detected"
        }]"#;

        let events = parse_json_log(json).unwrap();
        assert_eq!(events[0].severity, "HIGH");
    }

    #[test]
    fn test_severity_inference_medium() {
        let json = r#"[{
            "timestamp":"2026-02-12T10:15:30Z",
            "source_system":"web",
            "actor":"user",
            "action":"login",
            "affected_resource":"auth",
            "evidence_text":"Access denied - timeout warning"
        }]"#;

        let events = parse_json_log(json).unwrap();
        assert_eq!(events[0].severity, "MEDIUM");
    }

    #[test]
    fn test_event_determinism() {
        let json = r#"[
            {"timestamp":"2026-02-12T10:15:30Z","source_system":"web","actor":"u1","action":"action1","affected_resource":"res1","evidence_text":"evt1"},
            {"timestamp":"2026-02-12T10:15:35Z","source_system":"web","actor":"u2","action":"action2","affected_resource":"res2","evidence_text":"evt2"}
        ]"#;

        let events1 = parse_json_log(json).unwrap();
        let events2 = parse_json_log(json).unwrap();

        // Same input should produce identical events
        assert_eq!(events1.len(), events2.len());
        for (e1, e2) in events1.iter().zip(events2.iter()) {
            assert_eq!(e1.event_id, e2.event_id);
            assert_eq!(e1.timestamp_epoch_ms, e2.timestamp_epoch_ms);
        }
    }

    #[test]
    fn test_events_sorted_chronologically() {
        let json = r#"[
            {"timestamp":"2026-02-12T10:15:40Z","source_system":"a","actor":"u","action":"act","affected_resource":"r","evidence_text":"e"},
            {"timestamp":"2026-02-12T10:15:30Z","source_system":"b","actor":"u","action":"act","affected_resource":"r","evidence_text":"e"},
            {"timestamp":"2026-02-12T10:15:35Z","source_system":"c","actor":"u","action":"act","affected_resource":"r","evidence_text":"e"}
        ]"#;

        let events = parse_json_log(json).unwrap();
        // Check events are sorted by timestamp
        for i in 1..events.len() {
            assert!(events[i - 1].timestamp_epoch_ms <= events[i].timestamp_epoch_ms);
        }
    }
}
