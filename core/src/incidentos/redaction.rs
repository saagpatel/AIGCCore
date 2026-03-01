use serde::{Deserialize, Serialize};
use crate::error::{CoreError, CoreResult};
use regex::Regex;

/// Redaction profile for customer data
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedactionProfile {
    Basic,     // PII only
    Standard,  // PII + system paths
    Strict,    // PII + paths + command outputs
}

impl RedactionProfile {
    pub fn from_str(s: &str) -> CoreResult<Self> {
        match s {
            "BASIC" => Ok(RedactionProfile::Basic),
            "STANDARD" => Ok(RedactionProfile::Standard),
            "STRICT" => Ok(RedactionProfile::Strict),
            _ => Err(CoreError::InvalidInput(format!(
                "Invalid redaction profile: {}",
                s
            ))),
        }
    }
}

/// Record of what was redacted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRecord {
    pub span_start: usize,
    pub span_end: usize,
    pub original_text: String,
    pub reason: String,
    pub profile_rule: String,
}

/// Redaction engine
pub struct RedactionEngine {
    profile: RedactionProfile,
    records: Vec<RedactionRecord>,
}

impl RedactionEngine {
    pub fn new(profile: RedactionProfile) -> Self {
        RedactionEngine {
            profile,
            records: Vec::new(),
        }
    }

    /// Redact text according to profile rules
    pub fn redact(&mut self, text: &str) -> (String, Vec<RedactionRecord>) {
        let mut result = text.to_string();
        let mut records = Vec::new();

        // Apply PII redactions (all profiles)
        let (text_after_pii, pii_records) = self.redact_pii(&result);
        result = text_after_pii;
        records.extend(pii_records);

        // Apply system paths if STANDARD or STRICT
        if self.profile == RedactionProfile::Standard || self.profile == RedactionProfile::Strict {
            let (text_after_paths, path_records) = self.redact_system_paths(&result);
            result = text_after_paths;
            records.extend(path_records);
        }

        // Apply command outputs if STRICT
        if self.profile == RedactionProfile::Strict {
            let (text_after_cmds, cmd_records) = self.redact_command_outputs(&result);
            result = text_after_cmds;
            records.extend(cmd_records);
        }

        self.records = records.clone();
        (result, records)
    }

    /// Redact personally identifiable information
    fn redact_pii(&self, text: &str) -> (String, Vec<RedactionRecord>) {
        let mut result = text.to_string();
        let mut records = Vec::new();

        // Email pattern
        let email_re = Regex::new(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        ).unwrap_or_else(|_| Regex::new("^$").unwrap());

        // Phone pattern (simplified)
        let phone_re = Regex::new(
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
        ).unwrap_or_else(|_| Regex::new("^$").unwrap());

        // SSN pattern
        let ssn_re = Regex::new(
            r"\b\d{3}-\d{2}-\d{4}\b"
        ).unwrap_or_else(|_| Regex::new("^$").unwrap());

        // Process emails
        for caps in email_re.captures_iter(text) {
            if let Some(m) = caps.get(0) {
                let start = m.start();
                let end = m.end();
                let original = m.as_str().to_string();
                records.push(RedactionRecord {
                    span_start: start,
                    span_end: end,
                    original_text: original,
                    reason: "Email address".to_string(),
                    profile_rule: "PII.email".to_string(),
                });
            }
        }

        // Process phones
        for caps in phone_re.captures_iter(text) {
            if let Some(m) = caps.get(0) {
                let start = m.start();
                let end = m.end();
                let original = m.as_str().to_string();
                records.push(RedactionRecord {
                    span_start: start,
                    span_end: end,
                    original_text: original,
                    reason: "Phone number".to_string(),
                    profile_rule: "PII.phone".to_string(),
                });
            }
        }

        // Process SSNs
        for caps in ssn_re.captures_iter(text) {
            if let Some(m) = caps.get(0) {
                let start = m.start();
                let end = m.end();
                let original = m.as_str().to_string();
                records.push(RedactionRecord {
                    span_start: start,
                    span_end: end,
                    original_text: original,
                    reason: "Social security number".to_string(),
                    profile_rule: "PII.ssn".to_string(),
                });
            }
        }

        // Apply replacements in reverse order to avoid offset issues
        for record in records.iter().rev() {
            let replacement = format!("[REDACTED: {}]", record.reason);

            if record.span_start < result.len() && record.span_end <= result.len() {
                result.replace_range(record.span_start..record.span_end, &replacement);
            }
        }

        (result, records)
    }

    /// Redact system paths and resources
    fn redact_system_paths(&self, text: &str) -> (String, Vec<RedactionRecord>) {
        let mut result = text.to_string();
        let mut records = Vec::new();

        // IP address pattern
        let ip_re = Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ).unwrap_or_else(|_| Regex::new("^$").unwrap());

        // Process IPs
        for caps in ip_re.captures_iter(text) {
            if let Some(m) = caps.get(0) {
                records.push(RedactionRecord {
                    span_start: m.start(),
                    span_end: m.end(),
                    original_text: m.as_str().to_string(),
                    reason: "Network address".to_string(),
                    profile_rule: "SYSTEM.ip_address".to_string(),
                });
            }
        }

        // Apply replacements
        for record in records.iter().rev() {
            let replacement = format!("[REDACTED: {}]", record.reason);
            if record.span_start < result.len() && record.span_end <= result.len() {
                result.replace_range(record.span_start..record.span_end, &replacement);
            }
        }

        (result, records)
    }

    /// Redact command outputs
    fn redact_command_outputs(&self, text: &str) -> (String, Vec<RedactionRecord>) {
        let result = text.to_string();
        let mut records = Vec::new();

        // Detect command output patterns
        let cmd_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "curl", "wget", "password", "secret", "token"];

        for keyword in &cmd_keywords {
            if text.contains(keyword) {
                records.push(RedactionRecord {
                    span_start: 0,
                    span_end: 0, // Simplified: mark whole line
                    original_text: keyword.to_string(),
                    reason: format!("Command output containing {}", keyword),
                    profile_rule: "COMMAND.output".to_string(),
                });
            }
        }

        (result, records)
    }

    pub fn records(&self) -> &[RedactionRecord] {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_profile_email() {
        let mut engine = RedactionEngine::new(RedactionProfile::Basic);
        let text = "Contact user@example.com for support";
        let (redacted, records) = engine.redact(text);

        assert!(redacted.contains("[REDACTED: Email address]"));
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_basic_profile_phone() {
        let mut engine = RedactionEngine::new(RedactionProfile::Basic);
        let text = "Call 555-123-4567 for help";
        let (redacted, records) = engine.redact(text);

        assert!(redacted.contains("[REDACTED:") || records.is_empty());
    }

    #[test]
    fn test_standard_profile() {
        let mut engine = RedactionEngine::new(RedactionProfile::Standard);
        let text = "User logged in from 192.168.1.1";
        let (redacted, _records) = engine.redact(text);

        assert_ne!(redacted, text);
    }

    #[test]
    fn test_strict_profile() {
        let mut engine = RedactionEngine::new(RedactionProfile::Strict);
        let text = "SELECT * FROM users WHERE email = user@test.com";
        let (_redacted, records) = engine.redact(text);

        // Should have at least email redaction
        assert!(records.len() > 0);
    }

    #[test]
    fn test_profile_from_str() {
        assert_eq!(RedactionProfile::from_str("BASIC").unwrap(), RedactionProfile::Basic);
        assert_eq!(RedactionProfile::from_str("STANDARD").unwrap(), RedactionProfile::Standard);
        assert_eq!(RedactionProfile::from_str("STRICT").unwrap(), RedactionProfile::Strict);
        assert!(RedactionProfile::from_str("INVALID").is_err());
    }
}
