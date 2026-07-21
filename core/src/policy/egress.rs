use crate::audit::event::{Actor, AuditEvent};
use crate::audit::log::AuditLog;
use crate::error::CoreResult;
use crate::policy::allowlist::AllowlistEntry;
use crate::policy::types::{NetworkMode, ProofLevel};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub network_mode: NetworkMode,
    pub proof_level: ProofLevel,
    pub allowlist: Vec<AllowlistEntry>, // canonical + sorted
}

#[derive(Debug, Clone)]
pub enum EgressDecision {
    Allowed { allowlist_rule_id: String },
    Blocked { reason: String },
}

pub struct EgressClient<'a> {
    pub policy: EgressPolicy,
    pub audit: &'a mut AuditLog,
    pub run_id: String,
    pub vault_id: String,
}

impl<'a> EgressClient<'a> {
    pub fn decide(&self, url: &Url) -> CoreResult<EgressDecision> {
        match self.policy.network_mode {
            NetworkMode::OFFLINE => Ok(EgressDecision::Blocked {
                reason: "OFFLINE_MODE".to_string(),
            }),
            NetworkMode::ONLINE_ALLOWLISTED => {
                for (idx, e) in self.policy.allowlist.iter().enumerate() {
                    if e.matches_url(url) {
                        return Ok(EgressDecision::Allowed {
                            allowlist_rule_id: format!("ALW{:04}", idx),
                        });
                    }
                }
                Ok(EgressDecision::Blocked {
                    reason: "NOT_ALLOWLISTED".to_string(),
                })
            }
        }
    }

    pub fn record_attempt(
        &mut self,
        url: &Url,
        decision: &EgressDecision,
        request_bytes: &[u8],
    ) -> CoreResult<()> {
        let mut h = Sha256::new();
        h.update(request_bytes);
        let request_hash_sha256 = hex::encode(h.finalize());

        let destination = json!({
            "scheme": url.scheme(),
            "host": url.host_str().unwrap_or(""),
            "port": url.port_or_known_default().unwrap_or(0),
            "path": url.path(),
        });

        match decision {
            EgressDecision::Allowed { allowlist_rule_id } => {
                self.audit.append(AuditEvent {
                    ts_utc: now_rfc3339_utc(),
                    event_type: "EGRESS_REQUEST_ALLOWED".to_string(),
                    run_id: self.run_id.clone(),
                    vault_id: self.vault_id.clone(),
                    actor: Actor::System,
                    details: json!({
                        "destination": destination,
                        "allowlist_rule_id": allowlist_rule_id,
                        "request_hash_sha256": request_hash_sha256,
                        "evidence_origin": "RUNTIME_OBSERVATION"
                    }),
                    prev_event_hash: "".to_string(),
                    event_hash: "".to_string(),
                })?;
            }
            EgressDecision::Blocked { reason } => {
                self.audit.append(AuditEvent {
                    ts_utc: now_rfc3339_utc(),
                    event_type: "EGRESS_REQUEST_BLOCKED".to_string(),
                    run_id: self.run_id.clone(),
                    vault_id: self.vault_id.clone(),
                    actor: Actor::System,
                    details: json!({
                        "destination": destination,
                        "block_reason": reason,
                        "request_hash_sha256": request_hash_sha256,
                        "evidence_origin": "RUNTIME_OBSERVATION"
                    }),
                    prev_event_hash: "".to_string(),
                    event_hash: "".to_string(),
                })?;
            }
        }
        Ok(())
    }
}

fn now_rfc3339_utc() -> String {
    // Determinism rules forbid volatile timestamps in deliverables, but audit_log is allowed to include timestamps.
    // For deterministic test mode we will inject a fixed clock; this is a minimal runtime default.
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
