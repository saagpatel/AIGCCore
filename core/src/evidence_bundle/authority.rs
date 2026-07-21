use crate::determinism::run_id::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const EVIDENCE_AUTHORITY_SCHEMA_V1: &str = "EVIDENCE_AUTHORITY_V1";

pub const CLAIM_LOCAL_CONTROLLED_EXECUTION: &str = "LOCAL_CONTROLLED_EXECUTION";
pub const CLAIM_BUNDLE_INTEGRITY: &str = "BUNDLE_INTEGRITY";
pub const CLAIM_OFFLINE_POLICY_CONFIGURATION: &str = "OFFLINE_POLICY_CONFIGURATION";
pub const CLAIM_LIVE_EXECUTION: &str = "LIVE_EXECUTION";
pub const CLAIM_PRODUCTION_AUTHORITY: &str = "PRODUCTION_AUTHORITY";
pub const CLAIM_EXTERNAL_MUTATION: &str = "EXTERNAL_MUTATION";
pub const CLAIM_REAL_USER_SUCCESS: &str = "REAL_USER_SUCCESS";
pub const CLAIM_CURRENT_RUNTIME_CAPABILITY: &str = "CURRENT_RUNTIME_CAPABILITY";
pub const CLAIM_DEPLOYABILITY: &str = "DEPLOYABILITY";
pub const CLAIM_LIVE_EVALUATION_COMPLETION: &str = "LIVE_EVALUATION_COMPLETION";
pub const CLAIM_LIVE_EGRESS_BLOCKED: &str = "LIVE_EGRESS_BLOCKED";

const REQUIRED_SIMULATION_PROHIBITIONS: [&str; 8] = [
    CLAIM_LIVE_EXECUTION,
    CLAIM_PRODUCTION_AUTHORITY,
    CLAIM_EXTERNAL_MUTATION,
    CLAIM_REAL_USER_SUCCESS,
    CLAIM_CURRENT_RUNTIME_CAPABILITY,
    CLAIM_DEPLOYABILITY,
    CLAIM_LIVE_EVALUATION_COMPLETION,
    CLAIM_LIVE_EGRESS_BLOCKED,
];

const CONTROLLED_SIMULATION_CLAIMS: [&str; 3] = [
    CLAIM_LOCAL_CONTROLLED_EXECUTION,
    CLAIM_BUNDLE_INTEGRITY,
    CLAIM_OFFLINE_POLICY_CONFIGURATION,
];

const CONTROLLED_SIMULATION_EFFECTS: [&str; 3] = [
    "LOCAL_RUNTIME_DIRECTORY_WRITE",
    "LOCAL_AUDIT_LOG_WRITE",
    "LOCAL_EVIDENCE_BUNDLE_WRITE",
];

const CONTROLLED_SIMULATION_TOOLS: [&str; 3] = [
    "LOCAL_EVIDENCE_BUNDLE_EXPORT",
    "MODEL_INFERENCE",
    "EXTERNAL_PUBLICATION_OR_DEPLOYMENT",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceExecutionClass {
    Controlled,
    Simulated,
    Fixture,
    Replay,
    Natural,
    Live,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceOrigin {
    ControlSimulation,
    RuntimeObservation,
    Fixture,
    Replay,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceAvailability {
    Available,
    Unavailable,
    NotRequested,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSourceBinding {
    pub producer: String,
    pub source_revision: String,
    pub executable: String,
    pub executable_sha256: String,
    pub arguments_sha256: String,
    pub environment_sha256: String,
    pub audit_log_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolAuthority {
    pub tool_id: String,
    pub declared_available: bool,
    pub observed_used: bool,
    pub external_mutation_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceStateScope {
    pub cache_scope: String,
    pub prior_approval_reused: bool,
    pub credential_state_reused: bool,
    pub mutable_cache_reused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceClaimPolicy {
    pub may_satisfy: Vec<String>,
    pub must_not_satisfy: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAuthorityManifest {
    pub schema_version: String,
    pub case_id: String,
    pub requested_execution_class: EvidenceExecutionClass,
    pub observed_execution_class: EvidenceExecutionClass,
    pub evidence_origin: EvidenceOrigin,
    pub production_equivalent: bool,
    pub generated_at_utc: String,
    pub valid_until_utc: String,
    pub source: EvidenceSourceBinding,
    pub allowed_effects: Vec<String>,
    pub observed_effects: Vec<String>,
    pub credential_availability: EvidenceAvailability,
    pub tools: Vec<ToolAuthority>,
    pub state_scope: EvidenceStateScope,
    pub downstream_claims: EvidenceClaimPolicy,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceClaimContext {
    pub as_of_utc: String,
    pub expected_case_id: String,
    pub expected_source_revision: String,
    pub expected_executable_sha256: String,
    pub expected_arguments_sha256: String,
    pub expected_environment_sha256: String,
    pub expected_audit_log_sha256: String,
    pub required_tool_id: Option<String>,
    pub credentials_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClaimDecision {
    Authorized,
    Denied,
    Unknown,
}

impl EvidenceAuthorityManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn controlled_simulation(
        case_id: impl Into<String>,
        producer: impl Into<String>,
        source_revision: impl Into<String>,
        executable: impl Into<String>,
        executable_sha256: impl Into<String>,
        arguments_sha256: impl Into<String>,
        environment_sha256: impl Into<String>,
        generated_at_utc: impl Into<String>,
        valid_until_utc: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: EVIDENCE_AUTHORITY_SCHEMA_V1.to_string(),
            case_id: case_id.into(),
            requested_execution_class: EvidenceExecutionClass::Controlled,
            observed_execution_class: EvidenceExecutionClass::Controlled,
            evidence_origin: EvidenceOrigin::ControlSimulation,
            production_equivalent: false,
            generated_at_utc: generated_at_utc.into(),
            valid_until_utc: valid_until_utc.into(),
            source: EvidenceSourceBinding {
                producer: producer.into(),
                source_revision: source_revision.into(),
                executable: executable.into(),
                executable_sha256: executable_sha256.into(),
                arguments_sha256: arguments_sha256.into(),
                environment_sha256: environment_sha256.into(),
                audit_log_sha256: sha256_hex(b""),
            },
            allowed_effects: vec![
                "LOCAL_RUNTIME_DIRECTORY_WRITE".to_string(),
                "LOCAL_AUDIT_LOG_WRITE".to_string(),
                "LOCAL_EVIDENCE_BUNDLE_WRITE".to_string(),
            ],
            observed_effects: vec![
                "LOCAL_RUNTIME_DIRECTORY_WRITE".to_string(),
                "LOCAL_AUDIT_LOG_WRITE".to_string(),
                "LOCAL_EVIDENCE_BUNDLE_WRITE".to_string(),
            ],
            credential_availability: EvidenceAvailability::NotRequested,
            tools: vec![
                ToolAuthority {
                    tool_id: "LOCAL_EVIDENCE_BUNDLE_EXPORT".to_string(),
                    declared_available: true,
                    observed_used: true,
                    external_mutation_allowed: false,
                },
                ToolAuthority {
                    tool_id: "MODEL_INFERENCE".to_string(),
                    declared_available: false,
                    observed_used: false,
                    external_mutation_allowed: false,
                },
                ToolAuthority {
                    tool_id: "EXTERNAL_PUBLICATION_OR_DEPLOYMENT".to_string(),
                    declared_available: false,
                    observed_used: false,
                    external_mutation_allowed: false,
                },
            ],
            state_scope: EvidenceStateScope {
                cache_scope: "CASE_LOCAL".to_string(),
                prior_approval_reused: false,
                credential_state_reused: false,
                mutable_cache_reused: false,
            },
            downstream_claims: EvidenceClaimPolicy {
                may_satisfy: vec![
                    CLAIM_LOCAL_CONTROLLED_EXECUTION.to_string(),
                    CLAIM_BUNDLE_INTEGRITY.to_string(),
                    CLAIM_OFFLINE_POLICY_CONFIGURATION.to_string(),
                ],
                must_not_satisfy: vec![
                    CLAIM_LIVE_EXECUTION.to_string(),
                    CLAIM_PRODUCTION_AUTHORITY.to_string(),
                    CLAIM_EXTERNAL_MUTATION.to_string(),
                    CLAIM_REAL_USER_SUCCESS.to_string(),
                    CLAIM_CURRENT_RUNTIME_CAPABILITY.to_string(),
                    CLAIM_DEPLOYABILITY.to_string(),
                    CLAIM_LIVE_EVALUATION_COMPLETION.to_string(),
                    CLAIM_LIVE_EGRESS_BLOCKED.to_string(),
                ],
            },
            limitations: vec![
                "Blocked-egress evidence is a control simulation, not an observed network request."
                    .to_string(),
                "No production credentials, external mutation authority, deployment, publication, or real-user outcome was exercised."
                    .to_string(),
                "This receipt may not authorize live or production claims.".to_string(),
            ],
        }
    }

    pub fn bind_audit_log(&mut self, audit_log_ndjson: &str) {
        self.source.audit_log_sha256 = sha256_hex(audit_log_ndjson.as_bytes());
    }

    pub fn validate_internal(
        &self,
        expected_case_id: &str,
        audit_log_ndjson: &str,
    ) -> Result<(), String> {
        if self.schema_version != EVIDENCE_AUTHORITY_SCHEMA_V1 {
            return Err(format!(
                "unsupported evidence authority schema {}",
                self.schema_version
            ));
        }
        if self.case_id != expected_case_id {
            return Err("evidence authority case_id does not match run_id".to_string());
        }
        validate_nonempty("source.producer", &self.source.producer)?;
        validate_nonempty("source.source_revision", &self.source.source_revision)?;
        validate_nonempty("source.executable", &self.source.executable)?;
        validate_sha256("source.executable_sha256", &self.source.executable_sha256)?;
        validate_sha256("source.arguments_sha256", &self.source.arguments_sha256)?;
        validate_sha256("source.environment_sha256", &self.source.environment_sha256)?;
        validate_sha256("source.audit_log_sha256", &self.source.audit_log_sha256)?;
        if self.source.audit_log_sha256 != sha256_hex(audit_log_ndjson.as_bytes()) {
            return Err("evidence authority audit_log_sha256 mismatch".to_string());
        }

        let generated = parse_timestamp("generated_at_utc", &self.generated_at_utc)?;
        let valid_until = parse_timestamp("valid_until_utc", &self.valid_until_utc)?;
        if valid_until <= generated {
            return Err("valid_until_utc must be after generated_at_utc".to_string());
        }
        if valid_until - generated > time::Duration::hours(24) {
            return Err("evidence authority validity must not exceed 24 hours".to_string());
        }
        if self.allowed_effects.is_empty() || self.observed_effects.is_empty() {
            return Err("allowed_effects and observed_effects must be explicit".to_string());
        }
        let allowed: BTreeSet<_> = self.allowed_effects.iter().collect();
        if let Some(effect) = self
            .observed_effects
            .iter()
            .find(|effect| !allowed.contains(effect))
        {
            return Err(format!("observed effect {effect} was not allowed"));
        }
        if self.limitations.is_empty() {
            return Err("production-equivalence limitations must be explicit".to_string());
        }
        validate_tool_authority(&self.tools)?;
        if self.credential_availability == EvidenceAvailability::Unknown {
            return Err("credential availability must not be UNKNOWN".to_string());
        }
        if self.state_scope.cache_scope != "CASE_LOCAL"
            || self.state_scope.prior_approval_reused
            || self.state_scope.credential_state_reused
            || self.state_scope.mutable_cache_reused
        {
            return Err("evidence state scope is not case-local and stateless".to_string());
        }

        let permitted: BTreeSet<_> = self.downstream_claims.may_satisfy.iter().collect();
        let prohibited: BTreeSet<_> = self.downstream_claims.must_not_satisfy.iter().collect();
        if permitted.is_empty() || prohibited.is_empty() {
            return Err("downstream claim policy must be explicit".to_string());
        }
        if permitted.intersection(&prohibited).next().is_some() {
            return Err("a downstream claim cannot be both permitted and prohibited".to_string());
        }

        if self.evidence_origin == EvidenceOrigin::ControlSimulation {
            if self.production_equivalent {
                return Err("control simulation cannot be production-equivalent".to_string());
            }
            if self.observed_execution_class == EvidenceExecutionClass::Live {
                return Err("control simulation cannot declare live observed execution".to_string());
            }
            for claim in REQUIRED_SIMULATION_PROHIBITIONS {
                if !self
                    .downstream_claims
                    .must_not_satisfy
                    .iter()
                    .any(|candidate| candidate == claim)
                {
                    return Err(format!(
                        "control simulation must prohibit downstream claim {claim}"
                    ));
                }
            }
            require_exact_values(
                "control-simulation permitted claims",
                &self.downstream_claims.may_satisfy,
                &CONTROLLED_SIMULATION_CLAIMS,
            )?;
            require_exact_values(
                "control-simulation prohibited claims",
                &self.downstream_claims.must_not_satisfy,
                &REQUIRED_SIMULATION_PROHIBITIONS,
            )?;
            require_exact_values(
                "control-simulation allowed effects",
                &self.allowed_effects,
                &CONTROLLED_SIMULATION_EFFECTS,
            )?;
            require_exact_values(
                "control-simulation observed effects",
                &self.observed_effects,
                &CONTROLLED_SIMULATION_EFFECTS,
            )?;
            require_exact_tool_ids(&self.tools, &CONTROLLED_SIMULATION_TOOLS)?;
            if self
                .tools
                .iter()
                .any(|tool| tool.observed_used && tool.external_mutation_allowed)
            {
                return Err(
                    "control simulation cannot observe an external-mutation-authorized tool"
                        .to_string(),
                );
            }
            require_tool_state(&self.tools, "LOCAL_EVIDENCE_BUNDLE_EXPORT", true, true)?;
            require_tool_state(&self.tools, "MODEL_INFERENCE", false, false)?;
            require_tool_state(
                &self.tools,
                "EXTERNAL_PUBLICATION_OR_DEPLOYMENT",
                false,
                false,
            )?;
            validate_control_simulation_audit(audit_log_ndjson)?;
        }
        Ok(())
    }

    pub fn evaluate_claim(
        &self,
        claim: &str,
        context: &EvidenceClaimContext,
    ) -> EvidenceClaimDecision {
        if self.validate_shape_without_audit().is_err() {
            return EvidenceClaimDecision::Unknown;
        }
        if self.case_id != context.expected_case_id
            || self.source.source_revision != context.expected_source_revision
            || self.source.executable_sha256 != context.expected_executable_sha256
            || self.source.arguments_sha256 != context.expected_arguments_sha256
            || self.source.environment_sha256 != context.expected_environment_sha256
            || self.source.audit_log_sha256 != context.expected_audit_log_sha256
        {
            return EvidenceClaimDecision::Unknown;
        }

        let Ok(as_of) = parse_timestamp("as_of_utc", &context.as_of_utc) else {
            return EvidenceClaimDecision::Unknown;
        };
        let Ok(generated) = parse_timestamp("generated_at_utc", &self.generated_at_utc) else {
            return EvidenceClaimDecision::Unknown;
        };
        let Ok(valid_until) = parse_timestamp("valid_until_utc", &self.valid_until_utc) else {
            return EvidenceClaimDecision::Unknown;
        };
        if as_of < generated || as_of > valid_until {
            return EvidenceClaimDecision::Unknown;
        }
        if self
            .downstream_claims
            .must_not_satisfy
            .iter()
            .any(|candidate| candidate == claim)
        {
            return EvidenceClaimDecision::Denied;
        }
        if !self
            .downstream_claims
            .may_satisfy
            .iter()
            .any(|candidate| candidate == claim)
        {
            return EvidenceClaimDecision::Unknown;
        }
        if context.credentials_required
            && self.credential_availability != EvidenceAvailability::Available
        {
            return EvidenceClaimDecision::Unknown;
        }
        if let Some(required_tool) = &context.required_tool_id {
            let Some(tool) = self
                .tools
                .iter()
                .find(|tool| &tool.tool_id == required_tool)
            else {
                return EvidenceClaimDecision::Unknown;
            };
            if !tool.declared_available || !tool.observed_used {
                return EvidenceClaimDecision::Unknown;
            }
        }
        EvidenceClaimDecision::Authorized
    }

    fn validate_shape_without_audit(&self) -> Result<(), String> {
        if self.schema_version != EVIDENCE_AUTHORITY_SCHEMA_V1 {
            return Err("unsupported schema".to_string());
        }
        validate_nonempty("case_id", &self.case_id)?;
        validate_nonempty("source.producer", &self.source.producer)?;
        validate_nonempty("source.source_revision", &self.source.source_revision)?;
        validate_nonempty("source.executable", &self.source.executable)?;
        validate_sha256("source.executable_sha256", &self.source.executable_sha256)?;
        validate_sha256("source.arguments_sha256", &self.source.arguments_sha256)?;
        validate_sha256("source.environment_sha256", &self.source.environment_sha256)?;
        validate_sha256("source.audit_log_sha256", &self.source.audit_log_sha256)?;
        parse_timestamp("generated_at_utc", &self.generated_at_utc)?;
        let generated = parse_timestamp("generated_at_utc", &self.generated_at_utc)?;
        let valid_until = parse_timestamp("valid_until_utc", &self.valid_until_utc)?;
        if valid_until <= generated {
            return Err("invalid freshness interval".to_string());
        }
        if valid_until - generated > time::Duration::hours(24) {
            return Err("evidence authority validity exceeds 24 hours".to_string());
        }
        if self.state_scope.cache_scope != "CASE_LOCAL"
            || self.state_scope.prior_approval_reused
            || self.state_scope.credential_state_reused
            || self.state_scope.mutable_cache_reused
        {
            return Err("state scope not isolated".to_string());
        }
        validate_tool_authority(&self.tools)?;
        if self.credential_availability == EvidenceAvailability::Unknown {
            return Err("credential availability is unknown".to_string());
        }
        if self.allowed_effects.is_empty()
            || self.observed_effects.is_empty()
            || self.limitations.is_empty()
        {
            return Err("effects and limitations must be explicit".to_string());
        }
        let allowed: BTreeSet<_> = self.allowed_effects.iter().collect();
        if self
            .observed_effects
            .iter()
            .any(|effect| !allowed.contains(effect))
        {
            return Err("observed effects exceed allowed effects".to_string());
        }
        let permitted: BTreeSet<_> = self.downstream_claims.may_satisfy.iter().collect();
        let prohibited: BTreeSet<_> = self.downstream_claims.must_not_satisfy.iter().collect();
        if permitted.is_empty()
            || prohibited.is_empty()
            || permitted.intersection(&prohibited).next().is_some()
        {
            return Err("downstream claim policy is ambiguous".to_string());
        }
        if self.evidence_origin == EvidenceOrigin::ControlSimulation {
            if self.production_equivalent
                || self.observed_execution_class == EvidenceExecutionClass::Live
            {
                return Err("control simulation overclaims execution authority".to_string());
            }
            for claim in REQUIRED_SIMULATION_PROHIBITIONS {
                if !self
                    .downstream_claims
                    .must_not_satisfy
                    .iter()
                    .any(|candidate| candidate == claim)
                {
                    return Err("control simulation omits a required claim prohibition".to_string());
                }
            }
            require_exact_values(
                "control-simulation permitted claims",
                &self.downstream_claims.may_satisfy,
                &CONTROLLED_SIMULATION_CLAIMS,
            )?;
            require_exact_values(
                "control-simulation prohibited claims",
                &self.downstream_claims.must_not_satisfy,
                &REQUIRED_SIMULATION_PROHIBITIONS,
            )?;
            require_exact_values(
                "control-simulation allowed effects",
                &self.allowed_effects,
                &CONTROLLED_SIMULATION_EFFECTS,
            )?;
            require_exact_values(
                "control-simulation observed effects",
                &self.observed_effects,
                &CONTROLLED_SIMULATION_EFFECTS,
            )?;
            require_exact_tool_ids(&self.tools, &CONTROLLED_SIMULATION_TOOLS)?;
            require_tool_state(&self.tools, "LOCAL_EVIDENCE_BUNDLE_EXPORT", true, true)?;
            require_tool_state(&self.tools, "MODEL_INFERENCE", false, false)?;
            require_tool_state(
                &self.tools,
                "EXTERNAL_PUBLICATION_OR_DEPLOYMENT",
                false,
                false,
            )?;
        }
        Ok(())
    }
}

fn parse_timestamp(field: &str, value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| format!("{field} must be a valid RFC3339 timestamp"))
}

fn validate_nonempty(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value == "UNKNOWN" {
        return Err(format!("{field} must be known and non-empty"));
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{field} must be a 64-character SHA-256 digest"));
    }
    Ok(())
}

fn validate_tool_authority(tools: &[ToolAuthority]) -> Result<(), String> {
    if tools.is_empty() {
        return Err("tool authority must be explicit".to_string());
    }
    let mut tool_ids = BTreeSet::new();
    for tool in tools {
        validate_nonempty("tools.tool_id", &tool.tool_id)?;
        if !tool_ids.insert(tool.tool_id.as_str()) {
            return Err(format!("duplicate tool authority {}", tool.tool_id));
        }
        if tool.observed_used && !tool.declared_available {
            return Err(format!(
                "tool {} was observed used but not declared available",
                tool.tool_id
            ));
        }
        if tool.external_mutation_allowed && !tool.declared_available {
            return Err(format!(
                "tool {} grants external mutation while unavailable",
                tool.tool_id
            ));
        }
    }
    Ok(())
}

fn require_tool_state(
    tools: &[ToolAuthority],
    tool_id: &str,
    declared_available: bool,
    observed_used: bool,
) -> Result<(), String> {
    let Some(tool) = tools.iter().find(|tool| tool.tool_id == tool_id) else {
        return Err(format!("missing required tool authority {tool_id}"));
    };
    if tool.declared_available != declared_available
        || tool.observed_used != observed_used
        || tool.external_mutation_allowed
    {
        return Err(format!("invalid tool authority state for {tool_id}"));
    }
    Ok(())
}

fn require_exact_values<const N: usize>(
    field: &str,
    actual: &[String],
    expected: &[&str; N],
) -> Result<(), String> {
    let actual: BTreeSet<_> = actual.iter().map(String::as_str).collect();
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if actual != expected {
        return Err(format!("{field} must match the fixed contract"));
    }
    Ok(())
}

fn require_exact_tool_ids<const N: usize>(
    tools: &[ToolAuthority],
    expected: &[&str; N],
) -> Result<(), String> {
    let actual: BTreeSet<_> = tools.iter().map(|tool| tool.tool_id.as_str()).collect();
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if actual != expected {
        return Err("control-simulation tool authority must match the fixed contract".to_string());
    }
    Ok(())
}

fn validate_control_simulation_audit(audit_log_ndjson: &str) -> Result<(), String> {
    let mut egress_event_count = 0usize;
    for (line_number, line) in audit_log_ndjson.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(line).map_err(|error| {
            format!(
                "audit log line {} is not valid JSON: {error}",
                line_number + 1
            )
        })?;
        let event_type = event
            .get("event_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if matches!(
            event_type,
            "EGRESS_REQUEST_ALLOWED" | "EGRESS_REQUEST_BLOCKED"
        ) {
            egress_event_count += 1;
            let origin = event
                .pointer("/details/evidence_origin")
                .and_then(serde_json::Value::as_str);
            if origin != Some("CONTROL_SIMULATION") {
                return Err(format!(
                    "control-simulation authority conflicts with {event_type} audit origin"
                ));
            }
        }
    }
    if egress_event_count == 0 {
        return Err(
            "control-simulation authority requires its own control-simulation egress audit event"
                .to_string(),
        );
    }
    Ok(())
}
