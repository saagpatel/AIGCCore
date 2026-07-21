use aigc_core::audit::event::{finalize_event, Actor, AuditEvent, ZERO_HASH_64};
use aigc_core::determinism::run_id::sha256_hex;
use aigc_core::evidence_bundle::authority::{
    EvidenceAuthorityManifest, EvidenceAvailability, EvidenceClaimContext, EvidenceClaimDecision,
    EvidenceExecutionClass, EvidenceOrigin, CLAIM_LIVE_EXECUTION, CLAIM_LOCAL_CONTROLLED_EXECUTION,
};
use serde_json::json;

const AUDIT: &str =
    "{\"event_type\":\"EGRESS_REQUEST_BLOCKED\",\"details\":{\"evidence_origin\":\"CONTROL_SIMULATION\"}}\n";

fn authority() -> EvidenceAuthorityManifest {
    let mut authority = EvidenceAuthorityManifest::controlled_simulation(
        "case-a",
        "aigccore-test:authority",
        "revision-a",
        "aigccore-test",
        sha256_hex(b"executable-a"),
        sha256_hex(b"arguments-a"),
        sha256_hex(b"environment-a"),
        "2026-07-20T12:00:00Z",
        "2026-07-20T13:00:00Z",
    );
    authority.bind_audit_log(AUDIT);
    authority
}

fn context() -> EvidenceClaimContext {
    let authority = authority();
    EvidenceClaimContext {
        as_of_utc: "2026-07-20T12:30:00Z".to_string(),
        expected_case_id: authority.case_id.clone(),
        expected_source_revision: authority.source.source_revision.clone(),
        expected_executable_sha256: authority.source.executable_sha256.clone(),
        expected_arguments_sha256: authority.source.arguments_sha256.clone(),
        expected_environment_sha256: authority.source.environment_sha256.clone(),
        expected_audit_log_sha256: authority.source.audit_log_sha256.clone(),
        required_tool_id: Some("LOCAL_EVIDENCE_BUNDLE_EXPORT".to_string()),
        credentials_required: false,
    }
}

#[test]
fn controlled_simulation_authorizes_only_its_bounded_local_claim() {
    let authority = authority();
    authority
        .validate_internal("case-a", AUDIT)
        .expect("authority contract should be internally valid");
    assert_eq!(
        authority.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &context()),
        EvidenceClaimDecision::Authorized
    );
    assert_eq!(
        authority.evaluate_claim(CLAIM_LIVE_EXECUTION, &context()),
        EvidenceClaimDecision::Denied
    );
}

#[test]
fn stale_or_future_evidence_remains_unknown() {
    let authority = authority();
    for as_of in ["2026-07-20T11:59:59Z", "2026-07-20T13:00:01Z"] {
        let mut candidate = context();
        candidate.as_of_utc = as_of.to_string();
        assert_eq!(
            authority.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &candidate),
            EvidenceClaimDecision::Unknown
        );
    }
}

#[test]
fn source_executable_argument_and_environment_substitution_remain_unknown() {
    let authority = authority();
    let substitutions = [
        ("source", sha256_hex(b"unused")),
        ("executable", sha256_hex(b"executable-b")),
        ("arguments", sha256_hex(b"arguments-b")),
        ("environment", sha256_hex(b"environment-b")),
        ("audit", sha256_hex(b"audit-b")),
    ];
    for (field, replacement) in substitutions {
        let mut candidate = context();
        match field {
            "source" => candidate.expected_source_revision = "revision-b".to_string(),
            "executable" => candidate.expected_executable_sha256 = replacement,
            "arguments" => candidate.expected_arguments_sha256 = replacement,
            "environment" => candidate.expected_environment_sha256 = replacement,
            "audit" => candidate.expected_audit_log_sha256 = replacement,
            _ => unreachable!(),
        }
        assert_eq!(
            authority.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &candidate),
            EvidenceClaimDecision::Unknown,
            "{field} substitution must fail closed"
        );
    }
}

#[test]
fn malformed_provenance_cross_case_and_cache_reuse_remain_unknown() {
    let mut malformed = authority();
    malformed.source.executable_sha256 = "not-a-digest".to_string();
    assert_eq!(
        malformed.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &context()),
        EvidenceClaimDecision::Unknown
    );

    let authority = authority();
    let mut cross_case = context();
    cross_case.expected_case_id = "case-b".to_string();
    assert_eq!(
        authority.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &cross_case),
        EvidenceClaimDecision::Unknown
    );

    let mut contaminated = authority.clone();
    contaminated.state_scope.mutable_cache_reused = true;
    assert_eq!(
        contaminated.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &context()),
        EvidenceClaimDecision::Unknown
    );
}

#[test]
fn declared_but_unobserved_tool_and_unknown_claim_remain_unknown() {
    let mut unobserved_tool = authority();
    unobserved_tool.tools[0].observed_used = false;
    assert_eq!(
        unobserved_tool.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &context()),
        EvidenceClaimDecision::Unknown
    );

    let authority = authority();
    assert_eq!(
        authority.evaluate_claim("UNDECLARED_CLAIM", &context()),
        EvidenceClaimDecision::Unknown
    );
}

#[test]
fn audit_mismatch_and_simulation_overclaim_fail_validation() {
    let valid_authority = authority();
    assert!(valid_authority
        .validate_internal("case-a", "{\"different\":true}\n")
        .is_err());

    let mut overclaim = valid_authority;
    overclaim.production_equivalent = true;
    assert!(overclaim.validate_internal("case-a", AUDIT).is_err());

    let mut missing_tool = authority();
    missing_tool
        .tools
        .retain(|tool| tool.tool_id != "MODEL_INFERENCE");
    assert!(missing_tool.validate_internal("case-a", AUDIT).is_err());

    let mut unknown_credentials = authority();
    unknown_credentials.credential_availability = EvidenceAvailability::Unknown;
    assert!(unknown_credentials
        .validate_internal("case-a", AUDIT)
        .is_err());

    let mut widened_claims = authority();
    widened_claims
        .downstream_claims
        .may_satisfy
        .push("ARBITRARY_AUTHORITY".to_string());
    assert!(widened_claims.validate_internal("case-a", AUDIT).is_err());

    let mut widened_effects = authority();
    widened_effects
        .allowed_effects
        .push("EXTERNAL_MUTATION".to_string());
    assert!(widened_effects.validate_internal("case-a", AUDIT).is_err());

    let mut overlong = authority();
    overlong.valid_until_utc = "2026-07-21T13:00:01Z".to_string();
    assert!(overlong.validate_internal("case-a", AUDIT).is_err());

    let runtime_audit =
        "{\"event_type\":\"EGRESS_REQUEST_BLOCKED\",\"details\":{\"evidence_origin\":\"RUNTIME_OBSERVATION\"}}\n";
    let mut contradictory = authority();
    contradictory.bind_audit_log(runtime_audit);
    assert!(contradictory
        .validate_internal("case-a", runtime_audit)
        .is_err());
}

#[test]
fn unsupported_origins_cannot_authorize_live_or_production_claims() {
    let runtime_audit =
        "{\"event_type\":\"EGRESS_REQUEST_BLOCKED\",\"details\":{\"evidence_origin\":\"RUNTIME_OBSERVATION\"}}\n";
    for origin in [
        EvidenceOrigin::RuntimeObservation,
        EvidenceOrigin::Fixture,
        EvidenceOrigin::Replay,
    ] {
        let mut candidate = authority();
        candidate.evidence_origin = origin;
        candidate.observed_execution_class = EvidenceExecutionClass::Live;
        candidate.production_equivalent = true;
        candidate.downstream_claims.may_satisfy = vec![CLAIM_LIVE_EXECUTION.to_string()];
        candidate.bind_audit_log(runtime_audit);

        assert!(
            candidate
                .validate_internal("case-a", runtime_audit)
                .is_err(),
            "{origin:?} must be rejected until it has an explicit authority contract"
        );
        let mut claim_context = context();
        claim_context.expected_audit_log_sha256 = candidate.source.audit_log_sha256.clone();
        assert_eq!(
            candidate.evaluate_claim(CLAIM_LIVE_EXECUTION, &claim_context),
            EvidenceClaimDecision::Unknown,
            "{origin:?} must remain non-authorizing"
        );
    }
}

#[test]
fn control_simulation_requires_controlled_requested_and_observed_execution() {
    for (field, execution_class) in [
        ("requested", EvidenceExecutionClass::Live),
        ("requested", EvidenceExecutionClass::Natural),
        ("observed", EvidenceExecutionClass::Natural),
        ("observed", EvidenceExecutionClass::Simulated),
    ] {
        let mut candidate = authority();
        match field {
            "requested" => candidate.requested_execution_class = execution_class,
            "observed" => candidate.observed_execution_class = execution_class,
            _ => unreachable!(),
        }

        assert!(
            candidate.validate_internal("case-a", AUDIT).is_err(),
            "{field} {execution_class:?} must be rejected for control simulation"
        );
        assert_eq!(
            candidate.evaluate_claim(CLAIM_LOCAL_CONTROLLED_EXECUTION, &context()),
            EvidenceClaimDecision::Unknown,
            "{field} {execution_class:?} must not authorize a controlled claim"
        );
    }
}

#[test]
fn egress_audit_origin_is_required_and_closed_to_known_values() {
    let event = |origin: Option<&str>| AuditEvent {
        ts_utc: "2026-07-20T12:00:00Z".to_string(),
        event_type: "EGRESS_REQUEST_BLOCKED".to_string(),
        run_id: "case-a".to_string(),
        vault_id: "vault-a".to_string(),
        actor: Actor::System,
        details: json!({
            "destination": {"scheme": "https", "host": "example.invalid", "port": 443, "path": "/"},
            "block_reason": "OFFLINE_MODE",
            "request_hash_sha256": sha256_hex(b"request"),
            "evidence_origin": origin
        }),
        prev_event_hash: ZERO_HASH_64.to_string(),
        event_hash: ZERO_HASH_64.to_string(),
    };

    assert!(finalize_event(event(None)).is_err());
    assert!(finalize_event(event(Some("AMBIGUOUS"))).is_err());
    assert!(finalize_event(event(Some("CONTROL_SIMULATION"))).is_ok());
    assert!(finalize_event(event(Some("RUNTIME_OBSERVATION"))).is_ok());
}
