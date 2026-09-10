use aigc_core::audit::event::{finalize_event, Actor, AuditEvent};
use aigc_core::audit::log::AuditLog;
use aigc_core::determinism::json_canonical::to_canonical_bytes;
use aigc_core::determinism::run_id::run_id_from_manifest_inputs_fingerprint_hex32;
use std::fs;

fn audit_event(event_type: &str, details: serde_json::Value) -> AuditEvent {
    AuditEvent {
        ts_utc: "2026-02-10T00:00:00Z".to_string(),
        event_type: event_type.to_string(),
        run_id: "r_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        vault_id: "v_1".to_string(),
        actor: Actor::System,
        details,
        prev_event_hash: String::new(),
        event_hash: String::new(),
    }
}

#[test]
fn canonical_json_is_stable_for_key_order() {
    let a = serde_json::json!({"b": 1, "a": {"y": 2, "x": 3}});
    let b = serde_json::json!({"a": {"x": 3, "y": 2}, "b": 1});
    let ca = to_canonical_bytes(&a).unwrap();
    let cb = to_canonical_bytes(&b).unwrap();
    assert_eq!(ca, cb);
}

#[test]
fn event_hash_is_stable() {
    let ev = AuditEvent {
        ts_utc: "2026-02-10T00:00:00Z".to_string(),
        event_type: "RUN_CREATED".to_string(),
        run_id: "r_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        vault_id: "v_1".to_string(),
        actor: Actor::System,
        details: serde_json::json!({"pack_id":"p","pack_version":"1","policy_pack_id":"x","policy_pack_version":"1","determinism_enabled":true}),
        prev_event_hash: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        event_hash: "".to_string(),
    };
    let a = finalize_event(ev.clone()).unwrap().event_hash;
    let b = finalize_event(ev).unwrap().event_hash;
    assert_eq!(a, b);
}

#[test]
fn deterministic_run_id_rule() {
    let fp = "1234567890abcdef1234567890abcdef9999";
    let run = run_id_from_manifest_inputs_fingerprint_hex32(fp).unwrap();
    assert_eq!(run, "r_1234567890abcdef1234567890abcdef");
}

#[test]
fn audit_log_reopen_verifies_and_continues_the_chain() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.ndjson");
    let mut log = AuditLog::open_or_create(&path).unwrap();
    let first = log
        .append(audit_event(
            "RUN_CREATED",
            serde_json::json!({
                "pack_id": "pack",
                "pack_version": "1.0.0",
                "policy_pack_id": "policy",
                "policy_pack_version": "1.0.0",
                "determinism_enabled": true
            }),
        ))
        .unwrap();
    let second = log
        .append(audit_event(
            "RUN_STATE_CHANGED",
            serde_json::json!({
                "from_state": "CREATED",
                "to_state": "INGESTING",
                "reason": "test"
            }),
        ))
        .unwrap();

    let mut reopened = AuditLog::open_or_create(&path).unwrap();
    let third = reopened
        .append(audit_event("RUN_COMPLETED", serde_json::json!({})))
        .unwrap();

    assert_eq!(first.prev_event_hash, aigc_core::audit::event::ZERO_HASH_64);
    assert_eq!(second.prev_event_hash, first.event_hash);
    assert_eq!(third.prev_event_hash, second.event_hash);
    assert_eq!(fs::read_to_string(path).unwrap().lines().count(), 3);
}

#[test]
fn audit_log_reopen_rejects_tampered_event_hash() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.ndjson");
    let mut log = AuditLog::open_or_create(&path).unwrap();
    log.append(audit_event(
        "RUN_CREATED",
        serde_json::json!({
            "pack_id": "pack",
            "pack_version": "1.0.0",
            "policy_pack_id": "policy",
            "policy_pack_version": "1.0.0",
            "determinism_enabled": true
        }),
    ))
    .unwrap();
    let mut stale_writer = AuditLog::open_or_create(&path).unwrap();

    let tampered = fs::read_to_string(&path)
        .unwrap()
        .replace("\"pack\"", "\"tampered\"");
    fs::write(&path, tampered).unwrap();
    let append_error = stale_writer
        .append(audit_event("RUN_COMPLETED", serde_json::json!({})))
        .unwrap_err();
    assert!(append_error.to_string().contains("event_hash"));

    let error = AuditLog::open_or_create(&path).unwrap_err();
    assert!(error.to_string().contains("line 1"));
    assert!(error.to_string().contains("event_hash"));
}

#[test]
fn audit_log_reopen_rejects_broken_links_and_extra_top_level_keys() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("audit.ndjson");
    let mut log = AuditLog::open_or_create(&path).unwrap();
    log.append(audit_event(
        "RUN_CREATED",
        serde_json::json!({
            "pack_id": "pack",
            "pack_version": "1.0.0",
            "policy_pack_id": "policy",
            "policy_pack_version": "1.0.0",
            "determinism_enabled": true
        }),
    ))
    .unwrap();
    log.append(audit_event(
        "RUN_STATE_CHANGED",
        serde_json::json!({
            "from_state": "CREATED",
            "to_state": "INGESTING",
            "reason": "test"
        }),
    ))
    .unwrap();

    let mut lines: Vec<serde_json::Value> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    lines[1]["prev_event_hash"] =
        serde_json::Value::String(aigc_core::audit::event::ZERO_HASH_64.to_string());
    fs::write(
        &path,
        lines
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n")
            + "\n",
    )
    .unwrap();
    let error = AuditLog::open_or_create(&path).unwrap_err();
    assert!(error.to_string().contains("line 2"));
    assert!(error.to_string().contains("prev_event_hash"));

    lines[1]["prev_event_hash"] =
        serde_json::Value::String(lines[0]["event_hash"].as_str().unwrap().to_string());
    lines[0]["unexpected"] = serde_json::Value::Bool(true);
    fs::write(
        &path,
        lines
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n")
            + "\n",
    )
    .unwrap();
    let error = AuditLog::open_or_create(&path).unwrap_err();
    assert!(error.to_string().contains("line 1"));
    assert!(error.to_string().contains("locked event envelope"));
}

#[test]
fn audit_event_rejects_non_object_details() {
    let mut event = audit_event(
        "RUN_COMPLETED",
        serde_json::Value::String("not-an-object".to_string()),
    );
    event.prev_event_hash = aigc_core::audit::event::ZERO_HASH_64.to_string();
    let error = finalize_event(event).unwrap_err();
    assert!(error.to_string().contains("details must be a JSON object"));
}
