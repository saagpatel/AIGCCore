use aigc_core::execution::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn policy() -> ExecutionPolicyV1 {
    ExecutionPolicyV1 {
        schema_version: EXECUTION_POLICY_SCHEMA_V1.to_string(),
        policy_id: "policy-test".to_string(),
        backend_id: OCI_ZERO_EGRESS_BACKEND_V1.to_string(),
        input_tree_sha256: "a".repeat(64),
        image_id: format!("sha256:{}", "b".repeat(64)),
        argv: vec!["node".to_string(), "/input/fixture.js".to_string()],
        working_directory: "/workspace".to_string(),
        filesystem: FilesystemPolicyV1 {
            immutable_input_path: "/input".to_string(),
            writable_workspace_path: "/workspace".to_string(),
            output_path_allowlist: vec!["candidate.patch.json".to_string()],
            max_output_bytes: 8192,
            host_mounts_allowed: false,
        },
        network: NetworkPolicyV1 {
            mode: ExecutionNetworkModeV1::DenyAll,
            blocked_classes: BTreeSet::from([
                NetworkClassV1::Dns,
                NetworkClassV1::Ipv4,
                NetworkClassV1::Ipv6,
                NetworkClassV1::Metadata,
                NetworkClassV1::Loopback,
                NetworkClassV1::UnixSocket,
                NetworkClassV1::Proxy,
            ]),
        },
        process: ProcessPolicyV1 {
            child_processes_allowed: true,
            pid_limit: 16,
            wall_time_ms: 15_000,
            controller_death_cleanup_required: true,
            trusted_init_required: true,
        },
        resources: ResourcePolicyV1 {
            memory_bytes: 256 * 1024 * 1024,
            memory_swap_bytes: 256 * 1024 * 1024,
            cpu_quota_millis: 500,
            workspace_bytes: 64 * 1024 * 1024,
            max_file_bytes: 8 * 1024 * 1024,
            max_open_files: 64,
        },
        environment: EnvironmentPolicyV1 {
            allowed_keys: BTreeSet::from([
                "HOME".to_string(),
                "HOSTNAME".to_string(),
                "LANG".to_string(),
                "NODE_VERSION".to_string(),
                "PATH".to_string(),
                "TMPDIR".to_string(),
                "YARN_VERSION".to_string(),
            ]),
            secrets: SecretPolicyV1::None,
            synthetic_home: "/workspace/home".to_string(),
            synthetic_tmp: "/tmp".to_string(),
        },
        export: ExportPolicyV1 {
            patch_only: true,
            review_required: true,
            reviewer_kind: "DETERMINISTIC_FIXTURE_REVIEWER_V1".to_string(),
            max_patch_bytes: 8192,
        },
        evidence: EvidencePolicyV1 {
            required_control_ids: BTreeSet::from(["control-1".to_string()]),
            require_effective_policy_readback: true,
            require_zero_residue: true,
            maximum_claim: "exact qualified OCI runtime only".to_string(),
        },
    }
}

fn passing_receipt() -> ExecutionReceiptV1 {
    let requested = policy();
    let digest = "c".repeat(64);
    let seccomp_profile =
        r#"{"architectures":["SCMP_ARCH_AARCH64"],"defaultAction":"SCMP_ACT_ERRNO"}"#;
    let seccomp_digest = hex::encode(Sha256::digest(seccomp_profile.as_bytes()));
    let cold_sample = PerformanceSampleV1 {
        phase: PerformancePhaseV1::ColdCached,
        elapsed_ms: 10,
        cleanup_ms: 5,
        peak_disk_bytes: 1,
    };
    let warm_sample = PerformanceSampleV1 {
        phase: PerformancePhaseV1::Warm,
        ..cold_sample.clone()
    };
    let five_second_sample = PerformanceSampleV1 {
        phase: PerformancePhaseV1::FiveSecondOverhead,
        elapsed_ms: 5_000,
        ..cold_sample.clone()
    };
    let configured_environment = BTreeMap::from([
        ("HOME".to_string(), "/workspace/home".to_string()),
        ("TMPDIR".to_string(), "/tmp".to_string()),
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("NODE_VERSION".to_string(), "22.0.0".to_string()),
        ("PATH".to_string(), "/usr/local/bin:/usr/bin".to_string()),
        ("YARN_VERSION".to_string(), "1.22.0".to_string()),
    ]);
    let mut observed_environment = configured_environment.clone();
    observed_environment.insert("HOSTNAME".to_string(), "fixture-v1".to_string());
    ExecutionReceiptV1 {
        schema_version: EXECUTION_RECEIPT_SCHEMA_V1.to_string(),
        run_id: "run-test".to_string(),
        result: ExecutionTerminalResultV1::Pass,
        subject_identity: SubjectIdentityV1 {
            fixture_id: "fixture-v1".to_string(),
            fixture_sha256: "d".repeat(64),
            input_tree_sha256: requested.input_tree_sha256.clone(),
            argv: requested.argv.clone(),
        },
        backend_identity: BackendIdentityV1 {
            backend_id: requested.backend_id.clone(),
            engine_endpoint: "unix:///program-owned/docker.sock".to_string(),
            daemon_id: "daemon-test-v1".to_string(),
            architecture: "aarch64".to_string(),
            engine_version: "29.5.2".to_string(),
            runtime_version: "runc 1.3.5".to_string(),
            kernel_version: "6.8".to_string(),
            image_id: requested.image_id.clone(),
            enforcement_profile_sha256: seccomp_digest.clone(),
            controller_build: "test".to_string(),
            controller_executable_sha256: "e".repeat(64),
        },
        effective_policy: EffectivePolicyV1 {
            readback_complete: true,
            image_id: requested.image_id.clone(),
            enforcement_profile_sha256: seccomp_digest,
            seccomp_architectures: vec!["SCMP_ARCH_AARCH64".to_string()],
            argv: requested.argv.clone(),
            working_directory: requested.working_directory.clone(),
            user: "65534:65534".to_string(),
            network_mode: "none".to_string(),
            readonly_root: true,
            mount_count: 0,
            host_mount_count: 0,
            host_config_mount_count: 0,
            runtime_mount_count: 0,
            cap_drop: vec!["ALL".to_string()],
            security_options: vec![
                "no-new-privileges".to_string(),
                format!("seccomp={seccomp_profile}"),
            ],
            init_enabled: true,
            init_implementation: "docker-init".to_string(),
            init_version: "0.19.0".to_string(),
            pid_limit: 16,
            memory_bytes: 256 * 1024 * 1024,
            memory_swap_bytes: 256 * 1024 * 1024,
            cpu_quota_nanos: 500_000_000,
            tmpfs: BTreeMap::from([(
                "/workspace".to_string(),
                "rw,nosuid,nodev,size=67108864".to_string(),
            )]),
            ulimits: BTreeMap::from([
                ("nofile".to_string(), 64),
                ("fsize".to_string(), 8 * 1024 * 1024),
            ]),
            environment_key_names: observed_environment.keys().cloned().collect(),
            environment: configured_environment,
            observed_environment,
        },
        requested_policy: requested,
        observed_effects: vec![EffectObservationV1 {
            effect_id: "effect-1".to_string(),
            effect_class: "NETWORK".to_string(),
            attempted: true,
            allowed: false,
            persisted: false,
            evidence_origin: EvidenceOriginV1::RuntimeEnforced,
            sensor_identity: "docker-inspect".to_string(),
            detail: "socket denied".to_string(),
        }],
        controls: vec![ControlResultV1 {
            control_id: "control-1".to_string(),
            control_kind: "NEGATIVE".to_string(),
            expected: "denied".to_string(),
            observed: "denied".to_string(),
            evidence_refs: vec![ControlEvidenceRefV1 {
                effect_id: "effect-1".to_string(),
                expected_attempted: true,
                expected_allowed: false,
            }],
            result: ExecutionTerminalResultV1::Pass,
        }],
        export_review: ExportReviewV1 {
            candidate_sha256: digest.clone(),
            reviewed_sha256: digest.clone(),
            exported_sha256: digest,
            reviewer_kind: "DETERMINISTIC_FIXTURE_REVIEWER_V1".to_string(),
            approved: true,
            rejected_entries: vec![],
            bytes: 128,
        },
        cleanup: CleanupEvidenceV1 {
            attempted: true,
            completed: true,
            containers_remaining: 0,
            images_remaining: 0,
            networks_remaining: 0,
            volumes_remaining: 0,
            processes_remaining: 0,
            listeners_remaining: 0,
            mounts_remaining: 0,
            temporary_roots_remaining: 0,
            detail: "clean".to_string(),
        },
        performance: Some(PerformanceSummaryV1 {
            cold_samples: vec![cold_sample; 5],
            warm_samples: vec![warm_sample; 30],
            five_second_samples: vec![five_second_sample; 5],
            concurrency_observations: vec![
                ConcurrencyObservationV1 {
                    concurrency: 1,
                    batch_wall_samples_ms: vec![10; 5],
                    batch_wall_p95_ms: 10,
                    passed: true,
                },
                ConcurrencyObservationV1 {
                    concurrency: 2,
                    batch_wall_samples_ms: vec![15; 5],
                    batch_wall_p95_ms: 15,
                    passed: true,
                },
                ConcurrencyObservationV1 {
                    concurrency: 4,
                    batch_wall_samples_ms: vec![20; 5],
                    batch_wall_p95_ms: 20,
                    passed: true,
                },
            ],
            input_bytes: 1,
            warm_start_p95_ms: 10,
            cold_start_p95_ms: 10,
            cleanup_p95_ms: 5,
            cleanup_max_ms: 5,
            added_overhead_p95_ms: 0,
            added_overhead_percent: 0,
            peak_disk_bytes: 1,
            disk_amplification_ceiling_bytes: 128 * 1024 * 1024 + 2,
            highest_passing_concurrency: 4,
            gates_passed: true,
        }),
        evidence_ceiling: EvidenceCeilingV1 {
            enforced: vec!["exact config".to_string()],
            observed: vec!["socket denied".to_string()],
            unknown: vec!["outer VM integrity".to_string()],
            excluded_claims: vec!["hostile kernel resistance".to_string()],
            maximum_claim: "exact qualified OCI runtime only".to_string(),
        },
        limitations: vec!["fixture scoped".to_string()],
    }
}

#[test]
fn valid_contract_and_receipt_pass() {
    policy().validate().expect("policy should be valid");
    let validation = validate_execution_receipt(&passing_receipt());
    assert_eq!(validation.result, ExecutionTerminalResultV1::Pass);
    assert!(validation.reasons.is_empty());
}

#[test]
fn secret_bearing_environment_is_blocked() {
    let mut requested = policy();
    requested
        .environment
        .allowed_keys
        .insert("GITHUB_TOKEN".to_string());
    assert!(requested.validate().is_err());
}

#[test]
fn mutable_image_or_unsafe_export_path_is_blocked() {
    let mut requested = policy();
    requested.image_id = "sha256:latest".to_string();
    assert!(requested.validate().is_err());

    let mut requested = policy();
    requested.filesystem.output_path_allowlist = vec!["../escape".to_string()];
    assert!(requested.validate().is_err());
}

#[test]
fn simulated_or_incomplete_evidence_cannot_pass() {
    let mut receipt = passing_receipt();
    receipt.observed_effects[0].evidence_origin = EvidenceOriginV1::ControlSimulation;
    receipt.cleanup.containers_remaining = 1;
    let validation = validate_execution_receipt(&receipt);
    assert_eq!(validation.result, ExecutionTerminalResultV1::Error);
    assert!(validation
        .reasons
        .iter()
        .any(|reason| reason.contains("CONTROL_SIMULATION")));
    assert!(validation
        .reasons
        .iter()
        .any(|reason| reason.contains("zero named residue")));
}

#[test]
fn digest_mismatch_blocks_export_claim() {
    let mut receipt = passing_receipt();
    receipt.export_review.exported_sha256 = "f".repeat(64);
    let validation = validate_execution_receipt(&receipt);
    assert_eq!(validation.result, ExecutionTerminalResultV1::Error);
    assert!(validation
        .reasons
        .iter()
        .any(|reason| reason.contains("digest-bound")));
}

fn assert_receipt_rejected(receipt: &ExecutionReceiptV1, reason_fragment: &str) {
    let validation = validate_execution_receipt(receipt);
    assert_eq!(validation.result, ExecutionTerminalResultV1::Error);
    assert!(
        validation
            .reasons
            .iter()
            .any(|reason| reason.contains(reason_fragment)),
        "expected reason containing {reason_fragment:?}, got {:?}",
        validation.reasons
    );
}

#[test]
fn effective_seccomp_mount_environment_and_init_readback_are_bound() {
    let mut receipt = passing_receipt();
    receipt.effective_policy.enforcement_profile_sha256 = "f".repeat(64);
    assert_receipt_rejected(&receipt, "seccomp profile, architecture, and digest");

    let mut receipt = passing_receipt();
    receipt.effective_policy.seccomp_architectures = vec!["SCMP_ARCH_X86_64".to_string()];
    assert_receipt_rejected(&receipt, "seccomp profile, architecture, and digest");

    let mut receipt = passing_receipt();
    receipt.effective_policy.security_options[1] =
        "seccomp={\"defaultAction\":\"SCMP_ACT_ERRNO\"}".to_string();
    assert_receipt_rejected(&receipt, "architecture binding");

    for field in ["binds", "host-config-mounts", "runtime-mounts"] {
        let mut receipt = passing_receipt();
        receipt.effective_policy.mount_count = 1;
        match field {
            "binds" => receipt.effective_policy.host_mount_count = 1,
            "host-config-mounts" => receipt.effective_policy.host_config_mount_count = 1,
            "runtime-mounts" => receipt.effective_policy.runtime_mount_count = 1,
            _ => unreachable!(),
        }
        assert_receipt_rejected(&receipt, "requested and effective");
    }

    let mut receipt = passing_receipt();
    receipt
        .effective_policy
        .observed_environment
        .insert("PATH".to_string(), "/forged".to_string());
    assert_receipt_rejected(&receipt, "runtime values");

    let mut receipt = passing_receipt();
    receipt
        .effective_policy
        .environment
        .insert("HOME".to_string(), "/forged-home".to_string());
    receipt
        .effective_policy
        .observed_environment
        .insert("HOME".to_string(), "/forged-home".to_string());
    assert_receipt_rejected(&receipt, "synthetic environment");

    let mut receipt = passing_receipt();
    receipt
        .effective_policy
        .observed_environment
        .remove("TMPDIR");
    receipt
        .effective_policy
        .environment_key_names
        .retain(|key| key != "TMPDIR");
    assert_receipt_rejected(&receipt, "synthetic environment");

    let mut receipt = passing_receipt();
    receipt
        .effective_policy
        .environment_key_names
        .push("HOME".to_string());
    assert_receipt_rejected(&receipt, "incomplete or differ");

    let mut receipt = passing_receipt();
    receipt.effective_policy.init_implementation = "untrusted-init".to_string();
    assert_receipt_rejected(&receipt, "requested and effective");

    let mut receipt = passing_receipt();
    receipt.effective_policy.init_version = "UNKNOWN".to_string();
    assert_receipt_rejected(&receipt, "requested and effective");
}

#[test]
fn every_control_must_be_unique_and_pass_including_extras() {
    for result in [
        ExecutionTerminalResultV1::Fail,
        ExecutionTerminalResultV1::Blocked,
        ExecutionTerminalResultV1::Unknown,
        ExecutionTerminalResultV1::Error,
    ] {
        let mut receipt = passing_receipt();
        receipt.controls[0].result = result;
        assert_receipt_rejected(&receipt, "failed, blocked, unknown, or errored");
    }

    let mut receipt = passing_receipt();
    receipt.controls.push(receipt.controls[0].clone());
    assert_receipt_rejected(&receipt, "duplicate control IDs");

    let mut receipt = passing_receipt();
    let mut duplicate = receipt.controls[0].clone();
    duplicate.result = ExecutionTerminalResultV1::Fail;
    receipt.controls.push(duplicate);
    assert_receipt_rejected(&receipt, "duplicate control IDs");
    assert_receipt_rejected(&receipt, "failed, blocked, unknown, or errored");

    let mut receipt = passing_receipt();
    receipt.controls.push(ControlResultV1 {
        control_id: "extra-unhealthy".to_string(),
        control_kind: "NEGATIVE".to_string(),
        expected: "pass".to_string(),
        observed: "fail".to_string(),
        evidence_refs: vec![ControlEvidenceRefV1 {
            effect_id: "effect-1".to_string(),
            expected_attempted: true,
            expected_allowed: false,
        }],
        result: ExecutionTerminalResultV1::Fail,
    });
    assert_receipt_rejected(&receipt, "failed, blocked, unknown, or errored");
}

#[test]
fn control_evidence_references_reject_delete_flip_and_detach_mutations() {
    let mut receipt = passing_receipt();
    receipt.controls[0].evidence_refs.clear();
    assert_receipt_rejected(&receipt, "no effect evidence references");
    assert_receipt_rejected(&receipt, "exact set equality");

    let mut receipt = passing_receipt();
    receipt.controls[0].evidence_refs[0].expected_allowed = true;
    assert_receipt_rejected(&receipt, "flags contradict");

    let mut receipt = passing_receipt();
    receipt.observed_effects[0].allowed = true;
    assert_receipt_rejected(&receipt, "flags contradict");

    let mut receipt = passing_receipt();
    receipt.controls[0].evidence_refs[0].expected_attempted = false;
    assert_receipt_rejected(&receipt, "flags contradict");

    let mut receipt = passing_receipt();
    receipt.observed_effects.clear();
    assert_receipt_rejected(&receipt, "references missing observed effect");

    let mut receipt = passing_receipt();
    receipt.controls[0].evidence_refs[0].effect_id = "detached-effect".to_string();
    assert_receipt_rejected(&receipt, "references missing observed effect");
    assert_receipt_rejected(&receipt, "exact set equality");

    let mut receipt = passing_receipt();
    receipt.observed_effects.push(EffectObservationV1 {
        effect_id: "detached-effect".to_string(),
        effect_class: "FILESYSTEM".to_string(),
        attempted: true,
        allowed: false,
        persisted: false,
        evidence_origin: EvidenceOriginV1::TrustedSensor,
        sensor_identity: "fixture-sensor".to_string(),
        detail: "detached observation".to_string(),
    });
    assert_receipt_rejected(&receipt, "exact set equality");
}

#[test]
fn control_evidence_references_reject_duplicate_and_empty_identity_mutations() {
    let mut receipt = passing_receipt();
    let duplicate_ref = receipt.controls[0].evidence_refs[0].clone();
    receipt.controls[0].evidence_refs.push(duplicate_ref);
    assert_receipt_rejected(&receipt, "duplicate effect evidence references");

    let mut receipt = passing_receipt();
    let duplicate_effect = receipt.observed_effects[0].clone();
    receipt.observed_effects.push(duplicate_effect);
    assert_receipt_rejected(&receipt, "duplicate observed effect ID");

    let mut receipt = passing_receipt();
    receipt.observed_effects[0].attempted = false;
    receipt.controls[0].evidence_refs[0].expected_attempted = false;
    assert_receipt_rejected(&receipt, "does not prove an attempted effect");

    let mut receipt = passing_receipt();
    receipt.observed_effects[0].effect_id.clear();
    assert_receipt_rejected(&receipt, "effect identity");

    let mut receipt = passing_receipt();
    receipt.observed_effects[0].effect_class.clear();
    assert_receipt_rejected(&receipt, "effect identity");

    let mut receipt = passing_receipt();
    receipt.observed_effects[0].sensor_identity.clear();
    assert_receipt_rejected(&receipt, "effect identity");

    let mut receipt = passing_receipt();
    receipt.observed_effects[0].detail.clear();
    assert_receipt_rejected(&receipt, "effect identity");

    let mut receipt = passing_receipt();
    receipt.controls[0].control_id.clear();
    assert_receipt_rejected(&receipt, "control identity");

    let mut receipt = passing_receipt();
    receipt.controls[0].control_kind.clear();
    assert_receipt_rejected(&receipt, "control identity");

    let mut receipt = passing_receipt();
    receipt.controls[0].expected.clear();
    assert_receipt_rejected(&receipt, "control identity");

    let mut receipt = passing_receipt();
    receipt.controls[0].observed.clear();
    assert_receipt_rejected(&receipt, "control identity");

    let mut receipt = passing_receipt();
    receipt.controls[0].evidence_refs[0].effect_id.clear();
    assert_receipt_rejected(&receipt, "empty effect evidence reference");
}

#[test]
fn performance_summary_fields_are_recomputed_from_raw_samples() {
    let summary_mutations: Vec<fn(&mut PerformanceSummaryV1)> = vec![
        |performance| performance.cold_start_p95_ms += 1,
        |performance| performance.warm_start_p95_ms += 1,
        |performance| performance.cleanup_p95_ms += 1,
        |performance| performance.cleanup_max_ms += 1,
        |performance| performance.added_overhead_p95_ms += 1,
        |performance| performance.added_overhead_percent += 1,
        |performance| performance.peak_disk_bytes += 1,
        |performance| performance.disk_amplification_ceiling_bytes += 1,
        |performance| performance.highest_passing_concurrency = 2,
        |performance| performance.gates_passed = false,
    ];
    for mutate in summary_mutations {
        let mut receipt = passing_receipt();
        mutate(receipt.performance.as_mut().expect("performance"));
        assert_receipt_rejected(&receipt, "do not match raw structured samples");
    }
}

#[test]
fn performance_raw_sample_phase_duration_and_gate_forgery_are_rejected() {
    let mut receipt = passing_receipt();
    receipt
        .performance
        .as_mut()
        .expect("performance")
        .cold_samples[0]
        .phase = PerformancePhaseV1::Warm;
    assert_receipt_rejected(&receipt, "invalid counts, phases");

    let mut receipt = passing_receipt();
    receipt
        .performance
        .as_mut()
        .expect("performance")
        .five_second_samples[0]
        .elapsed_ms = 4_999;
    assert_receipt_rejected(&receipt, "five-second durations");

    let mut receipt = passing_receipt();
    receipt
        .performance
        .as_mut()
        .expect("performance")
        .warm_samples[28]
        .elapsed_ms = 2_001;
    receipt
        .performance
        .as_mut()
        .expect("performance")
        .warm_samples[29]
        .elapsed_ms = 2_001;
    receipt
        .performance
        .as_mut()
        .expect("performance")
        .warm_start_p95_ms = 2_001;
    receipt
        .performance
        .as_mut()
        .expect("performance")
        .gates_passed = false;
    assert_receipt_rejected(&receipt, "exact gates");

    let mut receipt = passing_receipt();
    let performance = receipt.performance.as_mut().expect("performance");
    performance.concurrency_observations[1].batch_wall_p95_ms += 1;
    assert_receipt_rejected(&receipt, "concurrency observations");

    let mut receipt = passing_receipt();
    let performance = receipt.performance.as_mut().expect("performance");
    performance.concurrency_observations[2].passed = false;
    assert_receipt_rejected(&receipt, "concurrency pass claims");

    let mut receipt = passing_receipt();
    let performance = receipt.performance.as_mut().expect("performance");
    performance.concurrency_observations[2].concurrency = 2;
    assert_receipt_rejected(&receipt, "missing, duplicate");
}

#[test]
fn every_performance_gate_is_driven_by_raw_observations() {
    let raw_gate_mutations: Vec<fn(&mut PerformanceSummaryV1)> = vec![
        |performance| {
            performance
                .cold_samples
                .iter_mut()
                .for_each(|sample| sample.elapsed_ms = 5_001)
        },
        |performance| {
            performance
                .warm_samples
                .iter_mut()
                .for_each(|sample| sample.elapsed_ms = 2_001)
        },
        |performance| {
            performance
                .cold_samples
                .iter_mut()
                .for_each(|sample| sample.cleanup_ms = 2_001)
        },
        |performance| performance.cold_samples[0].cleanup_ms = 5_001,
        |performance| {
            performance
                .five_second_samples
                .iter_mut()
                .for_each(|sample| sample.elapsed_ms = 6_001)
        },
        |performance| performance.cold_samples[0].peak_disk_bytes += 128 * 1024 * 1024 + 2,
        |performance| {
            performance.concurrency_observations[0].batch_wall_samples_ms = vec![2_001; 5]
        },
    ];
    for mutate in raw_gate_mutations {
        let mut receipt = passing_receipt();
        mutate(receipt.performance.as_mut().expect("performance"));
        assert_receipt_rejected(&receipt, "performance");
    }
}

#[test]
fn checked_in_execution_schemas_are_valid_json_and_exclude_simulation_origin() {
    let policy: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/execution-policy-v1.schema.json"))
            .expect("policy schema should be valid JSON");
    let receipt_text = include_str!("../schemas/execution-receipt-v1.schema.json");
    let receipt: serde_json::Value =
        serde_json::from_str(receipt_text).expect("receipt schema should be valid JSON");
    assert_eq!(policy["title"], "ExecutionPolicyV1");
    assert_eq!(receipt["title"], "ExecutionReceiptV1");
    assert!(!receipt_text.contains("CONTROL_SIMULATION"));
}

#[test]
fn durable_local_execution_evidence_is_self_contained_and_valid() {
    let receipt_bytes = include_bytes!("../../docs/evidence/local-execution-v1-receipt.json");
    let patch_bytes = include_bytes!("../../docs/evidence/local-execution-v1-reviewed.patch.json");
    let receipt: ExecutionReceiptV1 =
        serde_json::from_slice(receipt_bytes).expect("durable receipt should parse");
    let validation = validate_execution_receipt(&receipt);
    assert_eq!(
        validation.result,
        ExecutionTerminalResultV1::Pass,
        "{:?}",
        validation.reasons
    );
    assert_eq!(
        hex::encode(Sha256::digest(receipt_bytes)),
        "ca96016ca4d4ac050392dfa0f983e889e63df6ec9ece974ae828d9213f0c4a6e"
    );
    assert_eq!(
        hex::encode(Sha256::digest(patch_bytes)),
        receipt.export_review.exported_sha256
    );
    let patch: serde_json::Value =
        serde_json::from_slice(patch_bytes).expect("durable patch should parse");
    assert_eq!(patch["changes"][0]["path"], "allowed.txt");
    assert_eq!(patch["changes"][0]["after"], "qualified-change\n");
}
