use super::{
    EvidenceOriginV1, ExecutionReceiptV1, ExecutionTerminalResultV1, PerformancePhaseV1,
    PerformanceSummaryV1, EXECUTION_RECEIPT_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptValidationV1 {
    pub result: ExecutionTerminalResultV1,
    pub reasons: Vec<String>,
}

pub fn runtime_evidence_origin_is_admissible(origin: EvidenceOriginV1) -> bool {
    matches!(
        origin,
        EvidenceOriginV1::RuntimeEnforced | EvidenceOriginV1::TrustedSensor
    )
}

pub fn validate_execution_receipt(receipt: &ExecutionReceiptV1) -> ReceiptValidationV1 {
    let mut reasons = Vec::new();
    if receipt.schema_version != EXECUTION_RECEIPT_SCHEMA_V1 {
        reasons.push(format!(
            "unsupported receipt schema {}",
            receipt.schema_version
        ));
    }
    if let Err(error) = receipt.requested_policy.validate() {
        reasons.push(error.to_string());
    }
    if receipt.run_id.trim().is_empty()
        || receipt.subject_identity.fixture_id.trim().is_empty()
        || receipt.backend_identity.backend_id.trim().is_empty()
        || receipt.backend_identity.engine_endpoint.trim().is_empty()
        || receipt.backend_identity.daemon_id.trim().is_empty()
        || receipt.backend_identity.architecture.trim().is_empty()
        || receipt.backend_identity.engine_version.trim().is_empty()
        || receipt.backend_identity.runtime_version.trim().is_empty()
        || receipt.backend_identity.kernel_version.trim().is_empty()
        || receipt.backend_identity.image_id.trim().is_empty()
        || receipt.backend_identity.controller_build.trim().is_empty()
    {
        reasons.push(
            "run, fixture, and backend runtime/version/build identities must be non-empty"
                .to_string(),
        );
    }
    if !is_sha256(&receipt.subject_identity.fixture_sha256) {
        reasons.push("fixture identity must contain a lowercase SHA-256 digest".to_string());
    }
    if !receipt.effective_policy.readback_complete {
        reasons.push("effective runtime policy readback is incomplete".to_string());
    }
    let effective_seccomp = normalized_seccomp_identity(&receipt.effective_policy.security_options);
    match effective_seccomp {
        Ok((digest, architectures))
            if digest == receipt.effective_policy.enforcement_profile_sha256
                && digest == receipt.backend_identity.enforcement_profile_sha256
                && architectures == receipt.effective_policy.seccomp_architectures => {}
        Ok(_) => reasons.push(
            "normalized effective seccomp profile, architecture, and digest are not bound"
                .to_string(),
        ),
        Err(error) => reasons.push(error),
    }
    if receipt
        .effective_policy
        .seccomp_architectures
        .iter()
        .any(|architecture| !is_seccomp_architecture(architecture))
    {
        reasons.push("effective seccomp architecture identity is malformed".to_string());
    }
    let expected_tmpfs_paths = BTreeSet::from([
        receipt
            .requested_policy
            .filesystem
            .writable_workspace_path
            .as_str(),
        receipt.requested_policy.environment.synthetic_tmp.as_str(),
    ]);
    let effective_tmpfs_paths: BTreeSet<&str> = receipt
        .effective_policy
        .tmpfs
        .keys()
        .map(String::as_str)
        .collect();
    let workspace_tmpfs = receipt
        .effective_policy
        .tmpfs
        .get(&receipt.requested_policy.filesystem.writable_workspace_path);
    let synthetic_tmpfs = receipt
        .effective_policy
        .tmpfs
        .get(&receipt.requested_policy.environment.synthetic_tmp);
    if effective_tmpfs_paths != expected_tmpfs_paths
        || workspace_tmpfs.is_none_or(|options| {
            !tmpfs_options_match(
                options,
                &[
                    "rw".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    format!(
                        "size={}",
                        receipt.requested_policy.resources.workspace_bytes
                    ),
                    "mode=0700".to_string(),
                    "uid=65534".to_string(),
                    "gid=65534".to_string(),
                ],
            )
        })
        || synthetic_tmpfs.is_none_or(|options| {
            !tmpfs_options_match(
                options,
                &[
                    "rw".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    "noexec".to_string(),
                    format!("size={}", receipt.requested_policy.resources.max_file_bytes),
                    "mode=0700".to_string(),
                    "uid=65534".to_string(),
                    "gid=65534".to_string(),
                ],
            )
        })
    {
        reasons.push(
            "effective tmpfs destinations and exact options do not match the isolated policy"
                .to_string(),
        );
    }
    if receipt.subject_identity.input_tree_sha256 != receipt.requested_policy.input_tree_sha256
        || receipt.subject_identity.argv != receipt.requested_policy.argv
        || receipt.backend_identity.backend_id != receipt.requested_policy.backend_id
        || !receipt
            .backend_identity
            .engine_endpoint
            .starts_with("unix:///")
        || receipt.backend_identity.daemon_id.trim().is_empty()
        || receipt.backend_identity.architecture.trim().is_empty()
        || receipt.backend_identity.image_id != receipt.requested_policy.image_id
        || !is_sha256(&receipt.backend_identity.enforcement_profile_sha256)
        || !is_sha256(&receipt.backend_identity.controller_executable_sha256)
        || !is_sha256(&receipt.effective_policy.enforcement_profile_sha256)
        || receipt.effective_policy.image_id != receipt.requested_policy.image_id
        || receipt.effective_policy.argv != receipt.requested_policy.argv
        || receipt.effective_policy.working_directory != receipt.requested_policy.working_directory
        || receipt.effective_policy.network_mode != "none"
        || !receipt.effective_policy.readonly_root
        || receipt.effective_policy.mount_count != 0
        || receipt.effective_policy.host_mount_count != 0
        || receipt.effective_policy.host_config_mount_count != 0
        || receipt.effective_policy.runtime_mount_count != 0
        || receipt.effective_policy.mount_count
            != receipt
                .effective_policy
                .host_mount_count
                .saturating_add(receipt.effective_policy.host_config_mount_count)
                .saturating_add(receipt.effective_policy.runtime_mount_count)
        || receipt.effective_policy.user != "65534:65534"
        || !receipt
            .effective_policy
            .cap_drop
            .iter()
            .any(|value| value == "ALL")
        || !receipt
            .effective_policy
            .security_options
            .iter()
            .any(|value| value.contains("no-new-privileges"))
        || !receipt
            .effective_policy
            .security_options
            .iter()
            .any(|value| value.contains("seccomp"))
        || !receipt.effective_policy.init_enabled
        || receipt.effective_policy.init_implementation != "docker-init"
        || receipt.effective_policy.init_version.trim().is_empty()
        || receipt
            .effective_policy
            .init_version
            .eq_ignore_ascii_case("unknown")
        || receipt.effective_policy.pid_limit != receipt.requested_policy.process.pid_limit
        || receipt.effective_policy.memory_bytes != receipt.requested_policy.resources.memory_bytes
        || receipt.effective_policy.memory_swap_bytes
            != receipt.requested_policy.resources.memory_swap_bytes
        || receipt.effective_policy.cpu_quota_nanos
            != u64::from(receipt.requested_policy.resources.cpu_quota_millis) * 1_000_000
        || receipt.effective_policy.ulimits.get("nofile").copied()
            != Some(u64::from(receipt.requested_policy.resources.max_open_files))
        || receipt.effective_policy.ulimits.get("fsize").copied()
            != Some(receipt.requested_policy.resources.max_file_bytes)
        || receipt
            .effective_policy
            .ulimits
            .values()
            .any(|value| *value == 0)
    {
        reasons.push("requested and effective execution policies do not match".to_string());
    }
    let requested_keys = &receipt.requested_policy.environment.allowed_keys;
    let effective_keys: BTreeSet<String> = receipt
        .effective_policy
        .environment_key_names
        .iter()
        .cloned()
        .collect();
    let configured_keys: BTreeSet<String> = receipt
        .effective_policy
        .environment
        .keys()
        .cloned()
        .collect();
    let observed_keys: BTreeSet<String> = receipt
        .effective_policy
        .observed_environment
        .keys()
        .cloned()
        .collect();
    if effective_keys.len() != receipt.effective_policy.environment_key_names.len()
        || receipt
            .effective_policy
            .environment_key_names
            .iter()
            .any(String::is_empty)
        || effective_keys != observed_keys
        || !configured_keys.is_subset(&observed_keys)
        || !observed_keys.is_subset(requested_keys)
        || receipt
            .effective_policy
            .environment
            .iter()
            .any(|(key, value)| {
                receipt.effective_policy.observed_environment.get(key) != Some(value)
            })
    {
        reasons.push(
            "effective environment key names and permitted runtime values are incomplete or differ"
                .to_string(),
        );
    }
    if receipt.effective_policy.environment.get("HOME")
        != Some(&receipt.requested_policy.environment.synthetic_home)
        || receipt.effective_policy.environment.get("TMPDIR")
            != Some(&receipt.requested_policy.environment.synthetic_tmp)
        || receipt
            .effective_policy
            .environment
            .get("LANG")
            .map(String::as_str)
            != Some("C.UTF-8")
        || receipt.effective_policy.observed_environment.get("HOME")
            != Some(&receipt.requested_policy.environment.synthetic_home)
        || receipt.effective_policy.observed_environment.get("TMPDIR")
            != Some(&receipt.requested_policy.environment.synthetic_tmp)
        || receipt
            .effective_policy
            .observed_environment
            .get("LANG")
            .map(String::as_str)
            != Some("C.UTF-8")
        || receipt
            .effective_policy
            .observed_environment
            .values()
            .any(String::is_empty)
    {
        reasons.push("effective synthetic environment values do not match policy".to_string());
    }
    if receipt
        .observed_effects
        .iter()
        .any(|effect| !runtime_evidence_origin_is_admissible(effect.evidence_origin))
    {
        reasons.push("CONTROL_SIMULATION cannot satisfy runtime enforcement".to_string());
    }
    reasons.extend(validate_control_evidence(receipt));
    let required_controls = &receipt.requested_policy.evidence.required_control_ids;
    let passed_controls: BTreeSet<String> = receipt
        .controls
        .iter()
        .filter(|control| control.result == ExecutionTerminalResultV1::Pass)
        .map(|control| control.control_id.clone())
        .collect();
    let control_ids: BTreeSet<String> = receipt
        .controls
        .iter()
        .map(|control| control.control_id.clone())
        .collect();
    if control_ids.len() != receipt.controls.len() {
        reasons.push("duplicate control IDs are not admissible".to_string());
    }
    if !required_controls.is_subset(&passed_controls) {
        let missing_or_failed: Vec<&str> = required_controls
            .difference(&passed_controls)
            .map(String::as_str)
            .collect();
        reasons.push(format!(
            "required controls missing or not passed: {}",
            missing_or_failed.join(", ")
        ));
    }
    let unhealthy_controls: Vec<&str> = receipt
        .controls
        .iter()
        .filter(|control| control.result != ExecutionTerminalResultV1::Pass)
        .map(|control| control.control_id.as_str())
        .collect();
    if !unhealthy_controls.is_empty() {
        reasons.push(format!(
            "controls failed, blocked, unknown, or errored: {}",
            unhealthy_controls.join(", ")
        ));
    }
    if !receipt.cleanup.is_zero_residue() || receipt.cleanup.detail.is_empty() {
        reasons.push("cleanup evidence does not prove zero named residue".to_string());
    }
    if !is_sha256(&receipt.export_review.candidate_sha256)
        || !is_sha256(&receipt.export_review.reviewed_sha256)
        || !is_sha256(&receipt.export_review.exported_sha256)
        || receipt.export_review.bytes == 0
        || !receipt.export_review.approved
        || receipt.export_review.candidate_sha256 != receipt.export_review.reviewed_sha256
        || receipt.export_review.reviewed_sha256 != receipt.export_review.exported_sha256
        || receipt.export_review.bytes > receipt.requested_policy.export.max_patch_bytes
        || receipt.export_review.reviewer_kind != receipt.requested_policy.export.reviewer_kind
        || !receipt.export_review.rejected_entries.is_empty()
    {
        reasons.push("export review is not digest-bound and clean".to_string());
    }
    if receipt.evidence_ceiling.maximum_claim != receipt.requested_policy.evidence.maximum_claim
        || !is_nonempty_string_list(&receipt.evidence_ceiling.enforced)
        || !is_nonempty_string_list(&receipt.evidence_ceiling.observed)
        || !is_nonempty_string_list(&receipt.evidence_ceiling.unknown)
        || !is_nonempty_string_list(&receipt.evidence_ceiling.excluded_claims)
        || !is_nonempty_string_list(&receipt.limitations)
    {
        reasons.push("claim ceiling and residual unknowns are incomplete".to_string());
    }
    match &receipt.performance {
        Some(performance) => reasons.extend(validate_performance(performance)),
        None => reasons.push("performance qualification is missing".to_string()),
    }
    if receipt.result != ExecutionTerminalResultV1::Pass {
        reasons.push("receipt terminal result is not PASS".to_string());
    }
    if receipt.result == ExecutionTerminalResultV1::Pass && !reasons.is_empty() {
        reasons.push("receipt claims PASS despite contradictory evidence".to_string());
    }

    ReceiptValidationV1 {
        result: if reasons.is_empty() && receipt.result == ExecutionTerminalResultV1::Pass {
            ExecutionTerminalResultV1::Pass
        } else {
            ExecutionTerminalResultV1::Error
        },
        reasons,
    }
}

fn validate_control_evidence(receipt: &ExecutionReceiptV1) -> Vec<String> {
    let mut reasons = Vec::new();
    let mut effects_by_id = BTreeMap::new();
    let mut observed_effect_ids = BTreeSet::new();
    for effect in &receipt.observed_effects {
        if effect.effect_id.trim().is_empty()
            || effect.effect_class.trim().is_empty()
            || effect.sensor_identity.trim().is_empty()
            || effect.detail.trim().is_empty()
        {
            reasons.push(
                "observed effect identity, class, sensor, and detail must be non-empty".to_string(),
            );
        }
        if !effect.attempted {
            reasons.push(format!(
                "observed effect {} does not prove an attempted effect",
                effect.effect_id
            ));
        }
        if !observed_effect_ids.insert(effect.effect_id.clone()) {
            reasons.push(format!(
                "duplicate observed effect ID is not admissible: {}",
                effect.effect_id
            ));
        } else {
            effects_by_id.insert(effect.effect_id.clone(), effect);
        }
    }

    let mut referenced_effect_ids = BTreeSet::new();
    for control in &receipt.controls {
        if control.control_id.trim().is_empty()
            || control.control_kind.trim().is_empty()
            || control.expected.trim().is_empty()
            || control.observed.trim().is_empty()
        {
            reasons.push(
                "control identity, kind, expected detail, and observed detail must be non-empty"
                    .to_string(),
            );
        }
        if !matches!(
            control.control_kind.as_str(),
            "POSITIVE" | "VULNERABLE" | "NEGATIVE"
        ) {
            reasons.push(format!(
                "control {} has an unsupported control kind",
                control.control_id
            ));
        }
        if control.evidence_refs.is_empty() {
            reasons.push(format!(
                "control {} has no effect evidence references",
                control.control_id
            ));
            continue;
        }
        let mut control_ref_ids = BTreeSet::new();
        for evidence_ref in &control.evidence_refs {
            if evidence_ref.effect_id.trim().is_empty() {
                reasons.push(format!(
                    "control {} contains an empty effect evidence reference",
                    control.control_id
                ));
                continue;
            }
            if !control_ref_ids.insert(evidence_ref.effect_id.clone()) {
                reasons.push(format!(
                    "control {} contains duplicate effect evidence references: {}",
                    control.control_id, evidence_ref.effect_id
                ));
                continue;
            }
            referenced_effect_ids.insert(evidence_ref.effect_id.clone());
            match effects_by_id.get(&evidence_ref.effect_id) {
                Some(effect)
                    if effect.attempted == evidence_ref.expected_attempted
                        && effect.allowed == evidence_ref.expected_allowed => {}
                Some(_) => reasons.push(format!(
                    "control {} effect reference flags contradict observed effect {}",
                    control.control_id, evidence_ref.effect_id
                )),
                None => reasons.push(format!(
                    "control {} references missing observed effect {}",
                    control.control_id, evidence_ref.effect_id
                )),
            }
        }
    }
    if referenced_effect_ids != observed_effect_ids {
        reasons.push(
            "control evidence references and observed effects must have exact set equality"
                .to_string(),
        );
    }
    reasons
}

fn normalized_seccomp_identity(
    security_options: &[String],
) -> Result<(String, Vec<String>), String> {
    let profiles: Vec<&str> = security_options
        .iter()
        .filter_map(|option| option.strip_prefix("seccomp="))
        .collect();
    if profiles.len() != 1 {
        return Err("effective policy must contain exactly one seccomp profile".to_string());
    }
    let profile: serde_json::Value = serde_json::from_str(profiles[0])
        .map_err(|_| "effective seccomp profile is not normalized JSON".to_string())?;
    let canonical = serde_json::to_vec(&profile)
        .map_err(|_| "effective seccomp profile cannot be normalized".to_string())?;
    let architectures = if let Some(values) = profile
        .get("architectures")
        .and_then(serde_json::Value::as_array)
    {
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|architecture| !architecture.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        "effective seccomp profile contains an invalid architecture".to_string()
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        profile
            .get("archMap")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "effective seccomp profile has no architecture binding".to_string())?
            .iter()
            .flat_map(|entry| {
                entry
                    .get("architecture")
                    .and_then(serde_json::Value::as_str)
                    .into_iter()
                    .chain(
                        entry
                            .get("subArchitectures")
                            .and_then(serde_json::Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(serde_json::Value::as_str),
                    )
            })
            .map(str::to_string)
            .collect()
    };
    if architectures.is_empty()
        || architectures.iter().collect::<BTreeSet<_>>().len() != architectures.len()
    {
        return Err("effective seccomp profile has no architecture binding".to_string());
    }
    Ok((hex::encode(Sha256::digest(canonical)), architectures))
}

fn validate_performance(performance: &PerformanceSummaryV1) -> Vec<String> {
    let mut reasons = Vec::new();
    let sample_shape_valid = performance.input_bytes > 0
        && performance.cold_samples.len() == 5
        && performance.warm_samples.len() == 30
        && performance.five_second_samples.len() == 5
        && performance
            .cold_samples
            .iter()
            .all(|sample| sample.phase == PerformancePhaseV1::ColdCached)
        && performance
            .warm_samples
            .iter()
            .all(|sample| sample.phase == PerformancePhaseV1::Warm)
        && performance.five_second_samples.iter().all(|sample| {
            sample.phase == PerformancePhaseV1::FiveSecondOverhead && sample.elapsed_ms >= 5_000
        })
        && performance
            .cold_samples
            .iter()
            .chain(&performance.warm_samples)
            .all(|sample| sample.elapsed_ms > 0);
    if !sample_shape_valid {
        reasons.push(
            "performance samples have invalid counts, phases, or five-second durations".to_string(),
        );
    }

    let cold_elapsed: Vec<u64> = performance
        .cold_samples
        .iter()
        .map(|sample| sample.elapsed_ms)
        .collect();
    let warm_elapsed: Vec<u64> = performance
        .warm_samples
        .iter()
        .map(|sample| sample.elapsed_ms)
        .collect();
    let cleanup: Vec<u64> = performance
        .cold_samples
        .iter()
        .chain(&performance.warm_samples)
        .chain(&performance.five_second_samples)
        .map(|sample| sample.cleanup_ms)
        .collect();
    let overhead: Vec<u64> = performance
        .five_second_samples
        .iter()
        .map(|sample| sample.elapsed_ms.saturating_sub(5_000))
        .collect();
    let cold_start_p95_ms = percentile_95(&cold_elapsed);
    let warm_start_p95_ms = percentile_95(&warm_elapsed);
    let cleanup_p95_ms = percentile_95(&cleanup);
    let cleanup_max_ms = cleanup.iter().copied().max().unwrap_or(u64::MAX);
    let added_overhead_p95_ms = percentile_95(&overhead);
    let added_overhead_percent =
        u32::try_from((added_overhead_p95_ms.saturating_mul(100) + 4_999) / 5_000)
            .unwrap_or(u32::MAX);
    let peak_disk_bytes = performance
        .cold_samples
        .iter()
        .chain(&performance.warm_samples)
        .chain(&performance.five_second_samples)
        .map(|sample| sample.peak_disk_bytes)
        .max()
        .unwrap_or(u64::MAX);
    let disk_amplification_ceiling_bytes = performance
        .input_bytes
        .saturating_mul(5)
        .checked_div(2)
        .unwrap_or(u64::MAX)
        .saturating_add(128 * 1024 * 1024);

    let expected_levels = BTreeSet::from([1_u32, 2, 4]);
    let observed_levels: BTreeSet<u32> = performance
        .concurrency_observations
        .iter()
        .map(|observation| observation.concurrency)
        .collect();
    let concurrency_shape_valid = performance.concurrency_observations.len() == 3
        && observed_levels == expected_levels
        && performance
            .concurrency_observations
            .iter()
            .all(|observation| {
                observation.batch_wall_samples_ms.len() == 5
                    && observation
                        .batch_wall_samples_ms
                        .iter()
                        .all(|sample| *sample > 0)
                    && observation.batch_wall_p95_ms
                        == percentile_95(&observation.batch_wall_samples_ms)
            });
    if !concurrency_shape_valid {
        reasons.push(
            "performance concurrency observations are missing, duplicate, or inconsistent"
                .to_string(),
        );
    }
    let single_p95 = performance
        .concurrency_observations
        .iter()
        .find(|observation| observation.concurrency == 1)
        .map_or(u64::MAX, |observation| {
            percentile_95(&observation.batch_wall_samples_ms)
        });
    let expected_passes: Vec<(u32, bool)> = performance
        .concurrency_observations
        .iter()
        .map(|observation| {
            let observed = percentile_95(&observation.batch_wall_samples_ms);
            (
                observation.concurrency,
                observed <= 2_000
                    && observed <= single_p95.saturating_mul(2)
                    && cleanup_max_ms <= 5_000,
            )
        })
        .collect();
    if performance
        .concurrency_observations
        .iter()
        .zip(&expected_passes)
        .any(|(observation, (_, passed))| observation.passed != *passed)
    {
        reasons.push("performance concurrency pass claims do not match raw samples".to_string());
    }
    let highest_passing_concurrency = expected_passes
        .iter()
        .filter_map(|(level, passed)| passed.then_some(*level))
        .max()
        .unwrap_or(0);
    let gates_passed = sample_shape_valid
        && concurrency_shape_valid
        && cold_start_p95_ms <= 5_000
        && warm_start_p95_ms <= 2_000
        && cleanup_p95_ms <= 2_000
        && cleanup_max_ms <= 5_000
        && added_overhead_p95_ms <= 1_000
        && added_overhead_percent <= 20
        && peak_disk_bytes <= disk_amplification_ceiling_bytes
        && highest_passing_concurrency >= 1;

    if performance.cold_start_p95_ms != cold_start_p95_ms
        || performance.warm_start_p95_ms != warm_start_p95_ms
        || performance.cleanup_p95_ms != cleanup_p95_ms
        || performance.cleanup_max_ms != cleanup_max_ms
        || performance.added_overhead_p95_ms != added_overhead_p95_ms
        || performance.added_overhead_percent != added_overhead_percent
        || performance.peak_disk_bytes != peak_disk_bytes
        || performance.disk_amplification_ceiling_bytes != disk_amplification_ceiling_bytes
        || performance.highest_passing_concurrency != highest_passing_concurrency
        || performance.gates_passed != gates_passed
        || !gates_passed
    {
        reasons.push(
            "performance summary or exact gates do not match raw structured samples".to_string(),
        );
    }
    reasons
}

fn percentile_95(samples: &[u64]) -> u64 {
    if samples.is_empty() {
        return u64::MAX;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = (sorted.len() * 95).div_ceil(100).saturating_sub(1);
    sorted[index]
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

fn is_seccomp_architecture(value: &str) -> bool {
    value.strip_prefix("SCMP_ARCH_").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.chars().all(|character| {
                character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
            })
    })
}

fn is_nonempty_string_list(values: &[String]) -> bool {
    !values.is_empty() && values.iter().all(|value| !value.is_empty())
}

fn tmpfs_options_match(actual: &str, expected: &[String]) -> bool {
    let actual_tokens: Vec<&str> = actual.split(',').collect();
    let actual_unique: BTreeSet<&str> = actual_tokens.iter().copied().collect();
    let expected_tokens: BTreeSet<&str> = expected.iter().map(String::as_str).collect();
    actual_tokens.len() == expected.len() && actual_unique == expected_tokens
}
