use super::policy::ExecutionPolicyV1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const EXECUTION_RECEIPT_SCHEMA_V1: &str = "AIGC_EXECUTION_RECEIPT_V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionTerminalResultV1 {
    Pass,
    Fail,
    Blocked,
    Unknown,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceOriginV1 {
    RuntimeEnforced,
    TrustedSensor,
    ControlSimulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubjectIdentityV1 {
    pub fixture_id: String,
    pub fixture_sha256: String,
    pub input_tree_sha256: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackendIdentityV1 {
    pub backend_id: String,
    pub engine_endpoint: String,
    pub daemon_id: String,
    pub architecture: String,
    pub engine_version: String,
    pub runtime_version: String,
    pub kernel_version: String,
    pub image_id: String,
    pub enforcement_profile_sha256: String,
    pub controller_build: String,
    pub controller_executable_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicyV1 {
    pub readback_complete: bool,
    pub image_id: String,
    pub enforcement_profile_sha256: String,
    pub seccomp_architectures: Vec<String>,
    pub argv: Vec<String>,
    pub working_directory: String,
    pub user: String,
    pub network_mode: String,
    pub readonly_root: bool,
    pub mount_count: u32,
    pub host_mount_count: u32,
    pub host_config_mount_count: u32,
    pub runtime_mount_count: u32,
    pub cap_drop: Vec<String>,
    pub security_options: Vec<String>,
    pub init_enabled: bool,
    pub init_implementation: String,
    pub init_version: String,
    pub pid_limit: u32,
    pub memory_bytes: u64,
    pub memory_swap_bytes: u64,
    pub cpu_quota_nanos: u64,
    pub tmpfs: BTreeMap<String, String>,
    pub ulimits: BTreeMap<String, u64>,
    pub environment_key_names: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub observed_environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectObservationV1 {
    pub effect_id: String,
    pub effect_class: String,
    pub attempted: bool,
    pub allowed: bool,
    pub persisted: bool,
    pub evidence_origin: EvidenceOriginV1,
    pub sensor_identity: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlEvidenceRefV1 {
    pub effect_id: String,
    pub expected_attempted: bool,
    pub expected_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlResultV1 {
    pub control_id: String,
    pub control_kind: String,
    pub expected: String,
    pub observed: String,
    #[serde(default)]
    pub evidence_refs: Vec<ControlEvidenceRefV1>,
    pub result: ExecutionTerminalResultV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportReviewV1 {
    pub candidate_sha256: String,
    pub reviewed_sha256: String,
    pub exported_sha256: String,
    pub reviewer_kind: String,
    pub approved: bool,
    pub rejected_entries: Vec<String>,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CleanupEvidenceV1 {
    pub attempted: bool,
    pub completed: bool,
    pub containers_remaining: u32,
    pub images_remaining: u32,
    pub networks_remaining: u32,
    pub volumes_remaining: u32,
    pub processes_remaining: u32,
    pub listeners_remaining: u32,
    pub mounts_remaining: u32,
    pub temporary_roots_remaining: u32,
    pub detail: String,
}

impl CleanupEvidenceV1 {
    pub fn is_zero_residue(&self) -> bool {
        self.attempted
            && self.completed
            && self.containers_remaining == 0
            && self.images_remaining == 0
            && self.networks_remaining == 0
            && self.volumes_remaining == 0
            && self.processes_remaining == 0
            && self.listeners_remaining == 0
            && self.mounts_remaining == 0
            && self.temporary_roots_remaining == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PerformancePhaseV1 {
    ColdCached,
    Warm,
    FiveSecondOverhead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceSampleV1 {
    pub phase: PerformancePhaseV1,
    pub elapsed_ms: u64,
    pub cleanup_ms: u64,
    pub peak_disk_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyObservationV1 {
    pub concurrency: u32,
    pub batch_wall_samples_ms: Vec<u64>,
    pub batch_wall_p95_ms: u64,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PerformanceSummaryV1 {
    pub cold_samples: Vec<PerformanceSampleV1>,
    pub warm_samples: Vec<PerformanceSampleV1>,
    pub five_second_samples: Vec<PerformanceSampleV1>,
    pub concurrency_observations: Vec<ConcurrencyObservationV1>,
    pub input_bytes: u64,
    pub warm_start_p95_ms: u64,
    pub cold_start_p95_ms: u64,
    pub cleanup_p95_ms: u64,
    pub cleanup_max_ms: u64,
    pub added_overhead_p95_ms: u64,
    pub added_overhead_percent: u32,
    pub peak_disk_bytes: u64,
    pub disk_amplification_ceiling_bytes: u64,
    pub highest_passing_concurrency: u32,
    pub gates_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCeilingV1 {
    pub enforced: Vec<String>,
    pub observed: Vec<String>,
    pub unknown: Vec<String>,
    pub excluded_claims: Vec<String>,
    pub maximum_claim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceiptV1 {
    pub schema_version: String,
    pub run_id: String,
    pub result: ExecutionTerminalResultV1,
    pub subject_identity: SubjectIdentityV1,
    pub backend_identity: BackendIdentityV1,
    pub requested_policy: ExecutionPolicyV1,
    pub effective_policy: EffectivePolicyV1,
    pub observed_effects: Vec<EffectObservationV1>,
    pub controls: Vec<ControlResultV1>,
    pub export_review: ExportReviewV1,
    pub cleanup: CleanupEvidenceV1,
    pub performance: Option<PerformanceSummaryV1>,
    pub evidence_ceiling: EvidenceCeilingV1,
    pub limitations: Vec<String>,
}
