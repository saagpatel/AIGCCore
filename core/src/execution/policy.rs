use crate::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const EXECUTION_POLICY_SCHEMA_V1: &str = "AIGC_EXECUTION_POLICY_V1";
pub const OCI_ZERO_EGRESS_BACKEND_V1: &str = "OCI_ZERO_EGRESS_V1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionNetworkModeV1 {
    DenyAll,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkClassV1 {
    Dns,
    Ipv4,
    Ipv6,
    Metadata,
    Loopback,
    UnixSocket,
    Proxy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretPolicyV1 {
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicyV1 {
    pub immutable_input_path: String,
    pub writable_workspace_path: String,
    pub output_path_allowlist: Vec<String>,
    pub max_output_bytes: u64,
    pub host_mounts_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyV1 {
    pub mode: ExecutionNetworkModeV1,
    #[serde(deserialize_with = "deserialize_unique_btree_set")]
    pub blocked_classes: BTreeSet<NetworkClassV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicyV1 {
    pub child_processes_allowed: bool,
    pub pid_limit: u32,
    pub wall_time_ms: u64,
    pub controller_death_cleanup_required: bool,
    pub trusted_init_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicyV1 {
    pub memory_bytes: u64,
    pub memory_swap_bytes: u64,
    pub cpu_quota_millis: u32,
    pub workspace_bytes: u64,
    pub max_file_bytes: u64,
    pub max_open_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPolicyV1 {
    #[serde(deserialize_with = "deserialize_unique_btree_set")]
    pub allowed_keys: BTreeSet<String>,
    pub secrets: SecretPolicyV1,
    pub synthetic_home: String,
    pub synthetic_tmp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExportPolicyV1 {
    pub patch_only: bool,
    pub review_required: bool,
    pub reviewer_kind: String,
    pub max_patch_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidencePolicyV1 {
    #[serde(deserialize_with = "deserialize_unique_btree_set")]
    pub required_control_ids: BTreeSet<String>,
    pub require_effective_policy_readback: bool,
    pub require_zero_residue: bool,
    pub maximum_claim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicyV1 {
    pub schema_version: String,
    pub policy_id: String,
    pub backend_id: String,
    pub input_tree_sha256: String,
    pub image_id: String,
    pub argv: Vec<String>,
    pub working_directory: String,
    pub filesystem: FilesystemPolicyV1,
    pub network: NetworkPolicyV1,
    pub process: ProcessPolicyV1,
    pub resources: ResourcePolicyV1,
    pub environment: EnvironmentPolicyV1,
    pub export: ExportPolicyV1,
    pub evidence: EvidencePolicyV1,
}

impl ExecutionPolicyV1 {
    pub fn validate(&self) -> CoreResult<()> {
        if self.schema_version != EXECUTION_POLICY_SCHEMA_V1 {
            return Err(CoreError::PolicyBlocked(format!(
                "unsupported execution policy schema {}",
                self.schema_version
            )));
        }
        if self.backend_id != OCI_ZERO_EGRESS_BACKEND_V1 {
            return Err(CoreError::PolicyBlocked(format!(
                "unsupported execution backend {}",
                self.backend_id
            )));
        }
        if self.policy_id.trim().is_empty()
            || !is_sha256(&self.input_tree_sha256)
            || self
                .image_id
                .strip_prefix("sha256:")
                .is_none_or(|digest| !is_sha256(digest))
        {
            return Err(CoreError::PolicyBlocked(
                "policy, input tree, and image must use non-empty immutable identities".to_string(),
            ));
        }
        if self.argv.is_empty() || self.argv.iter().any(|value| value.is_empty()) {
            return Err(CoreError::PolicyBlocked(
                "execution argv must be a non-empty argv vector".to_string(),
            ));
        }
        if self.working_directory != self.filesystem.writable_workspace_path
            || !self.filesystem.immutable_input_path.starts_with('/')
            || !self.filesystem.writable_workspace_path.starts_with('/')
            || self.filesystem.host_mounts_allowed
        {
            return Err(CoreError::PolicyBlocked(
                "filesystem policy must use absolute isolated paths and deny host mounts"
                    .to_string(),
            ));
        }
        if self.filesystem.immutable_input_path == self.filesystem.writable_workspace_path
            || self.filesystem.output_path_allowlist.is_empty()
            || self
                .filesystem
                .output_path_allowlist
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.filesystem.output_path_allowlist.len()
            || self.filesystem.max_output_bytes == 0
            || self.filesystem.max_output_bytes != self.export.max_patch_bytes
            || self
                .filesystem
                .output_path_allowlist
                .iter()
                .any(|path| !is_safe_relative_path(path))
        {
            return Err(CoreError::PolicyBlocked(
                "filesystem output allowlist must contain bounded distinct relative regular paths"
                    .to_string(),
            ));
        }
        let required_network_classes = BTreeSet::from([
            NetworkClassV1::Dns,
            NetworkClassV1::Ipv4,
            NetworkClassV1::Ipv6,
            NetworkClassV1::Metadata,
            NetworkClassV1::Loopback,
            NetworkClassV1::UnixSocket,
            NetworkClassV1::Proxy,
        ]);
        if self.network.mode != ExecutionNetworkModeV1::DenyAll
            || self.network.blocked_classes != required_network_classes
        {
            return Err(CoreError::PolicyBlocked(
                "OCI_ZERO_EGRESS_V1 requires denial evidence for every network class".to_string(),
            ));
        }
        if self.environment.secrets != SecretPolicyV1::None
            || self.environment.allowed_keys.is_empty()
            || self.environment.allowed_keys.iter().any(|key| {
                let upper = key.to_ascii_uppercase();
                key.is_empty()
                    || key.contains('=')
                    || upper.contains("TOKEN")
                    || upper.contains("SECRET")
                    || upper.contains("PASSWORD")
                    || upper.contains("PROXY")
                    || upper.starts_with("AWS_")
                    || upper.starts_with("GITHUB_")
                    || upper.starts_with("DOCKER_")
                    || upper.starts_with("SSH_")
            })
            || !self
                .environment
                .synthetic_home
                .starts_with(&(self.filesystem.writable_workspace_path.clone() + "/"))
            || !self.environment.synthetic_tmp.starts_with('/')
        {
            return Err(CoreError::PolicyBlocked(
                "OCI_ZERO_EGRESS_V1 forbids secrets, proxy, Docker, SSH, GitHub, and cloud credentials"
                    .to_string(),
            ));
        }
        if !self.process.child_processes_allowed
            || self.process.pid_limit == 0
            || self.process.wall_time_ms == 0
            || !self.process.controller_death_cleanup_required
            || !self.process.trusted_init_required
            || self.resources.memory_bytes == 0
            || self.resources.memory_swap_bytes != self.resources.memory_bytes
            || self.resources.cpu_quota_millis == 0
            || self.resources.workspace_bytes == 0
            || self.resources.max_file_bytes == 0
            || self.resources.max_open_files == 0
        {
            return Err(CoreError::PolicyBlocked(
                "process and resource ceilings must be explicit and fail closed".to_string(),
            ));
        }
        if !self.export.patch_only
            || !self.export.review_required
            || self.export.max_patch_bytes == 0
            || self.export.reviewer_kind.trim().is_empty()
        {
            return Err(CoreError::PolicyBlocked(
                "export must be patch-only, bounded, and reviewer approved".to_string(),
            ));
        }
        if self.evidence.required_control_ids.is_empty()
            || !self.evidence.require_effective_policy_readback
            || !self.evidence.require_zero_residue
            || self.evidence.maximum_claim.trim().is_empty()
        {
            return Err(CoreError::PolicyBlocked(
                "evidence policy must require controls, readback, residue proof, and a claim ceiling"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

fn is_safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn deserialize_unique_btree_set<'de, D, T>(deserializer: D) -> Result<BTreeSet<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Ord,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    let value_count = values.len();
    let unique: BTreeSet<T> = values.into_iter().collect();
    if unique.len() != value_count {
        return Err(serde::de::Error::custom(
            "duplicate values are not admissible",
        ));
    }
    Ok(unique)
}
