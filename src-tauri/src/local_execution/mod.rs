use aigc_core::determinism::run_id::sha256_hex;
use aigc_core::execution::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FIXTURE: &str = include_str!("fixture.js");
const SECCOMP_PROFILE: &str = include_str!("socket-deny-seccomp.json");
const EXPECTED_IMAGE_ID: &str =
    "sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3";
const BACKEND_CLAIM: &str = "A deterministic synthetic fixture ran under the exact recorded OCI engine, image, effective configuration, socket-denial profile, controls, export review, and cleanup evidence.";
const LABEL_KEY: &str = "com.aigccore.local-execution-v1";
static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const REQUIRED_CONTROL_IDS: [&str; 22] = [
    "BACKEND-NEGATIVE-EXACT-REQUEST",
    "FS-POSITIVE-ALLOWED-WRITE",
    "FS-VULNERABLE-OUTSIDE-WRITE",
    "FS-NEGATIVE-BOUNDARY",
    "NETWORK-POSITIVE-RUN-OWNED-SENSORS",
    "NETWORK-VULNERABLE-SOCKETS",
    "NETWORK-NEGATIVE-ZERO-EGRESS",
    "ENV-NEGATIVE-SYNTHETIC",
    "PROCESS-POSITIVE-CHILD",
    "PROCESS-VULNERABLE-DELAYED-CHILD",
    "PROCESS-NEGATIVE-TIMEOUT",
    "PROCESS-NEGATIVE-CONTROLLER-DEATH",
    "EXPORT-POSITIVE-REVIEW",
    "EXPORT-VULNERABLE-NAIVE-ACCEPTANCE",
    "EXPORT-NEGATIVE-SMUGGLING",
    "EXPORT-NEGATIVE-TOCTOU",
    "CLEANUP-POSITIVE-EXACT-REMOVAL",
    "CLEANUP-VULNERABLE-RESIDUE-SENSOR",
    "CLEANUP-NEGATIVE-ZERO-RESIDUE",
    "EVIDENCE-POSITIVE-TRUSTED-SENSOR",
    "EVIDENCE-VULNERABLE-SIMULATION-PROBE",
    "EVIDENCE-NEGATIVE-SIMULATION-REJECTED",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Safe,
    Vulnerable,
    ProcessVulnerable,
    Timeout,
    ControllerDeath,
    Benchmark,
    Performance,
}

impl RunMode {
    fn fixture_arg(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Vulnerable => "vulnerable",
            Self::ProcessVulnerable => "process-vulnerable",
            Self::Timeout => "timeout",
            Self::ControllerDeath => "controller-death",
            Self::Benchmark => "benchmark",
            Self::Performance => "performance",
        }
    }

    fn seccomp_enforced(self) -> bool {
        !matches!(self, Self::Vulnerable)
    }

    fn readonly_root(self) -> bool {
        !matches!(self, Self::Vulnerable)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureEffect {
    attempted: bool,
    allowed: bool,
    detail: String,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureReport {
    fixture_version: String,
    mode: String,
    effects: BTreeMap<String, FixtureEffect>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    workspace_bytes: u64,
    candidate_patch_json: Option<String>,
}

#[derive(Debug, Clone)]
struct ContainerRun {
    output: Output,
    report: Option<FixtureReport>,
    inspect: Value,
    elapsed_ms: u64,
    cleanup_ms: u64,
    peak_disk_bytes: u64,
    timed_out: bool,
    process_count_before_termination: u32,
    process_domain_stopped: bool,
    delayed_deadline_elapsed: bool,
    delayed_canary_absent: bool,
    captured_candidate_bytes: Option<Vec<u8>>,
    captured_allowed_bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
struct CapturedWorkspace {
    candidate_bytes: Vec<u8>,
    allowed_bytes: Vec<u8>,
}

#[derive(Debug)]
struct ExportAttackControls {
    smuggling_rejected: bool,
    toctou_rejected_without_output: bool,
}

#[derive(Debug)]
struct FunctionalControlEvidence {
    controls: Vec<ControlResultV1>,
    controller_observations: Vec<EffectObservationV1>,
}

#[derive(Debug)]
struct ControllerDeathContainer {
    id: String,
    token: String,
    run_root: PathBuf,
}

struct RunResourceGuard {
    docker: PathBuf,
    engine_endpoint: String,
    container_ref: String,
    token: String,
    run_root: PathBuf,
    cleaned: bool,
}

impl RunResourceGuard {
    fn cleanup(&mut self) -> Result<u64, String> {
        let started = Instant::now();
        let removal = command_output(
            &self.docker,
            &self.engine_endpoint,
            &[
                "rm".to_string(),
                "--force".to_string(),
                self.container_ref.clone(),
            ],
            "remove guarded isolated container",
        )?;
        if !removal.status.success()
            && !String::from_utf8_lossy(&removal.stderr).contains("No such container")
        {
            return Err(command_failure(
                "remove guarded isolated container",
                &removal,
            ));
        }
        let residue = command_output(
            &self.docker,
            &self.engine_endpoint,
            &[
                "ps".to_string(),
                "-aq".to_string(),
                "--filter".to_string(),
                format!("label={LABEL_KEY}={}", self.token),
            ],
            "read guarded container cleanup residue",
        )?;
        if !residue.status.success() {
            return Err(command_failure(
                "read guarded container cleanup residue",
                &residue,
            ));
        }
        match fs::remove_dir_all(&self.run_root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove guarded runtime root {}: {error}",
                    self.run_root.display()
                ));
            }
        }
        if !String::from_utf8_lossy(&residue.stdout).trim().is_empty() || self.run_root.exists() {
            return Err(format!(
                "guarded cleanup residue for {}: container_ids={}, temp_root_exists={}",
                self.token,
                String::from_utf8_lossy(&residue.stdout).trim(),
                self.run_root.exists()
            ));
        }
        self.cleaned = true;
        Ok(millis(started.elapsed()))
    }
}

impl Drop for RunResourceGuard {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        let _ = Command::new(&self.docker)
            .args([
                "--host",
                &self.engine_endpoint,
                "rm",
                "--force",
                &self.container_ref,
            ])
            .env_clear()
            .env("HOME", "/tmp")
            .env("TMPDIR", "/tmp")
            .output();
        let _ = fs::remove_dir_all(&self.run_root);
    }
}

struct PreparationResourceGuard {
    docker: PathBuf,
    engine_endpoint: String,
    staging_root: PathBuf,
    staging_container: Option<String>,
    derived_image_tag: Option<String>,
    cleaned: bool,
}

impl Drop for PreparationResourceGuard {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        if let Some(container) = self.staging_container.as_deref() {
            let _ = Command::new(&self.docker)
                .args(["--host", &self.engine_endpoint, "rm", "--force", container])
                .env_clear()
                .env("HOME", "/tmp")
                .env("TMPDIR", "/tmp")
                .output();
        }
        if let Some(image) = self.derived_image_tag.as_deref() {
            let _ = Command::new(&self.docker)
                .args([
                    "--host",
                    &self.engine_endpoint,
                    "image",
                    "rm",
                    "--force",
                    image,
                ])
                .env_clear()
                .env("HOME", "/tmp")
                .env("TMPDIR", "/tmp")
                .output();
        }
        let _ = fs::remove_dir_all(&self.staging_root);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatchCandidateV1 {
    schema_version: String,
    changes: Vec<PatchChangeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatchChangeV1 {
    path: String,
    before_sha256: String,
    after: String,
}

#[derive(Debug, Clone)]
struct RuntimeIdentity {
    engine_endpoint: String,
    daemon_id: String,
    architecture: String,
    engine_version: String,
    runtime_version: String,
    kernel_version: String,
    image_id: String,
    base_image_bytes: u64,
    derived_image_delta_bytes: u64,
    init_implementation: String,
    init_version: String,
    controller_executable_sha256: String,
}

#[derive(Debug, Clone)]
pub struct OciZeroEgressBackendV1 {
    docker: PathBuf,
    workspace_root: PathBuf,
    identity: RuntimeIdentity,
    prepared_image: Option<(String, String)>,
}

impl OciZeroEgressBackendV1 {
    fn exact_request_matches(&self, request: &ExecutionRequestV1) -> bool {
        self.prepared_image.is_some()
            && request.policy == self.requested_policy()
            && request.fixture_bytes == FIXTURE.as_bytes()
            && request.input_bytes == b"canonical-base\n"
    }

    fn exact_request_negative_controls(&self, request: &ExecutionRequestV1) -> bool {
        let mut mutations = Vec::new();
        let mut changed_fixture = request.clone();
        changed_fixture.fixture_bytes.push(b'!');
        mutations.push(changed_fixture);
        let mut changed_input = request.clone();
        changed_input.input_bytes.push(b'!');
        mutations.push(changed_input);
        let mut changed_backend = request.clone();
        changed_backend.policy.backend_id.push_str("_CHANGED");
        mutations.push(changed_backend);
        let mut changed_image = request.clone();
        changed_image.policy.image_id = EXPECTED_IMAGE_ID.to_string();
        mutations.push(changed_image);
        let mut changed_argv = request.clone();
        changed_argv.policy.argv.push("--changed".to_string());
        mutations.push(changed_argv);
        let mut changed_environment = request.clone();
        changed_environment
            .policy
            .environment
            .allowed_keys
            .remove("LANG");
        mutations.push(changed_environment);
        let mut changed_destination = request.clone();
        changed_destination.policy.filesystem.output_path_allowlist =
            vec!["changed.txt".to_string()];
        mutations.push(changed_destination);
        self.exact_request_matches(request)
            && mutations
                .iter()
                .all(|mutation| !self.exact_request_matches(mutation))
    }

    fn discover(workspace_root: PathBuf) -> Result<Self, String> {
        let docker = PathBuf::from("/opt/homebrew/bin/docker");
        if !docker.is_file() {
            return Err(
                "required Docker CLI is unavailable at /opt/homebrew/bin/docker".to_string(),
            );
        }
        let engine_endpoint = docker_context_host(&docker)?;
        let version: Value = json_command(
            &docker,
            &engine_endpoint,
            &["version", "--format", "{{json .}}"],
            "read Docker runtime identity",
        )?;
        let server = version
            .get("Server")
            .ok_or_else(|| "Docker server identity is missing".to_string())?;
        let engine_version = json_string(server, &["Version"])?;
        let kernel_version = json_string(server, &["KernelVersion"])?;
        let runtime_version = server
            .pointer("/Components/2/Version")
            .and_then(Value::as_str)
            .ok_or_else(|| "runc identity is missing".to_string())?
            .to_string();
        let info: Value = json_command(
            &docker,
            &engine_endpoint,
            &["info", "--format", "{{json .}}"],
            "read Docker enforcement capabilities",
        )?;
        let init_implementation = json_string(&info, &["InitBinary"])?;
        let init_version = json_string(&info, &["InitCommit", "ID"])?;
        let daemon_id = json_string(&info, &["ID"])?;
        let architecture = json_string(&info, &["Architecture"])?;
        let controller_executable_sha256 = current_executable_sha256()?;
        let security_options = info
            .get("SecurityOptions")
            .and_then(Value::as_array)
            .ok_or_else(|| "Docker security option readback is missing".to_string())?;
        let cgroup_v2 = info
            .get("CgroupVersion")
            .is_some_and(|value| value.as_u64() == Some(2) || value.as_str() == Some("2"));
        if !security_options
            .iter()
            .filter_map(Value::as_str)
            .any(|option| option.contains("seccomp"))
            || !cgroup_v2
            || info.get("PidsLimit").and_then(Value::as_bool) != Some(true)
            || info.get("MemoryLimit").and_then(Value::as_bool) != Some(true)
            || info.get("SwapLimit").and_then(Value::as_bool) != Some(true)
        {
            return Err(
                "Docker does not report required seccomp, cgroup-v2, PID, memory, and swap enforcement"
                    .to_string(),
            );
        }
        let image: Value = json_command(
            &docker,
            &engine_endpoint,
            &[
                "image",
                "inspect",
                EXPECTED_IMAGE_ID,
                "--format",
                "{{json .}}",
            ],
            "read pinned cached image identity",
        )?;
        let image_id = image
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| "cached image ID is missing".to_string())?
            .to_string();
        let base_image_bytes = image
            .get("Size")
            .and_then(Value::as_u64)
            .ok_or_else(|| "cached image size readback is missing".to_string())?;
        if image_id != EXPECTED_IMAGE_ID {
            return Err(format!(
                "cached image identity mismatch: expected {EXPECTED_IMAGE_ID}, observed {image_id}"
            ));
        }
        fs::create_dir_all(&workspace_root)
            .map_err(|error| format!("create qualification workspace: {error}"))?;
        if fs::canonicalize(&workspace_root)
            .map_err(|error| format!("resolve qualification workspace: {error}"))?
            != workspace_root
        {
            return Err("qualification workspace must not traverse a symlink".to_string());
        }
        Ok(Self {
            docker,
            workspace_root,
            identity: RuntimeIdentity {
                engine_endpoint,
                daemon_id,
                architecture,
                engine_version,
                runtime_version,
                kernel_version,
                image_id,
                base_image_bytes,
                derived_image_delta_bytes: 0,
                init_implementation,
                init_version,
                controller_executable_sha256,
            },
            prepared_image: None,
        })
    }

    fn prepare_fixture_image(&mut self) -> Result<(), String> {
        let token = run_token();
        let tag = format!("aigccore-local-exec-fixture:{token}");
        let staging_name = format!("aigccore-local-exec-staging-{token}");
        let staging_root = self.workspace_root.join(format!("staging-{token}"));
        let input_root = staging_root.join("input");
        let sibling_root = staging_root.join("sibling");
        let mut resource_guard = PreparationResourceGuard {
            docker: self.docker.clone(),
            engine_endpoint: self.identity.engine_endpoint.clone(),
            staging_root: staging_root.clone(),
            staging_container: None,
            derived_image_tag: None,
            cleaned: false,
        };
        fs::create_dir_all(&input_root)
            .and_then(|_| fs::create_dir_all(&sibling_root))
            .map_err(|error| format!("create immutable-image staging root: {error}"))?;
        fs::write(input_root.join("fixture.js"), FIXTURE)
            .and_then(|_| fs::write(input_root.join("base.txt"), b"canonical-base\n"))
            .and_then(|_| fs::write(sibling_root.join(".keep"), b"program-owned\n"))
            .map_err(|error| format!("write immutable-image fixture: {error}"))?;
        harden_fixture_staging(&staging_root)?;

        let label = format!("{LABEL_KEY}={token}");
        let create = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "create".to_string(),
                "--pull".to_string(),
                "never".to_string(),
                "--name".to_string(),
                staging_name,
                "--label".to_string(),
                label.clone(),
                self.identity.image_id.clone(),
                "/bin/true".to_string(),
            ],
            "create never-started immutable-image staging container",
        )?;
        if !create.status.success() {
            return Err(command_failure(
                "create never-started immutable-image staging container",
                &create,
            ));
        }
        let staging_id = String::from_utf8_lossy(&create.stdout).trim().to_string();
        resource_guard.staging_container = Some(staging_id.clone());
        let stage_result = self
            .copy_into(&input_root, &staging_id, "/input")
            .and_then(|_| self.copy_into(&sibling_root, &staging_id, "/sibling"));
        if let Err(error) = stage_result {
            return Err(error);
        }
        resource_guard.derived_image_tag = Some(tag.clone());
        let commit = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "commit".to_string(),
                "--change".to_string(),
                format!("LABEL {label}"),
                staging_id.clone(),
                tag.clone(),
            ],
            "commit exact offline immutable fixture image",
        )?;
        if !commit.status.success() {
            return Err(command_failure(
                "commit exact offline immutable fixture image",
                &commit,
            ));
        }
        self.remove_container(&staging_id)?;
        resource_guard.staging_container = None;
        fs::remove_dir_all(&staging_root)
            .map_err(|error| format!("remove immutable-image staging root: {error}"))?;
        let derived_id = String::from_utf8_lossy(&commit.stdout).trim().to_string();
        if !derived_id.starts_with("sha256:") || derived_id == EXPECTED_IMAGE_ID {
            return Err("Docker returned an invalid derived fixture-image identity".to_string());
        }
        let derived: Value = json_command(
            &self.docker,
            &self.identity.engine_endpoint,
            &["image", "inspect", &derived_id, "--format", "{{json .}}"],
            "read derived fixture image storage",
        )?;
        let derived_bytes = derived
            .get("Size")
            .and_then(Value::as_u64)
            .ok_or_else(|| "derived fixture image size readback is missing".to_string())?;
        self.identity.derived_image_delta_bytes =
            derived_bytes.saturating_sub(self.identity.base_image_bytes);
        self.identity.image_id = derived_id;
        self.prepared_image = Some((tag, token));
        resource_guard.derived_image_tag = None;
        resource_guard.cleaned = true;
        Ok(())
    }

    fn cleanup_prepared_image(&mut self) -> Result<(), String> {
        let Some((tag, token)) = self.prepared_image.clone() else {
            return Ok(());
        };
        self.remove_image(&tag)?;
        let output = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "image".to_string(),
                "ls".to_string(),
                "-q".to_string(),
                "--filter".to_string(),
                format!("label={LABEL_KEY}={token}"),
            ],
            "read derived-image cleanup residue",
        )?;
        if !output.status.success() {
            return Err(command_failure(
                "read derived-image cleanup residue",
                &output,
            ));
        }
        if !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
            return Err(format!("derived fixture image residue remains for {token}"));
        }
        self.prepared_image = None;
        Ok(())
    }

    fn requested_policy(&self) -> ExecutionPolicyV1 {
        let fixture_digest = sha256_hex(FIXTURE.as_bytes());
        let input_digest =
            sha256_hex(format!("{fixture_digest}:{}", sha256_hex(b"canonical-base\n")).as_bytes());
        ExecutionPolicyV1 {
            schema_version: EXECUTION_POLICY_SCHEMA_V1.to_string(),
            policy_id: "AIGC_OCI_ZERO_EGRESS_POLICY_V1".to_string(),
            backend_id: OCI_ZERO_EGRESS_BACKEND_V1.to_string(),
            input_tree_sha256: input_digest,
            image_id: self.identity.image_id.clone(),
            argv: vec![
                "/usr/local/bin/node".to_string(),
                "/input/fixture.js".to_string(),
                "safe".to_string(),
            ],
            working_directory: "/workspace".to_string(),
            filesystem: FilesystemPolicyV1 {
                immutable_input_path: "/input".to_string(),
                writable_workspace_path: "/workspace".to_string(),
                output_path_allowlist: vec!["allowed.txt".to_string()],
                max_output_bytes: 8 * 1024,
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
                max_patch_bytes: 8 * 1024,
            },
            evidence: EvidencePolicyV1 {
                required_control_ids: REQUIRED_CONTROL_IDS
                    .iter()
                    .map(|control| (*control).to_string())
                    .collect(),
                require_effective_policy_readback: true,
                require_zero_residue: true,
                maximum_claim: BACKEND_CLAIM.to_string(),
            },
        }
    }

    fn revalidate_runtime_identity(&self) -> Result<(), String> {
        let final_engine_endpoint = docker_context_host(&self.docker)?;
        let version: Value = json_command(
            &self.docker,
            &self.identity.engine_endpoint,
            &["version", "--format", "{{json .}}"],
            "re-read final Docker runtime identity",
        )?;
        let server = version
            .get("Server")
            .ok_or_else(|| "final Docker server identity is missing".to_string())?;
        let info: Value = json_command(
            &self.docker,
            &self.identity.engine_endpoint,
            &["info", "--format", "{{json .}}"],
            "re-read final Docker daemon identity",
        )?;
        let final_runtime_version = server
            .pointer("/Components/2/Version")
            .and_then(Value::as_str)
            .ok_or_else(|| "final runc identity is missing".to_string())?;
        let unchanged = final_engine_endpoint == self.identity.engine_endpoint
            && json_string(server, &["Version"])? == self.identity.engine_version
            && json_string(server, &["KernelVersion"])? == self.identity.kernel_version
            && final_runtime_version == self.identity.runtime_version
            && json_string(&info, &["ID"])? == self.identity.daemon_id
            && json_string(&info, &["Architecture"])? == self.identity.architecture
            && json_string(&info, &["InitBinary"])? == self.identity.init_implementation
            && json_string(&info, &["InitCommit", "ID"])? == self.identity.init_version
            && current_executable_sha256()? == self.identity.controller_executable_sha256;
        if !unchanged {
            return Err(
                "endpoint, runtime, daemon, architecture, init, or controller executable identity changed during qualification"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn run_container(&self, mode: RunMode, wall_time: Duration) -> Result<ContainerRun, String> {
        let total_started = Instant::now();
        let token = run_token();
        let name = format!("aigccore-local-exec-{token}");
        let run_root = self.workspace_root.join(&token);
        fs::create_dir_all(&run_root)
            .map_err(|error| format!("create program-owned staging root: {error}"))?;
        fs::write(run_root.join("socket-deny-seccomp.json"), SECCOMP_PROFILE)
            .map_err(|error| format!("write embedded qualification fixture: {error}"))?;
        harden_profile_staging(&run_root)?;
        let mut resource_guard = RunResourceGuard {
            docker: self.docker.clone(),
            engine_endpoint: self.identity.engine_endpoint.clone(),
            container_ref: name.clone(),
            token: token.clone(),
            run_root: run_root.clone(),
            cleaned: false,
        };

        let label = format!("{LABEL_KEY}={token}");
        let profile = run_root.join("socket-deny-seccomp.json");
        let mut args = vec![
            "create".to_string(),
            "--pull".to_string(),
            "never".to_string(),
            "--name".to_string(),
            name.clone(),
            "--label".to_string(),
            label,
            "--hostname".to_string(),
            "aigc-fixture".to_string(),
            "--entrypoint".to_string(),
            "/usr/local/bin/node".to_string(),
            "--user".to_string(),
            "65534:65534".to_string(),
            "--workdir".to_string(),
            "/workspace".to_string(),
            "--network".to_string(),
            "none".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--pids-limit".to_string(),
            "16".to_string(),
            "--memory".to_string(),
            "268435456".to_string(),
            "--memory-swap".to_string(),
            "268435456".to_string(),
            "--cpus".to_string(),
            "0.5".to_string(),
            "--ulimit".to_string(),
            "nofile=64:64".to_string(),
            "--ulimit".to_string(),
            "fsize=8388608:8388608".to_string(),
            "--tmpfs".to_string(),
            "/workspace:rw,nosuid,nodev,size=67108864,mode=0700,uid=65534,gid=65534".to_string(),
            "--tmpfs".to_string(),
            "/tmp:rw,nosuid,nodev,noexec,size=8388608,mode=0700,uid=65534,gid=65534".to_string(),
            "--init".to_string(),
            "--env".to_string(),
            "HOME=/workspace/home".to_string(),
            "--env".to_string(),
            "TMPDIR=/tmp".to_string(),
            "--env".to_string(),
            "LANG=C.UTF-8".to_string(),
        ];
        if mode.readonly_root() {
            args.push("--read-only".to_string());
        } else {
            args.extend([
                "--env".to_string(),
                "HTTPS_PROXY=http://127.0.0.1:39091".to_string(),
            ]);
        }
        if mode.seccomp_enforced() {
            args.extend([
                "--security-opt".to_string(),
                format!("seccomp={}", profile.display()),
            ]);
        }
        args.extend([
            self.identity.image_id.clone(),
            "/input/fixture.js".to_string(),
            mode.fixture_arg().to_string(),
        ]);

        let create = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &args,
            "create isolated container",
        )?;
        if !create.status.success() {
            return Err(command_failure("create isolated container", &create));
        }
        let id = String::from_utf8_lossy(&create.stdout).trim().to_string();
        if id.len() < 12 {
            return Err("Docker returned an invalid immutable container ID".to_string());
        }
        resource_guard.container_ref.clone_from(&id);
        let inspect = self.inspect_container(&id)?;

        let execution_started = Instant::now();
        let start = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &["start".to_string(), id.clone()],
            "start isolated container",
        )?;
        if !start.status.success() {
            return Err(command_failure("start isolated container", &start));
        }
        let mut timed_out = false;
        let mut process_count_before_termination = 0;
        let mut process_domain_stopped = false;
        let mut delayed_deadline_elapsed = false;
        let mut delayed_canary_absent = false;
        let mut captured_workspace = None;
        loop {
            if mode == RunMode::Safe && captured_workspace.is_none() {
                let logs = command_output(
                    &self.docker,
                    &self.identity.engine_endpoint,
                    &["logs".to_string(), id.clone()],
                    "observe safe fixture capture boundary",
                )?;
                if !logs.status.success() {
                    return Err(command_failure(
                        "observe safe fixture capture boundary",
                        &logs,
                    ));
                }
                if parse_fixture_report(&logs.stdout)?.is_some() {
                    let capture = command_output(
                        &self.docker,
                        &self.identity.engine_endpoint,
                        &[
                            "exec".to_string(),
                            id.clone(),
                            "/bin/tar".to_string(),
                            "--format=ustar".to_string(),
                            "-C".to_string(),
                            "/workspace".to_string(),
                            "-cf".to_string(),
                            "-".to_string(),
                            ".".to_string(),
                        ],
                        "stream live tmpfs workspace at capture boundary",
                    )?;
                    if !capture.status.success() {
                        return Err(command_failure(
                            "stream live tmpfs workspace at capture boundary",
                            &capture,
                        ));
                    }
                    captured_workspace = Some(inspect_workspace_tar(
                        &capture.stdout,
                        self.requested_policy().export.max_patch_bytes,
                    )?);
                    let release = command_output(
                        &self.docker,
                        &self.identity.engine_endpoint,
                        &[
                            "exec".to_string(),
                            id.clone(),
                            "/usr/bin/touch".to_string(),
                            "/workspace/.capture-release".to_string(),
                        ],
                        "release safe fixture after trusted capture",
                    )?;
                    if !release.status.success() {
                        return Err(command_failure(
                            "release safe fixture after trusted capture",
                            &release,
                        ));
                    }
                }
            }
            let state = self.inspect_container(&id)?;
            let running = state
                .pointer("/State/Running")
                .and_then(Value::as_bool)
                .ok_or_else(|| "Docker running-state readback is missing".to_string())?;
            if !running {
                break;
            }
            if execution_started.elapsed() >= wall_time {
                timed_out = true;
                process_count_before_termination = self.container_process_count(&id)?;
                let kill = command_output(
                    &self.docker,
                    &self.identity.engine_endpoint,
                    &["kill".to_string(), id.clone()],
                    "kill timed-out container",
                )?;
                if !kill.status.success() {
                    return Err(command_failure("kill timed-out container", &kill));
                }
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let final_inspect = self.inspect_container(&id)?;
        let exit_code = final_inspect
            .pointer("/State/ExitCode")
            .and_then(Value::as_i64)
            .ok_or_else(|| "Docker exit-code readback is missing".to_string())?;
        if !(0..=255).contains(&exit_code) {
            return Err(format!(
                "Docker returned invalid container exit code {exit_code}"
            ));
        }
        let logs = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &["logs".to_string(), id.clone()],
            "collect isolated container output",
        )?;
        if !logs.status.success() {
            return Err(command_failure("collect isolated container output", &logs));
        }
        #[cfg(unix)]
        let output = {
            use std::os::unix::process::ExitStatusExt;
            Output {
                status: std::process::ExitStatus::from_raw((exit_code as i32) << 8),
                stdout: logs.stdout,
                stderr: logs.stderr,
            }
        };
        if timed_out {
            let delayed_deadline = Duration::from_millis(1_800);
            if execution_started.elapsed() < delayed_deadline {
                thread::sleep(delayed_deadline - execution_started.elapsed());
            }
            delayed_deadline_elapsed = true;
            process_domain_stopped = self.container_process_domain_stopped(&id)?;
            let canary_probe = command_output(
                &self.docker,
                &self.identity.engine_endpoint,
                &[
                    "cp".to_string(),
                    format!("{id}:/workspace/delayed-canary"),
                    run_root
                        .join("delayed-canary-probe")
                        .to_string_lossy()
                        .into_owned(),
                ],
                "probe delayed canary after process-domain termination",
            )?;
            if canary_probe.status.success() {
                delayed_canary_absent = false;
            } else {
                let detail = String::from_utf8_lossy(&canary_probe.stderr);
                if !detail.contains("Could not find")
                    && !detail.contains("no such file")
                    && !detail.contains("No such file")
                {
                    return Err(command_failure(
                        "probe delayed canary after process-domain termination",
                        &canary_probe,
                    ));
                }
                delayed_canary_absent = true;
            }
        }
        let elapsed_ms = millis(total_started.elapsed());
        let report = parse_fixture_report(&output.stdout)?;
        let peak_disk_bytes = self
            .container_rw_size(&id)?
            .saturating_add(
                report
                    .as_ref()
                    .map_or(0, |fixture_report| fixture_report.workspace_bytes),
            )
            .saturating_add(directory_size_no_follow(&run_root)?)
            .saturating_add(self.identity.derived_image_delta_bytes);
        let cleanup_ms = resource_guard.cleanup()?;

        Ok(ContainerRun {
            output,
            report,
            inspect,
            elapsed_ms,
            cleanup_ms,
            peak_disk_bytes,
            timed_out,
            process_count_before_termination,
            process_domain_stopped,
            delayed_deadline_elapsed,
            delayed_canary_absent,
            captured_candidate_bytes: captured_workspace
                .as_ref()
                .map(|capture| capture.candidate_bytes.clone()),
            captured_allowed_bytes: captured_workspace
                .as_ref()
                .map(|capture| capture.allowed_bytes.clone()),
        })
    }

    fn run_controller_death_control(&self) -> Result<bool, String> {
        let prepared = self.create_controller_death_container()?;
        let executable = std::env::current_exe()
            .map_err(|error| format!("resolve controller-death helper executable: {error}"))?;
        let helper = Command::new(executable)
            .args([
                "--controller-death-child",
                &prepared.id,
                &prepared.token,
                &prepared.run_root.to_string_lossy(),
                &self.identity.engine_endpoint,
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/tmp")
            .env("TMPDIR", "/tmp")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let helper = match helper {
            Ok(status) => status,
            Err(error) => {
                let _ = self.remove_container(&prepared.id);
                let _ = fs::remove_dir_all(&prepared.run_root);
                return Err(format!("launch controller-death helper: {error}"));
            }
        };
        if helper.code() != Some(77) {
            let _ = self.remove_container(&prepared.id);
            let _ = fs::remove_dir_all(&prepared.run_root);
            return Err(format!(
                "controller-death helper did not terminate at the crash boundary: {:?}",
                helper.code()
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.list_containers_for_token(&prepared.token)?.is_empty()
                && !prepared.run_root.exists()
            {
                thread::sleep(Duration::from_secs(3));
                let process_output = Command::new("/bin/ps")
                    .args(["-ax", "-o", "command="])
                    .output()
                    .map_err(|error| format!("read watchdog process residue: {error}"))?;
                let watchdog_remaining = String::from_utf8_lossy(&process_output.stdout)
                    .lines()
                    .any(|line| line.contains(&prepared.token));
                return Ok(!watchdog_remaining
                    && self.list_containers_for_token(&prepared.token)?.is_empty()
                    && !prepared.run_root.exists());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.remove_container(&prepared.id);
        let _ = fs::remove_dir_all(&prepared.run_root);
        Ok(false)
    }

    fn run_cleanup_vulnerable_control(&self) -> Result<bool, String> {
        let token = run_token();
        let name = format!("aigccore-local-exec-cleanup-vulnerable-{token}");
        let create = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "create".to_string(),
                "--pull".to_string(),
                "never".to_string(),
                "--name".to_string(),
                name.clone(),
                "--label".to_string(),
                format!("{LABEL_KEY}={token}"),
                "--network".to_string(),
                "none".to_string(),
                "--entrypoint".to_string(),
                "/bin/true".to_string(),
                self.identity.image_id.clone(),
            ],
            "create sacrificial cleanup-vulnerable container",
        )?;
        if !create.status.success() {
            let _ = self.remove_container(&name);
            return Err(command_failure(
                "create sacrificial cleanup-vulnerable container",
                &create,
            ));
        }
        let id = String::from_utf8_lossy(&create.stdout).trim().to_string();
        let observation = self.list_containers_for_token(&token);
        let removal = self.remove_container(&id);
        let residue_observed = !observation?.is_empty();
        removal?;
        let residue_removed = self.list_containers_for_token(&token)?.is_empty();
        Ok(residue_observed && residue_removed)
    }

    fn run_cleanup_fault_injection_control(&self) -> Result<bool, String> {
        for boundary in ["create", "inspect", "start", "output", "report"] {
            let token = run_token();
            let name = format!("aigccore-local-exec-cleanup-fault-{token}");
            let run_root = self.workspace_root.join(format!("cleanup-fault-{token}"));
            fs::create_dir(&run_root)
                .map_err(|error| format!("create cleanup fault root: {error}"))?;
            let mut guard = RunResourceGuard {
                docker: self.docker.clone(),
                engine_endpoint: self.identity.engine_endpoint.clone(),
                container_ref: name.clone(),
                token: token.clone(),
                run_root: run_root.clone(),
                cleaned: false,
            };
            let create = command_output(
                &self.docker,
                &self.identity.engine_endpoint,
                &[
                    "create".to_string(),
                    "--pull".to_string(),
                    "never".to_string(),
                    "--name".to_string(),
                    name,
                    "--label".to_string(),
                    format!("{LABEL_KEY}={token}"),
                    "--network".to_string(),
                    "none".to_string(),
                    "--entrypoint".to_string(),
                    "/usr/local/bin/node".to_string(),
                    self.identity.image_id.clone(),
                    "/input/fixture.js".to_string(),
                    RunMode::Performance.fixture_arg().to_string(),
                ],
                "create cleanup fault-injection container",
            )?;
            if !create.status.success() {
                return Err(command_failure(
                    "create cleanup fault-injection container",
                    &create,
                ));
            }
            let id = String::from_utf8_lossy(&create.stdout).trim().to_string();
            guard.container_ref.clone_from(&id);
            if boundary != "create" {
                self.inspect_container(&id)?;
            }
            if matches!(boundary, "start" | "output" | "report") {
                let start = command_output(
                    &self.docker,
                    &self.identity.engine_endpoint,
                    &["start".to_string(), id.clone()],
                    "start cleanup fault-injection container",
                )?;
                if !start.status.success() {
                    return Err(command_failure(
                        "start cleanup fault-injection container",
                        &start,
                    ));
                }
            }
            if matches!(boundary, "output" | "report") {
                let wait = command_output(
                    &self.docker,
                    &self.identity.engine_endpoint,
                    &["wait".to_string(), id.clone()],
                    "wait for cleanup fault-injection container",
                )?;
                if !wait.status.success() {
                    return Err(command_failure(
                        "wait for cleanup fault-injection container",
                        &wait,
                    ));
                }
                let logs = command_output(
                    &self.docker,
                    &self.identity.engine_endpoint,
                    &["logs".to_string(), id.clone()],
                    "read cleanup fault-injection output",
                )?;
                if !logs.status.success() {
                    return Err(command_failure(
                        "read cleanup fault-injection output",
                        &logs,
                    ));
                }
                if boundary == "report" && parse_fixture_report(&logs.stdout)?.is_none() {
                    return Err("cleanup fault-injection fixture report is missing".to_string());
                }
            }
            drop(guard);
            if !self.list_containers_for_token(&token)?.is_empty() || run_root.exists() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn run_performance_qualification(&self) -> Result<PerformanceSummaryV1, String> {
        let mut cold_samples = Vec::with_capacity(5);
        for _ in 0..5 {
            let run = self.run_container(RunMode::Performance, Duration::from_secs(10))?;
            require_success(&run, "cold cached performance run")?;
            validate_fixture_identity(
                run.report
                    .as_ref()
                    .ok_or_else(|| "cold performance run emitted no report".to_string())?,
                RunMode::Performance,
            )?;
            cold_samples.push(performance_sample(PerformancePhaseV1::ColdCached, &run));
        }

        let mut warm_samples = Vec::with_capacity(30);
        for _ in 0..30 {
            let run = self.run_container(RunMode::Performance, Duration::from_secs(10))?;
            require_success(&run, "warm performance run")?;
            validate_fixture_identity(
                run.report
                    .as_ref()
                    .ok_or_else(|| "warm performance run emitted no report".to_string())?,
                RunMode::Performance,
            )?;
            warm_samples.push(performance_sample(PerformancePhaseV1::Warm, &run));
        }

        let mut five_second_samples = Vec::with_capacity(5);
        for _ in 0..5 {
            let run = self.run_container(RunMode::Benchmark, Duration::from_secs(15))?;
            require_success(&run, "five-second overhead benchmark")?;
            validate_fixture_identity(
                run.report
                    .as_ref()
                    .ok_or_else(|| "overhead benchmark emitted no report".to_string())?,
                RunMode::Benchmark,
            )?;
            five_second_samples.push(performance_sample(
                PerformancePhaseV1::FiveSecondOverhead,
                &run,
            ));
        }

        let mut concurrency_observations = Vec::new();
        let mut concurrency_p95 = BTreeMap::new();
        let mut concurrency_samples = BTreeMap::new();
        for level in [1_u32, 2, 4] {
            let mut batch_samples = Vec::with_capacity(5);
            for _ in 0..5 {
                batch_samples.push(self.run_concurrency_batch(level)?);
            }
            let batch_p95 = percentile_95(&batch_samples);
            concurrency_p95.insert(level, batch_p95);
            concurrency_samples.insert(level, batch_samples);
        }

        let cold_elapsed: Vec<u64> = cold_samples
            .iter()
            .map(|sample| sample.elapsed_ms)
            .collect();
        let warm_elapsed: Vec<u64> = warm_samples
            .iter()
            .map(|sample| sample.elapsed_ms)
            .collect();
        let all_cleanup: Vec<u64> = cold_samples
            .iter()
            .chain(&warm_samples)
            .map(|sample| sample.cleanup_ms)
            .chain(five_second_samples.iter().map(|sample| sample.cleanup_ms))
            .collect();
        let cold_start_p95_ms = percentile_95(&cold_elapsed);
        let warm_start_p95_ms = percentile_95(&warm_elapsed);
        let cleanup_p95_ms = percentile_95(&all_cleanup);
        let cleanup_hard_max_ms = all_cleanup.iter().copied().max().unwrap_or(u64::MAX);
        let benchmark_overhead_ms: Vec<u64> = five_second_samples
            .iter()
            .map(|sample| sample.elapsed_ms.saturating_sub(5_000))
            .collect();
        let added_overhead_p95_ms = percentile_95(&benchmark_overhead_ms);
        let added_overhead_percent =
            ((added_overhead_p95_ms.saturating_mul(100) + 4_999) / 5_000) as u32;
        let peak_disk_bytes = cold_samples
            .iter()
            .chain(&warm_samples)
            .map(|sample| sample.peak_disk_bytes)
            .chain(
                five_second_samples
                    .iter()
                    .map(|sample| sample.peak_disk_bytes),
            )
            .max()
            .unwrap_or(0);
        let input_bytes = FIXTURE.len() as u64 + b"canonical-base\n".len() as u64;
        let disk_ceiling = input_bytes.saturating_mul(5) / 2 + 128 * 1024 * 1024;
        let single_p95 = concurrency_p95.get(&1).copied().unwrap_or(u64::MAX);
        let mut highest_passing_concurrency = 0;
        for level in [1_u32, 2, 4] {
            let observed = concurrency_p95.get(&level).copied().unwrap_or(u64::MAX);
            let passed = observed <= 2_000
                && observed <= single_p95.saturating_mul(2)
                && cleanup_hard_max_ms <= 5_000;
            concurrency_observations.push(ConcurrencyObservationV1 {
                concurrency: level,
                batch_wall_samples_ms: concurrency_samples
                    .remove(&level)
                    .ok_or_else(|| "concurrency samples disappeared".to_string())?,
                batch_wall_p95_ms: observed,
                passed,
            });
            if passed {
                highest_passing_concurrency = level;
            }
        }
        let gates_passed = cold_start_p95_ms <= 5_000
            && warm_start_p95_ms <= 2_000
            && cleanup_p95_ms <= 2_000
            && cleanup_hard_max_ms <= 5_000
            && added_overhead_p95_ms <= 1_000
            && added_overhead_percent <= 20
            && peak_disk_bytes <= disk_ceiling
            && highest_passing_concurrency >= 1;

        Ok(PerformanceSummaryV1 {
            cold_samples,
            warm_samples,
            five_second_samples,
            concurrency_observations,
            input_bytes,
            warm_start_p95_ms,
            cold_start_p95_ms,
            cleanup_p95_ms,
            cleanup_max_ms: cleanup_hard_max_ms,
            added_overhead_p95_ms,
            added_overhead_percent,
            peak_disk_bytes,
            disk_amplification_ceiling_bytes: disk_ceiling,
            highest_passing_concurrency,
            gates_passed,
        })
    }

    fn run_concurrency_batch(&self, level: u32) -> Result<u64, String> {
        let started = Instant::now();
        let runs = thread::scope(|scope| {
            let handles: Vec<_> = (0..level)
                .map(|_| {
                    scope
                        .spawn(|| self.run_container(RunMode::Performance, Duration::from_secs(10)))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| "concurrent performance worker panicked".to_string())?
                })
                .collect::<Result<Vec<_>, String>>()
        })?;
        for run in &runs {
            require_success(run, "concurrent performance run")?;
            validate_fixture_identity(
                run.report
                    .as_ref()
                    .ok_or_else(|| "concurrent performance run emitted no report".to_string())?,
                RunMode::Performance,
            )?;
        }
        Ok(millis(started.elapsed()))
    }

    fn create_controller_death_container(&self) -> Result<ControllerDeathContainer, String> {
        let token = run_token();
        let name = format!("aigccore-local-exec-controller-death-{token}");
        let run_root = self
            .workspace_root
            .join(format!("controller-death-{token}"));
        fs::create_dir_all(&run_root)
            .map_err(|error| format!("create controller-death staging root: {error}"))?;
        let run_root = fs::canonicalize(&run_root)
            .map_err(|error| format!("resolve controller-death staging root: {error}"))?;
        let profile = run_root.join("socket-deny-seccomp.json");
        fs::write(&profile, SECCOMP_PROFILE)
            .map_err(|error| format!("write controller-death seccomp profile: {error}"))?;
        harden_profile_staging(&run_root)?;
        let args = vec![
            "create".to_string(),
            "--pull".to_string(),
            "never".to_string(),
            "--name".to_string(),
            name.clone(),
            "--label".to_string(),
            format!("{LABEL_KEY}={token}"),
            "--hostname".to_string(),
            "aigc-fixture".to_string(),
            "--entrypoint".to_string(),
            "/usr/local/bin/node".to_string(),
            "--user".to_string(),
            "65534:65534".to_string(),
            "--workdir".to_string(),
            "/workspace".to_string(),
            "--network".to_string(),
            "none".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--security-opt".to_string(),
            format!("seccomp={}", profile.display()),
            "--pids-limit".to_string(),
            "16".to_string(),
            "--memory".to_string(),
            "268435456".to_string(),
            "--memory-swap".to_string(),
            "268435456".to_string(),
            "--cpus".to_string(),
            "0.5".to_string(),
            "--ulimit".to_string(),
            "nofile=64:64".to_string(),
            "--ulimit".to_string(),
            "fsize=8388608:8388608".to_string(),
            "--tmpfs".to_string(),
            "/workspace:rw,nosuid,nodev,size=67108864,mode=0700,uid=65534,gid=65534".to_string(),
            "--tmpfs".to_string(),
            "/tmp:rw,nosuid,nodev,noexec,size=8388608,mode=0700,uid=65534,gid=65534".to_string(),
            "--init".to_string(),
            "--read-only".to_string(),
            "--env".to_string(),
            "HOME=/workspace/home".to_string(),
            "--env".to_string(),
            "TMPDIR=/tmp".to_string(),
            "--env".to_string(),
            "LANG=C.UTF-8".to_string(),
            self.identity.image_id.clone(),
            "/input/fixture.js".to_string(),
            RunMode::ControllerDeath.fixture_arg().to_string(),
        ];
        let create = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &args,
            "create controller-death control container",
        )?;
        if !create.status.success() {
            let _ = self.remove_container(&name);
            let _ = fs::remove_dir_all(&run_root);
            return Err(command_failure(
                "create controller-death control container",
                &create,
            ));
        }
        let id = String::from_utf8_lossy(&create.stdout).trim().to_string();
        if id.len() < 12 {
            let _ = self.remove_container(&name);
            let _ = fs::remove_dir_all(&run_root);
            return Err("Docker returned an invalid controller-death container ID".to_string());
        }
        Ok(ControllerDeathContainer {
            id,
            token,
            run_root,
        })
    }

    fn copy_into(&self, source: &Path, id: &str, destination: &str) -> Result<(), String> {
        let source = format!("{}/.", source.display());
        let target = format!("{id}:{destination}");
        let output = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &["cp".to_string(), source, target],
            "stage immutable fixture without a host mount",
        )?;
        if output.status.success() {
            Ok(())
        } else {
            Err(command_failure(
                "stage immutable fixture without a host mount",
                &output,
            ))
        }
    }

    fn inspect_container(&self, id: &str) -> Result<Value, String> {
        let output = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "inspect".to_string(),
                "--format".to_string(),
                "{{json .}}".to_string(),
                id.to_string(),
            ],
            "read effective container configuration",
        )?;
        if !output.status.success() {
            return Err(command_failure(
                "read effective container configuration",
                &output,
            ));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("parse effective container configuration: {error}"))
    }

    fn container_rw_size(&self, id: &str) -> Result<u64, String> {
        let output = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "inspect".to_string(),
                "--size".to_string(),
                "--format".to_string(),
                "{{json .SizeRw}}".to_string(),
                id.to_string(),
            ],
            "read container disk amplification",
        )?;
        if !output.status.success() {
            return Err(command_failure(
                "read container disk amplification",
                &output,
            ));
        }
        serde_json::from_slice::<Option<u64>>(&output.stdout)
            .map_err(|error| format!("parse container disk amplification: {error}"))?
            .ok_or_else(|| "container disk amplification readback is unavailable".to_string())
    }

    fn container_process_count(&self, id: &str) -> Result<u32, String> {
        let output = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "top".to_string(),
                id.to_string(),
                "-eo".to_string(),
                "pid,ppid,comm".to_string(),
            ],
            "read container process-domain census",
        )?;
        if !output.status.success() {
            return Err(command_failure(
                "read container process-domain census",
                &output,
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .count() as u32)
    }

    fn container_process_domain_stopped(&self, id: &str) -> Result<bool, String> {
        let inspect = self.inspect_container(id)?;
        let running = inspect
            .pointer("/State/Running")
            .and_then(Value::as_bool)
            .ok_or_else(|| "Docker process-domain running readback is missing".to_string())?;
        let pid = inspect
            .pointer("/State/Pid")
            .and_then(Value::as_u64)
            .ok_or_else(|| "Docker process-domain PID readback is missing".to_string())?;
        let top = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "top".to_string(),
                id.to_string(),
                "-eo".to_string(),
                "pid,ppid,comm".to_string(),
            ],
            "confirm stopped container has no process-domain census",
        )?;
        Ok(!running && pid == 0 && !top.status.success())
    }

    fn remove_container(&self, id_or_name: &str) -> Result<(), String> {
        let output = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "rm".to_string(),
                "--force".to_string(),
                id_or_name.to_string(),
            ],
            "remove isolated container",
        )?;
        if output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("No such container")
        {
            Ok(())
        } else {
            Err(command_failure("remove isolated container", &output))
        }
    }

    fn remove_image(&self, id_or_tag: &str) -> Result<(), String> {
        let output = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "image".to_string(),
                "rm".to_string(),
                "--force".to_string(),
                id_or_tag.to_string(),
            ],
            "remove derived fixture image",
        )?;
        if output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("No such image")
        {
            Ok(())
        } else {
            Err(command_failure("remove derived fixture image", &output))
        }
    }

    fn list_containers_for_token(&self, token: &str) -> Result<Vec<String>, String> {
        let filter = format!("label={LABEL_KEY}={token}");
        let output = command_output(
            &self.docker,
            &self.identity.engine_endpoint,
            &[
                "ps".to_string(),
                "-aq".to_string(),
                "--filter".to_string(),
                filter,
            ],
            "read cleanup residue",
        )?;
        if !output.status.success() {
            return Err(command_failure("read cleanup residue", &output));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_string)
            .collect())
    }
}

impl LocalExecutionBackendV1 for OciZeroEgressBackendV1 {
    fn backend_id(&self) -> &'static str {
        OCI_ZERO_EGRESS_BACKEND_V1
    }

    fn execute(
        &mut self,
        request: &ExecutionRequestV1,
    ) -> aigc_core::error::CoreResult<ExecutionReceiptV1> {
        request.policy.validate()?;
        if !self.exact_request_matches(request) {
            return Err(aigc_core::error::CoreError::PolicyBlocked(
                "OCI_ZERO_EGRESS_V1 accepts only the exact embedded fixture, input, and prepared policy identity"
                    .to_string(),
            ));
        }
        let output = self
            .workspace_root
            .parent()
            .ok_or_else(|| {
                aigc_core::error::CoreError::PolicyViolationError(
                    "qualification runtime root has no program-owned parent".to_string(),
                )
            })?
            .join("qualification.json");
        let request_negative_controls_passed = self.exact_request_negative_controls(request);
        execute_qualification(self, &output, request_negative_controls_passed)
            .map_err(aigc_core::error::CoreError::PolicyViolationError)
    }
}

impl Drop for OciZeroEgressBackendV1 {
    fn drop(&mut self) {
        if let Some((tag, _)) = self.prepared_image.take() {
            let _ = Command::new(&self.docker)
                .args([
                    "--host",
                    &self.identity.engine_endpoint,
                    "image",
                    "rm",
                    "--force",
                    &tag,
                ])
                .env_clear()
                .env("HOME", "/tmp")
                .env("TMPDIR", "/tmp")
                .output();
        }
    }
}

pub fn run_controller_death_child(id: &str, token: &str, root: &str, engine_endpoint: &str) -> i32 {
    let valid_id = id.len() >= 12
        && id.len() <= 64
        && id.chars().all(|character| character.is_ascii_hexdigit());
    let valid_token = !token.is_empty()
        && token.len() <= 96
        && token
            .chars()
            .all(|character| character.is_ascii_digit() || character == '-');
    let root = PathBuf::from(root);
    let expected_leaf = format!("controller-death-{token}");
    let expected_runtime_root = std::env::current_dir()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok())
        .map(|path| path.join("target/local-execution-v1/runtime"));
    let valid_root = root.is_absolute()
        && root
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value == expected_leaf)
        && root.parent() == expected_runtime_root.as_deref();
    let endpoint_path = engine_endpoint.strip_prefix("unix://").map(Path::new);
    let valid_endpoint = endpoint_path.is_some_and(|path| path.is_absolute() && path.exists());
    #[cfg(unix)]
    let valid_endpoint = valid_endpoint
        && endpoint_path
            .and_then(|path| fs::metadata(path).ok())
            .is_some_and(|metadata| {
                use std::os::unix::fs::FileTypeExt;
                metadata.file_type().is_socket()
            });
    if !valid_id || !valid_token || !valid_root || !root.is_dir() || !valid_endpoint {
        return 64;
    }

    let docker = Path::new("/opt/homebrew/bin/docker");
    if !docker.is_file() {
        return 69;
    }
    let parent_pid = std::process::id().to_string();
    let watchdog = Command::new("/bin/sh")
        .args([
            "-c",
            r#"parent="$1"; docker="$2"; host="$3"; id="$4"; root="$5"; while kill -0 "$parent" 2>/dev/null; do /bin/sleep 0.05; done; "$docker" --host "$host" rm --force "$id" >/dev/null 2>&1; /bin/rm -rf "$root""#,
            "aigc-local-execution-watchdog",
            &parent_pid,
            docker.to_string_lossy().as_ref(),
            engine_endpoint,
            id,
            root.to_string_lossy().as_ref(),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/tmp")
        .env("TMPDIR", "/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if watchdog.is_err() {
        return 70;
    }
    thread::sleep(Duration::from_millis(100));
    let start = Command::new(docker)
        .args(["--host", engine_endpoint, "start", id])
        .env_clear()
        .env("HOME", "/tmp")
        .env("TMPDIR", "/tmp")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !start.is_ok_and(|status| status.success()) {
        return 71;
    }

    let census_deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < census_deadline {
        let census = Command::new(docker)
            .args(["--host", engine_endpoint, "top", id, "-eo", "pid,ppid,comm"])
            .env_clear()
            .env("HOME", "/tmp")
            .env("TMPDIR", "/tmp")
            .output();
        if census.is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .skip(1)
                    .filter(|line| !line.trim().is_empty())
                    .count()
                    >= 3
        }) {
            return 77;
        }
        thread::sleep(Duration::from_millis(25));
    }
    72
}

pub fn qualify_to_path(output: &Path) -> Result<ExecutionReceiptV1, String> {
    let current = fs::canonicalize(
        std::env::current_dir().map_err(|error| format!("read current directory: {error}"))?,
    )
    .map_err(|error| format!("resolve current directory: {error}"))?;
    let expected_output = current
        .join("target")
        .join("local-execution-v1")
        .join("qualification.json");
    let target_root = current.join("target");
    if fs::canonicalize(&target_root)
        .map_err(|error| format!("resolve program-owned target root: {error}"))?
        != target_root
    {
        return Err("program-owned target root must not traverse a symlink".to_string());
    }
    let output = if output.is_absolute() {
        output.to_path_buf()
    } else {
        current.join(output)
    };
    if output != expected_output {
        return Err(format!(
            "qualification output must be the program-owned path {}",
            expected_output.display()
        ));
    }
    let parent = output
        .parent()
        .ok_or_else(|| "qualification output requires a parent directory".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create qualification output directory: {error}"))?;
    if fs::canonicalize(parent)
        .map_err(|error| format!("resolve qualification output directory: {error}"))?
        != parent
    {
        return Err("qualification output directory must not traverse a symlink".to_string());
    }
    let export_path = parent.join("reviewed.patch.json");
    for stale_export in [&output, &export_path] {
        match fs::remove_file(stale_export) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove stale program-owned export {}: {error}",
                    stale_export.display()
                ));
            }
        }
    }
    let workspace = parent.join("runtime");
    let mut backend = OciZeroEgressBackendV1::discover(workspace)?;
    backend.prepare_fixture_image()?;
    let request = ExecutionRequestV1 {
        policy: backend.requested_policy(),
        fixture_bytes: FIXTURE.as_bytes().to_vec(),
        input_bytes: b"canonical-base\n".to_vec(),
    };
    backend.execute(&request).map_err(|error| error.to_string())
}

fn execute_qualification(
    backend: &mut OciZeroEgressBackendV1,
    output: &Path,
    request_negative_controls_passed: bool,
) -> Result<ExecutionReceiptV1, String> {
    let parent = output
        .parent()
        .ok_or_else(|| "qualification output requires a parent directory".to_string())?;
    let export_path = parent.join("reviewed.patch.json");
    let requested_policy = backend.requested_policy();
    requested_policy
        .validate()
        .map_err(|error| error.to_string())?;
    let performance = backend.run_performance_qualification()?;

    let safe = backend.run_container(RunMode::Safe, Duration::from_secs(15))?;
    require_success(&safe, "safe negative-control run")?;
    let vulnerable = backend.run_container(RunMode::Vulnerable, Duration::from_secs(15))?;
    require_success(&vulnerable, "deliberately vulnerable control run")?;
    let process_vulnerable =
        backend.run_container(RunMode::ProcessVulnerable, Duration::from_secs(15))?;
    require_success(
        &process_vulnerable,
        "deliberately vulnerable process control run",
    )?;
    let timeout = backend.run_container(RunMode::Timeout, Duration::from_millis(600))?;
    if !timeout.timed_out {
        return Err("forced-timeout control completed instead of timing out".to_string());
    }
    let controller_death_passed = backend.run_controller_death_control()?;
    let cleanup_vulnerable_passed = backend.run_cleanup_vulnerable_control()?;
    let cleanup_fault_injection_passed = backend.run_cleanup_fault_injection_control()?;

    let safe_report = safe
        .report
        .as_ref()
        .ok_or_else(|| "safe run emitted no trusted fixture report".to_string())?;
    let vulnerable_report = vulnerable
        .report
        .as_ref()
        .ok_or_else(|| "vulnerable run emitted no trusted fixture report".to_string())?;
    let process_vulnerable_report = process_vulnerable
        .report
        .as_ref()
        .ok_or_else(|| "process-vulnerable run emitted no trusted fixture report".to_string())?;
    validate_fixture_identity(safe_report, RunMode::Safe)?;
    validate_fixture_identity(vulnerable_report, RunMode::Vulnerable)?;
    validate_fixture_identity(process_vulnerable_report, RunMode::ProcessVulnerable)?;

    let candidate_bytes = safe
        .captured_candidate_bytes
        .clone()
        .ok_or_else(|| "trusted capture emitted no patch candidate bytes".to_string())?;
    let stdout_candidate = safe_report
        .candidate_patch_json
        .as_deref()
        .ok_or_else(|| "safe fixture report omitted its candidate sensor".to_string())?;
    if stdout_candidate.as_bytes() != candidate_bytes {
        return Err(
            "trusted captured patch candidate differs from the fixture stdout sensor".to_string(),
        );
    }
    let candidate = validate_patch_candidate(
        &candidate_bytes,
        requested_policy.export.max_patch_bytes,
        &requested_policy.filesystem.output_path_allowlist,
    )?;
    let captured_allowed = safe
        .captured_allowed_bytes
        .as_deref()
        .ok_or_else(|| "trusted capture emitted no allowed workspace bytes".to_string())?;
    if candidate.changes.len() != 1
        || candidate.changes[0].path != "allowed.txt"
        || candidate.changes[0].after.as_bytes() != captured_allowed
        || candidate.changes[0].before_sha256 != sha256_hex(b"")
    {
        return Err(
            "reviewed patch does not exactly reproduce the trusted captured workspace edit"
                .to_string(),
        );
    }
    let candidate_sha = sha256_hex(&candidate_bytes);
    let export_attacks = run_export_attack_controls(
        parent,
        &candidate_bytes,
        &candidate_sha,
        requested_policy.export.max_patch_bytes,
    )?;

    let effective_policy =
        effective_policy_from_inspect(&safe.inspect, safe_report, &backend.identity)?;
    backend.cleanup_prepared_image()?;
    let cleanup = cleanup_evidence(parent, &backend)?;
    let functional_evidence = build_functional_controls(
        request_negative_controls_passed,
        safe_report,
        vulnerable_report,
        process_vulnerable_report,
        &timeout,
        controller_death_passed,
        cleanup_vulnerable_passed,
        cleanup_fault_injection_passed,
        &candidate,
        &candidate_sha,
        &export_attacks,
        cleanup.is_zero_residue(),
        &backend.identity.controller_executable_sha256,
    )?;
    let controls = functional_evidence.controls;
    let mut observed_effects = observed_effects_from_report(safe_report, "safe");
    observed_effects.extend(observed_effects_from_report(
        vulnerable_report,
        "vulnerable",
    ));
    observed_effects.extend(observed_effects_from_report(
        process_vulnerable_report,
        "process-vulnerable",
    ));
    observed_effects.extend(functional_evidence.controller_observations);
    backend.revalidate_runtime_identity()?;
    let receipt = ExecutionReceiptV1 {
        schema_version: EXECUTION_RECEIPT_SCHEMA_V1.to_string(),
        run_id: format!("aigc-local-execution-{}", run_token()),
        result: ExecutionTerminalResultV1::Unknown,
        subject_identity: SubjectIdentityV1 {
            fixture_id: "AIGC_LOCAL_EXECUTION_FIXTURE_V1".to_string(),
            fixture_sha256: sha256_hex(FIXTURE.as_bytes()),
            input_tree_sha256: requested_policy.input_tree_sha256.clone(),
            argv: requested_policy.argv.clone(),
        },
        backend_identity: BackendIdentityV1 {
            backend_id: OCI_ZERO_EGRESS_BACKEND_V1.to_string(),
            engine_endpoint: backend.identity.engine_endpoint.clone(),
            daemon_id: backend.identity.daemon_id.clone(),
            architecture: backend.identity.architecture.clone(),
            engine_version: backend.identity.engine_version.clone(),
            runtime_version: backend.identity.runtime_version.clone(),
            kernel_version: backend.identity.kernel_version.clone(),
            image_id: backend.identity.image_id.clone(),
            enforcement_profile_sha256: seccomp_profile_digest(SECCOMP_PROFILE)?,
            controller_build: env!("CARGO_PKG_VERSION").to_string(),
            controller_executable_sha256: backend.identity.controller_executable_sha256.clone(),
        },
        requested_policy,
        effective_policy,
        observed_effects,
        controls,
        export_review: ExportReviewV1 {
            candidate_sha256: candidate_sha.clone(),
            reviewed_sha256: candidate_sha.clone(),
            exported_sha256: candidate_sha,
            reviewer_kind: "DETERMINISTIC_FIXTURE_REVIEWER_V1".to_string(),
            approved: true,
            rejected_entries: vec![],
            bytes: candidate_bytes.len() as u64,
        },
        cleanup,
        performance: Some(performance),
        evidence_ceiling: EvidenceCeilingV1 {
            enforced: vec![
                "the exact Docker create configuration recorded in effective_policy".to_string(),
                "socket and socketpair creation denied by the recorded seccomp profile".to_string(),
                "no host bind mount, daemon socket, credential, or proxy environment was supplied"
                    .to_string(),
            ],
            observed: vec![
                "the exact program-owned fixture observed permitted and denied effects".to_string(),
                "the deliberately vulnerable control observed the effects that safe controls deny"
                    .to_string(),
            ],
            unknown: vec![
                "outer Colima VM, Docker daemon, Linux kernel, and runc integrity".to_string(),
                "hostile workload resistance beyond the exact deterministic fixture".to_string(),
            ],
            excluded_claims: vec![
                "hostile-kernel or container-escape resistance".to_string(),
                "general-purpose safe execution of arbitrary repositories or credentials".to_string(),
                "portable enforcement on a different engine, image, architecture, or host"
                    .to_string(),
            ],
            maximum_claim: BACKEND_CLAIM.to_string(),
        },
        limitations: vec![
            "qualification is fixture-scoped and exact-runtime-scoped".to_string(),
            "the initial backend is experimental and is not registered as a normal product command"
                .to_string(),
            "live tmpfs capture is limited to a controller-invoked ustar stream for the exact fixture; hostile archive generation beyond the exercised parser controls is not proved".to_string(),
        ],
    };
    let mut receipt = receipt;
    receipt.result = ExecutionTerminalResultV1::Pass;
    let validation = validate_execution_receipt(&receipt);
    if validation.result != ExecutionTerminalResultV1::Pass {
        receipt.result = ExecutionTerminalResultV1::Error;
        return Err(format!(
            "receipt validation failed: {}",
            validation.reasons.join("; ")
        ));
    }
    backend.revalidate_runtime_identity()?;
    let pending_export = parent.join("reviewed.patch.pending");
    write_new_no_follow_file(
        &pending_export,
        &candidate_bytes,
        "immutable reviewed export candidate",
    )?;
    receipt.export_review.exported_sha256 = match export_reviewed_file(
        &pending_export,
        &export_path,
        &receipt.export_review.reviewed_sha256,
        receipt.requested_policy.export.max_patch_bytes,
    ) {
        Ok(digest) => digest,
        Err(error) => {
            let _ = fs::remove_file(&pending_export);
            let _ = fs::remove_file(&export_path);
            return Err(error);
        }
    };
    fs::remove_file(&pending_export)
        .map_err(|error| format!("remove immutable reviewed export candidate: {error}"))?;
    let final_validation = validate_execution_receipt(&receipt);
    if final_validation.result != ExecutionTerminalResultV1::Pass {
        let _ = fs::remove_file(&export_path);
        return Err(format!(
            "final exported-byte receipt validation failed: {}",
            final_validation.reasons.join("; ")
        ));
    }
    let bytes = match serde_json::to_vec_pretty(&receipt) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = fs::remove_file(&export_path);
            return Err(format!("serialize qualification receipt: {error}"));
        }
    };
    if let Err(error) = publish_new_file_atomically(&output, &bytes, "qualification receipt") {
        let _ = fs::remove_file(&export_path);
        let _ = fs::remove_file(&output);
        return Err(error);
    }
    Ok(receipt)
}

fn build_functional_controls(
    request_negative_controls_passed: bool,
    safe: &FixtureReport,
    vulnerable: &FixtureReport,
    process_vulnerable: &FixtureReport,
    timeout: &ContainerRun,
    controller_death_passed: bool,
    cleanup_vulnerable_passed: bool,
    cleanup_fault_injection_passed: bool,
    candidate: &PatchCandidateV1,
    candidate_sha: &str,
    export_attacks: &ExportAttackControls,
    cleanup_zero_residue: bool,
    controller_executable_sha256: &str,
) -> Result<FunctionalControlEvidence, String> {
    let safe_effect = |name: &str| {
        safe.effects
            .get(name)
            .ok_or_else(|| format!("safe fixture omitted effect {name}"))
    };
    let vulnerable_effect = |name: &str| {
        vulnerable
            .effects
            .get(name)
            .ok_or_else(|| format!("vulnerable fixture omitted effect {name}"))
    };
    let process_vulnerable_effect = |name: &str| {
        process_vulnerable
            .effects
            .get(name)
            .ok_or_else(|| format!("process-vulnerable fixture omitted effect {name}"))
    };
    let all_network_denied = [
        "loopback_ipv4",
        "loopback_ipv6",
        "ipv4_address_family",
        "ipv6_address_family",
        "unix_socket",
        "dns_protocol",
        "metadata_ipv4",
        "proxy_path",
    ]
    .iter()
    .all(|name| safe_effect(name).is_ok_and(|effect| !effect.allowed));
    let vulnerable_network_seen = [
        "loopback_ipv4",
        "loopback_ipv6",
        "ipv4_address_family",
        "ipv6_address_family",
        "unix_socket",
        "dns_protocol",
        "proxy_path",
    ]
    .iter()
    .all(|name| vulnerable_effect(name).is_ok_and(|effect| effect.allowed));
    let safe_fs_denied = [
        "immutable_input_write",
        "host_path_write",
        "sibling_write",
        "traversal_write",
        "symlink_follow_write",
        "hardlink_input",
        "device_create",
    ]
    .iter()
    .all(|name| safe_effect(name).is_ok_and(|effect| !effect.allowed));
    let vulnerable_fs_seen = ["immutable_input_write", "sibling_write", "traversal_write"]
        .iter()
        .all(|name| vulnerable_effect(name).is_ok_and(|effect| effect.allowed));
    let malicious_candidates: [&[u8]; 1] = [
        br#"{"schema_version":"AIGC_PATCH_CANDIDATE_V1","changes":[{"path":"../escape","before_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","after":"x"}]}"#.as_slice(),
    ];
    let naive_export_accepts_unsafe_candidate =
        serde_json::from_slice::<PatchCandidateV1>(malicious_candidates[0]).is_ok();
    let trusted_sensor_positive = !safe.effects.is_empty()
        && safe
            .effects
            .values()
            .all(|effect| effect.attempted && !effect.detail.is_empty());
    let simulation_probe = EvidenceOriginV1::ControlSimulation;
    let simulation_probe_constructed = simulation_probe == EvidenceOriginV1::ControlSimulation;
    let simulation_probe_rejected = !runtime_evidence_origin_is_admissible(simulation_probe);
    let timeout_process_domain_stopped = timeout.timed_out
        && !timeout.output.status.success()
        && timeout.process_count_before_termination >= 3
        && timeout.process_domain_stopped
        && timeout.delayed_deadline_elapsed
        && timeout.delayed_canary_absent;
    let reviewed_patch_is_exact = candidate.schema_version == "AIGC_PATCH_CANDIDATE_V1"
        && candidate.changes.len() == 1
        && !candidate_sha.is_empty();
    let cleanup_exact_removal = cleanup_fault_injection_passed && cleanup_zero_residue;
    let mut controls = vec![
        control(
            "BACKEND-NEGATIVE-EXACT-REQUEST",
            "NEGATIVE",
            "fixture, input, backend, image, argv, environment, and output identity mutations are rejected before execution",
            request_negative_controls_passed,
        ),
        control(
            "FS-POSITIVE-ALLOWED-WRITE",
            "POSITIVE",
            "workspace write succeeds",
            safe_effect("workspace_write")?.allowed,
        ),
        control(
            "FS-VULNERABLE-OUTSIDE-WRITE",
            "VULNERABLE",
            "omitted read-only root permits sacrificial outside-workspace writes",
            vulnerable_fs_seen,
        ),
        control(
            "FS-NEGATIVE-BOUNDARY",
            "NEGATIVE",
            "immutable, host, sibling, traversal, link, and device effects are denied",
            safe_fs_denied,
        ),
        control(
            "NETWORK-POSITIVE-RUN-OWNED-SENSORS",
            "POSITIVE",
            "run-owned IPv4, IPv6, Unix, datagram, and proxy sensors exchange nonces",
            vulnerable_network_seen,
        ),
        control(
            "NETWORK-VULNERABLE-SOCKETS",
            "VULNERABLE",
            "omitted socket profile permits run-owned loopback, IPv6, Unix, and datagram nonce paths",
            vulnerable_network_seen,
        ),
        control(
            "NETWORK-NEGATIVE-ZERO-EGRESS",
            "NEGATIVE",
            "DNS transport, IPv4, IPv6, metadata, loopback, and Unix socket attempts are denied",
            all_network_denied,
        ),
        control(
            "ENV-NEGATIVE-SYNTHETIC",
            "NEGATIVE",
            "safe environment exposes no secret or proxy key names while vulnerable control does",
            !safe_effect("proxy_or_secret_environment")?.allowed
                && vulnerable_effect("proxy_or_secret_environment")?.allowed,
        ),
        control(
            "PROCESS-POSITIVE-CHILD",
            "POSITIVE",
            "bounded normal child completes",
            safe_effect("normal_child")?.allowed,
        ),
        control(
            "PROCESS-VULNERABLE-DELAYED-CHILD",
            "VULNERABLE",
            "without a prompt timeout, a double-forked delayed child produces its canary effect",
            process_vulnerable_effect("delayed_child_without_timeout")?.allowed,
        ),
        control(
            "PROCESS-NEGATIVE-TIMEOUT",
            "NEGATIVE",
            "forced timeout kills the complete container process domain",
            timeout_process_domain_stopped,
        ),
        control(
            "PROCESS-NEGATIVE-CONTROLLER-DEATH",
            "NEGATIVE",
            "independent watchdog removes an exact immutable container after controller death",
            controller_death_passed,
        ),
        control(
            "EXPORT-POSITIVE-REVIEW",
            "POSITIVE",
            "one bounded allowlisted patch is captured and digest reviewed",
            reviewed_patch_is_exact,
        ),
        control(
            "EXPORT-VULNERABLE-NAIVE-ACCEPTANCE",
            "VULNERABLE",
            "schema-only parsing accepts a sacrificial traversal candidate when path controls are omitted",
            naive_export_accepts_unsafe_candidate,
        ),
        control(
            "EXPORT-NEGATIVE-SMUGGLING",
            "NEGATIVE",
            "absolute, traversal, and non-allowlisted special-file paths are rejected",
            export_attacks.smuggling_rejected,
        ),
        control(
            "EXPORT-NEGATIVE-TOCTOU",
            "NEGATIVE",
            "post-review mutation changes the digest and is blocked",
            export_attacks.toctou_rejected_without_output,
        ),
        control(
            "CLEANUP-POSITIVE-EXACT-REMOVAL",
            "POSITIVE",
            "exact labelled resources are removed and verified absent",
            cleanup_exact_removal,
        ),
        control(
            "CLEANUP-VULNERABLE-RESIDUE-SENSOR",
            "VULNERABLE",
            "omitted cleanup leaves a sacrificial labelled container observable before exact removal",
            cleanup_vulnerable_passed,
        ),
        control(
            "CLEANUP-NEGATIVE-ZERO-RESIDUE",
            "NEGATIVE",
            "all run-labelled containers and temporary roots are absent",
            cleanup_zero_residue,
        ),
        control(
            "EVIDENCE-POSITIVE-TRUSTED-SENSOR",
            "POSITIVE",
            "the exact embedded fixture emits attempted effects with non-empty sensor detail",
            trusted_sensor_positive,
        ),
        control(
            "EVIDENCE-VULNERABLE-SIMULATION-PROBE",
            "VULNERABLE",
            "a CONTROL_SIMULATION candidate can be constructed but is not admitted as enforcement",
            simulation_probe_constructed,
        ),
        control(
            "EVIDENCE-NEGATIVE-SIMULATION-REJECTED",
            "NEGATIVE",
            "the core runtime-evidence admissibility rule rejects CONTROL_SIMULATION",
            simulation_probe_rejected,
        ),
    ];
    bind_control_evidence(&mut controls, safe, vulnerable, process_vulnerable)?;
    let controller_observations = vec![
        controller_observation(
            "BACKEND-NEGATIVE-EXACT-REQUEST",
            request_negative_controls_passed,
            "seven exact request-identity mutations were rejected before execution".to_string(),
            controller_executable_sha256,
        ),
        controller_observation(
            "PROCESS-NEGATIVE-TIMEOUT",
            timeout_process_domain_stopped,
            format!(
                "timed_out={}, nonzero_status={}, process_count_before_termination={}, process_domain_stopped={}, delayed_deadline_elapsed={}, delayed_canary_absent={}",
                timeout.timed_out,
                !timeout.output.status.success(),
                timeout.process_count_before_termination,
                timeout.process_domain_stopped,
                timeout.delayed_deadline_elapsed,
                timeout.delayed_canary_absent
            ),
            controller_executable_sha256,
        ),
        controller_observation(
            "PROCESS-NEGATIVE-CONTROLLER-DEATH",
            controller_death_passed,
            "independent watchdog exact-ID removal and absence readback completed".to_string(),
            controller_executable_sha256,
        ),
        controller_observation(
            "EXPORT-POSITIVE-REVIEW",
            reviewed_patch_is_exact,
            format!(
                "schema={}, change_count={}, reviewed_sha256={candidate_sha}",
                candidate.schema_version,
                candidate.changes.len()
            ),
            controller_executable_sha256,
        ),
        controller_observation(
            "EXPORT-VULNERABLE-NAIVE-ACCEPTANCE",
            naive_export_accepts_unsafe_candidate,
            "schema-only parser accepted the sacrificial traversal candidate".to_string(),
            controller_executable_sha256,
        ),
        controller_observation(
            "EXPORT-NEGATIVE-SMUGGLING",
            export_attacks.smuggling_rejected,
            "unexpected regular, symlink, hardlink, FIFO, socket, device, oversize, traversal, and absolute cases were rejected".to_string(),
            controller_executable_sha256,
        ),
        controller_observation(
            "EXPORT-NEGATIVE-TOCTOU",
            export_attacks.toctou_rejected_without_output,
            "content mutation plus pending and destination symlink attacks produced no reviewed target write".to_string(),
            controller_executable_sha256,
        ),
        controller_observation(
            "CLEANUP-POSITIVE-EXACT-REMOVAL",
            cleanup_exact_removal,
            format!(
                "fault_injection_passed={cleanup_fault_injection_passed}, final_zero_residue={cleanup_zero_residue}"
            ),
            controller_executable_sha256,
        ),
        controller_observation(
            "CLEANUP-VULNERABLE-RESIDUE-SENSOR",
            cleanup_vulnerable_passed,
            "sacrificial labeled container residue was observed before exact removal".to_string(),
            controller_executable_sha256,
        ),
        controller_observation(
            "CLEANUP-NEGATIVE-ZERO-RESIDUE",
            cleanup_zero_residue,
            "all final container, image, network, volume, process, listener, mount, and runtime-root counts were zero".to_string(),
            controller_executable_sha256,
        ),
        controller_observation(
            "EVIDENCE-VULNERABLE-SIMULATION-PROBE",
            simulation_probe_constructed,
            "CONTROL_SIMULATION enum probe was constructed as a sacrificial candidate".to_string(),
            controller_executable_sha256,
        ),
        controller_observation(
            "EVIDENCE-NEGATIVE-SIMULATION-REJECTED",
            simulation_probe_rejected,
            "runtime_evidence_origin_is_admissible returned false for CONTROL_SIMULATION".to_string(),
            controller_executable_sha256,
        ),
    ];
    Ok(FunctionalControlEvidence {
        controls,
        controller_observations,
    })
}

fn bind_control_evidence(
    controls: &mut [ControlResultV1],
    safe: &FixtureReport,
    vulnerable: &FixtureReport,
    process_vulnerable: &FixtureReport,
) -> Result<(), String> {
    let fixture_ref = |prefix: &str, effect_id: &str, allowed: bool| ControlEvidenceRefV1 {
        effect_id: format!("{prefix}:{effect_id}"),
        expected_attempted: true,
        expected_allowed: allowed,
    };
    let controller_ref = |control_id: &str| ControlEvidenceRefV1 {
        effect_id: format!("controller:{control_id}"),
        expected_attempted: true,
        expected_allowed: true,
    };
    let attach = |controls: &mut [ControlResultV1],
                  control_id: &str,
                  refs: Vec<ControlEvidenceRefV1>|
     -> Result<(), String> {
        let control = controls
            .iter_mut()
            .find(|control| control.control_id == control_id)
            .ok_or_else(|| format!("control evidence target is missing: {control_id}"))?;
        control.evidence_refs = refs;
        Ok(())
    };

    attach(
        controls,
        "BACKEND-NEGATIVE-EXACT-REQUEST",
        vec![controller_ref("BACKEND-NEGATIVE-EXACT-REQUEST")],
    )?;
    attach(
        controls,
        "FS-POSITIVE-ALLOWED-WRITE",
        vec![fixture_ref("safe", "workspace_write", true)],
    )?;
    attach(
        controls,
        "FS-VULNERABLE-OUTSIDE-WRITE",
        ["immutable_input_write", "sibling_write", "traversal_write"]
            .into_iter()
            .map(|id| fixture_ref("vulnerable", id, true))
            .collect(),
    )?;
    attach(
        controls,
        "FS-NEGATIVE-BOUNDARY",
        [
            "immutable_input_write",
            "host_path_write",
            "sibling_write",
            "traversal_write",
            "symlink_follow_write",
            "hardlink_input",
            "device_create",
        ]
        .into_iter()
        .map(|id| fixture_ref("safe", id, false))
        .collect(),
    )?;
    let vulnerable_network_refs = || {
        [
            "loopback_ipv4",
            "loopback_ipv6",
            "ipv4_address_family",
            "ipv6_address_family",
            "unix_socket",
            "dns_protocol",
            "proxy_path",
        ]
        .into_iter()
        .map(|id| fixture_ref("vulnerable", id, true))
        .collect::<Vec<_>>()
    };
    attach(
        controls,
        "NETWORK-POSITIVE-RUN-OWNED-SENSORS",
        vulnerable_network_refs(),
    )?;
    attach(
        controls,
        "NETWORK-VULNERABLE-SOCKETS",
        vulnerable_network_refs(),
    )?;
    attach(
        controls,
        "NETWORK-NEGATIVE-ZERO-EGRESS",
        [
            "loopback_ipv4",
            "loopback_ipv6",
            "ipv4_address_family",
            "ipv6_address_family",
            "unix_socket",
            "dns_protocol",
            "metadata_ipv4",
            "proxy_path",
        ]
        .into_iter()
        .map(|id| fixture_ref("safe", id, false))
        .collect(),
    )?;
    attach(
        controls,
        "ENV-NEGATIVE-SYNTHETIC",
        vec![
            fixture_ref("safe", "proxy_or_secret_environment", false),
            fixture_ref("vulnerable", "proxy_or_secret_environment", true),
        ],
    )?;
    attach(
        controls,
        "PROCESS-POSITIVE-CHILD",
        vec![fixture_ref("safe", "normal_child", true)],
    )?;
    attach(
        controls,
        "PROCESS-VULNERABLE-DELAYED-CHILD",
        vec![fixture_ref(
            "process-vulnerable",
            "delayed_child_without_timeout",
            true,
        )],
    )?;

    for control_id in [
        "PROCESS-NEGATIVE-TIMEOUT",
        "PROCESS-NEGATIVE-CONTROLLER-DEATH",
        "EXPORT-POSITIVE-REVIEW",
        "EXPORT-VULNERABLE-NAIVE-ACCEPTANCE",
        "EXPORT-NEGATIVE-SMUGGLING",
        "EXPORT-NEGATIVE-TOCTOU",
        "CLEANUP-POSITIVE-EXACT-REMOVAL",
        "CLEANUP-VULNERABLE-RESIDUE-SENSOR",
        "CLEANUP-NEGATIVE-ZERO-RESIDUE",
        "EVIDENCE-VULNERABLE-SIMULATION-PROBE",
        "EVIDENCE-NEGATIVE-SIMULATION-REJECTED",
    ] {
        attach(controls, control_id, vec![controller_ref(control_id)])?;
    }

    let mut all_fixture_refs = Vec::new();
    for (prefix, report) in [
        ("safe", safe),
        ("vulnerable", vulnerable),
        ("process-vulnerable", process_vulnerable),
    ] {
        all_fixture_refs.extend(
            report
                .effects
                .iter()
                .map(|(effect_id, effect)| fixture_ref(prefix, effect_id, effect.allowed)),
        );
    }
    attach(
        controls,
        "EVIDENCE-POSITIVE-TRUSTED-SENSOR",
        all_fixture_refs,
    )?;
    Ok(())
}

fn controller_observation(
    control_id: &str,
    allowed: bool,
    detail: String,
    controller_executable_sha256: &str,
) -> EffectObservationV1 {
    EffectObservationV1 {
        effect_id: format!("controller:{control_id}"),
        effect_class: "CONTROLLER_CONTROL".to_string(),
        attempted: true,
        allowed,
        persisted: false,
        evidence_origin: EvidenceOriginV1::TrustedSensor,
        sensor_identity: format!("controller-executable:{controller_executable_sha256}"),
        detail,
    }
}

fn effective_policy_from_inspect(
    inspect: &Value,
    report: &FixtureReport,
    identity: &RuntimeIdentity,
) -> Result<EffectivePolicyV1, String> {
    let config = inspect
        .get("Config")
        .ok_or_else(|| "Docker inspect Config is missing".to_string())?;
    let host = inspect
        .get("HostConfig")
        .ok_or_else(|| "Docker inspect HostConfig is missing".to_string())?;
    let entrypoint = config
        .get("Entrypoint")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    let command = config
        .get("Cmd")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    let argv = entrypoint.chain(command).map(str::to_string).collect();
    let environment: BTreeMap<String, String> = config
        .get("Env")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|value| {
            value
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect();
    let environment_key_names = report.environment.keys().cloned().collect();
    let cap_drop = host
        .get("CapDrop")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    let security_options = host
        .get("SecurityOpt")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let enforcement_profile_sha256 = security_options
        .iter()
        .find_map(|option| option.strip_prefix("seccomp="))
        .map(seccomp_profile_digest)
        .transpose()?
        .ok_or_else(|| "Docker inspect seccomp profile readback is missing".to_string())?;
    let seccomp: Value = serde_json::from_str(SECCOMP_PROFILE)
        .map_err(|error| format!("parse embedded seccomp architecture binding: {error}"))?;
    let seccomp_architectures = seccomp
        .get("archMap")
        .and_then(Value::as_array)
        .ok_or_else(|| "embedded seccomp architecture binding is missing".to_string())?
        .iter()
        .flat_map(|entry| {
            entry
                .get("architecture")
                .and_then(Value::as_str)
                .into_iter()
                .chain(
                    entry
                        .get("subArchitectures")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str),
                )
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    if seccomp_architectures.is_empty() {
        return Err("embedded seccomp architecture binding is empty".to_string());
    }
    let tmpfs = host
        .get("Tmpfs")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(path, value)| {
            value
                .as_str()
                .map(|value| (path.clone(), value.to_string()))
        })
        .collect();
    let ulimits = host
        .get("Ulimits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| {
            Some((
                value.get("Name")?.as_str()?.to_string(),
                value.get("Hard")?.as_u64()?,
            ))
        })
        .collect();
    let host_mount_count = host
        .get("Binds")
        .and_then(Value::as_array)
        .map_or(0, |binds| binds.len() as u32);
    let host_config_mount_count = host
        .get("Mounts")
        .and_then(Value::as_array)
        .map_or(0, |mounts| mounts.len() as u32);
    let runtime_mount_count = inspect
        .get("Mounts")
        .and_then(Value::as_array)
        .map_or(0, |mounts| mounts.len() as u32);
    Ok(EffectivePolicyV1 {
        readback_complete: true,
        image_id: inspect
            .get("Image")
            .and_then(Value::as_str)
            .ok_or_else(|| "Docker inspect image ID is missing".to_string())?
            .to_string(),
        enforcement_profile_sha256,
        seccomp_architectures,
        argv,
        working_directory: json_string(config, &["WorkingDir"])?,
        user: json_string(config, &["User"])?,
        network_mode: json_string(host, &["NetworkMode"])?,
        readonly_root: host
            .get("ReadonlyRootfs")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        mount_count: host_mount_count
            .saturating_add(host_config_mount_count)
            .saturating_add(runtime_mount_count),
        host_mount_count,
        host_config_mount_count,
        runtime_mount_count,
        cap_drop,
        security_options,
        init_enabled: host.get("Init").and_then(Value::as_bool).unwrap_or(false),
        init_implementation: identity.init_implementation.clone(),
        init_version: identity.init_version.clone(),
        pid_limit: host
            .get("PidsLimit")
            .and_then(Value::as_i64)
            .unwrap_or_default() as u32,
        memory_bytes: host
            .get("Memory")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        memory_swap_bytes: host
            .get("MemorySwap")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        cpu_quota_nanos: host
            .get("NanoCpus")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        tmpfs,
        ulimits,
        environment_key_names,
        environment,
        observed_environment: report.environment.clone(),
    })
}

fn observed_effects_from_report(
    report: &FixtureReport,
    run_kind: &str,
) -> Vec<EffectObservationV1> {
    report
        .effects
        .iter()
        .map(|(id, effect)| EffectObservationV1 {
            effect_id: format!("{run_kind}:{id}"),
            effect_class: classify_effect(id).to_string(),
            attempted: effect.attempted,
            allowed: effect.allowed,
            persisted: effect.allowed && matches!(id.as_str(), "workspace_write" | "normal_child"),
            evidence_origin: EvidenceOriginV1::TrustedSensor,
            sensor_identity: format!("fixture:{}:{run_kind}", sha256_hex(FIXTURE.as_bytes())),
            detail: effect.detail.clone(),
        })
        .collect()
}

fn cleanup_evidence(
    parent: &Path,
    backend: &OciZeroEgressBackendV1,
) -> Result<CleanupEvidenceV1, String> {
    let output = command_output(
        &backend.docker,
        &backend.identity.engine_endpoint,
        &[
            "ps".to_string(),
            "-aq".to_string(),
            "--filter".to_string(),
            format!("label={LABEL_KEY}"),
        ],
        "read final program-labelled container residue",
    )?;
    if !output.status.success() {
        return Err(command_failure(
            "read final program-labelled container residue",
            &output,
        ));
    }
    let containers_remaining = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u32;
    let image_output = command_output(
        &backend.docker,
        &backend.identity.engine_endpoint,
        &[
            "image".to_string(),
            "ls".to_string(),
            "-q".to_string(),
            "--filter".to_string(),
            format!("label={LABEL_KEY}"),
        ],
        "read final program-labelled image residue",
    )?;
    if !image_output.status.success() {
        return Err(command_failure(
            "read final program-labelled image residue",
            &image_output,
        ));
    }
    let images_remaining = String::from_utf8_lossy(&image_output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u32;
    let network_output = command_output(
        &backend.docker,
        &backend.identity.engine_endpoint,
        &[
            "network".to_string(),
            "ls".to_string(),
            "-q".to_string(),
            "--filter".to_string(),
            format!("label={LABEL_KEY}"),
        ],
        "read final program-labelled network residue",
    )?;
    if !network_output.status.success() {
        return Err(command_failure(
            "read final program-labelled network residue",
            &network_output,
        ));
    }
    let networks_remaining = String::from_utf8_lossy(&network_output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u32;
    let volume_output = command_output(
        &backend.docker,
        &backend.identity.engine_endpoint,
        &[
            "volume".to_string(),
            "ls".to_string(),
            "-q".to_string(),
            "--filter".to_string(),
            format!("label={LABEL_KEY}"),
        ],
        "read final program-labelled volume residue",
    )?;
    if !volume_output.status.success() {
        return Err(command_failure(
            "read final program-labelled volume residue",
            &volume_output,
        ));
    }
    let volumes_remaining = String::from_utf8_lossy(&volume_output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u32;
    let process_output = Command::new("/bin/ps")
        .args(["-ax", "-o", "command="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/tmp")
        .env("TMPDIR", "/tmp")
        .output()
        .map_err(|error| format!("read final watchdog process residue: {error}"))?;
    if !process_output.status.success() {
        return Err(command_failure(
            "read final watchdog process residue",
            &process_output,
        ));
    }
    let processes_remaining = String::from_utf8_lossy(&process_output.stdout)
        .lines()
        .filter(|line| line.contains("aigc-local-execution-watchdog"))
        .count() as u32;
    let listener_output = Command::new("/usr/sbin/lsof")
        .args(["-nP", "-a", "-p", &std::process::id().to_string(), "-i"])
        .env_clear()
        .env("HOME", "/tmp")
        .env("TMPDIR", "/tmp")
        .output()
        .map_err(|error| format!("read final controller listener residue: {error}"))?;
    if !listener_output.status.success() && listener_output.status.code() != Some(1) {
        return Err(command_failure(
            "read final controller listener residue",
            &listener_output,
        ));
    }
    let listeners_remaining = if listener_output.status.success() {
        String::from_utf8_lossy(&listener_output.stdout)
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .count() as u32
    } else {
        0
    };
    let mount_output = Command::new("/sbin/mount")
        .env_clear()
        .env("HOME", "/tmp")
        .env("TMPDIR", "/tmp")
        .output()
        .map_err(|error| format!("read final program runtime mount residue: {error}"))?;
    if !mount_output.status.success() {
        return Err(command_failure(
            "read final program runtime mount residue",
            &mount_output,
        ));
    }
    let runtime_root = parent.join("runtime");
    let runtime_root_text = runtime_root.to_string_lossy();
    let mounts_remaining = String::from_utf8_lossy(&mount_output.stdout)
        .lines()
        .filter(|line| line.contains(LABEL_KEY) || line.contains(runtime_root_text.as_ref()))
        .count() as u32;
    let temporary_roots_remaining = fs::read_dir(&runtime_root)
        .map_err(|error| format!("enumerate final program runtime roots: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read final program runtime root entry: {error}"))?
        .len() as u32;
    Ok(CleanupEvidenceV1 {
        attempted: true,
        completed: containers_remaining == 0
            && images_remaining == 0
            && networks_remaining == 0
            && volumes_remaining == 0
            && processes_remaining == 0
            && listeners_remaining == 0
            && mounts_remaining == 0
            && temporary_roots_remaining == 0,
        containers_remaining,
        images_remaining,
        networks_remaining,
        volumes_remaining,
        processes_remaining,
        listeners_remaining,
        mounts_remaining,
        temporary_roots_remaining,
        detail: "explicit Docker label queries for containers/images/networks/volumes; host process, listener, and mount queries; controller-owned runtime-root enumeration".to_string(),
    })
}

fn tar_text(field: &[u8], label: &str) -> Result<String, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    std::str::from_utf8(&field[..end])
        .map(str::to_string)
        .map_err(|_| format!("workspace tar {label} is not UTF-8"))
}

fn tar_octal(field: &[u8], label: &str) -> Result<u64, String> {
    let text = tar_text(field, label)?;
    let trimmed = text.trim_matches(|character: char| character == '\0' || character == ' ');
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 8).map_err(|_| format!("workspace tar {label} is not valid octal"))
}

fn inspect_workspace_tar(
    archive: &[u8],
    max_patch_bytes: u64,
) -> Result<CapturedWorkspace, String> {
    if archive.is_empty() || archive.len() > 65 * 1024 * 1024 {
        return Err("workspace tar is empty or exceeds its archive ceiling".to_string());
    }
    let allowed_directories: BTreeSet<String> = ["home", "project"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let allowed_files: BTreeSet<String> = ["candidate.patch.json", "project/allowed.txt"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let mut observed_directories = BTreeSet::new();
    let mut observed_files = BTreeSet::new();
    let mut candidate_bytes = None;
    let mut allowed_bytes = None;
    let mut total_bytes = 0_u64;
    let mut offset = 0_usize;
    let mut saw_end = false;

    while offset
        .checked_add(512)
        .is_some_and(|end| end <= archive.len())
    {
        let header = &archive[offset..offset + 512];
        offset += 512;
        if header.iter().all(|byte| *byte == 0) {
            saw_end = true;
            break;
        }
        let expected_checksum = tar_octal(&header[148..156], "checksum")?;
        let observed_checksum: u64 = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    u64::from(b' ')
                } else {
                    u64::from(*byte)
                }
            })
            .sum();
        if observed_checksum != expected_checksum {
            return Err("workspace tar header checksum mismatch".to_string());
        }
        if &header[257..263] != b"ustar\0" && &header[257..263] != b"ustar " {
            return Err("workspace tar is not the required ustar format".to_string());
        }
        let name = tar_text(&header[0..100], "name")?;
        let prefix = tar_text(&header[345..500], "prefix")?;
        let raw_path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let normalized = raw_path
            .strip_prefix("./")
            .unwrap_or(&raw_path)
            .trim_end_matches('/')
            .to_string();
        let type_flag = header[156];
        let size = tar_octal(&header[124..136], "size")?;
        if normalized.is_empty() {
            if type_flag != b'5' {
                return Err("workspace tar root entry is not a directory".to_string());
            }
            continue;
        }
        let relative = Path::new(&normalized);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(format!("workspace tar unsafe path rejected: {normalized}"));
        }
        match type_flag {
            b'5' => {
                if size != 0 || !allowed_directories.contains(&normalized) {
                    return Err(format!(
                        "workspace tar unexpected directory rejected: {normalized}"
                    ));
                }
                observed_directories.insert(normalized);
            }
            0 | b'0' => {
                if !allowed_files.contains(&normalized) {
                    return Err(format!(
                        "workspace tar unexpected regular file rejected: {normalized}"
                    ));
                }
                if normalized == "candidate.patch.json" && size > max_patch_bytes {
                    return Err("workspace tar patch exceeds its byte ceiling".to_string());
                }
                total_bytes = total_bytes
                    .checked_add(size)
                    .ok_or_else(|| "workspace tar byte accounting overflowed".to_string())?;
                if total_bytes > 64 * 1024 * 1024 {
                    return Err("workspace tar exceeds its total byte ceiling".to_string());
                }
                let size = usize::try_from(size)
                    .map_err(|_| "workspace tar entry size is unsupported".to_string())?;
                let end = offset
                    .checked_add(size)
                    .ok_or_else(|| "workspace tar entry range overflowed".to_string())?;
                if end > archive.len() {
                    return Err("workspace tar entry is truncated".to_string());
                }
                let bytes = archive[offset..end].to_vec();
                if normalized == "candidate.patch.json" {
                    candidate_bytes = Some(bytes);
                } else if normalized == "project/allowed.txt" {
                    allowed_bytes = Some(bytes);
                }
                observed_files.insert(normalized);
                offset = end.div_ceil(512).saturating_mul(512);
                if offset > archive.len() {
                    return Err("workspace tar padding is truncated".to_string());
                }
            }
            b'1' => return Err(format!("workspace tar hardlink rejected: {normalized}")),
            b'2' => return Err(format!("workspace tar symlink rejected: {normalized}")),
            b'3' | b'4' | b'6' | b'7' => {
                return Err(format!(
                    "workspace tar special entry rejected: {normalized}"
                ));
            }
            other => {
                return Err(format!(
                    "workspace tar unsupported type {other} rejected: {normalized}"
                ));
            }
        }
    }
    if !saw_end || observed_directories != allowed_directories || observed_files != allowed_files {
        return Err(format!(
            "workspace tar shape mismatch: end={saw_end}, directories={observed_directories:?}, files={observed_files:?}"
        ));
    }
    Ok(CapturedWorkspace {
        candidate_bytes: candidate_bytes
            .ok_or_else(|| "workspace tar omitted the patch candidate".to_string())?,
        allowed_bytes: allowed_bytes
            .ok_or_else(|| "workspace tar omitted the allowed edit".to_string())?,
    })
}

fn inspect_captured_workspace(
    root: &Path,
    max_patch_bytes: u64,
) -> Result<CapturedWorkspace, String> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("read captured workspace root metadata: {error}"))?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err("captured workspace root is not a no-follow directory".to_string());
    }

    let allowed_directories: BTreeSet<String> = ["home", "project"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let allowed_files: BTreeSet<String> = ["candidate.patch.json", "project/allowed.txt"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let mut observed_directories = BTreeSet::new();
    let mut observed_files = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    let mut total_bytes = 0_u64;

    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("enumerate captured workspace: {error}"))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("read captured workspace entry: {error}"))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "captured workspace entry escaped its root".to_string())?;
            if relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(format!(
                    "captured workspace entry is not a safe relative path: {}",
                    relative.display()
                ));
            }
            let relative = relative
                .to_str()
                .ok_or_else(|| "captured workspace entry is not UTF-8".to_string())?
                .replace(std::path::MAIN_SEPARATOR, "/");
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("read captured entry metadata {relative}: {error}"))?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!("captured workspace symlink rejected: {relative}"));
            }
            if file_type.is_dir() {
                if !allowed_directories.contains(relative.as_str()) {
                    return Err(format!(
                        "captured workspace unexpected directory rejected: {relative}"
                    ));
                }
                observed_directories.insert(relative);
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                return Err(format!(
                    "captured workspace special entry rejected: {relative}"
                ));
            }
            #[cfg(unix)]
            if metadata.nlink() != 1 {
                return Err(format!(
                    "captured workspace hardlinked file rejected: {relative}"
                ));
            }
            if !allowed_files.contains(relative.as_str()) {
                return Err(format!(
                    "captured workspace unexpected file rejected: {relative}"
                ));
            }
            if relative == "candidate.patch.json" && metadata.len() > max_patch_bytes {
                return Err("captured patch exceeds its byte ceiling".to_string());
            }
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| "captured workspace byte accounting overflowed".to_string())?;
            if total_bytes > 64 * 1024 * 1024 {
                return Err("captured workspace exceeds its total byte ceiling".to_string());
            }
            observed_files.insert(relative);
        }
    }

    if observed_directories != allowed_directories || observed_files != allowed_files {
        return Err(format!(
            "captured workspace shape mismatch: directories={observed_directories:?}, files={observed_files:?}"
        ));
    }
    let candidate_bytes = fs::read(root.join("candidate.patch.json"))
        .map_err(|error| format!("read captured patch candidate: {error}"))?;
    let allowed_bytes = fs::read(root.join("project/allowed.txt"))
        .map_err(|error| format!("read captured allowed workspace edit: {error}"))?;
    Ok(CapturedWorkspace {
        candidate_bytes,
        allowed_bytes,
    })
}

fn write_valid_capture_tree(root: &Path, candidate_bytes: &[u8]) -> Result<(), String> {
    fs::create_dir_all(root.join("home"))
        .and_then(|_| fs::create_dir_all(root.join("project")))
        .and_then(|_| fs::write(root.join("project/allowed.txt"), b"qualified-change\n"))
        .and_then(|_| fs::write(root.join("candidate.patch.json"), candidate_bytes))
        .map_err(|error| format!("prepare sacrificial export capture tree: {error}"))
}

fn run_export_attack_controls(
    parent: &Path,
    candidate_bytes: &[u8],
    candidate_sha256: &str,
    max_patch_bytes: u64,
) -> Result<ExportAttackControls, String> {
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;

    let root = parent.join("export-attack-controls");
    let result = (|| {
        match fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("reset export attack root: {error}")),
        }
        fs::create_dir(&root).map_err(|error| format!("create export attack root: {error}"))?;

        let mut observations = Vec::new();
        let mut exercise = |name: &str,
                            mutate: &mut dyn FnMut(&Path) -> Result<(), String>|
         -> Result<(), String> {
            let case = root.join(name);
            write_valid_capture_tree(&case, candidate_bytes)?;
            mutate(&case)?;
            observations.push(inspect_captured_workspace(&case, max_patch_bytes).is_err());
            fs::remove_dir_all(&case)
                .map_err(|error| format!("remove sacrificial export case {name}: {error}"))?;
            Ok(())
        };

        exercise("unexpected-regular", &mut |case| {
            fs::write(case.join("unexpected.txt"), b"smuggled\n")
                .map_err(|error| format!("create unexpected regular file: {error}"))
        })?;
        exercise("symlink", &mut |case| {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(
                    case.join("project/allowed.txt"),
                    case.join("project/smuggled-link"),
                )
                .map_err(|error| format!("create sacrificial symlink: {error}"))
            }
            #[cfg(not(unix))]
            {
                let _ = case;
                Err("symlink control requires Unix".to_string())
            }
        })?;
        exercise("hardlink", &mut |case| {
            fs::hard_link(
                case.join("project/allowed.txt"),
                case.join("project/smuggled-hardlink"),
            )
            .map_err(|error| format!("create sacrificial hardlink: {error}"))
        })?;
        exercise("fifo", &mut |case| {
            let fifo = case.join("project/smuggled.fifo");
            let output = Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .env_clear()
                .env("HOME", "/tmp")
                .env("TMPDIR", "/tmp")
                .output()
                .map_err(|error| format!("create sacrificial FIFO: {error}"))?;
            if output.status.success() {
                Ok(())
            } else {
                Err(command_failure("create sacrificial FIFO", &output))
            }
        })?;
        exercise("socket", &mut |case| {
            #[cfg(unix)]
            {
                let socket = case.join("project/smuggled.sock");
                let current = std::env::current_dir()
                    .map_err(|error| format!("resolve Unix socket control directory: {error}"))?;
                let socket_binding = socket.strip_prefix(&current).unwrap_or(&socket);
                let _listener = UnixListener::bind(socket_binding)
                    .map_err(|error| format!("create sacrificial Unix socket: {error}"))?;
                Ok(())
            }
            #[cfg(not(unix))]
            {
                let _ = case;
                Err("Unix-socket control requires Unix".to_string())
            }
        })?;
        exercise("oversize", &mut |case| {
            fs::write(
                case.join("candidate.patch.json"),
                vec![b'x'; max_patch_bytes as usize + 1],
            )
            .map_err(|error| format!("create oversized patch candidate: {error}"))
        })?;

        let path_candidates: [&[u8]; 2] = [
            br#"{"schema_version":"AIGC_PATCH_CANDIDATE_V1","changes":[{"path":"../escape","before_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","after":"x"}]}"#,
            br#"{"schema_version":"AIGC_PATCH_CANDIDATE_V1","changes":[{"path":"/absolute","before_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","after":"x"}]}"#,
        ];
        observations.extend(path_candidates.iter().map(|bytes| {
            validate_patch_candidate(bytes, max_patch_bytes, &["allowed.txt".to_string()]).is_err()
        }));

        let device_case = root.join("device");
        write_valid_capture_tree(&device_case, candidate_bytes)?;
        let device_path = device_case.join("project/smuggled.device");
        let device_attempt = Command::new("/sbin/mknod")
            .arg(&device_path)
            .args(["c", "1", "3"])
            .env_clear()
            .env("HOME", "/tmp")
            .env("TMPDIR", "/tmp")
            .output()
            .map_err(|error| format!("attempt sacrificial device node: {error}"))?;
        observations.push(
            !device_attempt.status.success()
                || inspect_captured_workspace(&device_case, max_patch_bytes).is_err(),
        );
        fs::remove_dir_all(&device_case)
            .map_err(|error| format!("remove sacrificial device case: {error}"))?;

        let pending = root.join("pending.patch.json");
        let rejected_output = root.join("must-not-exist.patch.json");
        write_new_no_follow_file(&pending, candidate_bytes, "sacrificial reviewed candidate")?;
        fs::write(
            &pending,
            [candidate_bytes, b"\npost-review-mutation"].concat(),
        )
        .map_err(|error| format!("mutate sacrificial reviewed candidate: {error}"))?;
        let toctou_rejected_without_output = export_reviewed_file(
            &pending,
            &rejected_output,
            candidate_sha256,
            max_patch_bytes,
        )
        .is_err()
            && !rejected_output.exists();

        fs::remove_file(&pending)
            .map_err(|error| format!("remove mutated sacrificial candidate: {error}"))?;
        let external_target = root.join("external-target.txt");
        let external_bytes = b"external-unchanged\n";
        write_new_no_follow_file(
            &external_target,
            external_bytes,
            "sacrificial external target",
        )?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&external_target, &pending)
            .map_err(|error| format!("create pending-export symlink attack: {error}"))?;
        #[cfg(not(unix))]
        return Err("pending-export symlink control requires Unix".to_string());
        let pending_symlink_rejected = export_reviewed_file(
            &pending,
            &rejected_output,
            candidate_sha256,
            max_patch_bytes,
        )
        .is_err()
            && !rejected_output.exists()
            && fs::read(&external_target).is_ok_and(|bytes| bytes.as_slice() == external_bytes);
        fs::remove_file(&pending)
            .map_err(|error| format!("remove pending-export symlink attack: {error}"))?;

        write_new_no_follow_file(
            &pending,
            candidate_bytes,
            "sacrificial reviewed candidate for destination attack",
        )?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&external_target, &rejected_output)
            .map_err(|error| format!("create destination symlink attack: {error}"))?;
        #[cfg(not(unix))]
        return Err("destination symlink control requires Unix".to_string());
        let destination_symlink_rejected = export_reviewed_file(
            &pending,
            &rejected_output,
            candidate_sha256,
            max_patch_bytes,
        )
        .is_err()
            && fs::symlink_metadata(&rejected_output)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            && fs::read(&external_target).is_ok_and(|bytes| bytes.as_slice() == external_bytes);

        let toctou_rejected_without_output = toctou_rejected_without_output
            && pending_symlink_rejected
            && destination_symlink_rejected;

        Ok(ExportAttackControls {
            smuggling_rejected: observations.into_iter().all(|observed| observed),
            toctou_rejected_without_output,
        })
    })();
    let cleanup = fs::remove_dir_all(&root);
    match (result, cleanup) {
        (Ok(result), Ok(())) => Ok(result),
        (Ok(_), Err(error)) => Err(format!("remove export attack root: {error}")),
        (Err(error), _) => Err(error),
    }
}

fn export_reviewed_file(
    pending: &Path,
    output: &Path,
    reviewed_sha256: &str,
    max_patch_bytes: u64,
) -> Result<String, String> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    match fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err("reviewed export output already exists".to_string()),
        Err(error) => {
            return Err(format!(
                "read reviewed export destination metadata: {error}"
            ))
        }
    }
    let mut pending_options = OpenOptions::new();
    pending_options.read(true);
    #[cfg(target_os = "macos")]
    pending_options.custom_flags(0x0000_0100);
    #[cfg(target_os = "linux")]
    pending_options.custom_flags(0x0002_0000);
    let mut pending_file = pending_options
        .open(pending)
        .map_err(|error| format!("open pending export without following links: {error}"))?;
    let metadata = pending_file
        .metadata()
        .map_err(|error| format!("read pending export handle metadata: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max_patch_bytes {
        return Err("pending export is not a bounded no-follow regular file".to_string());
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err("pending export is hardlinked".to_string());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    pending_file
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read pending reviewed export handle: {error}"))?;
    let path_metadata = fs::symlink_metadata(pending)
        .map_err(|error| format!("re-read pending export path identity: {error}"))?;
    #[cfg(unix)]
    if path_metadata.file_type().is_symlink()
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
        || path_metadata.nlink() != 1
    {
        return Err("pending export path identity changed after open".to_string());
    }
    let digest = sha256_hex(&bytes);
    if digest != reviewed_sha256 {
        return Err("pending export digest differs from reviewed bytes".to_string());
    }
    let exported_sha256 = publish_new_file_atomically(output, &bytes, "reviewed export")?;
    if exported_sha256 != reviewed_sha256 {
        let _ = fs::remove_file(output);
        return Err("exported bytes differ from reviewed bytes".to_string());
    }
    Ok(exported_sha256)
}

fn publish_new_file_atomically(output: &Path, bytes: &[u8], label: &str) -> Result<String, String> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    match fs::symlink_metadata(output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(format!("{label} destination already exists")),
        Err(error) => return Err(format!("read {label} destination metadata: {error}")),
    }
    let output_parent = output
        .parent()
        .ok_or_else(|| format!("{label} destination has no parent"))?;
    let parent_metadata = fs::symlink_metadata(output_parent)
        .map_err(|error| format!("read {label} parent identity: {error}"))?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(format!("{label} parent is not a no-follow directory"));
    }
    let temp_output = output_parent.join(format!(".atomic-publish-{}.tmp", run_token()));
    let mut output_options = OpenOptions::new();
    output_options.write(true).create_new(true);
    #[cfg(target_os = "macos")]
    output_options.custom_flags(0x0000_0100);
    #[cfg(target_os = "linux")]
    output_options.custom_flags(0x0002_0000);
    let mut output_file = output_options
        .open(&temp_output)
        .map_err(|error| format!("atomically create {label} temp file: {error}"))?;
    let write_result = (|| {
        output_file
            .write_all(&bytes)
            .map_err(|error| format!("write {label} handle: {error}"))?;
        output_file
            .sync_all()
            .map_err(|error| format!("sync {label} handle: {error}"))?;
        let temp_metadata = output_file
            .metadata()
            .map_err(|error| format!("read {label} temp handle identity: {error}"))?;
        let temp_path_metadata = fs::symlink_metadata(&temp_output)
            .map_err(|error| format!("re-read {label} temp path identity: {error}"))?;
        let final_parent_metadata = fs::symlink_metadata(output_parent)
            .map_err(|error| format!("re-read {label} parent identity: {error}"))?;
        #[cfg(unix)]
        if temp_path_metadata.file_type().is_symlink()
            || temp_path_metadata.dev() != temp_metadata.dev()
            || temp_path_metadata.ino() != temp_metadata.ino()
            || temp_path_metadata.nlink() != 1
            || final_parent_metadata.file_type().is_symlink()
            || final_parent_metadata.dev() != parent_metadata.dev()
            || final_parent_metadata.ino() != parent_metadata.ino()
        {
            return Err(format!(
                "{label} temp or parent identity changed before rename"
            ));
        }
        match fs::symlink_metadata(output) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(format!("{label} destination appeared before rename")),
            Err(error) => {
                return Err(format!(
                    "re-read {label} destination before rename: {error}"
                ));
            }
        }
        fs::rename(&temp_output, output)
            .map_err(|error| format!("atomically publish {label}: {error}"))?;
        let parent_file = OpenOptions::new()
            .read(true)
            .open(output_parent)
            .map_err(|error| format!("open {label} parent for sync: {error}"))?;
        parent_file
            .sync_all()
            .map_err(|error| format!("sync {label} parent: {error}"))?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_output);
        return Err(error);
    }
    let mut exported_options = OpenOptions::new();
    exported_options.read(true);
    #[cfg(target_os = "macos")]
    exported_options.custom_flags(0x0000_0100);
    #[cfg(target_os = "linux")]
    exported_options.custom_flags(0x0002_0000);
    let mut exported_file = exported_options
        .open(output)
        .map_err(|error| format!("open final {label} without following links: {error}"))?;
    let exported_metadata = exported_file
        .metadata()
        .map_err(|error| format!("read final {label} handle identity: {error}"))?;
    let exported_path_metadata = fs::symlink_metadata(output)
        .map_err(|error| format!("re-read final {label} path identity: {error}"))?;
    #[cfg(unix)]
    if !exported_metadata.file_type().is_file()
        || exported_path_metadata.file_type().is_symlink()
        || exported_path_metadata.dev() != exported_metadata.dev()
        || exported_path_metadata.ino() != exported_metadata.ino()
        || exported_path_metadata.nlink() != 1
    {
        let _ = fs::remove_file(output);
        return Err(format!("final {label} path identity changed after rename"));
    }
    let mut exported = Vec::with_capacity(bytes.len());
    exported_file
        .read_to_end(&mut exported)
        .map_err(|error| format!("rehash final {label} handle: {error}"))?;
    if exported != bytes {
        let _ = fs::remove_file(output);
        return Err(format!("final {label} bytes differ from source bytes"));
    }
    Ok(sha256_hex(&exported))
}

fn write_new_no_follow_file(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(format!("{label} path already exists")),
        Err(error) => return Err(format!("read {label} path metadata: {error}")),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(target_os = "macos")]
    options.custom_flags(0x0000_0100);
    #[cfg(target_os = "linux")]
    options.custom_flags(0x0002_0000);
    let mut file = options
        .open(path)
        .map_err(|error| format!("create {label} without following links: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {label} handle: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync {label} handle: {error}"))
}

fn validate_patch_candidate(
    bytes: &[u8],
    max_bytes: u64,
    allowlist: &[String],
) -> Result<PatchCandidateV1, String> {
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err("patch candidate is empty or exceeds its byte ceiling".to_string());
    }
    let candidate: PatchCandidateV1 = serde_json::from_slice(bytes)
        .map_err(|error| format!("patch candidate is not valid JSON: {error}"))?;
    if candidate.schema_version != "AIGC_PATCH_CANDIDATE_V1"
        || candidate.changes.is_empty()
        || candidate.changes.len() > 16
    {
        return Err("patch candidate schema or change count is invalid".to_string());
    }
    let allowed: BTreeSet<&str> = allowlist.iter().map(String::as_str).collect();
    for change in &candidate.changes {
        let path = Path::new(&change.path);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || !allowed.contains(change.path.as_str())
            || change.before_sha256.len() != 64
            || !change
                .before_sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(format!("patch path or digest rejected: {}", change.path));
        }
    }
    Ok(candidate)
}

fn seccomp_profile_digest(profile: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(profile)
        .map_err(|error| format!("parse seccomp profile for identity: {error}"))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("canonicalize seccomp profile identity: {error}"))?;
    Ok(sha256_hex(&canonical))
}

fn require_success(run: &ContainerRun, label: &str) -> Result<(), String> {
    if run.timed_out || !run.output.status.success() {
        return Err(format!(
            "{label} failed: status={:?}, stdout={}, stderr={}",
            run.output.status.code(),
            String::from_utf8_lossy(&run.output.stdout),
            String::from_utf8_lossy(&run.output.stderr)
        ));
    }
    Ok(())
}

fn validate_fixture_identity(report: &FixtureReport, mode: RunMode) -> Result<(), String> {
    if report.fixture_version != "AIGC_LOCAL_EXECUTION_FIXTURE_V1"
        || report.mode != mode.fixture_arg()
    {
        return Err("fixture identity or mode mismatch".to_string());
    }
    Ok(())
}

fn parse_fixture_report(bytes: &[u8]) -> Result<Option<FixtureReport>, String> {
    for line in String::from_utf8_lossy(bytes).lines() {
        if let Some(json) = line.strip_prefix("AIGC_FIXTURE_REPORT=") {
            let report = serde_json::from_str(json)
                .map_err(|error| format!("parse trusted fixture report: {error}"))?;
            return Ok(Some(report));
        }
    }
    Ok(None)
}

fn control(id: &str, kind: &str, expected: &str, passed: bool) -> ControlResultV1 {
    ControlResultV1 {
        control_id: id.to_string(),
        control_kind: kind.to_string(),
        expected: expected.to_string(),
        observed: if passed {
            "expected observation recorded".to_string()
        } else {
            "expected observation missing or contradicted".to_string()
        },
        evidence_refs: Vec::new(),
        result: if passed {
            ExecutionTerminalResultV1::Pass
        } else {
            ExecutionTerminalResultV1::Error
        },
    }
}

fn performance_sample(phase: PerformancePhaseV1, run: &ContainerRun) -> PerformanceSampleV1 {
    PerformanceSampleV1 {
        phase,
        elapsed_ms: run.elapsed_ms,
        cleanup_ms: run.cleanup_ms,
        peak_disk_bytes: run.peak_disk_bytes,
    }
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

fn classify_effect(id: &str) -> &'static str {
    if id.contains("write") || id.contains("link") || id.contains("fifo") || id.contains("device") {
        "FILESYSTEM"
    } else if id.contains("loopback")
        || id.contains("ipv")
        || id.contains("socket")
        || id.contains("dns")
        || id.contains("metadata")
        || id.contains("proxy")
    {
        "NETWORK"
    } else if id.contains("child") {
        "PROCESS"
    } else {
        "OTHER"
    }
}

fn docker_context_host(docker: &Path) -> Result<String, String> {
    let output = Command::new(docker)
        .args([
            "context",
            "inspect",
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ])
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .output()
        .map_err(|error| format!("read Docker context endpoint: {error}"))?;
    if !output.status.success() {
        return Err(command_failure("read Docker context endpoint", &output));
    }
    let endpoint: String = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse Docker context endpoint: {error}"))?;
    let socket_path = endpoint
        .strip_prefix("unix://")
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "Docker context must resolve to an absolute Unix socket".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let metadata = fs::metadata(socket_path)
            .map_err(|error| format!("read Docker Unix socket metadata: {error}"))?;
        if !metadata.file_type().is_socket() {
            return Err("Docker context endpoint is not a Unix socket".to_string());
        }
    }
    Ok(endpoint)
}

fn json_command(
    docker: &Path,
    engine_endpoint: &str,
    args: &[&str],
    label: &str,
) -> Result<Value, String> {
    let args: Vec<String> = args.iter().map(|value| (*value).to_string()).collect();
    let output = command_output(docker, engine_endpoint, &args, label)?;
    if !output.status.success() {
        return Err(command_failure(label, &output));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{label}: invalid JSON: {error}"))
}

fn command_output(
    docker: &Path,
    engine_endpoint: &str,
    args: &[String],
    label: &str,
) -> Result<Output, String> {
    Command::new(docker)
        .args(["--host", engine_endpoint])
        .args(args)
        .env_clear()
        .env("HOME", "/tmp")
        .env("TMPDIR", "/tmp")
        .output()
        .map_err(|error| format!("{label}: {error}"))
}

fn command_failure(label: &str, output: &Output) -> String {
    format!(
        "{label} failed with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn json_string(value: &Value, path: &[&str]) -> Result<String, String> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .ok_or_else(|| format!("missing JSON field {}", path.join(".")))?;
    }
    current
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("JSON field {} is not a string", path.join(".")))
}

fn run_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{sequence}", std::process::id())
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn directory_size_no_follow(root: &Path) -> Result<u64, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut total = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("enumerate run-owned storage: {error}"))?
        {
            let entry = entry.map_err(|error| format!("read run-owned storage entry: {error}"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("read run-owned storage metadata: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "run-owned storage contains an unexpected symlink: {}",
                    entry.path().display()
                ));
            }
            if metadata.file_type().is_dir() {
                pending.push(entry.path());
            } else if metadata.file_type().is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| "run-owned storage byte accounting overflowed".to_string())?;
            } else {
                return Err(format!(
                    "run-owned storage contains an unexpected special entry: {}",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(total)
}

fn current_executable_sha256() -> Result<String, String> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve controller executable identity: {error}"))?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    options.custom_flags(0x0000_0100);
    #[cfg(target_os = "linux")]
    options.custom_flags(0x0002_0000);
    let mut file = options
        .open(&executable)
        .map_err(|error| format!("open controller executable without following links: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("read controller executable handle metadata: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("controller executable identity is not a no-follow regular file".to_string());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read controller executable handle: {error}"))?;
    let path_metadata = fs::symlink_metadata(&executable)
        .map_err(|error| format!("re-read controller executable path identity: {error}"))?;
    #[cfg(unix)]
    if path_metadata.file_type().is_symlink()
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
    {
        return Err("controller executable path identity changed during hashing".to_string());
    }
    Ok(sha256_hex(&bytes))
}

fn harden_fixture_staging(root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("harden staging root: {error}"))?;
        for path in [
            root.join("input"),
            root.join("input/fixture.js"),
            root.join("sibling/.keep"),
        ] {
            let mode = if path.is_dir() { 0o755 } else { 0o644 };
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .map_err(|error| format!("harden {}: {error}", path.display()))?;
        }
        for path in [root.join("sibling"), root.join("input/base.txt")] {
            let mode = if path.is_dir() { 0o777 } else { 0o666 };
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .map_err(|error| format!("prepare sacrificial {}: {error}", path.display()))?;
        }
    }
    Ok(())
}

fn harden_profile_staging(root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("harden profile staging root: {error}"))?;
        let profile = root.join("socket-deny-seccomp.json");
        fs::set_permissions(profile, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("harden seccomp profile: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_validator_accepts_exact_allowlisted_regular_change() {
        let bytes = br#"{"schema_version":"AIGC_PATCH_CANDIDATE_V1","changes":[{"path":"allowed.txt","before_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","after":"ok\n"}]}"#;
        let candidate =
            validate_patch_candidate(bytes, 8192, &["allowed.txt".to_string()]).expect("valid");
        assert_eq!(candidate.changes.len(), 1);
        assert_eq!(candidate.changes[0].path, "allowed.txt");
    }

    #[test]
    fn patch_validator_rejects_traversal_absolute_and_non_allowlisted_paths() {
        for path in ["../escape", "/absolute", "smuggled.fifo"] {
            let bytes = format!(
                r#"{{"schema_version":"AIGC_PATCH_CANDIDATE_V1","changes":[{{"path":"{path}","before_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","after":"x"}}]}}"#
            );
            assert!(
                validate_patch_candidate(bytes.as_bytes(), 8192, &["allowed.txt".to_string()])
                    .is_err()
            );
        }
    }

    #[test]
    fn seccomp_profile_is_restrictive_and_omits_socket_creation() {
        let profile: Value = serde_json::from_str(SECCOMP_PROFILE).expect("valid profile");
        assert_eq!(profile["defaultAction"], "SCMP_ACT_ERRNO");
        let allowed: BTreeSet<&str> = profile["syscalls"]
            .as_array()
            .expect("syscalls")
            .iter()
            .filter(|entry| entry["action"] == "SCMP_ACT_ALLOW")
            .flat_map(|entry| entry["names"].as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .collect();
        assert!(!allowed.contains("socket"));
        assert!(!allowed.contains("socketpair"));
        assert!(!allowed.contains("socketcall"));
        assert!(allowed.contains("clone"));
    }

    #[test]
    fn controller_death_helper_rejects_unscoped_arguments_before_effects() {
        assert_eq!(
            run_controller_death_child(
                "not-a-container-id",
                "1-2-3",
                "/tmp/runtime/controller-death-1-2-3",
                "tcp://127.0.0.1:2375",
            ),
            64
        );
    }

    #[test]
    fn qualification_rejects_non_program_owned_output_before_runtime_discovery() {
        let error = qualify_to_path(Path::new("/tmp/not-aigccore-qualification.json"))
            .expect_err("unscoped output must fail");
        assert!(error.contains("program-owned path"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn reviewed_and_receipt_exports_reject_symlinks_without_target_writes() {
        let root = std::env::current_dir()
            .expect("current directory")
            .join("target/local-execution-v1/unit-export")
            .join(run_token());
        fs::create_dir_all(&root).expect("create unit export root");
        let result = (|| -> Result<(), String> {
            let candidate = b"reviewed-candidate\n";
            let digest = sha256_hex(candidate);
            let pending = root.join("pending.patch.json");
            let output = root.join("reviewed.patch.json");
            let external = root.join("external.txt");
            let external_bytes = b"external-unchanged\n";
            write_new_no_follow_file(&external, external_bytes, "unit external target")?;

            std::os::unix::fs::symlink(&external, &pending)
                .map_err(|error| format!("create unit pending symlink: {error}"))?;
            if export_reviewed_file(&pending, &output, &digest, 8192).is_ok()
                || output.exists()
                || fs::read(&external).ok().as_deref() != Some(external_bytes)
            {
                return Err("pending symlink attack was not rejected cleanly".to_string());
            }
            fs::remove_file(&pending)
                .map_err(|error| format!("remove unit pending symlink: {error}"))?;

            write_new_no_follow_file(&pending, candidate, "unit reviewed candidate")?;
            std::os::unix::fs::symlink(&external, &output)
                .map_err(|error| format!("create unit destination symlink: {error}"))?;
            if export_reviewed_file(&pending, &output, &digest, 8192).is_ok()
                || !fs::symlink_metadata(&output)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                || fs::read(&external).ok().as_deref() != Some(external_bytes)
            {
                return Err("destination symlink attack was not rejected cleanly".to_string());
            }
            fs::remove_file(&output)
                .map_err(|error| format!("remove unit destination symlink: {error}"))?;

            let receipt_output = root.join("qualification.json");
            std::os::unix::fs::symlink(&external, &receipt_output)
                .map_err(|error| format!("create unit receipt destination symlink: {error}"))?;
            if publish_new_file_atomically(
                &receipt_output,
                b"{\"result\":\"PASS\"}\n",
                "unit qualification receipt",
            )
            .is_ok()
                || !fs::symlink_metadata(&receipt_output)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                || fs::read(&external).ok().as_deref() != Some(external_bytes)
            {
                return Err(
                    "receipt destination symlink attack was not rejected cleanly".to_string(),
                );
            }
            Ok(())
        })();
        let cleanup = fs::remove_dir_all(&root);
        assert!(result.is_ok(), "{}", result.unwrap_err());
        assert!(cleanup.is_ok(), "unit export cleanup failed: {cleanup:?}");
    }
}
