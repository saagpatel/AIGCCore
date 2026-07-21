# 0007. Experimental fixture-scoped local execution backend

## Status

Accepted as an experimental, feature-gated qualification surface.

## Context

AIGCCore needs a source-owned way to test whether a deterministic synthetic
workload can run with materially enforced filesystem, network, process,
environment, resource, export, and cleanup boundaries. Static policy inspection
and `CONTROL_SIMULATION` events cannot establish that runtime claim.

The available local substrate is Docker under Colima. Its cached
`node:22-slim` image, seccomp support, cgroup v2, PID limits, memory limits, and
swap limits are qualification inputs, not trusted components.

## Decision

Portable `ExecutionPolicyV1`, `ExecutionReceiptV1`, validation, terminal result,
evidence ceiling, and `LocalExecutionBackendV1` contracts live in the locked
Rust core. They have no Docker or operating-system dependency.

The Tauri crate contains an opt-in `local-execution-backend-v1` feature and a
qualification binary. The binary is not registered as a normal Tauri command.
It stages only an embedded, program-owned fixture into a never-started
container, commits that staging container to an exact derived image ID, and
runs containers by immutable image ID with `--pull never`.

The safe configuration uses:

- no host mounts, non-root UID/GID `65534:65534`, a read-only root, and bounded
  tmpfs workspaces;
- Docker `network=none` plus a restrictive seccomp allowlist that denies socket
  creation, including loopback and Unix sockets;
- all capabilities dropped, no-new-privileges, bounded PID/memory/swap/CPU/file
  limits, and Docker init;
- an allowlisted synthetic environment without credentials or proxy variables;
- effective Docker inspect readback before execution;
- endpoint, daemon, architecture, engine, runtime, kernel, init, and controller
  executable identity readback at discovery and again before PASS/export;
- exact-label cleanup, RAII cleanup across injected failure boundaries, timeout
  process-domain kill, and an independent controller-death watchdog;
- live tmpfs capture through a controller-invoked ustar stream, a non-extracting
  safe archive parser, immutable patch candidate bytes, real path/type/size
  smuggling controls, no-follow descriptor identity checks, same-directory
  atomic rename with directory sync, digest parity through export, and the same
  no-follow atomic publication boundary for the final qualification receipt.

Qualification requires positive, deliberately vulnerable, and negative
controls whose machine-readable effect references exactly cover the observed
effect inventory; final receipt validation; zero named residue; five cold cached and
thirty warm samples; five five-second overhead samples; and concurrency tests at
1, 2, and 4.

The qualification routes through `LocalExecutionBackendV1::execute`. The
backend accepts only the exact prepared policy, embedded fixture bytes, and
pinned input bytes. Mutated fixture, input, backend, image, argv, environment,
or output identities return `PolicyBlocked` before substrate execution. No
normal Tauri command is registered.

## Claim ceiling

The maximum claim is limited to the exact fixture, engine, runtime, kernel,
derived image, policy readback, seccomp profile, controls, export digest, and
cleanup receipt recorded by a passing run.

The receipt does not prove the integrity of Colima, Docker, runc, the outer VM,
the Linux kernel, or the macOS host. It does not prove resistance to a hostile
workload, container escape, kernel compromise, or a different runtime identity.
`CONTROL_SIMULATION` is explicitly rejected as runtime-enforcement evidence.

## Consequences

This adds a real, bounded substrate-enforcement slice without creating a
general-purpose agent execution product surface. Qualification is expected to
fail closed when a cached image, runtime capability, effective configuration,
control, export digest, performance gate, or cleanup observation differs.

The derived image and all labeled containers are deleted after each run. The
reviewed patch and receipt are evidence outputs; no user repository, credential,
daemon socket, external destination, or host data path is exposed to the
fixture.
