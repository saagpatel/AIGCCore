# LocalExecutionBackendV1 Threat Model

## Protected assets

- User repositories, files, credentials, proxy configuration, and environment.
- Docker daemon socket, host mounts, external network destinations, and sibling
  workloads.
- Integrity of the requested execution policy, effective runtime readback,
  effect observations, reviewed patch bytes, qualification receipt, and cleanup
  result.

## Trust boundary

The controller, embedded fixture bytes, embedded seccomp profile, policy and
receipt validators, exact Docker inspect response, and run-owned loopback/Unix
socket sensors participate in the qualification.

Docker, Colima, runc, the guest kernel, the host kernel, and the hardware are
outside the proved boundary. Their identities are recorded; their integrity is
unknown.

## Threats and controls

| Threat | Control and evidence | Residual boundary |
|---|---|---|
| Input or sibling mutation | Derived image input, read-only root, isolated tmpfs workspace, non-root UID, no host mounts; vulnerable and safe filesystem controls | Runtime or kernel compromise is not covered |
| Host path access | No binds and effective `Binds` count of zero; fixture host-path attempt | A hostile runtime could falsify inspect or isolation |
| DNS, IP, metadata, loopback, Unix-socket, or proxy use | `network=none`, socket-creation-denying seccomp profile, no safe-run proxy variables, and distinct nonce-bound DNS protocol, IPv4/IPv6 family, loopback, metadata, Unix-socket, and local HTTP proxy vulnerable/safe sensors | No claim beyond the exact syscall profile, architecture, fixture, and recorded runtime |
| Credential inheritance | Allowlisted synthetic key names and a no-secret policy; fixture scans key names | Values outside the declared environment or a compromised runtime are not proved absent |
| Process escape or orphaning | Docker init, PID ceiling, container-domain timeout kill, double-forked delayed child, and independent exact-ID watchdog | Kernel/container escape resistance is excluded |
| Resource exhaustion | PID, memory, swap, CPU, tmpfs, file-size, and file-count ceilings with inspect readback | Host-level denial of service by the engine is excluded |
| Patch smuggling | Live tmpfs ustar capture; checksum/path/type/size validation without extraction; real sacrificial symlink, hardlink, FIFO, socket, device-attempt, unexpected-entry, oversize, traversal, and absolute-path controls | Arbitrary repository application and hostile archive generation beyond the exercised parser are not implemented |
| Review/export TOCTOU | Candidate bytes captured before review; no-follow single-link descriptor reads; pending/temp/parent/final identity readback; same-directory atomic rename and directory sync for patch and receipt; real content, pending-symlink, patch-destination-symlink, and receipt-destination-symlink attacks leave no target write; candidate, reviewed, and exported SHA-256 values must match | Reviewer correctness is limited to the deterministic fixture reviewer |
| Evidence substitution | Requested/effective agreement; endpoint/daemon/architecture/runtime/controller revalidation; trusted-sensor origins; exact unique observed-effect inventory; every control carries non-empty effect references whose attempted/allowed predicates are recomputed; final receipt validation | Trusted controller or sensor compromise remains unknown |
| Cleanup failure | RAII cleanup injected after create/inspect/start/output/report boundaries; exact labels and IDs; explicit container/image/network/volume/process/listener/mount/runtime-root queries; delayed watchdog scan; zero-residue receipt fields | Unlabeled substrate residue is outside the claim |

## Fail-closed rules

A missing or mismatched runtime capability, identity, policy readback, control,
digest, performance sample, or cleanup observation yields `ERROR`, `BLOCKED`, or
`UNKNOWN`; it cannot yield `PASS`. A `CONTROL_SIMULATION` observation cannot
satisfy runtime enforcement.
