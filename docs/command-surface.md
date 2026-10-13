# Local Command Surface

AIGCCore exposes the governance kernel and EvidenceOS only. The app is wired in
`src-tauri/src/lib.rs`; commands live in `src-tauri/src/commands/`, and the
EvidenceOS bundle path lives in `src-tauri/src/export/`. Invocations use
`invoke(command, arguments)`; these are local IPC commands, not HTTP endpoints.
The documentation contract is `openapi/openapi.generated.json`. Despite its
filename, this contract is hand-maintained; no generator is defined in the repo.
Rust DTO serialization is checked against its network schemas by a Cargo test
using Ajv (run `pnpm install --frozen-lockfile` before Rust tests).

## Command: `get_network_snapshot`

Purpose: Return the current command's network posture declaration. No arguments.
Implementation: `commands/network.rs`.

Response:

```json
{
  "network_mode": "OFFLINE",
  "proof_level": "OFFLINE_STRICT",
  "proof_source": "POLICY_DECLARATION",
  "ui_remote_fetch_disabled": true
}
```

`POLICY_DECLARATION` means this response reports the enforced offline policy;
it does not report a network measurement. This command reports policy only.
The bundle network snapshot separately records `adapter_endpoints` as objects
with `endpoint`, `is_loopback`, and an optional `validation_error`; its list is
empty when no adapter ran.

## Command: `list_control_library`

Purpose: Return EvidenceOS controls for the requested capabilities. An omitted,
null, or empty `enabledCapabilities` returns all controls. The argument key uses
Tauri's default camelCase naming; nested serialized DTO fields use snake_case.
Implementation: `commands/evidenceos.rs`.

Request:

```json
{ "enabledCapabilities": ["Traceability"] }
```

Response entries have this shape (illustrative control identifier):

```json
[
  {
    "control_id": "CTRL_EXAMPLE",
    "title": "Example control",
    "capability": "Traceability",
    "control_family": "Traceability",
    "description": "Example control description."
  }
]
```

## Command: `generate_evidenceos_bundle`

Purpose: Run EvidenceOS capability mapping and strict-citation export through
the kernel pipeline. Implementation: `commands/evidenceos.rs` delegates to
`export/mod.rs`. The six base input fields are required by the serialized DTO;
`artifact_sha256` is optional.

Request:

```json
{
  "input": {
    "enabled_capabilities": ["Traceability"],
    "artifact_title": "Controlled evidence",
    "artifact_body": "Bounded local evidence",
    "artifact_sha256": "a73e5152bf4d84940a7f0e552bbf99478b5e6882c74f89ac804cd3e4af0ad1e2",
    "artifact_tags_csv": "OPS,NETWORK",
    "control_families_csv": "Traceability",
    "claim_text": "The controlled bundle path was exercised."
  }
}
```

`artifact_sha256`, when present, must be the lowercase SHA-256 of the exact
UTF-8 bytes of `artifact_body`, including an empty body as zero bytes. The
backend rejects malformed digests and digests that do not match. If omitted,
the backend computes the digest from those exact bytes; it does not substitute
fallback text or bytes.

Invalid requests include both a malformed digest and a well-formed digest for
different payload bytes:

```json
{"input":{"enabled_capabilities":["Traceability"],"artifact_title":"Example","artifact_body":"Bounded local evidence","artifact_sha256":"demo_sha256","artifact_tags_csv":"OPS","control_families_csv":"Traceability","claim_text":"Example claim"}}
```

```json
{"input":{"enabled_capabilities":["Traceability"],"artifact_title":"Example","artifact_body":"Bounded local evidence","artifact_sha256":"0000000000000000000000000000000000000000000000000000000000000000","artifact_tags_csv":"OPS","control_families_csv":"Traceability","claim_text":"Example claim"}}
```

Both invocations reject with a command error. The first digest fails format
validation; the second does not match the payload bytes.

Successful response fields:

- `status`: `COMPLETED` (other export outcomes become command errors).
- `bundle_path`: path to the exported ZIP.
- `bundle_sha256`: SHA-256 of the ZIP bytes.
- `missing_control_ids`: array of controls without mapped evidence.
- `encryption_at_rest`: whether this exported run actually used at-rest
  encryption.
- `model_used`: whether model inference ran in this exported run.
- `evidence_authority`: the `EVIDENCE_AUTHORITY_V1` object bound into the final
  run manifest, including producer, executable/arguments/environment/audit
  digests, timestamps, tools, effects, state scope, and permitted/prohibited
  downstream claims. See `core/src/evidence_bundle/authority.rs` for the contract.

The exported archive uses `bundle_version: "1.1.0"`. Its snapshots report
`encryption_at_rest: false` with no algorithm and `model_snapshot.json: null`
when the EvidenceOS run uses neither vault encryption nor model inference;
`network_snapshot.adapter_endpoints` is empty in the same no-adapter case.
The run manifest has an empty `model_calls` array. Build metadata identifies
the package version and compiled source revision. Older archives remain
inspectable but validators label their truth status `LEGACY_UNVERIFIABLE`.
The network snapshot's `POLICY_DECLARATION` describes enforced offline policy;
the export records no network measurement or blocked request.

Failures reject the invocation with a string. They do not return a demo-pack
status/error-code object. An export blocked by policy also rejects; there is no
successful response until the kernel export outcome is `COMPLETED`.

The UI checks required non-empty fields. The backend hashes the body exactly as
received, including an empty body if invoked directly, and does not replace its
bytes with fallback content. This archive export uses
`CONTROLLED / LOCAL_ARTIFACT_EXPORT`; `CONTROL_SIMULATION` is reserved for
actual control-simulation runs. The local export records no blocked-egress
event or network measurement. Its required audit `vault_id` is a logical
namespace derived from run input identity and does not mean vault storage was
used. The authority receipt cannot authorize live execution or production
authority.

## Test-only command: `authority_integrity_probe_adapter`

Purpose: Exercise the source-owned Tauri IPC dispatcher through the production
loopback adapter policy to a run-owned socket-attempt sensor.

Availability: The command is registered only when the
`authority-integrity-test-hooks` Cargo feature is enabled. Production builds do
not enable the feature or expose this command.

Request:

```json
{
  "input": {
    "endpoint": "http://127.0.0.1:<run-owned-port>"
  }
}
```

Response:

```json
{
  "adapter_id": "authority-integrity-probe",
  "endpoint": "http://127.0.0.1:<run-owned-port>",
  "dependency_path_reached": true
}
```

The feature-enabled Rust test proves the Tauri IPC-to-adapter-dependency path.
The TypeScript invocation envelope is covered separately by
`src/ui/authorityIntegrity.spec.ts`; there is no single cross-language test from
executing frontend code through the dependency sensor, so this evidence does
not claim a frontend-to-dependency `FULL_PATH` result.
