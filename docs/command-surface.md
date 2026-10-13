# Local Command Surface

AIGCCore exposes the governance kernel and EvidenceOS only. The app is wired in
`src-tauri/src/lib.rs`; commands live in `src-tauri/src/commands/`, and the
EvidenceOS bundle path lives in `src-tauri/src/export/`. Invocations use
`invoke(command, arguments)`; these are local IPC commands, not HTTP endpoints.
The documentation contract is `openapi/openapi.generated.json`.

## Command: `get_network_snapshot`

Purpose: Return the current command's network posture declaration. No arguments.
Implementation: `commands/network.rs`.

Response:

```json
{
  "network_mode": "OFFLINE",
  "proof_level": "OFFLINE_STRICT",
  "ui_remote_fetch_disabled": true
}
```

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
`export/mod.rs`. All six input fields are required by the serialized DTO.

Request:

```json
{
  "input": {
    "enabled_capabilities": ["Traceability"],
    "artifact_title": "Controlled evidence",
    "artifact_body": "Bounded local evidence",
    "artifact_tags_csv": "OPS,NETWORK",
    "control_families_csv": "Traceability",
    "claim_text": "The controlled bundle path was exercised."
  }
}
```

Successful response fields:

- `status`: `COMPLETED` (other export outcomes become command errors).
- `bundle_path`: path to the exported ZIP.
- `bundle_sha256`: SHA-256 of the ZIP bytes.
- `missing_control_ids`: array of controls without mapped evidence.
- `evidence_authority`: the `EVIDENCE_AUTHORITY_V1` object bound into the final
  run manifest, including producer, executable/arguments/environment/audit
  digests, timestamps, tools, effects, state scope, and permitted/prohibited
  downstream claims. See `core/src/evidence_bundle/authority.rs` for the contract.

Failures reject the invocation with a string. They do not return a demo-pack
status/error-code object. An export blocked by policy also rejects; there is no
successful response until the kernel export outcome is `COMPLETED`.

Behavior is unchanged in this scope reduction: the UI checks required non-empty
fields, while the backend retains its existing fallback text for empty title,
body, and claim. Evidence authority remains `CONTROLLED / CONTROL_SIMULATION`;
it cannot authorize live execution or production authority. Existing encryption
and model stamps are deferred to wave 2.

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
