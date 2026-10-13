# Annex A — Evidence Bundle v1 Specification (Locked)

**Status:** Locked; truthful bundle contract v1.1.0
**Purpose:** A portable, verifiable, versioned export package that records a Run’s inputs, enforced policies, model activity, outputs, and evaluation status. A bundle records only activity that occurred; absence is represented explicitly and is not inferred as success.

---

## A.1 Bundle goals
- Portable: single zip file.
- Verifiable: hashes + manifest + tamper-evident logs.
- Versioned: forward/backward compatibility via `bundle_version`.
- Pack-agnostic: identical structure across packs.
- Deterministic where it matters: deliverables avoid volatile timestamps; metadata may include timestamps.

---

## A.2 Naming
- `evidence_bundle_<run_id>_v1.zip` (stable filename; the embedded `bundle_version` identifies the contract revision)

---

## A.3 Directory layout (inside the zip)
```text
/BUNDLE_INFO.json
/run_manifest.json
/audit_log.ndjson
/eval_report.json
/artifact_hashes.csv
/exports/<pack_id>/
  /deliverables/
  /attachments/
    citations_map.json
    redactions_map.json
    templates_used.json
/inputs_snapshot/
  artifact_list.json
  policy_snapshot.json
  network_snapshot.json
  model_snapshot.json
```

---

## A.4 Required files (and why)
- `BUNDLE_INFO.json` — entrypoint, schema versions, build metadata.
- `run_manifest.json` — canonical record of run inputs/config/outputs.
- `audit_log.ndjson` — tamper-evident event chain for the run.
- `eval_report.json` — test suite results and gate status.
- `artifact_hashes.csv` — chain-of-custody for inputs.
- `exports/**` — deliverables + machine-readable maps.
- `inputs_snapshot/**` — frozen configuration snapshots.

---

## A.5 Determinism rules
- Deliverables SHOULD NOT include “generated at <time>” strings.
- Use `run_id` and content hashes for traceability.
- `BUNDLE_INFO.core_build` records the package version and compiled source revision; it is never a placeholder such as `dev`.
- Runtime timestamps record the clock time when determinism is disabled. When determinism is enabled, only fields explicitly normalized by Addendum A use its locked epoch/normalization rules. In particular, `citations_map.json` and `redactions_map.json` `generated_at_ms` use `LOCKED_EPOCH` in deterministic mode and actual generation time otherwise. Determinism does not authorize substituting constants for build identity or run facts.

---

## A.6 Minimum validation rules (bundle is “valid” iff)
- All required files exist.
- All listed input/output hashes verify.
- Audit log hash chain verifies (no breaks).
- Eval report exists and includes `overall_status` and named gates.
- If policy requires citations, `citations_map.json` exists and validates.
- `bundle_version` is `1.1.0` for a bundle asserting the truthful snapshot contract. Older bundle versions may be inspected, but validation reports `LEGACY_UNVERIFIABLE`; they do not pass as truthful bundles.
- Snapshot claims agree with the run manifest, network snapshot, and audit events as specified below.

---

## A.7 Schema highlights
### `BUNDLE_INFO.json`
- `bundle_version`: "1.1.0" for the truthful contract. A validator may inspect older versions but labels their truth claims `LEGACY_UNVERIFIABLE`.
- `schema_versions`: { run_manifest, eval_report, citations_map, redactions_map }
- `pack_id`, `pack_version`, `core_build`, `run_id`; `core_build` identifies the package version and compiled source revision.

### `run_manifest.json`
- `inputs[]`: { artifact_id, sha256, bytes, mime_type, logical_role }
- `outputs[]`: { path, sha256, bytes, content_type, logical_role }
- `model_calls[]`: summary (no raw prompts required); empty when no model call ran.
- `eval.gate_status`: PASS|FAIL|WARN

Declared SHA-256 values MUST be exactly 64 lowercase hexadecimal characters. A missing hash may be treated according to the selected export profile, but a present malformed value is invalid and MUST NOT be downgraded to “legacy/missing.”

### `inputs_snapshot/policy_snapshot.json`
- `encryption_at_rest`: `false` when the run's exported storage was not encrypted at rest. In this case `encryption_algorithm` is omitted.
- `encryption_at_rest`: `true` is permitted only when the exported run actually used the vault and the snapshot names an accepted algorithm. It MUST have a matching `VAULT_ENCRYPTION_STATUS` audit event with `encryption_at_rest: true`, the same algorithm, and an accepted `key_storage` value.
- Exporting plain runtime files does not establish vault encryption. `VAULT_ENCRYPTION_STATUS` MUST NOT be emitted unless the vault was used.

### `inputs_snapshot/network_snapshot.json` and `inputs_snapshot/model_snapshot.json`
- `network_snapshot.adapter_endpoints` is empty when no adapter endpoint was used. Every listed endpoint is activity evidence, not a configured example.
- `network_snapshot.proof_source` is `POLICY_DECLARATION` when `proof_level` describes the application's enforced offline policy rather than an observed network measurement. The declaration MUST NOT be described as a measured egress result.
- `model_snapshot` is JSON `null` and `run_manifest.model_calls` is empty when no model ran.
- When a model ran, `network_snapshot.adapter_endpoints` MUST contain exactly the endpoint in `model_snapshot.adapter_endpoint`, and the manifest MUST contain at least one corresponding `model_calls` entry. Conversely, an adapter endpoint recorded as run activity requires a model snapshot and corresponding model call for this contract.

### `run_manifest.json` evidence authority
- A local EvidenceOS archive export records `evidence_authority.evidence_origin: LOCAL_ARTIFACT_EXPORT`. `CONTROL_SIMULATION` is reserved for actual control-simulation runs and their own blocked-egress evidence contract.
- A local archive export MUST NOT add a fabricated blocked-egress event to satisfy control-simulation authority requirements.

### `audit_log.ndjson`
- per event: `ts_utc`, `event_type`, `run_id`, `vault_id`, `actor`, `details`, `prev_event_hash`, `event_hash`
- `vault_id` is a required audit namespace identifier. It may be logical and derived from run input identity; its presence alone does not prove vault storage use or encryption.

### `eval_report.json`
- `overall_status`: PASS|FAIL|WARN
- `tests[]`: { test_id, category, status, details }
- `gates[]`: named gate results

### `citations_map.json`
- output_path → list of { artifact_id, locator_type, locator }

### `redactions_map.json`
- artifact_id → list of redaction regions + method + reason

## A.8 Compatibility and legacy inspection
Version 1.0.0 and earlier bundles predate truthful activity snapshots. Validators SHOULD continue parsing and reporting their structural integrity and legacy checks, while returning an explicit `LEGACY_UNVERIFIABLE` truth status. They MUST NOT silently classify such bundles as truthful or apply 1.1.0 consistency semantics as if the old producer had recorded them. Version 1.1.0 is the first version whose absent encryption/model activity and policy-declared network posture have unambiguous meanings.
