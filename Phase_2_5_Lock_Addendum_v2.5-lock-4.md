# Phase 2.5 Lock Addendum (AIGC Core) — Format & Proof Hardening

**Document status:** Normative current lock addendum.
Version: **v2.5-lock-4**  
Status: **LOCKED** (applies to Phase 2+; Packs MUST NOT modify these contracts)  
Scope: Locks enforcement mechanisms and canonicalization rules to eliminate rewinds across OS/builds/Packs.

**Lock-4 delta (tightening only; no direction change):**

- Reconciles input-hash verifiability with **Evidence Bundle v1** by introducing an explicit `export_profile` for inputs (HASH_ONLY vs INCLUDE_INPUT_BYTES) without changing Annex A required paths.
- Moves any optional input-byte export under `inputs_snapshot/artifacts/` (extension within an existing directory) and makes validator behavior deterministic for both profiles.
- Updates canonicalization reference IDs from lock-3 to lock-4.

---

---

## 0) Non-Negotiable Invariants (Mechanisms)

**AIGC Core SHALL be offline-by-default.** Any network access is:

- Explicitly gated (user action + policy permission),
- Allowlisted (canonical rules),
- Proven in bundle artifacts (snapshots + audit events),
- Default-deny enforced (mechanical, not best-effort).

**AIGC Core SHALL produce a provably-auditable Evidence Bundle** for every exported run, compliant with **Evidence Bundle v1.1.0**. Older bundle versions remain inspectable and are reported as `LEGACY_UNVERIFIABLE`; they do not pass the truthful-contract validation status.

**AIGC Core SHALL be deterministic where determinism is claimed**, per Addendum A (Determinism Matrix v1).

---

## 1) Offline Enforcement Mechanism (Not Just UI)

### 1.1 Runtime Egress Model

Core implements an explicit **Egress Gate** with three enforcement layers:

**Layer A — Core Network Client Wrapper**

- All Core-initiated HTTP(S) MUST route through a single Rust `EgressClient`.
- Any attempt to create a non-Egress network client in Core code is a build violation (lint + CI gate).

**Layer B — Webview / UI Egress Rules**

- The UI (Tauri webview) MUST NOT be able to make arbitrary network calls.
- UI network calls MUST go through `tauri::invoke` into Rust, which uses `EgressClient`.
- Remote origin loading MUST be disabled (CSP + Tauri config; no remote pages).

**Layer C — Adapter Containment**

- Adapters are local HTTP only (127.0.0.1). Core SHALL reject adapter endpoints not bound to loopback.
- When Online Mode is OFF, Core SHALL prevent any Core-mediated external access and SHALL record any attempted egress as blocked.
- Core SHALL NOT claim “adapter egress is prevented” unless an OS-level firewall profile is active (proof level below).

### 1.2 Allowlist Semantics (Canonical)

Allowlist entries canonicalize to:

- `scheme` ∈ {`https`, `http`} (default: `https`)
- `host` (ASCII; punycode normalized)
- `port` (explicit; default 443 for https, 80 for http)
- `path_prefix` (optional; normalized, no `..`)
- `purpose` (enum string: `updates`, `license`, `pack_optional_fetch`, etc.)
- `policy_pack_id` + `policy_pack_version` authorizing it

**Rule match:** `scheme + host + port` MUST match; `path_prefix` MUST match if present.

### 1.3 Online Mode Proof Levels

Core records `proof_level` in `inputs_snapshot/network_snapshot.json`:

- `OFFLINE_STRICT`
- `ONLINE_ALLOWLIST_CORE_ONLY`
- `ONLINE_ALLOWLIST_WITH_OS_FIREWALL_PROFILE`

Core MUST NOT claim a stronger proof level than it can enforce.

If the snapshot describes an enforced application policy and no network probe was run, it MUST set `proof_source: POLICY_DECLARATION`. That value means the proof level is derived from policy; it is not a measurement of attempted or successful network traffic. A measured source may be recorded only when a measurement actually occurred.

### 1.4 Required Evidence (Bundle)

**Default behavior (LOCKED):**

- New vaults and new runs default to `network_mode=OFFLINE` with `proof_level=OFFLINE_STRICT`.
- Switching to `ONLINE_ALLOWLISTED` MUST be a **user** action (actor=`user`) with explicit acknowledgement.

Every exported run MUST include:

- `inputs_snapshot/network_snapshot.json` with:
  - `network_mode`
  - `proof_level`
  - `proof_source` (`POLICY_DECLARATION` when derived from enforced policy rather than measurement)
  - `allowlist` (canonical entries; sorted)
  - `ui_remote_fetch_disabled: true/false`
  - `adapter_endpoints` (with loopback validation results)
- Audit events:
  - `NETWORK_MODE_SET`
  - `ALLOWLIST_UPDATED` (with allowlist hash)
  - `EGRESS_REQUEST_ALLOWED` / `EGRESS_REQUEST_BLOCKED`

An adapter endpoint array is empty when the run used no adapter. Network posture defaults or application policy do not establish that an adapter was used.

### 1.5 Truthful activity snapshots (LOCKED for bundle v1.1.0)

- Bundle exporters MUST derive each snapshot field from the run, enforced policy, or build provenance. Examples and defaults MUST NOT be emitted as evidence of runtime activity.
- `policy_snapshot.encryption_at_rest` is `false` when exported run data was not protected by the vault; `encryption_algorithm` is omitted in that state. A `true` value requires actual vault use, an accepted algorithm, and a matching `VAULT_ENCRYPTION_STATUS` audit event whose `encryption_at_rest`, `algorithm`, and accepted `key_storage` agree with the snapshot. The exporter MUST emit that event only when the vault was used.
- `model_snapshot.json` is JSON `null` and `run_manifest.model_calls` is empty when inference did not run. If inference ran, `network_snapshot.adapter_endpoints` MUST contain exactly the endpoint in `model_snapshot.adapter_endpoint`, and at least one model call MUST be recorded. An adapter endpoint in the snapshot is run evidence and therefore requires a matching model snapshot and model call.
- A declared SHA-256 is valid only when it is 64 lowercase hexadecimal characters. Missing values may follow the export profile's missing-hash semantics; malformed declared hashes are invalid and cannot be treated as legacy/missing.
- `BUNDLE_INFO.core_build` identifies the package version and compiled source revision. It MUST NOT use placeholder build identifiers such as `dev`.
- `bundle_version: "1.1.0"` identifies the truthful snapshot contract. Validators may inspect bundles at earlier versions but MUST report their truth status as `LEGACY_UNVERIFIABLE`, never as truthful.
- A local EvidenceOS archive export MUST use `evidence_authority.evidence_origin: LOCAL_ARTIFACT_EXPORT`. `CONTROL_SIMULATION` remains for actual control-simulation runs and retains its blocked-egress evidence requirements. A local archive export MUST NOT fabricate a blocked-egress event to satisfy that simulation contract.
- The required audit `vault_id` may be a logical namespace derived from the run input fingerprint. It identifies the audit namespace only and MUST NOT be treated as evidence of vault storage use or encryption.

---

## 2) Audit Log Hash-Chain Canonicalization (Tamper-Evident Baseline)

### 2.1 Hash Algorithm

- `event_hash` = `SHA-256(canonical_event_bytes)`
- `prev_event_hash` = prior event’s `event_hash` (or 64 zeros for first event)

### 2.2 Canonical Event Serialization (LOCKED)

**Canonicalization ID:** `PHASE_2_5_LOCK_ADDENDUM_V2_5_LOCK_4`

Canonical bytes are:

- UTF-8 JSON (no BOM)
- Keys sorted lexicographically
- No insignificant whitespace
- Strings JSON-escaped per RFC 8259
- Numbers:
  - integers only (no floats); base-10; no leading zeros

### 2.3 Event Envelope (Minimum Required Fields)

To remain compatible with Annex A, each audit event MUST include at minimum:

- `ts_utc` (RFC3339 UTC string, e.g. `2026-02-10T21:05:33.123Z`)
- `event_type` (string)
- `run_id` (string)
- `vault_id` (string)
- `actor` (`system` | `user`)
- `details` (object; may be empty)
- `prev_event_hash` (hex 64)
- `event_hash` (hex 64)

`vault_id` identifies the event's logical audit namespace. It does not assert that the vault storage subsystem was used; encryption claims follow the separate vault-status requirements in §1.5.

**Additional fields are allowed ONLY under** `details.meta` (e.g., `details.meta.event_id`, `details.meta.session_id`).

### 2.4 Verification Rule (Bundle Validator MUST enforce)

Recompute `event_hash` using canonicalization rules above and ensure:

- matches stored `event_hash`
- matches next line’s `prev_event_hash`
- required keys exist on every line

---

## 3) Deterministic Export Rules (Including PDF) — LOCKED

Determinism requirements are governed by **Addendum A (Determinism Matrix v1)**.

### 3.1 Zip Packaging Determinism

When producing `evidence_bundle_<run_id>_v1.zip`, Core SHALL:

- Sort files by full path lexicographically
- Set per-file mtime to `0` (Unix epoch) in zip metadata
- Use fixed compression method and fixed compression level
- Normalize line endings to `\n` for Core-authored text artifacts

### 3.2 Stable IDs / “No now() Drift”

If determinism is enabled:

- `run_id` MUST be derived from `manifest_inputs_fingerprint` (per Addendum A)
- Deliverables MUST NOT include wall-clock timestamps or random IDs
- Any `generated_at_*` fields that appear in **D2** artifacts MUST be set to `LOCKED_EPOCH` (defined below)

**run_id derivation (LOCKED):**

- If `run_manifest.json.determinism.enabled == true`:
  - `run_id = "r_" + manifest_inputs_fingerprint[0:32]` (hex prefix, 32 chars)
- Else (determinism disabled):
  - `run_id = "r_" + ULID` (26 chars, Crockford Base32)

**LOCKED_EPOCH (LOCKED):**

- `LOCKED_EPOCH = 0` (milliseconds since Unix epoch)

### 3.3 PDF Determinism

If deterministic PDFs are enabled:

- `CreationDate` and `ModDate` fixed to epoch
- Document IDs derived from `run_id`
- Fonts pinned; metadata stripped
  If platform is not capable, policy must downgrade to content-deterministic PDF (D1) and record downgrade.

---

## 4) Evidence Bundle v1 Path Lock (Deliverables vs Attachments)

Per Annex A:

- Human-readable deliverables go under: `exports/<pack_id>/deliverables/`
- Machine-readable maps go under: `exports/<pack_id>/attachments/`
  - `citations_map.json`
  - `redactions_map.json`
  - `templates_used.json`

Core MUST write these maps to `attachments/` (not `deliverables/`).

### 4.1 Input Export Profile (LOCKED)

Evidence Bundle v1 is locked (Annex A). To support privacy-first exports while remaining auditable, Core MUST record an explicit input export profile in `inputs_snapshot/policy_snapshot.json`:

- `export_profile.inputs` = `HASH_ONLY` | `INCLUDE_INPUT_BYTES`

**Default:** `HASH_ONLY` unless the user explicitly chooses otherwise at export time.

#### 4.1.1 `HASH_ONLY` (default)

- Bundle MUST include **input hashes and metadata** via:
  - `run_manifest.json.inputs[]` (sha256, bytes, mime_type, logical_role)
  - `artifact_hashes.csv` rows for inputs (see §4.2)
  - `audit_log.ndjson` ingest events anchoring `artifact_id`, `sha256`, `bytes`
- Bundle MUST NOT include raw input bytes.
- Validation MUST prove **internal consistency + tamper-evidence** (manifest ↔ hashes ↔ audit chain). Recomputing input hashes from bytes is not applicable.

#### 4.1.2 `INCLUDE_INPUT_BYTES` (opt-in)

- Bundle MUST include raw bytes for every input artifact under an **extension path within Annex A’s existing directory**:
  - `inputs_snapshot/artifacts/<artifact_id>/bytes`
  - `inputs_snapshot/artifacts/<artifact_id>/meta.json` (optional; if present must be deterministic JSON)
- Validation MUST recompute SHA-256 of each included input and match `artifact_hashes.csv` + `run_manifest.json`.

**Rules (both profiles):**

- Input artifacts MUST correspond 1:1 to `run_manifest.json.inputs[]`.
- If a policy pack forbids retention of certain inputs, Core MUST not store those bytes at rest; export MUST remain `HASH_ONLY`.

### 4.2 `artifact_hashes.csv` Schema + Ordering (LOCKED)

`artifact_hashes.csv` is the recomputation anchor. It MUST be a UTF-8 CSV with header row and the columns:

`artifact_id, bundle_rel_path, sha256, bytes, content_type, logical_role`

Where:

- `artifact_id`:
  - For input artifacts: the vault artifact ID (e.g., `a_01H...`)
  - For export files: `o:` + `<bundle_rel_path>` (e.g., `o:exports/evidenceos/deliverables/report.md`)
- `bundle_rel_path`: path inside the zip (no leading slash)
- `sha256`: lowercase hex, 64 chars, SHA-256 of file bytes at `bundle_rel_path`
- `bytes`: integer size
- `content_type`: MIME type string
- `logical_role`: `INPUT` | `DELIVERABLE` | `ATTACHMENT`

**Row order (LOCKED):**

- Sort by `artifact_id` (lex) then `bundle_rel_path` (lex).

### 4.3 `templates_used.json` Schema (LOCKED: `TEMPLATES_USED_V1`)

Each pack export MUST include `exports/<pack_id>/attachments/templates_used.json`:

```json
{
  "schema_version": "TEMPLATES_USED_V1",
  "pack_id": "<pack_id>",
  "pack_version": "<pack_version>",
  "run_id": "<run_id>",
  "templates": [
    {
      "template_id": "<string>",
      "template_version": "<string>",
      "output_paths": ["exports/<pack_id>/deliverables/<file>"],
      "render_engine": { "name": "core_template_renderer", "version": "<string>" }
    }
  ]
}
```

**Ordering (LOCKED):**

- `templates[]` sorted by `template_id`, then `template_version`.
- `output_paths[]` sorted lexicographically.

---

## 5) Citation Locator Schema (LOCKED: `LOCATOR_SCHEMA_V1`)

Citations MUST be stored at:

- `exports/<pack_id>/attachments/citations_map.json`

Strict policy requires “no citation, no claim.”

### 5.1 `citations_map.json` Envelope (LOCKED)

```json
{
  "schema_version": "LOCATOR_SCHEMA_V1",
  "pack_id": "<pack_id>",
  "pack_version": "<pack_version>",
  "run_id": "<run_id>",
  "generated_at_ms": 0,
  "claims": [
    {
      "claim_id": "C0001",
      "output_path": "exports/<pack_id>/deliverables/<file>.md",
      "output_claim_locator": {
        "locator_type": "TEXT_LINE_RANGE_V1",
        "locator": { "start_line": 1, "end_line": 3 }
      },
      "citations": [
        {
          "citation_index": 0,
          "artifact_id": "<artifact_id>",
          "locator_type": "PDF_TEXT_SPAN_V1",
          "locator": {}
        }
      ]
    }
  ]
}
```

**generated_at_ms rule (LOCKED):**

- If determinism is enabled, `generated_at_ms` MUST be `LOCKED_EPOCH` as defined by Addendum A.
- If determinism is disabled, `generated_at_ms` MUST be the actual wall-clock generation time.
- Any literal `0` in a schema/example is an illustrative normalized epoch value only; it is not a permitted nondeterministic runtime timestamp.

**Ordering (LOCKED):**

- `claims[]` sorted by `claim_id` lexicographically.
- `citations[]` sorted by `citation_index` ascending.

### 5.2 “Claim” Definition + Claim IDs (LOCKED)

A **claim** is a discrete, citable unit in a deliverable (sentence, bullet, or short paragraph) that asserts a fact or conclusion.

**Claim marking (LOCKED for Strict):**

- All Strict-exportable deliverables MUST include explicit claim markers in the Markdown:
  - `<!-- CLAIM:C0001 -->` (HTML comment) immediately preceding the claim text.
- Claim IDs MUST be unique per output file and stable within a run.
- Default claim numbering rule: first claim is `C0001`, then `C0002`, etc in file order.

**Validator expectation (Strict):**

- Every `<!-- CLAIM:... -->` marker MUST have ≥1 citation entry in `citations_map.json`.

### 5.3 Locator Types (LOCKED ENUM)

Each citation MUST use one locator type:

**PDF text span**

- `locator_type`: `PDF_TEXT_SPAN_V1`
- `locator`:
  - `page_index` (0-based int)
  - `start_char` (int)
  - `end_char` (int)
  - `text_sha256` (hex sha256 of normalized full-page text per Addendum A §7)

**PDF bounding box (optional VLM-backed)**

- `locator_type`: `PDF_BBOX_V1`
- `locator`:
  - `page_index` (0-based int)
  - `bbox` `{ "x": 0.0, "y": 0.0, "w": 0.0, "h": 0.0, "coords": "REL_0_1" }`

**Plain text line range**

- `locator_type`: `TEXT_LINE_RANGE_V1`
- `locator`:
  - `start_line` (1-based int)
  - `end_line` (1-based int)
  - `text_sha256` (hex sha256 of normalized full text)

**Audio time range**

- `locator_type`: `AUDIO_TIME_RANGE_V1`
- `locator`:
  - `start_ms` (int)
  - `end_ms` (int)
  - `transcript_sha256` (hex sha256 of normalized transcript)

**Image bounding box**

- `locator_type`: `IMAGE_BBOX_V1`
- `locator`:
  - `bbox` `{ "x": 0.0, "y": 0.0, "w": 0.0, "h": 0.0, "coords": "REL_0_1" }`

---

## 6) Redaction Schema + Export Gate (LOCKED: `REDACTION_SCHEMA_V1`)

Redaction map MUST be stored at:

- `exports/<pack_id>/attachments/redactions_map.json`

### 6.1 `redactions_map.json` Envelope (LOCKED)

**generated_at_ms rule (LOCKED):**

- If determinism is enabled, `generated_at_ms` MUST be `LOCKED_EPOCH` as defined by Addendum A.
- If determinism is disabled, `generated_at_ms` MUST be the actual wall-clock generation time.
- Any literal `0` in a schema/example is an illustrative normalized epoch value only; it is not a permitted nondeterministic runtime timestamp.

```json
{
  "schema_version": "REDACTION_SCHEMA_V1",
  "pack_id": "<pack_id>",
  "pack_version": "<pack_version>",
  "run_id": "<run_id>",
  "generated_at_ms": 0,
  "artifacts": [
    {
      "artifact_id": "<artifact_id>",
      "redactions": [
        {
          "redaction_id": "R0001",
          "redaction_type": "TEXT_SPAN",
          "region": {},
          "method": "MASK",
          "reason": "PII",
          "policy_rule_id": "<string>"
        }
      ]
    }
  ]
}
```

**Ordering (LOCKED):**

- `artifacts[]` sorted by `artifact_id` lexicographically.
- `redactions[]` sorted by `redaction_id` ascending.

### 6.2 Region Shapes (LOCKED)

`redaction_type=TEXT_SPAN`:

- `region`:
  - `page_index` (optional int; use for PDFs)
  - `start_char` (int)
  - `end_char` (int)
  - `text_sha256` (hex sha256 of normalized text for the addressed unit: page text for PDFs; full text otherwise)

`redaction_type=IMAGE_BBOX`:

- `region`:
  - `page_index` (optional int)
  - `bbox` `{ "x": 0.0, "y": 0.0, "w": 0.0, "h": 0.0, "coords": "REL_0_1" }`

### 6.3 Export Gate (LOCKED)

If policy requires redaction:

- Export MUST be blocked until required redactions are applied and validated.
- Validation rule (deterministic):
  - For each citation in `citations_map.json`, if the cited artifact is classified `Restricted` or tagged with any of `PII|PHI|PCI|SECRET` (from `inputs_snapshot/artifact_list.json`), then a redaction MUST exist whose region fully covers that cited locator region.
  - The audit event `REDACTION_VALIDATION_RESULT` MUST report `missing_required_redactions == 0` on PASS.

---

## 7) Model Identity Pinning Rules (LOCKED; aligned to Annex B v1)

Core records pinning in `inputs_snapshot/model_snapshot.json`.

For bundle v1.1.0, `model_snapshot.json` is JSON `null` when no model ran. Pinning levels below apply only to recorded model activity; an absent model is not a `NAME_ONLY` model and does not assert adapter use.

Pinning levels (locked enum):

- `CRYPTO_PINNED` (best)
- `VERSION_PINNED`
- `NAME_ONLY` (weakest)

**Pinning classification (LOCKED):**

- `CRYPTO_PINNED` iff adapter capabilities reports `model_sha256` for the selected `model_id` (Annex B: `GET /v1/capabilities` → `models[].model_sha256?`) AND Core records `adapter_id` + `adapter_version`.
- `VERSION_PINNED` iff Core records `adapter_id`, `adapter_version`, and `model_id`, but `model_sha256` is absent.
- `NAME_ONLY` otherwise.

Policy enforcement (LOCKED):

- Strict: `pinning_level ∈ {CRYPTO_PINNED, VERSION_PINNED}`
- Balanced: `pinning_level ∈ {VERSION_PINNED, CRYPTO_PINNED}`
- Draft-only: `pinning_level ∈ {NAME_ONLY, VERSION_PINNED, CRYPTO_PINNED}`

If `pinning_level` is insufficient for policy, export MUST be blocked with `EXPORT_BLOCKED.block_reason = INSUFFICIENT_PINNING`.

---

## 8) Evaluation Gate Registry (LOCKED Contract) Evaluation Gate Registry (LOCKED Contract)

Core MUST ship:

- `gates_registry_v2.json` (versioned)
  Eval results must reference stable gate IDs.

Export blocking:

- Any BLOCKER gate failure MUST block export under the policy that applies.

---

## 9) Bundle Validator Requirement (LOCKED)

Core SHALL include a bundle validator that enforces:

- Evidence Bundle v1 required structure and required files
- Artifact hash verification
- Audit hash-chain verification per this addendum
- Citations/redactions presence and schema per policy
- Gate IDs and eval report consistency

---

## 10) Vault Crypto v1 (LOCKED)

### 10.1 What MUST be encrypted at rest

- Vault SQLite database file
- Artifact blob store bytes
- Extracted text caches, embeddings caches, model outputs caches (if persisted)

### 10.2 Key model

- Per-vault Data Encryption Key (DEK)
- DEK stored encrypted with a KEK held by OS secure storage:
  - macOS Keychain
  - Windows DPAPI

### 10.3 Algorithms (LOCKED)

- Preferred: XChaCha20-Poly1305
- Acceptable: AES-256-GCM
- Key derivation: HKDF-SHA256 for subkeys (db, blobs, caches)

### 10.4 Rotation

- Support DEK rotation per vault
- Emit audit event `VAULT_KEY_ROTATED` (store key IDs only; never key material)

### 10.5 Evidence

- `inputs_snapshot/policy_snapshot.json` includes encryption flags and algorithm IDs
- Audit event `VAULT_ENCRYPTION_STATUS` on vault create/open

---

## 11) Retention & Deletion v1 (LOCKED)

### 11.1 Retention metadata

Each artifact MUST record:

- classification: `Public|Internal|Confidential|Restricted`
- tags: `PII|PHI|PCI|SECRET|CUSTOM`
- `retention_policy_id` from active policy pack

### 11.2 Deletion requirements

- Deletion is an irreversible user-confirmed action
- Emit:
  - `DELETION_REQUESTED`
  - `DELETION_COMPLETED` with list of removed artifact_ids and verification status

### 11.3 Secure deletion semantics

- Blob store deletion records method used:
  - `unlink_only`
  - `overwrite_then_unlink`
  - `fs_unsupported`
- SQLite deletion records vacuum/compaction attempts and outcomes

Deletion events remain in the audit log.

---

## 12) Prompt Persistence Default (LOCKED)

- Default: `persist_raw_prompts=false`
- `run_manifest.json.model_calls[]` stores summaries (hashes/metadata), not raw prompt text
- If user enables prompt persistence:
  - prompts become Restricted artifacts
  - export inclusion is OFF by default and requires explicit user confirmation + policy permission

End.
