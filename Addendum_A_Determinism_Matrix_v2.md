# Addendum A — Determinism Matrix v2 (LOCKED)

**Document status:** Normative current determinism rules.

Version: determinism_matrix_v2  
Status: LOCKED (claims and compare methods are contract; do not weaken)  
Purpose: Defines determinism categories, preconditions, and the exact compare method for Evidence Bundle v1 artifacts.

This v2 is a tightening only:

- Makes ZIP determinism rules explicit (previously implied by gates/locks).
- Aligns run_id derivation and LOCKED_EPOCH behavior to Phase 2.5 lock addendum.

---

## 1) Determinism categories (Normative)

### D0 — Nondeterministic Allowed

- Content may vary run-to-run. No byte-stability claims.
- Example: UI caches, temporary previews.

### D1 — Semantically Deterministic

- Meaning must be stable; bytes may vary.
- Validator compares by parsing and canonicalizing into a stable form, then comparing canonical hashes.
- Example: PDFs when byte determinism is not enabled/possible.

### D2 — Byte Deterministic (bit-identical required)

- Byte-for-byte identical under identical inputs and determinism-enabled configuration.
- Validator compares raw SHA-256 of bytes.

---

## 2) Preconditions for determinism claims (Normative)

Determinism claims apply only when ALL are true:

- `inputs_snapshot/policy_snapshot.json.determinism.enabled == true`
- `inputs_snapshot/policy_snapshot.json.export_profile.inputs` is explicitly set (`HASH_ONLY` or `INCLUDE_INPUT_BYTES`)
- All Core canonicalization rules referenced in `Phase_2_5_Lock_Addendum_v2.5-lock-4.md` are in effect:
  - JSON canonicalization
  - NDJSON audit hash-chain canonicalization
  - ZIP packaging canonicalization
- Any Pack-specific templates referenced in `templates_used.json` are pinned (version or sha256 as defined there)

---

## 3) Artifact determinism matrix (Normative)

### 3.1 Core manifests and maps

| Artifact                                     | Category | Compare Method | Notes                                                          |
| -------------------------------------------- | -------: | -------------- | -------------------------------------------------------------- |
| `BUNDLE_INFO.json`                           |       D2 | raw sha256     | `generated_at` MUST be `LOCKED_EPOCH` when determinism enabled |
| `run_manifest.json`                          |       D2 | raw sha256     | Canonical JSON encoding; stable key order                      |
| `inputs_snapshot/policy_snapshot.json`       |       D2 | raw sha256     | Canonical JSON encoding; includes `export_profile`             |
| `inputs_snapshot/network_snapshot.json`      |       D2 | raw sha256     | Canonical JSON; sorted allowlist                               |
| `inputs_snapshot/model_snapshot.json`        |       D2 | raw sha256     | Canonical JSON                                                 |
| `exports/**/attachments/citations_map.json`  |       D2 | raw sha256     | Must validate against `LOCATOR_SCHEMA_V1`                      |
| `exports/**/attachments/redactions_map.json` |       D2 | raw sha256     | Must validate against `REDACTION_SCHEMA_V1`                    |
| `exports/**/attachments/templates_used.json` |       D2 | raw sha256     | Must validate against `TEMPLATES_USED_V1`                      |

### 3.2 Input bytes (conditional)

| Artifact                                        | Category | Compare Method | Notes                                                    |
| ----------------------------------------------- | -------: | -------------- | -------------------------------------------------------- |
| `inputs_snapshot/artifacts/<artifact_id>/bytes` |       D2 | raw sha256     | Only when `export_profile.inputs == INCLUDE_INPUT_BYTES` |

### 3.3 Deliverables

| Artifact                         | Category | Compare Method                | Notes                                                                            |
| -------------------------------- | -------: | ----------------------------- | -------------------------------------------------------------------------------- |
| `exports/**/deliverables/*.md`   |       D2 | raw sha256                    | Core-authored; no volatile timestamps                                            |
| `exports/**/deliverables/*.json` |       D2 | raw sha256                    | Canonical JSON                                                                   |
| `exports/**/deliverables/*.pdf`  | D1 or D2 | parse+canonical OR raw sha256 | D2 only if PDF determinism is enabled and the deterministic PDF pipeline is used |

---

## 4) ZIP packaging determinism (Normative)

Applies to `evidence_bundle_<run_id>_v1.zip` when determinism enabled.

### 4.1 Entry ordering

- Sort all entries by `bundle_rel_path` ascending (bytewise lexicographic, `/` separators).

### 4.2 Timestamps

- All ZIP entry mtimes MUST be set to Unix epoch (`0`) or DOS epoch equivalent; no per-file timestamps.

### 4.3 Permissions and extra fields

- Normalize file mode bits across platforms (fixed 0644 for files, 0755 for directories).
- Do not emit platform-specific extra fields unless explicitly pinned and identical across OSes.

### 4.4 Compression

- Use DEFLATE with fixed compression level = 9 for all compressible entries.
- Store already-compressed formats (e.g., certain PDFs) using DEFLATE level 9 anyway (no heuristics).

### 4.5 ZIP comment

- ZIP comment MUST be empty.

---

## 5) Allowed nondeterministic fields (Normative)

When determinism enabled:

- Any field marked `LOCKED_EPOCH` MUST be the literal `LOCKED_EPOCH` string (not a real time).
- If determinism disabled, timestamps may be real but MUST be ISO-8601 UTC.
