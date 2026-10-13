# 0012. Truthful Evidence Bundle Snapshots

## Status
Accepted — 2026-10-12

## Context
EvidenceOS previously exported fixed encryption, adapter, model, build, and timestamp values even when those operations or identities were not present in the run. The validator also required some of those claims. This made an internally consistent archive capable of describing activity that never occurred, and treated malformed declared hashes as though hashes were missing.

## Decision
Evidence Bundle `bundle_version: "1.1.0"` is the first version of the truthful snapshot contract. Exporters derive snapshot values from recorded run activity, enforced policy, and build provenance.

- Encryption is `false` and has no algorithm when the run did not use vault encryption. A `true` claim requires actual vault use, an accepted algorithm and key-storage value, and a matching `VAULT_ENCRYPTION_STATUS` audit event. EvidenceOS's plain runtime export directory does not qualify; adopting `VaultStorage` is outside this decision.
- No model run is represented as JSON `null` in `model_snapshot.json`, an empty `model_calls` array, and no adapter endpoints. When inference occurs, model endpoint, network endpoint, and model-call evidence must agree.
- `proof_source: POLICY_DECLARATION` labels network posture derived from the enforced policy. It is not evidence of measured traffic.
- A local EvidenceOS archive export uses `evidence_authority.evidence_origin: LOCAL_ARTIFACT_EXPORT`. `CONTROL_SIMULATION` remains reserved for actual control-simulation runs, which have their own blocked-egress evidence contract. A local archive export records no fabricated blocked-egress event.
- The audit envelope's required `vault_id` may be a stable logical namespace derived from the run input fingerprint. Its presence alone does not establish vault storage use or encryption.
- Build identity records the package version and compiled source revision. Declared SHA-256 values must be 64 lowercase hexadecimal characters; malformed values are rejected.
- Actual clock time is recorded when determinism is disabled. Deterministic mode normalizes only fields the determinism contract names, including citation and redaction `generated_at_ms` values, to Addendum A's `LOCKED_EPOCH`. Determinism does not replace run facts or build identity with constants.
- Validators can inspect older bundles, but their truth status is `LEGACY_UNVERIFIABLE`. They cannot silently pass those archives as truthful v1.1.0 bundles.

## Consequences
Consumers can distinguish an unused capability from activity that ran and can treat network declarations according to their evidence source. Validators may report legacy structural results while withholding truthful status for bundles produced before v1.1.0. Existing consumers that assumed an encryption algorithm or model always exists must handle explicit absence. Encryption claims remain unavailable to EvidenceOS until it actually adopts and uses the vault storage path.

## Alternatives Considered
- Continue exporting fixed values and document them as defaults. Rejected because readers could not distinguish a default from observed activity.
- Treat missing fields in old bundles as proof that the capability was unused. Rejected because old producers did not preserve enough information to establish that fact.
- Reject all old bundles. Rejected because inspection of their integrity and recorded contents remains useful; the validator instead reports the limitation explicitly.
