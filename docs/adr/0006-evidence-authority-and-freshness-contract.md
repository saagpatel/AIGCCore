# ADR 0006: Evidence Authority and Freshness Contract

- Status: Accepted
- Date: 2026-07-20

## Context

Pack exports append a synthetic blocked-egress event to exercise the offline policy path. The event
was marked `CONTROL_SIMULATION`, but that distinction was not carried into the run manifest or the
operator result. The allowlist eval also counted the synthetic event as a passing blocked-egress
observation. A valid bundle could therefore be mistaken for proof of live traffic, production
authority, external mutation, or current runtime capability.

## Decision

1. `RUN_MANIFEST_V2` requires `evidence_authority` with schema
   `EVIDENCE_AUTHORITY_V1`.
2. The authority contract binds the case, source revision, executable, invocation arguments,
   classified environment, and bundled audit log by SHA-256.
3. It records requested and observed execution class, evidence origin, credential and tool
   availability, allowed and observed effects, generation and expiry, case-local state isolation,
   production-equivalence limitations, and explicit permitted/prohibited downstream claims.
4. Missing, malformed, stale, cross-case, source-mismatched, executable-mismatched,
   argument-mismatched, environment-mismatched, cache-contaminated, or ambiguous evidence returns
   a non-authorizing `UNKNOWN` decision.
5. `CONTROL_SIMULATION` can authorize bounded local controlled-execution and bundle-integrity
   claims only. It must prohibit live execution, production authority, external mutation,
   real-user success, deployability, live evaluation completion, and live blocked-egress claims.
6. Egress audit events require an explicit `evidence_origin` of `CONTROL_SIMULATION` or
   `RUNTIME_OBSERVATION`.
7. A simulation-only allowlist eval is `NOT_APPLICABLE` for live observation. Only an explicit
   runtime-observed event can pass that gate.
8. Tauri command results surface the authority contract so operator-visible success cannot hide
   the controlled/simulated boundary.
9. `RUNTIME_OBSERVATION`, `FIXTURE`, and `REPLAY` remain reserved evidence origins. Until each has
   an explicit manifest and audit-evidence contract, the authority validator rejects it and claim
   evaluation returns `UNKNOWN`; an origin label alone never authorizes live or production claims.

## Consequences

- Bundle integrity and controlled local processing may still succeed.
- Success no longer implies live execution or production authority.
- Older `RUN_MANIFEST_V1` bundles fail the current authority-contract validator and remain
  non-authorizing until migrated or handled by an explicitly versioned legacy reader.
- Evidence remains auditable after expiry, but it cannot authorize a current claim once stale.
