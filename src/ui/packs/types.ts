/** Terminal statuses understood by the status badge. */
export type PackStatus = "SUCCESS" | "BLOCKED" | "FAILED";

/**
 * EvidenceOS export status. src-tauri/src/export/mod.rs rejects any outcome other
 * than COMPLETED before it reaches the UI, so COMPLETED is the only value the
 * frontend can observe. ExportOutcome itself is wider (core/src/run/manager.rs:41).
 */
export type EvidenceExportStatus = "COMPLETED";

/**
 * Gate outcomes. Source: core/src/eval/runner.rs:96/:102/:141/:159 and the
 * PASS/NOT_APPLICABLE acceptance check at core/src/run/manager.rs:150.
 */
export type GateStatus = "PASS" | "NOT_APPLICABLE";

/**
 * Rendered when the UI holds no verified value. Never emitted as a run outcome;
 * the validator uses the same token for an unresolvable field
 * (core/src/validator/mod.rs:785).
 */
export type UnresolvedStatus = "UNKNOWN";

/** Every status StatusBadge is able to render. */
export type StatusValue = PackStatus | EvidenceExportStatus | GateStatus | UnresolvedStatus;

export type EvidenceAuthorityManifest = {
  schema_version: string;
  case_id: string;
  requested_execution_class: string;
  observed_execution_class: string;
  evidence_origin: string;
  production_equivalent: boolean;
  generated_at_utc: string;
  valid_until_utc: string;
  source: {
    producer: string;
    source_revision: string;
    executable: string;
    executable_sha256: string;
    arguments_sha256: string;
    environment_sha256: string;
    audit_log_sha256: string;
  };
  allowed_effects: string[];
  observed_effects: string[];
  credential_availability: string;
  tools: Array<{
    tool_id: string;
    declared_available: boolean;
    observed_used: boolean;
    external_mutation_allowed: boolean;
  }>;
  state_scope: {
    cache_scope: string;
    prior_approval_reused: boolean;
    credential_state_reused: boolean;
    mutable_cache_reused: boolean;
  };
  downstream_claims: {
    may_satisfy: string[];
    must_not_satisfy: string[];
  };
  limitations: string[];
};
