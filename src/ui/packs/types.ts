/**
 * Terminal statuses the Tauri pack commands emit.
 * Source: src-tauri/src/lib.rs:2228 (SUCCESS), :2237 (BLOCKED), :2246 (FAILED);
 * PackCommandError::blocked :294 and ::failed :304/:319 cover the error paths.
 */
export type PackStatus = "SUCCESS" | "BLOCKED" | "FAILED";

/**
 * EvidenceOS export status. src-tauri/src/lib.rs:660 rejects any outcome other
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

export type PackCommandStatus = {
  status: PackStatus;
  message: string;
  bundle_path?: string | null;
  bundle_sha256?: string | null;
  error_code?: string | null;
  run_id?: string | null;
  audit_path?: string | null;
  evidence_authority?: EvidenceAuthorityManifest | null;
};

export type ArtifactPayloadInput = {
  artifact_id: string;
  content_text?: string;
  content_base64?: string;
};

export type RedlineOSInput = {
  schema_version: string;
  contract_artifacts: Array<{ artifact_id: string; sha256: string; filename: string }>;
  extraction_mode: "NATIVE_PDF" | "OCR";
  jurisdiction_hint: string | null;
  review_profile: "default" | "aggressive" | "conservative";
};

export type RedlineCommandInput = RedlineOSInput & {
  artifact_payloads: ArtifactPayloadInput[];
};

export type IncidentCommandInput = {
  schema_version: string;
  incident_artifacts: Array<{ artifact_id: string; sha256: string; source_type: string }>;
  timeline_start_hint: string | null;
  timeline_end_hint: string | null;
  customer_redaction_profile: string;
  artifact_payloads: ArtifactPayloadInput[];
};

export type FinanceCommandInput = {
  schema_version: string;
  finance_artifacts: Array<{ artifact_id: string; sha256: string; artifact_kind: string }>;
  period: string;
  exception_rules_profile: string;
  retention_profile: string;
  artifact_payloads: ArtifactPayloadInput[];
};

export type HealthcareCommandInput = {
  schema_version: string;
  consent_artifacts: Array<{ artifact_id: string; sha256: string; artifact_kind: string }>;
  transcript_artifacts: Array<{ artifact_id: string; sha256: string; artifact_kind: string }>;
  draft_template_profile: string;
  verifier_identity: string;
  artifact_payloads: ArtifactPayloadInput[];
};
