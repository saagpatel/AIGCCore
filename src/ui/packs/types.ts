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
  status: string;
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
