export type PackCommandStatus = {
  status: string;
  message: string;
  bundle_path?: string | null;
  bundle_sha256?: string | null;
  error_code?: string | null;
  run_id?: string | null;
  audit_path?: string | null;
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
