import type {
  ArtifactPayloadInput,
  FinanceCommandInput,
  HealthcareCommandInput,
  IncidentCommandInput,
} from "./types";

export const SAMPLE_INCIDENT_LOG = `{"timestamp":"2026-02-12T09:00:00Z","source_system":"web-server","actor":"admin@company.com","action":"system_startup","affected_resource":"prod-web-01","evidence_text":"Web server started normally with no errors"}
{"timestamp":"2026-02-12T09:15:30Z","source_system":"auth-service","actor":"user@company.com","action":"login_attempt","affected_resource":"auth-service","evidence_text":"User successfully authenticated via LDAP"}
{"timestamp":"2026-02-12T10:30:00Z","source_system":"database","actor":"app-service","action":"query_executed","affected_resource":"users-table","evidence_text":"SELECT * FROM users executed successfully"}
{"timestamp":"2026-02-12T11:00:00Z","source_system":"firewall","actor":"system","action":"alert_triggered","affected_resource":"network-perimeter","evidence_text":"Suspicious traffic detected from 192.168.1.100 attempting port scan"}
{"timestamp":"2026-02-12T11:15:00Z","source_system":"intrusion-detection","actor":"system","action":"critical_alert","affected_resource":"ids-sensor-1","evidence_text":"Potential breach attempt detected - malicious payload signature matched"}
{"timestamp":"2026-02-12T11:16:00Z","source_system":"incident-response","actor":"security-ops","action":"incident_created","affected_resource":"incident-tracker","evidence_text":"Incident INC-2026-001234 created with severity CRITICAL"}
{"timestamp":"2026-02-12T11:30:00Z","source_system":"audit-log","actor":"system","action":"access_violation","affected_resource":"data-warehouse","evidence_text":"Unauthorized access attempt to PII database from IP 203.0.113.42"}
{"timestamp":"2026-02-12T12:00:00Z","source_system":"forensics","actor":"incident-team","action":"analysis_complete","affected_resource":"evidence-store","evidence_text":"Forensic analysis indicates lateral movement to 5 internal systems"}`;

export const SAMPLE_FINANCE_STATEMENT = `{
  "statement_id": "STMT_2026_01",
  "period_start": "2026-01-01",
  "period_end": "2026-01-31",
  "transactions": [
    {
      "date": "2026-01-05",
      "amount": 1000.00,
      "account": "checking",
      "category": "salary",
      "description": "Monthly salary deposit"
    },
    {
      "date": "2026-01-10",
      "amount": 15000.00,
      "account": "checking",
      "category": "transfer",
      "description": "Large inter-account transfer"
    },
    {
      "date": "2026-01-10",
      "amount": 5000.00,
      "account": "checking",
      "category": "utilities",
      "description": "Electric and water bill"
    },
    {
      "date": "2026-01-15",
      "amount": 5000.00,
      "account": "savings",
      "category": "transfer",
      "description": "Monthly savings deposit"
    },
    {
      "date": "2026-01-20",
      "amount": 2500.00,
      "account": "checking",
      "category": "groceries",
      "description": "Grocery store purchase"
    },
    {
      "date": "2026-01-25",
      "amount": 1000.00,
      "account": "credit_card",
      "category": "purchase",
      "description": "Online retailer payment"
    }
  ]
}`;

export const SAMPLE_HEALTHCARE_TRANSCRIPT = `{
  "patient_id": "PT-2026-001",
  "date": "2026-02-12",
  "provider": "Dr. Smith",
  "specialty": "Cardiology",
  "content": "Patient presents with chest pain. EKG normal. Recommend stress test. Patient has history of hypertension controlled with medication. Currently taking lisinopril 10mg daily. No known allergies. Vital signs stable.",
  "confidence": 0.95
}`;

export const SAMPLE_HEALTHCARE_CONSENT = `{
  "patient_id": "PT-2026-001",
  "date_given": "2024-02-12",
  "scope": "general",
  "status": "VALID"
}`;

export const SAMPLE_REDLINE_CONTRACT_BASE64 =
  "JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVudCAyIDAgUiAvUmVzb3VyY2VzIDw8IC9Gb250IDw8IC9GMSA0IDAgUiA+PiA+PiAvTWVkaWFCb3ggWzAgMCA2MTIgNzkyXSAvQ29udGVudHMgNSAwIFIgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL1R5cGUgL0ZvbnQgL1N1YnR5cGUgL1R5cGUxIC9CYXNlRm9udCAvSGVsdmV0aWNhID4+CmVuZG9iago1IDAgb2JqCjw8IC9MZW5ndGggMjAwID4+CnN0cmVhbQpCVAovRjEgMTIgVGYKNTAgNzAwIFRkCihTYW1wbGUgQ29udHJhY3QgLSBEaWdpdGFsIFBERikgVGoKMCAtMzAgVGQKKDEuMSBEZWZpbml0aW9ucykgVGoKMCAtMjAgVGQKKFRoaXMgYWdyZWVtZW50IGRlZmluZXMgdGhlIHRlcm1zIGFuZCBjb25kaXRpb25zIGdvdmVybmluZyB0aGUgcmVsYXRpb25zaGlwLikgVGoKMCAtMzAgVGQKKDEuMiBUZXJtIGFuZCBJbmRlbW5pZmljYXRpb24pIFRqCjAgLTIwIFRkCihMaWNlbnNvciBzaGFsbCBpbmRlbW5pZnkgTGljZW5zZWUgcGVycGV0dWFsbHkgZm9yIGFsbCBjbGFpbXMuKSBUagowIC0zMCBUZAooMi4wIExpbWl0YXRpb24gb2YgTGlhYmlsaXR5KSBUagowIC0yMCBUZAooSW4gbm8gZXZlbnQgc2hhbGwgZWl0aGVyIHBhcnR5IGxpbWl0IGxpYWJpbGl0eSB0byB0aGUgZXh0ZW50IHBlcm1pdHRlZCBieSBsYXcuKSBUagpFVAplbmRzdHJlYW0KZW5kb2JqCnhyZWYKMCA2CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDAwOSAwMDAwMCBuIAowMDAwMDAwMDU4IDAwMDAwIG4gCjAwMDAwMDAxMTUgMDAwMDAgbiAKMDAwMDAwMDI1MyAwMDAwMCBuIAowMDAwMDAwMzM3IDAwMDAwIG4gCnRyYWlsZXIKPDwgL1NpemUgNiAvUm9vdCAxIDAgUiA+PgpzdGFydHhyZWYKNTg4CiUlRU9GCg==";

export function buildIncidentCommandInput(logContent = SAMPLE_INCIDENT_LOG): IncidentCommandInput {
  const payload: ArtifactPayloadInput = {
    artifact_id: "i_demo",
    content_text: logContent,
  };
  return {
    schema_version: "INCIDENTOS_INPUT_V1",
    incident_artifacts: [{ artifact_id: "i_demo", sha256: "demo", source_type: "syslog" }],
    timeline_start_hint: null,
    timeline_end_hint: null,
    customer_redaction_profile: "strict",
    artifact_payloads: [payload],
  };
}

export function buildFinanceCommandInput(): FinanceCommandInput {
  return buildFinanceCommandInputFromStatement(SAMPLE_FINANCE_STATEMENT);
}

export function buildFinanceCommandInputFromStatement(
  statementContent: string,
): FinanceCommandInput {
  const payload: ArtifactPayloadInput = {
    artifact_id: "f_demo",
    content_text: statementContent,
  };
  return {
    schema_version: "FINANCEOS_INPUT_V1",
    finance_artifacts: [{ artifact_id: "f_demo", sha256: "demo", artifact_kind: "statement" }],
    period: "2026-01",
    exception_rules_profile: "default",
    retention_profile: "ret_min",
    artifact_payloads: [payload],
  };
}

export function buildHealthcareCommandInput(
  transcriptContent = SAMPLE_HEALTHCARE_TRANSCRIPT,
  consentContent = SAMPLE_HEALTHCARE_CONSENT,
): HealthcareCommandInput {
  const transcriptPayload: ArtifactPayloadInput = {
    artifact_id: "t_demo",
    content_text: transcriptContent,
  };
  const consentPayload: ArtifactPayloadInput = {
    artifact_id: "c_demo",
    content_text: consentContent,
  };
  return {
    schema_version: "HEALTHCAREOS_INPUT_V1",
    consent_artifacts: [{ artifact_id: "c_demo", sha256: "demo", artifact_kind: "consent" }],
    transcript_artifacts: [{ artifact_id: "t_demo", sha256: "demo", artifact_kind: "transcript" }],
    draft_template_profile: "soap",
    verifier_identity: "clinician_1",
    artifact_payloads: [consentPayload, transcriptPayload],
  };
}
