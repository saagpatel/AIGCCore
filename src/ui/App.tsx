import React, { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { FinanceOSPanel } from "./packs/FinanceOSPanel";
import { HealthcareOSPanel } from "./packs/HealthcareOSPanel";
import { IncidentOSPanel } from "./packs/IncidentOSPanel";
import { RedlineOSPanel } from "./packs/RedlineOSPanel";
import { StatusBadge } from "./StatusBadge";
import { EvidenceAuthorityNotice } from "./packs/EvidenceAuthorityNotice";
import {
  SAMPLE_FINANCE_STATEMENT,
  SAMPLE_HEALTHCARE_CONSENT,
  SAMPLE_HEALTHCARE_TRANSCRIPT,
  SAMPLE_INCIDENT_LOG,
  buildFinanceCommandInputFromStatement,
  buildHealthcareCommandInput,
  buildIncidentCommandInput,
} from "./packs/samplePayloads";
import type {
  EvidenceAuthorityManifest,
  EvidenceExportStatus,
  PackCommandStatus,
} from "./packs/types";

type NetworkSnapshot = {
  network_mode: "OFFLINE" | "ONLINE_ALLOWLISTED";
  proof_level:
    "OFFLINE_STRICT" | "ONLINE_ALLOWLIST_CORE_ONLY" | "ONLINE_ALLOWLIST_WITH_OS_FIREWALL_PROFILE";
  ui_remote_fetch_disabled: boolean;
};

type ControlDefinition = {
  control_id: string;
  title: string;
  capability: string;
  control_family: string;
  description: string;
};

type EvidenceOsRunResult = {
  status: EvidenceExportStatus;
  bundle_path: string;
  bundle_sha256: string;
  missing_control_ids: string[];
  evidence_authority: EvidenceAuthorityManifest;
};

type EvidenceOsRunInput = {
  enabled_capabilities: string[];
  artifact_title: string;
  artifact_body: string;
  artifact_tags_csv: string;
  control_families_csv: string;
  claim_text: string;
};

const evidenceFieldLabels = {
  "artifact-title": "Artifact title",
  "artifact-body": "Artifact text",
  "artifact-tags": "Artifact tags",
  "control-families": "Control families",
  "claim-text": "Narrative claim",
} as const;

type EvidenceFieldId = keyof typeof evidenceFieldLabels;

export function App() {
  const [snap, setSnap] = useState<NetworkSnapshot | null>(null);
  const [snapError, setSnapError] = useState<string | null>(null);
  const [controls, setControls] = useState<ControlDefinition[]>([]);
  const [controlsLoading, setControlsLoading] = useState(true);
  const [controlsError, setControlsError] = useState<string | null>(null);
  const [runResult, setRunResult] = useState<EvidenceOsRunResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [evidenceInvalidFields, setEvidenceInvalidFields] = useState<EvidenceFieldId[]>([]);
  const [running, setRunning] = useState(false);
  const [selectedCapability, setSelectedCapability] = useState("ALL");
  const [artifactTitle, setArtifactTitle] = useState("Network policy evidence");
  const [artifactBody, setArtifactBody] = useState(
    "Audit log excerpt from a controlled offline-policy simulation.",
  );
  const [artifactTags, setArtifactTags] = useState("OPS,NETWORK");
  const [controlFamilies, setControlFamilies] = useState(
    "Auditability,NetworkGovernance,Traceability",
  );
  const [claimText, setClaimText] = useState(
    "A controlled simulation exercised the offline block path; no live traffic.",
  );

  const [futurePackRunning, setFuturePackRunning] = useState<string | null>(null);
  const [futurePackResult, setFuturePackResult] = useState<Record<string, PackCommandStatus>>({});
  const [incidentPayload, setIncidentPayload] = useState("");
  const [financePayload, setFinancePayload] = useState("");
  const [healthcareTranscriptPayload, setHealthcareTranscriptPayload] = useState("");
  const [healthcareConsentPayload, setHealthcareConsentPayload] = useState("");
  const operationLockRef = useRef(false);

  const networkStatus = useMemo(() => {
    if (snapError) {
      return <StatusBadge status="UNKNOWN" detail="Enforcement layer unreachable, state unknown" />;
    }
    if (!snap) return <strong>Loading…</strong>;
    return <strong>{`${snap.network_mode} (${snap.proof_level})`}</strong>;
  }, [snap, snapError]);

  const capabilities = useMemo(() => {
    const all = controls.map((control) => control.capability);
    return ["ALL", ...Array.from(new Set(all)).sort()];
  }, [controls]);

  useEffect(() => {
    (async () => {
      try {
        const s = await invoke<NetworkSnapshot>("get_network_snapshot");
        setSnap(s);
        setSnapError(null);
      } catch (error) {
        // The enforcement layer is what proves the network posture. If it is
        // unreachable we have no posture to report, so report exactly that
        // rather than asserting the strongest claim the app can make.
        setSnap(null);
        setSnapError(String(error));
      }

      try {
        const list = await invoke<ControlDefinition[]>("list_control_library");
        setControls(list);
        setControlsError(null);
      } catch (error) {
        setControls([]);
        setControlsError(String(error));
      } finally {
        setControlsLoading(false);
      }
    })();
  }, []);

  const filteredControls = useMemo(() => {
    if (selectedCapability === "ALL") return controls;
    return controls.filter((control) => control.capability === selectedCapability);
  }, [controls, selectedCapability]);

  const operationalReady = snap !== null && !snapError && !controlsLoading && !controlsError;
  const operationRunning = running || futurePackRunning !== null;
  const writeUnavailable = useMemo(() => {
    if (snapError)
      return {
        kind: "error" as const,
        message: "Exports are unavailable because network enforcement status is unknown.",
      };
    if (!snap)
      return {
        kind: "status" as const,
        message: "Exports are unavailable while network enforcement status is loading.",
      };
    if (controlsError)
      return {
        kind: "error" as const,
        message: `Control library unavailable: ${controlsError}. Exports are unavailable.`,
      };
    if (controlsLoading)
      return {
        kind: "status" as const,
        message: "Exports are unavailable while the control library is loading.",
      };
    if (operationRunning)
      return {
        kind: "status" as const,
        message:
          "Another local export is in progress. Wait for it to finish before starting another.",
      };
    return null;
  }, [controlsError, controlsLoading, operationRunning, snap, snapError]);

  const evidenceValidationMessage = useMemo(() => {
    if (evidenceInvalidFields.length === 0) return null;
    const labels = evidenceInvalidFields.map((field) => evidenceFieldLabels[field]);
    return `Complete the required EvidenceOS fields: ${labels.join(", ")}.`;
  }, [evidenceInvalidFields]);

  const updateEvidenceField = (
    field: EvidenceFieldId,
    setValue: React.Dispatch<React.SetStateAction<string>>,
    value: string,
  ) => {
    setValue(value);
    setEvidenceInvalidFields((current) => current.filter((candidate) => candidate !== field));
  };

  const onRunEvidenceOs = async () => {
    const missingFields: EvidenceFieldId[] = [];
    if (!artifactTitle.trim()) missingFields.push("artifact-title");
    if (!artifactBody.trim()) missingFields.push("artifact-body");
    if (!artifactTags.trim()) missingFields.push("artifact-tags");
    if (!controlFamilies.trim()) missingFields.push("control-families");
    if (!claimText.trim()) missingFields.push("claim-text");
    setEvidenceInvalidFields(missingFields);
    if (missingFields.length > 0) {
      setRunError(null);
      setRunResult(null);
      return;
    }
    if (!operationalReady || operationLockRef.current) return;

    operationLockRef.current = true;
    setRunning(true);
    setRunError(null);
    try {
      const payload: EvidenceOsRunInput = {
        enabled_capabilities: selectedCapability === "ALL" ? [] : [selectedCapability],
        artifact_title: artifactTitle,
        artifact_body: artifactBody,
        artifact_tags_csv: artifactTags,
        control_families_csv: controlFamilies,
        claim_text: claimText,
      };
      const result = await invoke<EvidenceOsRunResult>("generate_evidenceos_bundle", {
        input: payload,
      });
      setRunResult(result);
    } catch (error) {
      setRunError(String(error));
      setRunResult(null);
    } finally {
      setRunning(false);
      operationLockRef.current = false;
    }
  };

  const runFuturePack = async (command: string, input: unknown) => {
    if (!operationalReady || operationLockRef.current) return;

    operationLockRef.current = true;
    setFuturePackRunning(command);
    try {
      const result = await invoke<PackCommandStatus>(command, { input });
      setFuturePackResult((prev) => ({ ...prev, [command]: result }));
    } catch (error) {
      setFuturePackResult((prev) => ({
        ...prev,
        [command]: {
          status: "FAILED",
          message: String(error),
          error_code: "INVOKE_RUNTIME_ERROR",
        },
      }));
    } finally {
      setFuturePackRunning(null);
      operationLockRef.current = false;
    }
  };

  return (
    <div className="app">
      <header className="topbar">
        <h1 className="brand">AIGC Core</h1>
        <div
          className="badge"
          data-mode={snap?.network_mode ?? (snapError ? "UNKNOWN" : "LOADING")}
          data-testid="network-status"
          role="status"
          aria-live="polite"
          aria-atomic="true"
        >
          Network: {networkStatus}
        </div>
      </header>

      <main className="main" aria-busy={!operationalReady || operationRunning || undefined}>
        {writeUnavailable && (
          <p
            id="write-readiness"
            className="readiness"
            data-state={writeUnavailable.kind}
            role={writeUnavailable.kind === "error" ? "alert" : "status"}
            aria-live={writeUnavailable.kind === "error" ? "assertive" : "polite"}
          >
            {writeUnavailable.message}
          </p>
        )}
        <section className="card">
          <h2>Phase 2 Hard Guarantees</h2>
          <ul>
            <li>Offline-by-default enforced in Rust core</li>
            <li>Hash-chained canonical audit log</li>
            <li>Deterministic Evidence Bundle v1 export</li>
            <li>Validator checklist + eval gates runnable locally</li>
          </ul>
        </section>

        <section className="card">
          <h2>Phase 3 EvidenceOS Pack</h2>
          <p>
            Capability-based control mapping and strict-citation narrative export through the Core
            export pipeline.
          </p>
          <div className="row">
            <label htmlFor="capability-filter">Capability</label>
            <select
              id="capability-filter"
              value={selectedCapability}
              onChange={(event) => setSelectedCapability(event.target.value)}
            >
              {capabilities.map((capability) => (
                <option key={capability} value={capability}>
                  {capability}
                </option>
              ))}
            </select>
          </div>
          <div className="form-grid">
            <label htmlFor="artifact-title">Artifact title</label>
            <input
              id="artifact-title"
              required
              aria-invalid={evidenceInvalidFields.includes("artifact-title") || undefined}
              aria-describedby={
                evidenceInvalidFields.includes("artifact-title")
                  ? "evidence-validation-error"
                  : undefined
              }
              value={artifactTitle}
              onChange={(event) =>
                updateEvidenceField("artifact-title", setArtifactTitle, event.target.value)
              }
            />
            <label htmlFor="artifact-body">Artifact text</label>
            <textarea
              id="artifact-body"
              rows={3}
              required
              aria-invalid={evidenceInvalidFields.includes("artifact-body") || undefined}
              aria-describedby={
                evidenceInvalidFields.includes("artifact-body")
                  ? "evidence-validation-error"
                  : undefined
              }
              value={artifactBody}
              onChange={(event) =>
                updateEvidenceField("artifact-body", setArtifactBody, event.target.value)
              }
            />
            <label htmlFor="artifact-tags">Artifact tags (CSV)</label>
            <input
              id="artifact-tags"
              required
              aria-invalid={evidenceInvalidFields.includes("artifact-tags") || undefined}
              aria-describedby={
                evidenceInvalidFields.includes("artifact-tags")
                  ? "evidence-validation-error"
                  : undefined
              }
              value={artifactTags}
              onChange={(event) =>
                updateEvidenceField("artifact-tags", setArtifactTags, event.target.value)
              }
            />
            <label htmlFor="control-families">Control families (CSV)</label>
            <input
              id="control-families"
              required
              aria-invalid={evidenceInvalidFields.includes("control-families") || undefined}
              aria-describedby={
                evidenceInvalidFields.includes("control-families")
                  ? "evidence-validation-error"
                  : undefined
              }
              value={controlFamilies}
              onChange={(event) =>
                updateEvidenceField("control-families", setControlFamilies, event.target.value)
              }
            />
            <label htmlFor="claim-text">Narrative claim</label>
            <textarea
              id="claim-text"
              rows={3}
              required
              aria-invalid={evidenceInvalidFields.includes("claim-text") || undefined}
              aria-describedby={
                evidenceInvalidFields.includes("claim-text")
                  ? "evidence-validation-error"
                  : undefined
              }
              value={claimText}
              onChange={(event) =>
                updateEvidenceField("claim-text", setClaimText, event.target.value)
              }
            />
          </div>
          <div className="controls-grid">
            {controlsLoading && <p role="status">Loading control library…</p>}
            {!controlsLoading && !controlsError && filteredControls.length === 0 && (
              <p className="meta">No controls are available for this capability.</p>
            )}
            {filteredControls.map((control) => (
              <article key={control.control_id} className="control-card">
                <h3>{control.control_id}</h3>
                <p className="control-title">{control.title}</p>
                <p className="meta">
                  {control.capability} / {control.control_family}
                </p>
                <p>{control.description}</p>
              </article>
            ))}
          </div>
          <button
            type="button"
            disabled={Boolean(writeUnavailable)}
            aria-describedby={writeUnavailable ? "write-readiness" : undefined}
            onClick={onRunEvidenceOs}
          >
            {running ? "Generating EvidenceOS Bundle…" : "Generate EvidenceOS Bundle"}
          </button>
          {evidenceValidationMessage && (
            <p id="evidence-validation-error" className="error" role="alert">
              {evidenceValidationMessage}
            </p>
          )}
          {runError && (
            <p className="error" role="alert">
              Phase 3 run failed: {runError}
            </p>
          )}
          {runResult && (
            <div className="result" role="status" aria-live="polite" aria-atomic="true">
              <p>
                Export status: <StatusBadge status={runResult.status} />
              </p>
              <p>Bundle path: {runResult.bundle_path}</p>
              <p>Bundle SHA-256: {runResult.bundle_sha256}</p>
              <p>
                Missing controls:{" "}
                {runResult.missing_control_ids.length > 0
                  ? runResult.missing_control_ids.join(", ")
                  : "None"}
              </p>
              <EvidenceAuthorityNotice authority={runResult.evidence_authority} />
            </div>
          )}
        </section>

        <RedlineOSPanel
          running={futurePackRunning === "run_redlineos"}
          operationDisabled={Boolean(writeUnavailable)}
          result={futurePackResult.run_redlineos ?? null}
          onRun={(input) => runFuturePack("run_redlineos", input)}
        />
        <IncidentOSPanel
          running={futurePackRunning === "run_incidentos"}
          operationDisabled={Boolean(writeUnavailable)}
          result={futurePackResult.run_incidentos ?? null}
          payloadText={incidentPayload}
          onPayloadChange={setIncidentPayload}
          onLoadSample={() => setIncidentPayload(SAMPLE_INCIDENT_LOG)}
          onRun={() => runFuturePack("run_incidentos", buildIncidentCommandInput(incidentPayload))}
        />
        <FinanceOSPanel
          running={futurePackRunning === "run_financeos"}
          operationDisabled={Boolean(writeUnavailable)}
          result={futurePackResult.run_financeos ?? null}
          payloadText={financePayload}
          onPayloadChange={setFinancePayload}
          onLoadSample={() => setFinancePayload(SAMPLE_FINANCE_STATEMENT)}
          onRun={() =>
            runFuturePack("run_financeos", buildFinanceCommandInputFromStatement(financePayload))
          }
        />
        <HealthcareOSPanel
          running={futurePackRunning === "run_healthcareos"}
          operationDisabled={Boolean(writeUnavailable)}
          result={futurePackResult.run_healthcareos ?? null}
          transcriptText={healthcareTranscriptPayload}
          consentText={healthcareConsentPayload}
          onTranscriptChange={setHealthcareTranscriptPayload}
          onConsentChange={setHealthcareConsentPayload}
          onLoadSample={() => {
            setHealthcareTranscriptPayload(SAMPLE_HEALTHCARE_TRANSCRIPT);
            setHealthcareConsentPayload(SAMPLE_HEALTHCARE_CONSENT);
          }}
          onRun={() =>
            runFuturePack(
              "run_healthcareos",
              buildHealthcareCommandInput(healthcareTranscriptPayload, healthcareConsentPayload),
            )
          }
        />
      </main>
    </div>
  );
}
