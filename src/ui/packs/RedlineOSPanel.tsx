import React, { useState } from "react";
import type { PackCommandStatus, RedlineCommandInput, RedlineOSInput } from "./types";
import { SAMPLE_REDLINE_CONTRACT_BASE64 } from "./samplePayloads";

type Props = {
  running: boolean;
  result: PackCommandStatus | null;
  error: string | null;
  onRun: (input: RedlineCommandInput) => Promise<void>;
};

export function RedlineOSPanel({ running, result, error, onRun }: Props) {
  const [extractionMode, setExtractionMode] = useState<"NATIVE_PDF" | "OCR">("NATIVE_PDF");
  const [jurisdiction, setJurisdiction] = useState<string>("US-CA");
  const [reviewProfile, setReviewProfile] = useState<"default" | "aggressive" | "conservative">(
    "default",
  );
  const [contractBase64, setContractBase64] = useState<string>("");
  const [localError, setLocalError] = useState<string>("");

  const handleRun = async () => {
    const base64Payload = contractBase64.trim();
    if (!base64Payload) {
      setLocalError("Provide contract payload bytes or load sample data.");
      return;
    }
    setLocalError("");
    const workflowInput: RedlineOSInput = {
      schema_version: "REDLINEOS_INPUT_V1",
      contract_artifacts: [
        {
          artifact_id: "a_demo_contract",
          sha256: "demo_sha256",
          filename: "contract.pdf",
        },
      ],
      extraction_mode: extractionMode,
      jurisdiction_hint: jurisdiction || null,
      review_profile: reviewProfile,
    };
    const input: RedlineCommandInput = {
      ...workflowInput,
      artifact_payloads: [
        {
          artifact_id: "a_demo_contract",
          content_base64: base64Payload,
        },
      ],
    };
    await onRun(input);
  };

  const handleLoadSampleData = () => {
    setContractBase64(SAMPLE_REDLINE_CONTRACT_BASE64);
    setLocalError("");
  };

  return (
    <section className="card">
      <h2>Phase 4: RedlineOS (Contract Review)</h2>
      <p>Extract clauses, assess risks, generate risk memo with citations.</p>

      <div className="form-grid">
        <label htmlFor="extraction-mode">Extraction Mode</label>
        <select
          id="extraction-mode"
          value={extractionMode}
          onChange={(e) => setExtractionMode(e.target.value as "NATIVE_PDF" | "OCR")}
        >
          <option value="NATIVE_PDF">Native PDF (digital)</option>
          <option value="OCR">OCR (scanned)</option>
        </select>

        <label htmlFor="jurisdiction">Jurisdiction Hint</label>
        <input
          id="jurisdiction"
          type="text"
          value={jurisdiction}
          onChange={(e) => setJurisdiction(e.target.value)}
          placeholder="US-CA"
        />

        <label htmlFor="review-profile">Review Profile</label>
        <select
          id="review-profile"
          value={reviewProfile}
          onChange={(e) =>
            setReviewProfile(e.target.value as "default" | "aggressive" | "conservative")
          }
        >
          <option value="default">Default</option>
          <option value="aggressive">Aggressive</option>
          <option value="conservative">Conservative</option>
        </select>

        <label htmlFor="contract-base64">Contract payload (Base64 PDF)</label>
        <textarea
          id="contract-base64"
          rows={4}
          value={contractBase64}
          onChange={(e) => setContractBase64(e.target.value)}
        />
      </div>

      <button type="button" disabled={running || !contractBase64.trim()} onClick={handleRun}>
        {running ? "Analyzing Contract..." : "Generate Risk Assessment"}
      </button>
      <button type="button" onClick={handleLoadSampleData}>
        Load RedlineOS sample data
      </button>

      {!contractBase64.trim() && (
        <p className="meta">Provide PDF payload bytes in Base64 or load sample data.</p>
      )}
      {localError && <p className="error">{localError}</p>}
      {error && <p className="error">{error}</p>}
      {result && (
        <div className="result">
          <p>
            Status: <strong>{result.status}</strong>
          </p>
          <p>{result.message}</p>
          {result.error_code && <p>Error code: {result.error_code}</p>}
          {result.run_id && <p>Run ID: {result.run_id}</p>}
          {result.audit_path && <p>Audit path: {result.audit_path}</p>}
          {result.bundle_path && <p>Bundle path: {result.bundle_path}</p>}
          {result.bundle_sha256 && <p>Bundle SHA-256: {result.bundle_sha256}</p>}
        </div>
      )}
    </section>
  );
}
