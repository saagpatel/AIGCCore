import type { PackCommandStatus } from "./types";

type Props = {
  running: boolean;
  result: PackCommandStatus | null;
  error: string | null;
  transcriptText: string;
  consentText: string;
  onTranscriptChange: (value: string) => void;
  onConsentChange: (value: string) => void;
  onLoadSample: () => void;
  onRun: () => Promise<void>;
};

export function HealthcareOSPanel({
  running,
  result,
  error,
  transcriptText,
  consentText,
  onTranscriptChange,
  onConsentChange,
  onLoadSample,
  onRun,
}: Props) {
  const canRun = transcriptText.trim().length > 0 && consentText.trim().length > 0;
  return (
    <section className="card">
      <h2>Phase 7 HealthcareOS</h2>
      <p>Run consent-gated clinical drafting with verification outputs and export bundle.</p>
      <div className="form-grid">
        <label htmlFor="healthcare-transcript-payload">Transcript payload (JSON)</label>
        <textarea
          id="healthcare-transcript-payload"
          rows={4}
          value={transcriptText}
          onChange={(event) => onTranscriptChange(event.target.value)}
          placeholder="Paste transcript JSON here"
        />
        <label htmlFor="healthcare-consent-payload">Consent payload (JSON)</label>
        <textarea
          id="healthcare-consent-payload"
          rows={4}
          value={consentText}
          onChange={(event) => onConsentChange(event.target.value)}
          placeholder="Paste consent JSON here"
        />
      </div>
      <button type="button" onClick={onLoadSample}>
        Load HealthcareOS sample data
      </button>
      <button type="button" disabled={running || !canRun} onClick={() => void onRun()}>
        {running ? "Running HealthcareOS..." : "Run HealthcareOS Export"}
      </button>
      {!canRun && (
        <p className="meta">Provide transcript and consent payloads or load sample data.</p>
      )}
      {error && <p className="error">{error}</p>}
      {result && (
        <div className="result">
          <p>Status: {result.status}</p>
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
