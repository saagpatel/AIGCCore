import type { PackCommandStatus } from "./types";

type Props = {
  running: boolean;
  result: PackCommandStatus | null;
  error: string | null;
  payloadText: string;
  onPayloadChange: (value: string) => void;
  onLoadSample: () => void;
  onRun: () => Promise<void>;
};

export function IncidentOSPanel({
  running,
  result,
  error,
  payloadText,
  onPayloadChange,
  onLoadSample,
  onRun,
}: Props) {
  const canRun = payloadText.trim().length > 0;
  return (
    <section className="card">
      <h2>Phase 5 IncidentOS</h2>
      <p>
        Run timeline reconstruction with redacted customer packet, internal packet, and export
        bundle.
      </p>
      <div className="form-grid">
        <label htmlFor="incident-payload">Incident payload (JSON/NDJSON)</label>
        <textarea
          id="incident-payload"
          rows={5}
          value={payloadText}
          onChange={(event) => onPayloadChange(event.target.value)}
          placeholder="Paste incident records here"
        />
      </div>
      <button type="button" onClick={onLoadSample}>
        Load IncidentOS sample data
      </button>
      <button type="button" disabled={running || !canRun} onClick={() => void onRun()}>
        {running ? "Running IncidentOS..." : "Run IncidentOS Export"}
      </button>
      {!canRun && <p className="meta">Provide incident payload text or load sample data.</p>}
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
