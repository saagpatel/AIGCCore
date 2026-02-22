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

export function FinanceOSPanel({
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
      <h2>Phase 6 FinanceOS</h2>
      <p>Run exception detection with audit deliverables, compliance summary, and export bundle.</p>
      <div className="form-grid">
        <label htmlFor="finance-payload">Finance statement payload (JSON)</label>
        <textarea
          id="finance-payload"
          rows={5}
          value={payloadText}
          onChange={(event) => onPayloadChange(event.target.value)}
          placeholder="Paste statement JSON here"
        />
      </div>
      <button type="button" onClick={onLoadSample}>
        Load FinanceOS sample data
      </button>
      <button type="button" disabled={running || !canRun} onClick={() => void onRun()}>
        {running ? "Running FinanceOS..." : "Run FinanceOS Export"}
      </button>
      {!canRun && <p className="meta">Provide statement JSON or load sample data.</p>}
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
