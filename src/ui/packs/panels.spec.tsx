import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { FinanceOSPanel } from "./FinanceOSPanel";
import { HealthcareOSPanel } from "./HealthcareOSPanel";
import { IncidentOSPanel } from "./IncidentOSPanel";
import { RedlineOSPanel } from "./RedlineOSPanel";

describe("pack panels", () => {
  it("renders incident, finance, and healthcare runtime input states", () => {
    const resolved = () => Promise.resolve();
    const noop = () => {};

    const { rerender } = render(
      <IncidentOSPanel
        running={false}
        result={null}
        error={null}
        payloadText=""
        onPayloadChange={noop}
        onLoadSample={noop}
        onRun={resolved}
      />,
    );
    expect(
      (screen.getByRole("button", { name: "Run IncidentOS Export" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(screen.getByText("Provide incident payload text or load sample data.")).toBeTruthy();

    rerender(
      <IncidentOSPanel
        running={false}
        result={{
          status: "SUCCESS",
          message: "ok",
          bundle_path: "/tmp/inc.zip",
          bundle_sha256: "abc",
          run_id: "r_incident",
          audit_path: "/tmp/inc/audit.ndjson",
        }}
        error="incident error"
        payloadText={'{"ok":true}'}
        onPayloadChange={noop}
        onLoadSample={noop}
        onRun={resolved}
      />,
    );
    expect(screen.getByText("incident error")).toBeTruthy();
    expect(screen.getByText("Bundle path: /tmp/inc.zip")).toBeTruthy();
    expect(screen.getByText("Run ID: r_incident")).toBeTruthy();

    rerender(
      <FinanceOSPanel
        running
        result={{
          status: "BLOCKED",
          message: "Missing statement payload",
          error_code: "ARTIFACT_PAYLOAD_MISSING",
        }}
        error={null}
        payloadText={'{"statement_id":"x"}'}
        onPayloadChange={noop}
        onLoadSample={noop}
        onRun={resolved}
      />,
    );
    expect(
      (screen.getByRole("button", { name: "Running FinanceOS..." }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(screen.getByText("Error code: ARTIFACT_PAYLOAD_MISSING")).toBeTruthy();

    rerender(
      <HealthcareOSPanel
        running={false}
        result={{
          status: "SUCCESS",
          message: "ok",
          bundle_path: "/tmp/health.zip",
          bundle_sha256: "ghi",
          run_id: "r_health",
          audit_path: "/tmp/health/audit.ndjson",
        }}
        error={null}
        transcriptText={'{"transcript":true}'}
        consentText={'{"consent":true}'}
        onTranscriptChange={noop}
        onConsentChange={noop}
        onLoadSample={noop}
        onRun={resolved}
      />,
    );
    expect(
      (screen.getByRole("button", { name: "Run HealthcareOS Export" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    expect(screen.getByText("Bundle path: /tmp/health.zip")).toBeTruthy();
    expect(screen.getByText("Audit path: /tmp/health/audit.ndjson")).toBeTruthy();
  });

  it("supports redline sample toggle and command payload generation", async () => {
    const onRun = vi.fn(async (_input: unknown) => {});
    render(<RedlineOSPanel running={false} result={null} error={null} onRun={onRun} />);

    const runButton = screen.getByRole("button", { name: "Generate Risk Assessment" });
    expect((runButton as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Load RedlineOS sample data" }));
    expect((runButton as HTMLButtonElement).disabled).toBe(false);

    fireEvent.change(screen.getByLabelText("Extraction Mode"), {
      target: { value: "OCR" },
    });
    fireEvent.change(screen.getByLabelText("Jurisdiction Hint"), {
      target: { value: "US-NY" },
    });
    fireEvent.change(screen.getByLabelText("Review Profile"), {
      target: { value: "aggressive" },
    });
    fireEvent.change(screen.getByLabelText("Contract payload (Base64 PDF)"), {
      target: { value: "  abc123  " },
    });
    fireEvent.click(runButton);

    await waitFor(() => {
      expect(onRun).toHaveBeenCalledTimes(1);
    });

    const commandInput = onRun.mock.calls[0]?.[0] as {
      extraction_mode: string;
      jurisdiction_hint: string;
      review_profile: string;
      artifact_payloads: Array<{ content_base64: string }>;
    };
    expect(commandInput.extraction_mode).toBe("OCR");
    expect(commandInput.jurisdiction_hint).toBe("US-NY");
    expect(commandInput.review_profile).toBe("aggressive");
    expect(commandInput.artifact_payloads[0].content_base64).toBe("abc123");
  });
});
