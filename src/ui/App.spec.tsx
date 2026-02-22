import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

describe("App", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockImplementation(async (command: string) => {
      switch (command) {
        case "get_network_snapshot":
          return {
            network_mode: "OFFLINE",
            proof_level: "OFFLINE_STRICT",
            ui_remote_fetch_disabled: true,
          };
        case "list_control_library":
          return [
            {
              control_id: "CTRL-1",
              title: "Offline enforcement",
              capability: "Network",
              control_family: "NetworkGovernance",
              description: "No direct egress is allowed.",
            },
          ];
        case "generate_evidenceos_bundle":
          return {
            status: "SUCCESS",
            bundle_path: "/tmp/evidence.zip",
            bundle_sha256: "abc123",
            missing_control_ids: ["CTRL-9"],
          };
        case "run_redlineos":
          return {
            status: "SUCCESS",
            message: "run_redlineos complete",
            bundle_path: "/tmp/redline.zip",
            bundle_sha256: "sha-redline",
            run_id: "r_redline",
          };
        case "run_incidentos":
          return {
            status: "SUCCESS",
            message: "run_incidentos complete",
            bundle_path: "/tmp/incident.zip",
            bundle_sha256: "sha-incident",
            run_id: "r_incident",
          };
        case "run_financeos":
          return {
            status: "SUCCESS",
            message: "run_financeos complete",
            bundle_path: "/tmp/finance.zip",
            bundle_sha256: "sha-finance",
            run_id: "r_finance",
          };
        case "run_healthcareos":
          return {
            status: "SUCCESS",
            message: "run_healthcareos complete",
            bundle_path: "/tmp/healthcare.zip",
            bundle_sha256: "sha-healthcare",
            run_id: "r_healthcare",
          };
        default:
          throw new Error(`Unexpected command: ${command}`);
      }
    });
  });

  it("renders and runs EvidenceOS plus all pack commands", async () => {
    render(<App />);

    await screen.findByRole("heading", { level: 1, name: "AIGC Core" });
    await screen.findByText("CTRL-1");

    fireEvent.click(screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }));
    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("generate_evidenceos_bundle", expect.any(Object));
    });
    await screen.findByText("Missing controls: CTRL-9");

    fireEvent.click(screen.getByRole("button", { name: "Load RedlineOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Generate Risk Assessment" }));
    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("run_redlineos", expect.any(Object));
    });
    await screen.findByText("Bundle path: /tmp/redline.zip");

    fireEvent.click(screen.getByRole("button", { name: "Load IncidentOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run IncidentOS Export" }));
    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("run_incidentos", expect.any(Object));
    });
    await screen.findByText("Bundle path: /tmp/incident.zip");

    fireEvent.click(screen.getByRole("button", { name: "Load FinanceOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run FinanceOS Export" }));
    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("run_financeos", expect.any(Object));
    });
    await screen.findByText("Bundle path: /tmp/finance.zip");

    fireEvent.click(screen.getByRole("button", { name: "Load HealthcareOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run HealthcareOS Export" }));
    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("run_healthcareos", expect.any(Object));
    });
    await screen.findByText("Bundle path: /tmp/healthcare.zip");
  });

  it("starts in real-input mode with pack run buttons disabled until payload exists", async () => {
    render(<App />);
    await screen.findByRole("heading", { level: 1, name: "AIGC Core" });

    expect(
      (screen.getByRole("button", { name: "Generate Risk Assessment" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(
      (screen.getByRole("button", { name: "Run IncidentOS Export" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(
      (screen.getByRole("button", { name: "Run FinanceOS Export" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(
      (screen.getByRole("button", { name: "Run HealthcareOS Export" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Load IncidentOS sample data" }));
    expect(
      (screen.getByRole("button", { name: "Run IncidentOS Export" }) as HTMLButtonElement).disabled,
    ).toBe(false);
  });

  it("surfaces actionable blocked errors across pack commands", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_network_snapshot") {
        return {
          network_mode: "OFFLINE",
          proof_level: "OFFLINE_STRICT",
          ui_remote_fetch_disabled: true,
        };
      }
      if (command === "list_control_library") {
        return [];
      }
      if (command === "run_incidentos") {
        return {
          status: "BLOCKED",
          message: "Missing artifact payload for artifact_id=i_demo",
        };
      }
      if (command === "run_financeos") {
        return {
          status: "BLOCKED",
          message: "Failed to parse finance statement payload",
          error_code: "FINANCE_STATEMENT_INVALID_FORMAT",
        };
      }
      if (command === "run_healthcareos") {
        return {
          status: "BLOCKED",
          message: "HealthcareOS workflow failed: revoked consent",
          error_code: "HEALTHCAREOS_WORKFLOW_INVALID_INPUT",
        };
      }
      return { status: "SUCCESS", message: `${command} complete` };
    });

    render(<App />);
    await screen.findByRole("heading", { level: 1, name: "AIGC Core" });

    fireEvent.click(screen.getByRole("button", { name: "Load IncidentOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run IncidentOS Export" }));
    await waitFor(() => {
      expect(
        screen.getAllByText("Missing artifact payload for artifact_id=i_demo").length,
      ).toBeGreaterThanOrEqual(1);
    });

    fireEvent.click(screen.getByRole("button", { name: "Load FinanceOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run FinanceOS Export" }));
    await waitFor(() => {
      expect(
        screen.getByText(
          "Failed to parse finance statement payload (FINANCE_STATEMENT_INVALID_FORMAT)",
        ),
      ).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Load HealthcareOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run HealthcareOS Export" }));
    await waitFor(() => {
      expect(
        screen.getByText(
          "HealthcareOS workflow failed: revoked consent (HEALTHCAREOS_WORKFLOW_INVALID_INPUT)",
        ),
      ).toBeTruthy();
    });
  });

  it("maps invoke runtime exceptions to failed pack status metadata", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_network_snapshot") {
        return {
          network_mode: "OFFLINE",
          proof_level: "OFFLINE_STRICT",
          ui_remote_fetch_disabled: true,
        };
      }
      if (command === "list_control_library") {
        return [];
      }
      if (command === "run_healthcareos") {
        throw new Error("invoke exploded");
      }
      return { status: "SUCCESS", message: `${command} complete` };
    });

    render(<App />);
    await screen.findByRole("heading", { level: 1, name: "AIGC Core" });

    fireEvent.click(screen.getByRole("button", { name: "Load HealthcareOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run HealthcareOS Export" }));
    await waitFor(() => {
      expect(screen.getByText("Status: FAILED")).toBeTruthy();
      expect(screen.getByText("Error code: INVOKE_RUNTIME_ERROR")).toBeTruthy();
      expect(screen.getAllByText("Error: invoke exploded").length).toBeGreaterThanOrEqual(1);
    });
  });
});
