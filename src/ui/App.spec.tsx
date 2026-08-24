import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const invokeMock = vi.fn();

const controlledAuthority = {
  schema_version: "EVIDENCE_AUTHORITY_V1",
  case_id: "r_test",
  requested_execution_class: "CONTROLLED",
  observed_execution_class: "CONTROLLED",
  evidence_origin: "CONTROL_SIMULATION",
  production_equivalent: false,
  generated_at_utc: "2026-07-20T12:00:00Z",
  valid_until_utc: "2026-07-21T12:00:00Z",
  source: {
    producer: "aigccore-tauri:generate_evidenceos_bundle",
    source_revision: "test-revision",
    executable: "/tmp/aigccore",
    executable_sha256: "a".repeat(64),
    arguments_sha256: "b".repeat(64),
    environment_sha256: "c".repeat(64),
    audit_log_sha256: "d".repeat(64),
  },
  allowed_effects: ["LOCAL_EVIDENCE_BUNDLE_WRITE"],
  observed_effects: ["LOCAL_EVIDENCE_BUNDLE_WRITE"],
  credential_availability: "NOT_REQUESTED",
  tools: [
    {
      tool_id: "LOCAL_EVIDENCE_BUNDLE_EXPORT",
      declared_available: true,
      observed_used: true,
      external_mutation_allowed: false,
    },
  ],
  state_scope: {
    cache_scope: "CASE_LOCAL",
    prior_approval_reused: false,
    credential_state_reused: false,
    mutable_cache_reused: false,
  },
  downstream_claims: {
    may_satisfy: ["LOCAL_CONTROLLED_EXECUTION", "BUNDLE_INTEGRITY"],
    must_not_satisfy: ["LIVE_EXECUTION", "PRODUCTION_AUTHORITY", "EXTERNAL_MUTATION"],
  },
  limitations: ["Blocked-egress evidence is simulated, not live traffic."],
};

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
            evidence_authority: controlledAuthority,
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
    expect(screen.getByText("Missing controls: CTRL-9").closest("[role='status']")).toBeTruthy();
    await screen.findByText("CONTROLLED / CONTROL_SIMULATION");
    await screen.findByText(
      "Must not satisfy: LIVE_EXECUTION, PRODUCTION_AUTHORITY, EXTERNAL_MUTATION",
    );

    fireEvent.click(screen.getByRole("button", { name: "Load RedlineOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Generate Risk Assessment" }));
    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("run_redlineos", expect.any(Object));
    });
    const redlineBundlePath = await screen.findByText("Bundle path: /tmp/redline.zip");
    const redlineResult = redlineBundlePath.closest(".result");
    expect(redlineResult?.getAttribute("role")).toBe("status");
    expect(redlineResult?.textContent).toContain("Evidence authority: UNKNOWN");
    expect(redlineResult?.textContent).toContain("This result is non-authorizing");

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
      expect(screen.getAllByText("Missing artifact payload for artifact_id=i_demo")).toHaveLength(
        1,
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Load FinanceOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run FinanceOS Export" }));
    await waitFor(() => {
      expect(screen.getByText("Failed to parse finance statement payload")).toBeTruthy();
      expect(screen.getByText("Error code: FINANCE_STATEMENT_INVALID_FORMAT")).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Load HealthcareOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run HealthcareOS Export" }));
    await waitFor(() => {
      expect(screen.getByText("HealthcareOS workflow failed: revoked consent")).toBeTruthy();
      expect(screen.getByText("Error code: HEALTHCAREOS_WORKFLOW_INVALID_INPUT")).toBeTruthy();
    });
  });

  it("blocks exports until runtime readiness is known", async () => {
    let resolveNetwork: ((value: unknown) => void) | undefined;
    invokeMock.mockImplementation((command: string) => {
      if (command === "get_network_snapshot") {
        return new Promise((resolve) => {
          resolveNetwork = resolve;
        });
      }
      if (command === "list_control_library") return Promise.resolve([]);
      return Promise.resolve({ status: "SUCCESS", message: `${command} complete` });
    });

    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Load IncidentOS sample data" }));

    const evidenceButton = screen.getByRole("button", { name: "Generate EvidenceOS Bundle" });
    const incidentButton = screen.getByRole("button", { name: "Run IncidentOS Export" });
    expect((evidenceButton as HTMLButtonElement).disabled).toBe(true);
    expect((incidentButton as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("main").getAttribute("aria-busy")).toBe("true");
    expect(
      screen.getByText("Exports are unavailable while network enforcement status is loading."),
    ).toBeTruthy();

    resolveNetwork?.({
      network_mode: "OFFLINE",
      proof_level: "OFFLINE_STRICT",
      ui_remote_fetch_disabled: true,
    });

    await waitFor(() => {
      expect((evidenceButton as HTMLButtonElement).disabled).toBe(false);
      expect((incidentButton as HTMLButtonElement).disabled).toBe(false);
      expect(screen.getByRole("main").getAttribute("aria-busy")).toBeNull();
    });
  });

  it("uses one canonical alert when the control library is unavailable", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_network_snapshot") {
        return {
          network_mode: "OFFLINE",
          proof_level: "OFFLINE_STRICT",
          ui_remote_fetch_disabled: true,
        };
      }
      if (command === "list_control_library") throw new Error("fixture controls unavailable");
      return { status: "SUCCESS", message: `${command} complete` };
    });

    render(<App />);

    const alert = await screen.findByRole("alert");
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(alert.textContent).toContain("fixture controls unavailable");
    expect(
      (screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it("rejects empty EvidenceOS fields without replacing or losing input", async () => {
    render(<App />);
    await screen.findByText("CTRL-1");

    const artifactTitle = screen.getByLabelText("Artifact title") as HTMLInputElement;
    fireEvent.change(artifactTitle, { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }));

    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Artifact title");
    expect(artifactTitle.value).toBe("");
    expect(artifactTitle.getAttribute("aria-invalid")).toBe("true");
    expect(
      invokeMock.mock.calls.some(([command]) => command === "generate_evidenceos_bundle"),
    ).toBe(false);

    fireEvent.change(artifactTitle, { target: { value: "Recovered title 🧭" } });
    expect(artifactTitle.value).toBe("Recovered title 🧭");
    expect(artifactTitle.getAttribute("aria-invalid")).toBeNull();
    expect(screen.queryByText(/Complete the required EvidenceOS fields/)).toBeNull();
  });

  it("serializes local export operations across packs", async () => {
    let resolveIncident: ((value: unknown) => void) | undefined;
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_network_snapshot") {
        return {
          network_mode: "OFFLINE",
          proof_level: "OFFLINE_STRICT",
          ui_remote_fetch_disabled: true,
        };
      }
      if (command === "list_control_library") return [];
      if (command === "run_incidentos") {
        return new Promise((resolve) => {
          resolveIncident = resolve;
        });
      }
      return { status: "SUCCESS", message: `${command} complete` };
    });

    render(<App />);
    await screen.findByText("No controls are available for this capability.");
    fireEvent.click(screen.getByRole("button", { name: "Load IncidentOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Load FinanceOS sample data" }));
    fireEvent.click(screen.getByRole("button", { name: "Run IncidentOS Export" }));

    const financeButton = screen.getByRole("button", { name: "Run FinanceOS Export" });
    await waitFor(() => {
      expect((financeButton as HTMLButtonElement).disabled).toBe(true);
      expect(
        (screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }) as HTMLButtonElement)
          .disabled,
      ).toBe(true);
    });
    fireEvent.click(financeButton);
    expect(invokeMock.mock.calls.filter(([command]) => command === "run_financeos")).toHaveLength(
      0,
    );

    resolveIncident?.({ status: "SUCCESS", message: "Incident complete" });
    await screen.findByText("Incident complete");
    await waitFor(() => expect((financeButton as HTMLButtonElement).disabled).toBe(false));
  });

  it("reports the network state as unresolved instead of fabricating OFFLINE_STRICT", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_network_snapshot") {
        throw new Error("ipc unavailable");
      }
      if (command === "list_control_library") {
        return [];
      }
      return { status: "SUCCESS", message: `${command} complete` };
    });

    render(<App />);
    await screen.findByRole("heading", { level: 1, name: "AIGC Core" });

    const networkBadge = await screen.findByTestId("network-status");
    await waitFor(() => {
      expect(networkBadge.textContent).toContain("UNKNOWN");
    });

    expect(networkBadge.textContent).not.toContain("OFFLINE_STRICT");
    expect(networkBadge.textContent).not.toContain("OFFLINE");
    expect(networkBadge.textContent).toContain("Enforcement layer unreachable");
    expect(networkBadge.querySelector("[data-status]")?.getAttribute("data-status")).toBe(
      "UNKNOWN",
    );
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
      const failedWord = screen.getByText("FAILED");
      expect(failedWord.closest(".status-badge")?.getAttribute("data-tone")).toBe("bad");
      expect(screen.getByText("Error code: INVOKE_RUNTIME_ERROR")).toBeTruthy();
      expect(screen.getAllByText("Error: invoke exploded").length).toBeGreaterThanOrEqual(1);
    });
  });
});
