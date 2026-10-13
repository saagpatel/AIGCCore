import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const invokeMock = vi.fn();

const localExportAuthority = {
  schema_version: "EVIDENCE_AUTHORITY_V1",
  case_id: "r_test",
  requested_execution_class: "CONTROLLED",
  observed_execution_class: "CONTROLLED",
  evidence_origin: "LOCAL_ARTIFACT_EXPORT",
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
  limitations: ["Local artifact export only; no runtime network traffic was measured."],
};

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

describe("App", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockImplementation(async (command: string) => {
      switch (command) {
        case "get_network_snapshot":
          return {
            network_mode: "OFFLINE",
            proof_level: "OFFLINE_STRICT",
            proof_source: "POLICY_DECLARATION",
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
            status: "COMPLETED",
            bundle_path: "/tmp/evidence.zip",
            bundle_sha256: "abc123",
            encryption_at_rest: false,
            model_used: false,
            missing_control_ids: ["CTRL-9"],
            evidence_authority: localExportAuthority,
          };
        default:
          throw new Error(`Unexpected command: ${command}`);
      }
    });
  });

  it("renders and runs only the EvidenceOS pack", async () => {
    render(<App />);

    await screen.findByRole("heading", { level: 1, name: "AIGC Core" });
    await screen.findByText("CTRL-1");
    expect(screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent)).toEqual([
      "Phase 2 Hard Guarantees",
      "Phase 3 EvidenceOS Pack",
    ]);

    fireEvent.click(screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }));
    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("generate_evidenceos_bundle", expect.any(Object));
    });
    await screen.findByText("Missing controls: CTRL-9");
    expect(screen.getByText("Encryption at rest: Not used")).toBeTruthy();
    expect(screen.getByText("Model or adapter: Not run")).toBeTruthy();
    expect(screen.getByText(/Declared by enforced policy; not runtime measured/)).toBeTruthy();
    const exportCall = invokeMock.mock.calls.find(
      ([command]) => command === "generate_evidenceos_bundle",
    );
    expect(exportCall?.[1]).toMatchObject({
      input: { artifact_sha256: "40b42acfb2d022e6e11ed46ddb9f3dcf4c3b3669bd7ac9520a15da393ff0d2f0" },
    });
    expect(screen.getByText("Missing controls: CTRL-9").closest("[role='status']")).toBeTruthy();
    await screen.findByText("CONTROLLED / LOCAL_ARTIFACT_EXPORT");
    await screen.findByText(
      "Must not satisfy: LIVE_EXECUTION, PRODUCTION_AUTHORITY, EXTERNAL_MUTATION",
    );
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

    const evidenceButton = screen.getByRole("button", { name: "Generate EvidenceOS Bundle" });
    expect((evidenceButton as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("main").getAttribute("aria-busy")).toBe("true");
    expect(
      screen.getByText("Exports are unavailable while network enforcement status is loading."),
    ).toBeTruthy();

    resolveNetwork?.({
      network_mode: "OFFLINE",
      proof_level: "OFFLINE_STRICT",
      proof_source: "POLICY_DECLARATION",
      ui_remote_fetch_disabled: true,
    });

    await waitFor(() => {
      expect((evidenceButton as HTMLButtonElement).disabled).toBe(false);
      expect(screen.getByRole("main").getAttribute("aria-busy")).toBeNull();
    });
  });

  it("uses one canonical alert when the control library is unavailable", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "get_network_snapshot") {
        return {
          network_mode: "OFFLINE",
          proof_level: "OFFLINE_STRICT",
          proof_source: "POLICY_DECLARATION",
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

  it("shows an error and skips export when the payload digest is malformed", async () => {
    vi.spyOn(globalThis.crypto.subtle, "digest").mockResolvedValue(
      new Uint8Array([1, 2, 3]).buffer,
    );
    render(<App />);
    await screen.findByText("CTRL-1");

    fireEvent.click(screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Could not compute a valid SHA-256");
    expect(
      invokeMock.mock.calls.some(([command]) => command === "generate_evidenceos_bundle"),
    ).toBe(false);
    expect(
      (screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });

  it("shows an error and skips export when Web Crypto rejects the digest request", async () => {
    vi.spyOn(globalThis.crypto.subtle, "digest").mockRejectedValue(
      new Error("Web Crypto unavailable"),
    );
    render(<App />);
    await screen.findByText("CTRL-1");

    fireEvent.click(screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Web Crypto unavailable");
    expect(
      invokeMock.mock.calls.some(([command]) => command === "generate_evidenceos_bundle"),
    ).toBe(false);
    expect(screen.getByRole("button", { name: "Generate EvidenceOS Bundle" })).toBeTruthy();
  });

  it("reports unavailable encryption and model state as unknown", async () => {
    const defaultInvoke = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation(async (command: string, ...args: unknown[]) => {
      const result = await defaultInvoke(command, ...args);
      if (command === "generate_evidenceos_bundle") {
        return Object.fromEntries(
          Object.entries(result as Record<string, unknown>).filter(
            ([key]) => key !== "encryption_at_rest" && key !== "model_used",
          ),
        );
      }
      return result;
    });
    render(<App />);
    await screen.findByText("CTRL-1");

    fireEvent.click(screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }));

    expect(await screen.findByText("Encryption at rest: Unknown")).toBeTruthy();
    expect(screen.getByText("Model or adapter: Unknown")).toBeTruthy();
    expect(screen.queryByText("Encryption at rest: Not used")).toBeNull();
    expect(screen.queryByText("Model or adapter: Not run")).toBeNull();
  });

  it("reports encryption and model use only when the result records them", async () => {
    const defaultInvoke = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation(async (command: string, ...args: unknown[]) => {
      const result = await defaultInvoke(command, ...args);
      if (command === "generate_evidenceos_bundle") {
        return { ...(result as Record<string, unknown>), encryption_at_rest: true, model_used: true };
      }
      return result;
    });
    render(<App />);
    await screen.findByText("CTRL-1");

    fireEvent.click(screen.getByRole("button", { name: "Generate EvidenceOS Bundle" }));

    expect(await screen.findByText("Encryption at rest: Used")).toBeTruthy();
    expect(screen.getByText("Model or adapter: Used")).toBeTruthy();
  });

  it("serializes EvidenceOS exports and releases the operation lock after failure", async () => {
    let rejectExport: ((reason: Error) => void) | undefined;
    const defaultInvoke = invokeMock.getMockImplementation()!;
    invokeMock.mockImplementation((command: string, ...args: unknown[]) => {
      if (command === "generate_evidenceos_bundle") {
        return new Promise((_resolve, reject) => {
          rejectExport = reject;
        });
      }
      return defaultInvoke(command, ...args);
    });

    render(<App />);
    await screen.findByText("CTRL-1");
    const button = screen.getByRole("button", { name: "Generate EvidenceOS Bundle" });
    fireEvent.click(button);

    await waitFor(() => {
      expect((button as HTMLButtonElement).disabled).toBe(true);
      expect(
        invokeMock.mock.calls.filter(([command]) => command === "generate_evidenceos_bundle"),
      ).toHaveLength(1);
    });
    expect(button.textContent).toBe("Generating EvidenceOS Bundle…");
    expect(screen.getByRole("main").getAttribute("aria-busy")).toBe("true");
    fireEvent.click(button);
    expect(
      invokeMock.mock.calls.filter(([command]) => command === "generate_evidenceos_bundle"),
    ).toHaveLength(1);

    rejectExport?.(new Error("fixture export failed"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("fixture export failed");
    expect((button as HTMLButtonElement).disabled).toBe(false);
    expect(screen.getByRole("main").getAttribute("aria-busy")).toBeNull();
    expect(screen.queryByText(/Bundle path:/)).toBeNull();

    invokeMock.mockImplementation(defaultInvoke);
    fireEvent.click(button);
    await screen.findByText("Bundle path: /tmp/evidence.zip");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(
      invokeMock.mock.calls.filter(([command]) => command === "generate_evidenceos_bundle"),
    ).toHaveLength(2);
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
});
