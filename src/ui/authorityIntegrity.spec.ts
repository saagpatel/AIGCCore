import { beforeEach, describe, expect, it, vi } from "vitest";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { probeAuthorityIntegrityAdapter } from "./authorityIntegrity";

describe("authority integrity adapter hook", () => {
  beforeEach(() => {
    invoke.mockReset();
  });

  it("uses the registered Tauri command and stable input envelope", async () => {
    invoke.mockResolvedValue({
      adapter_id: "authority-integrity-probe",
      endpoint: "http://127.0.0.1:4000",
      dependency_path_reached: true,
    });

    await expect(probeAuthorityIntegrityAdapter("http://127.0.0.1:4000")).resolves.toMatchObject({
      dependency_path_reached: true,
    });
    expect(invoke).toHaveBeenCalledWith("authority_integrity_probe_adapter", {
      input: { endpoint: "http://127.0.0.1:4000" },
    });
  });

  it("propagates a policy rejection", async () => {
    invoke.mockRejectedValue(new Error("adapter endpoint rejected"));

    await expect(probeAuthorityIntegrityAdapter("http://203.0.113.1:9")).rejects.toThrow(
      "adapter endpoint rejected",
    );
  });

  it("does not normalize malformed input before the Rust policy sees it", async () => {
    invoke.mockRejectedValue(new Error("invalid adapter endpoint URL"));

    await expect(probeAuthorityIntegrityAdapter("not-a-url")).rejects.toThrow(
      "invalid adapter endpoint URL",
    );
    expect(invoke).toHaveBeenCalledWith("authority_integrity_probe_adapter", {
      input: { endpoint: "not-a-url" },
    });
  });
});
