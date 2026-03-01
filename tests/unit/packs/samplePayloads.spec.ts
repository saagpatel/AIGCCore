import { describe, expect, it } from "vitest";
import {
  buildFinanceCommandInput,
  buildHealthcareCommandInput,
  buildIncidentCommandInput,
  SAMPLE_REDLINE_CONTRACT_BASE64,
} from "../../../src/ui/packs/samplePayloads";

describe("sample pack command payload builders", () => {
  it("builds incident command input with matching artifact payload", () => {
    const input = buildIncidentCommandInput();
    expect(input.schema_version).toBe("INCIDENTOS_INPUT_V1");
    expect(input.artifact_payloads).toHaveLength(1);
    expect(input.artifact_payloads[0].artifact_id).toBe(input.incident_artifacts[0].artifact_id);
    expect(input.artifact_payloads[0].content_text?.length ?? 0).toBeGreaterThan(100);
  });

  it("builds finance command input with statement JSON payload", () => {
    const input = buildFinanceCommandInput();
    expect(input.schema_version).toBe("FINANCEOS_INPUT_V1");
    expect(input.artifact_payloads).toHaveLength(1);
    expect(input.artifact_payloads[0].artifact_id).toBe(input.finance_artifacts[0].artifact_id);
    expect(input.artifact_payloads[0].content_text).toContain('"transactions"');
  });

  it("builds healthcare command input with consent and transcript payloads", () => {
    const input = buildHealthcareCommandInput();
    expect(input.schema_version).toBe("HEALTHCAREOS_INPUT_V1");
    expect(input.artifact_payloads).toHaveLength(2);
    const ids = input.artifact_payloads.map((payload) => payload.artifact_id).sort();
    expect(ids).toEqual(["c_demo", "t_demo"]);
    expect(input.artifact_payloads.some((payload) => !payload.content_text)).toBe(false);
  });

  it("ships non-empty redline base64 payload", () => {
    expect(SAMPLE_REDLINE_CONTRACT_BASE64.length).toBeGreaterThan(100);
    expect(SAMPLE_REDLINE_CONTRACT_BASE64.startsWith("JVBERi0")).toBe(true);
  });
});
