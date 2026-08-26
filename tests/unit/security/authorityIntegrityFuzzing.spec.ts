import { describe, expect, it } from "vitest";
import fc from "fast-check";

import { authorityIntegrityInvokeRequest } from "../../../src/ui/authorityIntegrityContract";

describe("authority integrity request fuzzing", () => {
  it("property-tests arbitrary endpoint preservation in the Tauri command envelope", () => {
    fc.assert(
      fc.property(fc.string(), (endpoint) => {
        expect(authorityIntegrityInvokeRequest(endpoint)).toStrictEqual({
          command: "authority_integrity_probe_adapter",
          body: { input: { endpoint } },
        });
      }),
      { numRuns: 256, seed: 20260826 },
    );
  });
});
