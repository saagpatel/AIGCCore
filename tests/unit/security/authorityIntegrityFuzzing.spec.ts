import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { authorityIntegrityInvokeRequest } from "../../../src/ui/authorityIntegrityContract";

describe("authority integrity request fuzzing", () => {
  it("preserves arbitrary endpoint strings for Rust-side policy validation", () => {
    fc.assert(
      fc.property(fc.string(), (endpoint) => {
        const request = authorityIntegrityInvokeRequest(endpoint);

        expect(request.command).toBe("authority_integrity_probe_adapter");
        expect(request.body).toEqual({ input: { endpoint } });
        expect(request.body.input.endpoint).toBe(endpoint);
      }),
    );
  });
});
