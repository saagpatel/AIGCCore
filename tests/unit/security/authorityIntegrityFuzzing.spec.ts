import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { authorityIntegrityInvokeRequest } from "../../../src/ui/authorityIntegrityContract";

describe("authority integrity request fuzzing", () => {
  // Tauri carries the request body as JSON. Whatever string the UI is given, including lone
  // surrogates and control characters, the Rust side must receive exactly that endpoint.
  it("survives the JSON transport byte-for-byte for arbitrary endpoint strings", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary" }), (endpoint) => {
        const request = authorityIntegrityInvokeRequest(endpoint);

        const received = JSON.parse(JSON.stringify(request)) as typeof request;

        expect(received).toEqual(request);
        expect(received.body.input.endpoint).toBe(endpoint);
        expect(Object.keys(received.body.input)).toEqual(["endpoint"]);
      }),
    );
  });

  it("builds an independent request per call so one probe cannot alter another", () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (first, second) => {
        const a = authorityIntegrityInvokeRequest(first);
        const b = authorityIntegrityInvokeRequest(second);

        a.body.input.endpoint = "mutated";

        expect(b.body.input.endpoint).toBe(second);
        expect(authorityIntegrityInvokeRequest(first).body.input.endpoint).toBe(first);
        expect(a.body).not.toBe(b.body);
      }),
    );
  });
});
