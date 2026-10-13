import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

// Rust supplies serialized DTOs over stdin; validate the actual OpenAPI contract.
const contract = JSON.parse(
  readFileSync(new URL("../openapi/openapi.generated.json", import.meta.url), "utf8"),
);
const ajv = new Ajv2020({ strict: false, allErrors: true });
for (const { schema, value, valid = true } of JSON.parse(readFileSync(0, "utf8"))) {
  const validate = ajv.compile({
    $ref: `#/components/schemas/${schema}`,
    components: contract.components,
  });
  assert.equal(validate(value), valid, `${schema}: ${JSON.stringify(validate.errors)}`);
}
