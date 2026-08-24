import assert from "node:assert/strict";
import test from "node:test";

import { FAST_COMMANDS, parseVerifyCommands } from "./local-build.mjs";
import { parseAvailableKibibytes } from "./local-doctor.mjs";
import { ROLLBACK_SEQUENCE } from "./local-rollback.mjs";

test("fast command plan keeps UI coverage without duplicated lint", () => {
  assert.deepEqual(FAST_COMMANDS, [
    ["pnpm", "ui:lint"],
    ["pnpm", "ui:typecheck"],
    ["pnpm", "test"],
    ["pnpm", "test:build:desktop"],
  ]);
});

test("verify command parser keeps ordered executable commands", () => {
  assert.deepEqual(parseVerifyCommands("# source\n\npnpm lint\r\ncargo test --workspace\n"), [
    "pnpm lint",
    "cargo test --workspace",
  ]);
});

test("disk parser reads the available-kibibyte column", () => {
  assert.equal(
    parseAvailableKibibytes(
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/test 100 40 60 40% /\n",
    ),
    60,
  );
});

test("rollback sequence returns to the prior generation", () => {
  assert.deepEqual(ROLLBACK_SEQUENCE, ["prior", "current", "prior"]);
});
