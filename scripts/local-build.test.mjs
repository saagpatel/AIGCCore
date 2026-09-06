import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";

import {
  FAST_COMMANDS,
  FULL_COMMAND,
  parseVerifyCommands,
  repositoryRoot,
  resolveReleaseApp,
} from "./local-build.mjs";
import { parseAvailableKibibytes } from "./local-doctor.mjs";
import { manifestIdentitySha256, ROLLBACK_SEQUENCE } from "./local-rollback.mjs";

test("fast command plan keeps UI coverage without duplicated lint", () => {
  assert.deepEqual(FAST_COMMANDS, [
    [process.execPath, `${repositoryRoot}/node_modules/eslint/bin/eslint.js`, "."],
    [
      process.execPath,
      `${repositoryRoot}/node_modules/stylelint/bin/stylelint.mjs`,
      "src/**/*.{css,scss}",
      "--allow-empty-input",
    ],
    [process.execPath, `${repositoryRoot}/node_modules/typescript/bin/tsc`, "--noEmit"],
    [
      process.execPath,
      `${repositoryRoot}/node_modules/vitest/vitest.mjs`,
      "run",
      "--config",
      "vitest.config.ts",
    ],
    [
      process.execPath,
      "--test",
      "scripts/local-build.test.mjs",
      "scripts/build-desktop.test.mjs",
      "scripts/tauri-window-config.test.mjs",
    ],
  ]);
});

test("full command delegates to the canonical portable verifier", () => {
  assert.deepEqual(FULL_COMMAND, [`${repositoryRoot}/.codex/scripts/run_verify_commands.sh`]);
});

test("release artifact resolver selects exactly one app from the current target", (context) => {
  const target = mkdtempSync(resolve(tmpdir(), "aigccore-release-target-"));
  context.after(() => rmSync(target, { recursive: true, force: true }));
  const bundleRoot = resolve(target, "release/bundle/macos");
  mkdirSync(resolve(bundleRoot, "AIGC Core.app"), { recursive: true });
  const unrelatedPreview = resolve(target, "stale-preview.app");
  mkdirSync(unrelatedPreview);
  const previousPreview = process.env.AIGCCORE_PREVIEW_APP;
  process.env.AIGCCORE_PREVIEW_APP = unrelatedPreview;
  context.after(() => {
    if (previousPreview === undefined) delete process.env.AIGCCORE_PREVIEW_APP;
    else process.env.AIGCCORE_PREVIEW_APP = previousPreview;
  });
  assert.equal(resolveReleaseApp(target), resolve(bundleRoot, "AIGC Core.app"));
});

test("release artifact resolver rejects a missing app", (context) => {
  const target = mkdtempSync(resolve(tmpdir(), "aigccore-release-target-"));
  context.after(() => rmSync(target, { recursive: true, force: true }));
  assert.equal(resolveReleaseApp(target), undefined);
});

test("release artifact resolver rejects ambiguous apps", (context) => {
  const target = mkdtempSync(resolve(tmpdir(), "aigccore-release-target-"));
  context.after(() => rmSync(target, { recursive: true, force: true }));
  const bundleRoot = resolve(target, "release/bundle/macos");
  mkdirSync(resolve(bundleRoot, "One.app"), { recursive: true });
  mkdirSync(resolve(bundleRoot, "Two.app"), { recursive: true });
  assert.equal(resolveReleaseApp(target), undefined);
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

test("rollback identity ignores activation pointer basename", () => {
  const manifest = { app_name: "active-01.app", entries_sha256: "abc", revision: "prior" };
  assert.equal(
    manifestIdentitySha256(manifest),
    manifestIdentitySha256({ ...manifest, app_name: "active-03.app" }),
  );
});

test("rollback identity changes when artifact content changes", () => {
  const manifest = { app_name: "active-01.app", entries_sha256: "abc", revision: "prior" };
  assert.notEqual(
    manifestIdentitySha256(manifest),
    manifestIdentitySha256({ ...manifest, entries_sha256: "def" }),
  );
});

test("rollback identity changes when source revision changes", () => {
  const manifest = { app_name: "active-01.app", entries_sha256: "abc", revision: "prior" };
  assert.notEqual(
    manifestIdentitySha256(manifest),
    manifestIdentitySha256({ ...manifest, revision: "current" }),
  );
});
