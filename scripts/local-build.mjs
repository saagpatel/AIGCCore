#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
export const repositoryRoot = resolve(scriptDirectory, "..");

export const FAST_COMMANDS = Object.freeze([
  Object.freeze([
    process.execPath,
    resolve(repositoryRoot, "node_modules/eslint/bin/eslint.js"),
    ".",
  ]),
  Object.freeze([
    process.execPath,
    resolve(repositoryRoot, "node_modules/stylelint/bin/stylelint.mjs"),
    "src/**/*.{css,scss}",
    "--allow-empty-input",
  ]),
  Object.freeze([
    process.execPath,
    resolve(repositoryRoot, "node_modules/typescript/bin/tsc"),
    "--noEmit",
  ]),
  Object.freeze([
    process.execPath,
    resolve(repositoryRoot, "node_modules/vitest/vitest.mjs"),
    "run",
    "--config",
    "vitest.config.ts",
  ]),
  Object.freeze([
    process.execPath,
    "--test",
    "scripts/local-build.test.mjs",
    "scripts/build-desktop.test.mjs",
  ]),
]);

export function parseVerifyCommands(source) {
  return source
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    env: process.env,
    stdio: "inherit",
    ...options,
  });
  if (result.error) {
    console.error(`${command} failed to start: ${result.error.message}`);
    return 1;
  }
  return Number.isInteger(result.status) ? result.status : 1;
}

function runPnpmScript(script) {
  return run("pnpm", [script]);
}

function runFast() {
  for (const [command, ...args] of FAST_COMMANDS) {
    const status = run(command, args);
    if (status !== 0) return status;
  }
  return 0;
}

function runFull() {
  const verifyFile = resolve(repositoryRoot, ".codex/verify.commands");
  const commands = parseVerifyCommands(readFileSync(verifyFile, "utf8"));
  for (const command of commands) {
    console.log(`>>> ${command}`);
    const status = run("/bin/zsh", ["-c", command]);
    if (status !== 0) return status;
  }
  return 0;
}

function resolveBuiltApp() {
  const targetRoot = resolve(process.env.CARGO_TARGET_DIR ?? resolve(repositoryRoot, "target"));
  const bundleRoot = resolve(targetRoot, "release/bundle/macos");
  if (!existsSync(bundleRoot)) return undefined;
  const apps = readdirSync(bundleRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.endsWith(".app"))
    .map((entry) => resolve(bundleRoot, entry.name));
  return apps.length === 1 ? apps[0] : undefined;
}

function runPreviewCheck() {
  const app = process.env.AIGCCORE_PREVIEW_APP ?? resolveBuiltApp();
  if (!app || !existsSync(app)) {
    console.error("exactly one built app or AIGCCORE_PREVIEW_APP is required");
    return 2;
  }
  const status = run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", app]);
  if (status !== 0) return status;
  console.log(
    JSON.stringify({
      app: resolve(app),
      claim: "artifact-ready-for-external-sandboxed-gui-review",
      gui_verified: false,
      status: "PASS",
    }),
  );
  return 0;
}

function runReleaseCheck() {
  const buildStatus = runPnpmScript("build");
  if (buildStatus !== 0) return buildStatus;
  const previewStatus = runPreviewCheck();
  if (previewStatus !== 0) return previewStatus;
  const app = process.env.AIGCCORE_PREVIEW_APP ?? resolveBuiltApp();
  const manifest =
    process.env.AIGCCORE_RELEASE_MANIFEST ??
    resolve(repositoryRoot, ".local-build/release/app-manifest.json");
  return run(process.execPath, [
    resolve(scriptDirectory, "local-app-manifest.mjs"),
    "--app",
    app,
    "--output",
    manifest,
  ]);
}

const COMMANDS = {
  fast: runFast,
  full: runFull,
  fixtures: () => run(process.execPath, [resolve(repositoryRoot, "tools/gates/run-all.mjs")]),
  "controlled-failure": () =>
    run("cargo", [
      "test",
      "--locked",
      "-p",
      "aigc_core_tauri",
      "--features",
      "authority-integrity-test-hooks",
      "authority_integrity_tests",
      "--",
      "--show-output",
    ]),
  "preview-check": runPreviewCheck,
  "release-check": runReleaseCheck,
};

export function main(argv = process.argv.slice(2)) {
  const command = argv[0];
  if (!command || !(command in COMMANDS)) {
    console.error(`usage: local-build.mjs ${Object.keys(COMMANDS).join("|")}`);
    return 2;
  }
  return COMMANDS[command]();
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
