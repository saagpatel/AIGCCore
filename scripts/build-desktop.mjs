#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export function buildInvocationForPlatform(platform = process.platform) {
  const command = platform === "win32" ? "pnpm.cmd" : "pnpm";
  const args = ["exec", "tauri", "build"];

  if (platform === "darwin") {
    args.push("--bundles", "app");
  }

  return { command, args };
}

export function runDesktopBuild({
  platform = process.platform,
  spawn = spawnSync,
} = {}) {
  const { command, args } = buildInvocationForPlatform(platform);
  const result = spawn(command, args, { stdio: "inherit" });

  if (result.error) {
    console.error(`desktop build failed to start: ${result.error.message}`);
    return 1;
  }

  return Number.isInteger(result.status) ? result.status : 1;
}

const entrypoint = process.argv[1]
  ? pathToFileURL(process.argv[1]).href
  : undefined;

if (entrypoint === import.meta.url) {
  process.exitCode = runDesktopBuild();
}
