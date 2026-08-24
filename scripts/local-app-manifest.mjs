#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function plist(app) {
  const result = spawnSync(
    "/usr/bin/plutil",
    ["-convert", "json", "-o", "-", resolve(app, "Contents/Info.plist")],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(`plutil failed: ${result.stderr.trim()}`);
  }
  return JSON.parse(result.stdout);
}

function walk(root, current = root) {
  const entries = [];
  for (const name of readdirSync(current).sort()) {
    const path = resolve(current, name);
    const stat = lstatSync(path);
    const item = {
      mode: (stat.mode & 0o7777).toString(8).padStart(4, "0"),
      path: relative(root, path),
    };
    if (stat.isSymbolicLink()) {
      const target = readlinkSync(path);
      entries.push({ ...item, sha256: sha256(target), target, type: "symlink" });
    } else if (stat.isDirectory()) {
      entries.push({ ...item, type: "directory" });
      entries.push(...walk(root, path));
    } else if (stat.isFile()) {
      const data = readFileSync(path);
      entries.push({ ...item, bytes: data.length, sha256: sha256(data), type: "file" });
    }
  }
  return entries;
}

export function buildManifest(app, revision) {
  const resolvedApp = resolve(app);
  const info = plist(resolvedApp);
  const entries = walk(resolvedApp);
  const executable = info.CFBundleExecutable;
  return {
    app_name: basename(resolvedApp),
    bundle_identifier: info.CFBundleIdentifier,
    bundle_version: info.CFBundleVersion,
    entries,
    entries_sha256: sha256(JSON.stringify(entries)),
    entry_count: entries.length,
    executable,
    executable_sha256: sha256(readFileSync(resolve(resolvedApp, "Contents/MacOS", executable))),
    revision,
    schema: "AIGCCoreLocalAppManifestV1",
    short_version: info.CFBundleShortVersionString,
  };
}

function argumentsFrom(argv) {
  const filtered = argv.filter((argument) => argument !== "--");
  const values = {};
  for (let index = 0; index < filtered.length; index += 2) {
    values[filtered[index]] = filtered[index + 1];
  }
  return values;
}

function gitRevision() {
  const result = spawnSync("git", ["rev-parse", "HEAD"], {
    encoding: "utf8",
  });
  return result.status === 0 ? result.stdout.trim() : "UNKNOWN";
}

function main() {
  const args = argumentsFrom(process.argv.slice(2));
  const app = args["--app"];
  const output = args["--output"];
  if (!app || !output || !existsSync(app)) {
    console.error("--app and --output are required and app must exist");
    return 2;
  }
  const resolvedOutput = resolve(output);
  if (existsSync(resolvedOutput)) {
    console.error(`refusing to overwrite manifest: ${resolvedOutput}`);
    return 2;
  }
  mkdirSync(dirname(resolvedOutput), { recursive: true });
  const manifest = buildManifest(app, process.env.AIGCCORE_SOURCE_REVISION ?? gitRevision());
  writeFileSync(resolvedOutput, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(JSON.stringify({ output: resolvedOutput, status: "PASS" }));
  return 0;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
