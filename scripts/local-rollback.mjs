#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readlinkSync, symlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildManifest } from "./local-app-manifest.mjs";

export const ROLLBACK_SEQUENCE = Object.freeze(["prior", "current", "prior"]);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function manifestIdentitySha256(manifest) {
  const artifactIdentity = { ...manifest };
  delete artifactIdentity.app_name;
  return sha256(JSON.stringify(artifactIdentity));
}

function argumentsFrom(argv) {
  const filtered = argv.filter((argument) => argument !== "--");
  const values = {};
  for (let index = 0; index < filtered.length; index += 2) {
    values[filtered[index]] = filtered[index + 1];
  }
  return values;
}

function main() {
  const args = argumentsFrom(process.argv.slice(2));
  const priorApp = args["--prior-app"];
  const currentApp = args["--current-app"];
  const output = args["--output"];
  const priorRevision = args["--prior-revision"];
  const currentRevision = args["--current-revision"];
  if (![priorApp, currentApp, output, priorRevision, currentRevision].every(Boolean)) {
    console.error(
      "--prior-app, --current-app, --output, --prior-revision, and --current-revision are required",
    );
    return 2;
  }
  const outputRoot = resolve(output);
  if (existsSync(outputRoot)) {
    console.error(`refusing to overwrite rollback output: ${outputRoot}`);
    return 2;
  }
  const generations = {
    current: { app: resolve(currentApp), revision: currentRevision },
    prior: { app: resolve(priorApp), revision: priorRevision },
  };
  if (!Object.values(generations).every((generation) => existsSync(generation.app))) {
    console.error("both immutable app generations must exist");
    return 2;
  }
  mkdirSync(outputRoot, { recursive: true });
  const activations = ROLLBACK_SEQUENCE.map((name, offset) => {
    const index = offset + 1;
    const generation = generations[name];
    const pointer = resolve(outputRoot, `active-${String(index).padStart(2, "0")}.app`);
    symlinkSync(generation.app, pointer);
    const manifest = buildManifest(pointer, generation.revision);
    return {
      generation: name,
      index,
      manifest_identity_sha256: manifestIdentitySha256(manifest),
      pointer,
      pointer_target: readlinkSync(pointer),
      revision: generation.revision,
    };
  });
  const restoredIdentity =
    activations[0].manifest_identity_sha256 === activations[2].manifest_identity_sha256;
  const trace = {
    activations,
    claim_boundary: "task-local append-only generation-pointer rehearsal only",
    schema: "AIGCCoreLocalRollbackV1",
    sequence: activations.map((activation) => activation.revision),
    restored_identity_verified: restoredIdentity,
    status: restoredIdentity ? "PASS" : "FAIL",
  };
  const tracePath = resolve(outputRoot, "trace.json");
  writeFileSync(tracePath, `${JSON.stringify(trace, null, 2)}\n`);
  console.log(JSON.stringify({ status: trace.status, trace: tracePath }));
  return restoredIdentity ? 0 : 1;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
