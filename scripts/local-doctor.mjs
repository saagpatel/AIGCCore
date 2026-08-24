#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function command(commandName, args, cwd = repositoryRoot) {
  const result = spawnSync(commandName, args, { cwd, encoding: "utf8" });
  return {
    exit_code: Number.isInteger(result.status) ? result.status : 1,
    stderr: (result.stderr ?? "").trim(),
    stdout: (result.stdout ?? "").trim(),
  };
}

function check(name, passed, detail) {
  return { detail, name, status: passed ? "PASS" : "FAIL" };
}

export function parseAvailableKibibytes(dfOutput) {
  const lines = dfOutput.trim().split(/\r?\n/u);
  const fields = lines.at(-1)?.trim().split(/\s+/u) ?? [];
  const value = Number(fields[3]);
  return Number.isFinite(value) ? value : 0;
}

function canonicalChecks(snapshotPath) {
  if (!snapshotPath) {
    return [
      {
        detail: "AIGCCORE_CANONICAL_SNAPSHOT is unset",
        name: "canonical-preservation",
        status: "SKIP",
      },
    ];
  }
  const snapshot = JSON.parse(readFileSync(snapshotPath, "utf8"));
  return snapshot.repositories.map((repository) => {
    const revision = command("git", ["rev-parse", "HEAD"], repository.path);
    const status = command("git", ["status", "--porcelain=v1"], repository.path);
    const passed =
      revision.exit_code === 0 &&
      revision.stdout === repository.revision &&
      status.exit_code === 0 &&
      (repository.clean !== true || status.stdout.length === 0);
    return check(`canonical:${repository.path}`, passed, {
      clean: status.stdout.length === 0,
      expected_revision: repository.revision,
      observed_revision: revision.stdout,
    });
  });
}

function main() {
  const checks = [];
  const expectedRevision = process.env.AIGCCORE_EXPECT_REVISION;
  const revision = command("git", ["rev-parse", "HEAD"]);
  checks.push(
    check(
      "revision",
      revision.exit_code === 0 && (!expectedRevision || revision.stdout === expectedRevision),
      { expected: expectedRevision ?? "current HEAD", observed: revision.stdout },
    ),
  );
  const status = command("git", ["status", "--porcelain=v1"]);
  checks.push(
    check("source-clean", status.exit_code === 0 && status.stdout === "", {
      clean: status.stdout === "",
    }),
  );

  const toolPlans = [
    ["node", process.execPath, ["--version"], "v22."],
    ["pnpm", "pnpm", ["--version"], "10.29.2"],
    ["rustc", "rustc", ["--version"], "rustc 1.97.1"],
    ["cargo", "cargo", ["--version"], "cargo 1.97.1"],
    ["xcode", "/usr/bin/xcodebuild", ["-version"], "Xcode 26.6"],
  ];
  for (const [name, executable, args, expected] of toolPlans) {
    const observed = command(executable, args);
    checks.push(
      check(`tool:${name}`, observed.exit_code === 0 && observed.stdout.startsWith(expected), {
        expected_prefix: expected,
        observed: observed.stdout,
      }),
    );
  }

  checks.push(
    check("dependencies", existsSync(resolve(repositoryRoot, "node_modules")), {
      path: resolve(repositoryRoot, "node_modules"),
    }),
  );
  const buildRoot = resolve(
    process.env.AIGCCORE_LOCAL_BUILD_ROOT ?? resolve(repositoryRoot, ".local-build"),
  );
  checks.push(
    check("build-root", buildRoot.startsWith(`${repositoryRoot}/`), {
      path: buildRoot,
      repository_local: buildRoot.startsWith(`${repositoryRoot}/`),
    }),
  );

  const minimumDiskGib = Number(process.env.AIGCCORE_DOCTOR_MIN_DISK_GIB ?? "10");
  const df = command("/bin/df", ["-Pk", repositoryRoot]);
  const availableKibibytes = parseAvailableKibibytes(df.stdout);
  const availableGibFloor = Math.floor(availableKibibytes / 1024 / 1024);
  checks.push(
    check("disk", df.exit_code === 0 && availableGibFloor >= minimumDiskGib, {
      available_gib_floor: availableGibFloor,
      minimum_gib: minimumDiskGib,
    }),
  );

  const previewApp = process.env.AIGCCORE_PREVIEW_APP;
  const preview = previewApp
    ? command("/usr/bin/codesign", ["--verify", "--deep", "--strict", previewApp])
    : { exit_code: 2 };
  checks.push(
    check(
      "preview-artifact",
      Boolean(previewApp) && existsSync(previewApp) && preview.exit_code === 0,
      {
        app: previewApp ?? "UNSET",
        codesign_verified: preview.exit_code === 0,
        gui_verified: false,
      },
    ),
  );

  const signingVariables = [
    "APPLE_API_ISSUER",
    "APPLE_API_KEY",
    "APPLE_API_KEY_PATH",
    "APPLE_SIGNING_IDENTITY",
  ];
  const presentSigningVariables = signingVariables.filter((name) => process.env[name]);
  checks.push(
    check("signing-boundary", presentSigningVariables.length === 0, {
      present_variable_names: presentSigningVariables,
    }),
  );
  checks.push(...canonicalChecks(process.env.AIGCCORE_CANONICAL_SNAPSHOT));

  const failed = checks.filter((item) => item.status === "FAIL");
  const result = {
    checks,
    claim_boundary:
      "local readiness only; GUI, hosted CI, signing, notarization, provider, deployment, and publication state are not proven",
    failed_check_names: failed.map((item) => item.name),
    repository: repositoryRoot,
    schema: "AIGCCoreLocalDoctorV1",
    status: failed.length === 0 ? "ready" : "degraded",
  };
  console.log(JSON.stringify(result));
  return failed.length === 0 ? 0 : 2;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
