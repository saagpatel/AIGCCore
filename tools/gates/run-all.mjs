import { spawnSync } from "node:child_process";

// Single command runner required by packet: pnpm gate:all -> executes all gates locally.
// Source-of-truth wiring is package.json scripts.

const enforce = spawnSync("node", ["tools/gates/check-egress-enforcement.mjs"], {
  stdio: "inherit",
  env: process.env,
});
if ((enforce.status ?? 1) !== 0) process.exit(enforce.status ?? 1);

const parity = spawnSync("node", ["tools/gates/check-redlineos-parity.mjs"], {
  stdio: "inherit",
  env: process.env,
});
if ((parity.status ?? 1) !== 0) process.exit(parity.status ?? 1);

const futurePackDeterminism = spawnSync("node", ["tools/gates/check-future-pack-determinism.mjs"], {
  stdio: "inherit",
  env: process.env,
});
if ((futurePackDeterminism.status ?? 1) !== 0) process.exit(futurePackDeterminism.status ?? 1);

const artifactIngestionContract = spawnSync(
  "node",
  ["tools/gates/check-artifact-ingestion-contract.mjs"],
  {
    stdio: "inherit",
    env: process.env,
  },
);
if ((artifactIngestionContract.status ?? 1) !== 0) {
  process.exit(artifactIngestionContract.status ?? 1);
}

const res = spawnSync("cargo", ["run", "-p", "gate_runner"], {
  stdio: "inherit",
  env: process.env,
});

process.exit(res.status ?? 1);
