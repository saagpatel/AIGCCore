import { spawnSync } from "node:child_process";

export async function checkFuturePackDeterminism() {
  console.log("GATE: FUTURE_PACKS.EXPORT_DETERMINISM_V1");

  try {
    const testRun = spawnSync(
      "cargo",
      [
        "test",
        "--package",
        "aigc_core",
        "--test",
        "future_pack_exports",
        "--",
        "deterministic_export",
      ],
      { stdio: "inherit", env: process.env },
    );
    if ((testRun.status ?? 1) === 0) {
      return {
        gate_id: "FUTURE_PACKS.EXPORT_DETERMINISM_V1",
        severity: "BLOCKER",
        status: "PASS",
        message: "IncidentOS/FinanceOS/HealthcareOS exports are deterministic",
      };
    }
    return {
      gate_id: "FUTURE_PACKS.EXPORT_DETERMINISM_V1",
      severity: "BLOCKER",
      status: "FAIL",
      message: "Future pack deterministic export tests failed",
    };
  } catch (error) {
    return {
      gate_id: "FUTURE_PACKS.EXPORT_DETERMINISM_V1",
      severity: "BLOCKER",
      status: "FAIL",
      message: `Gate execution error: ${String(error)}`,
      error: String(error),
    };
  }
}

export default checkFuturePackDeterminism;

if (import.meta.url === `file://${process.argv[1]}`) {
  checkFuturePackDeterminism()
    .then((result) => {
      const status = result?.status ?? "FAIL";
      const msg = result?.message ?? "unknown future pack determinism gate status";
      console.log(`${result.gate_id} ${status} ${msg}`);
      process.exit(status === "PASS" ? 0 : 1);
    })
    .catch((error) => {
      console.error(`FUTURE_PACKS.EXPORT_DETERMINISM_V1 FAIL ${String(error)}`);
      process.exit(1);
    });
}
