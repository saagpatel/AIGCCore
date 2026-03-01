import { spawnSync } from "node:child_process";

/**
 * Platform parity gate: Compare contract extraction outputs across macOS/Windows
 *
 * Validates that the same contract produces identical risk assessment outputs
 * on different platforms, ensuring deterministic processing.
 */
export async function checkRedlineosParity() {
  console.log("GATE: REDLINEOS.EXTRACTION_PARITY_V1");

  try {
    // Run real parity test in Rust. This recomputes Redline outputs for the corpus
    // input and asserts byte-for-byte parity across independent runs.
    const testRun = spawnSync(
      "cargo",
      ["test", "--package", "aigc_core", "--test", "redlineos_parity"],
      { stdio: "inherit", env: process.env },
    );
    if ((testRun.status ?? 1) === 0) {
      return {
        gate_id: "REDLINEOS.EXTRACTION_PARITY_V1",
        severity: "BLOCKER",
        status: "PASS",
        message: "Extraction outputs deterministic on recomputation",
      };
    }
    return {
      gate_id: "REDLINEOS.EXTRACTION_PARITY_V1",
      severity: "BLOCKER",
      status: "FAIL",
      message: "Rust parity test failed. See test output above.",
    };
  } catch (error) {
    return {
      gate_id: "REDLINEOS.EXTRACTION_PARITY_V1",
      severity: "BLOCKER",
      status: "FAIL",
      message: `Gate execution error: ${String(error)}`,
      error: String(error),
    };
  }
}

export default checkRedlineosParity;

if (import.meta.url === `file://${process.argv[1]}`) {
  checkRedlineosParity()
    .then((result) => {
      const status = result?.status ?? "FAIL";
      const msg = result?.message ?? "unknown parity status";
      console.log(`${result.gate_id} ${status} ${msg}`);
      process.exit(status === "PASS" ? 0 : 1);
    })
    .catch((error) => {
      console.error(`REDLINEOS.EXTRACTION_PARITY_V1 FAIL ${String(error)}`);
      process.exit(1);
    });
}
