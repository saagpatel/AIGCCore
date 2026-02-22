import { spawnSync } from "node:child_process";

export async function checkArtifactIngestionContract() {
  console.log("GATE: ARTIFACT_INGESTION.CONTRACT_V1");

  try {
    const testRun = spawnSync(
      "cargo",
      ["test", "--package", "aigc_core_tauri", "--", "ingestion_contract_"],
      { stdio: "inherit", env: process.env },
    );
    if ((testRun.status ?? 1) === 0) {
      return {
        gate_id: "ARTIFACT_INGESTION.CONTRACT_V1",
        severity: "BLOCKER",
        status: "PASS",
        message: "Artifact ingestion contract tests passed",
      };
    }
    return {
      gate_id: "ARTIFACT_INGESTION.CONTRACT_V1",
      severity: "BLOCKER",
      status: "FAIL",
      message: "Artifact ingestion contract tests failed",
    };
  } catch (error) {
    return {
      gate_id: "ARTIFACT_INGESTION.CONTRACT_V1",
      severity: "BLOCKER",
      status: "FAIL",
      message: `Gate execution error: ${String(error)}`,
      error: String(error),
    };
  }
}

export default checkArtifactIngestionContract;

if (import.meta.url === `file://${process.argv[1]}`) {
  checkArtifactIngestionContract()
    .then((result) => {
      const status = result?.status ?? "FAIL";
      const msg = result?.message ?? "unknown artifact ingestion contract status";
      console.log(`${result.gate_id} ${status} ${msg}`);
      process.exit(status === "PASS" ? 0 : 1);
    })
    .catch((error) => {
      console.error(`ARTIFACT_INGESTION.CONTRACT_V1 FAIL ${String(error)}`);
      process.exit(1);
    });
}
