import { invoke } from "@tauri-apps/api/core";
import { authorityIntegrityInvokeRequest } from "./authorityIntegrityContract";

export type AuthorityIntegrityProbeResult = {
  adapter_id: string;
  endpoint: string;
  dependency_path_reached: boolean;
};

/**
 * Source-owned integrity hook for an isolated test build. Production UI does
 * not import this module, and the matching Tauri command exists only when the
 * `authority-integrity-test-hooks` Cargo feature is enabled.
 */
export function probeAuthorityIntegrityAdapter(
  endpoint: string,
): Promise<AuthorityIntegrityProbeResult> {
  const request = authorityIntegrityInvokeRequest(endpoint);
  return invoke<AuthorityIntegrityProbeResult>(request.command, request.body);
}
