export type AuthorityIntegrityInvokeRequest = {
  command: "authority_integrity_probe_adapter";
  body: { input: { endpoint: string } };
};

export function authorityIntegrityInvokeRequest(endpoint: string): AuthorityIntegrityInvokeRequest {
  return {
    command: "authority_integrity_probe_adapter",
    body: { input: { endpoint } },
  };
}
