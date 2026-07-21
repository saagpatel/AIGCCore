import type { EvidenceAuthorityManifest } from "./types";

type Props = {
  authority: EvidenceAuthorityManifest | null | undefined;
};

export function EvidenceAuthorityNotice({ authority }: Props) {
  if (!authority) return null;

  return (
    <section className="authority-notice" aria-label="Evidence authority">
      <p>
        Evidence authority:{" "}
        <strong>
          {authority.observed_execution_class} / {authority.evidence_origin}
        </strong>
      </p>
      <p>
        Production-equivalent: <strong>{authority.production_equivalent ? "Yes" : "No"}</strong>
      </p>
      <p>Credentials: {authority.credential_availability}</p>
      <p>Generated: {authority.generated_at_utc}</p>
      <p>
        Source: {authority.source.producer} @ {authority.source.source_revision}
      </p>
      <p>Executable SHA-256: {authority.source.executable_sha256}</p>
      <p>Arguments SHA-256: {authority.source.arguments_sha256}</p>
      <p>Environment SHA-256: {authority.source.environment_sha256}</p>
      <p>Audit SHA-256: {authority.source.audit_log_sha256}</p>
      <p>Allowed effects: {authority.allowed_effects.join(", ")}</p>
      <p>Observed effects: {authority.observed_effects.join(", ")}</p>
      <p>
        Tools:{" "}
        {authority.tools
          .map(
            (tool) =>
              `${tool.tool_id} (available=${tool.declared_available}, used=${tool.observed_used}, external_mutation=${tool.external_mutation_allowed})`,
          )
          .join("; ")}
      </p>
      <p>
        State: {authority.state_scope.cache_scope}; prior approval reused=
        {String(authority.state_scope.prior_approval_reused)}; credentials reused=
        {String(authority.state_scope.credential_state_reused)}; mutable cache reused=
        {String(authority.state_scope.mutable_cache_reused)}
      </p>
      <p>Fresh until: {authority.valid_until_utc}</p>
      <p>May satisfy: {authority.downstream_claims.may_satisfy.join(", ")}</p>
      <p>Must not satisfy: {authority.downstream_claims.must_not_satisfy.join(", ")}</p>
      <ul>
        {authority.limitations.map((limitation) => (
          <li key={limitation}>{limitation}</li>
        ))}
      </ul>
    </section>
  );
}
