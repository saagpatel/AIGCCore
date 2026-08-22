# ADR 0009: Eval Report Finalization Boundary

- Status: Accepted
- Date: 2026-08-11

## Context

Bundle producers construct their inputs before the evaluator runs. They therefore supplied an
empty `eval_report.json` placeholder with `overall_status: PASS`. The same final validator was used
both to compute gate results and to authorize exported bytes, so the validator accepted the empty
placeholder to avoid a circular dependency. `RunManager` then exported that placeholder instead of
the gate results it had actually evaluated.

This allowed a final bundle to claim PASS without carrying any named gate evidence. Missing gate
results in prefix and export-policy lookups also defaulted to success.

## Decision

1. Evaluation and final authorization are separate phases.
2. The evaluator may use a crate-internal, explicitly non-authorizing preflight validation path.
   Preflight validates the bundle inputs needed to execute gates but defers final eval-report
   authorization.
3. `EvalRunner` materializes one registry-bound `EvalReport` from the complete set of applicable
   gate results. Missing, duplicate, unexpected, invalid, or severity-downgraded results fail
   closed.
4. `RunManager` writes that report into the final bundle and binds
   `run_manifest.eval.gate_status` to its derived overall status before strict validation.
5. Final v3 validation requires the exact policy-applicable gate set, valid statuses, registry
   category and severity integrity, registry evidence pointers, a derived overall status, and a
   matching run-manifest status.
6. Legacy v1/v2 reports remain inspectable for diagnostics but never authorize final validation;
   current evidence must be re-evaluated against v3. This prevents a version-label downgrade from
   bypassing v3 completeness checks.
7. Missing checklist-prefix results and missing applicable export-gate evidence return failure.
8. `NOT_APPLICABLE` remains visible and non-authorizing. In particular, ADR 0008's
   simulation-only allowlist result remains `NOT_APPLICABLE`; finalization must preserve that claim
   boundary rather than converting controlled evidence into live proof. Only gates with explicit
   evaluator semantics may use `NOT_APPLICABLE`; it is not a generic escape hatch.

## Consequences

- Exported bundles carry the gate evidence that authorized them.
- External validation rejects empty PASS placeholders and partial v3 reports.
- Evaluation avoids a circular dependency without exposing the preflight path as final proof.
- Adding a policy-applicable registry gate requires an evaluator result before export can succeed.
- Controlled simulations can still complete as bounded local evidence, while the report and
  evidence-authority contract continue to prohibit live-observation claims.

## Alternatives Considered

- Continue accepting empty reports and rely on in-memory gate decisions. Rejected because exported
  evidence would remain unverifiable and misleading.
- Treat every BLOCKER `NOT_APPLICABLE` result as a failure. Rejected because registry policy
  applicability and evidence applicability are currently distinct, and ADR 0008 intentionally
  permits simulation-only controlled exports while denying live claims.
- Run the final validator before evaluation. Rejected because a complete eval report cannot exist
  until evaluation has finished.
