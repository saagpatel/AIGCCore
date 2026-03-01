# ADR 0005: Security Hardening Cycle and Ownership Codification

- Status: Accepted
- Date: 2026-03-01

## Context

Phase closeout security audit identified five material risks:

1. weak merge review controls during temporary closeout mode;
2. fallback KEK file writes without explicit least-privilege file modes;
3. preflight bundle artifacts created in temp paths without explicit permission hardening;
4. synthetic egress-proof audit events not explicitly distinguished from live egress attempts;
5. missing `CODEOWNERS` and `SECURITY.md` ownership/disclosure controls.

## Decision

1. Enforce Unix fallback secret file permissions at owner-only (`0o600`) and parent directories at (`0o700`).
2. Harden preflight artifact directory/file permissions on Unix (`0o700` dir, `0o600` file) and ensure cleanup via scoped drop.
3. Mark synthetic offline-proof egress events with `details.evidence_origin = CONTROL_SIMULATION`.
4. Add repo-level ownership and disclosure controls:
   - `.github/CODEOWNERS`
   - `SECURITY.md`
5. Re-tighten branch protection to `required_approving_review_count = 1` and track reviewer-capacity sustainability as explicit follow-up work.

## Consequences

1. Reduced local disclosure risk for runtime secret material and transient preflight outputs.
2. Improved audit trace interpretation by operators and reviewers.
3. Clearer accountability for critical paths and security reporting.
4. Remaining governance debt is explicit and time-bound rather than implicit (reviewer sustainability tracked in issue `#32`).
