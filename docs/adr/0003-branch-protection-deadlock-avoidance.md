# ADR 0003: Branch Protection Deadlock Avoidance

- Status: Accepted
- Date: 2026-02-22

## Context

Phase closeout was blocked when branch protection required approving reviews, but available reviewer capacity did not guarantee an independent approver for every change window.

## Decision

1. Use temporary `required_approving_review_count = 0` during Phase 5 closeout.
2. Keep required status checks as merge blockers:
   - `quality-gates`
   - `ui-quality`
   - `codex-quality-security`
3. Keep conversation-resolution discipline in PRs and require evidence tables for required gates.
4. Track policy debt explicitly: re-tighten approvals after reviewer capacity is expanded.

## Consequences

1. Merge deadlocks are removed for closeout work.
2. Safety remains enforced through deterministic CI status checks and release evidence.
3. Governance follow-up is mandatory:
   - owner: Engineering manager (or repo admin)
   - target date: 2026-03-31
   - action: restore `required_approving_review_count >= 1`
