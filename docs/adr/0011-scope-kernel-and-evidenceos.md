# 0011. Scope AIGCCore to the governance kernel and EvidenceOS

## Status

Accepted (2026-10-12). Supersedes [ADR 0007](0007-experimental-local-execution-backend-v1.md).

## Context

The owner decided that AIGCCore is the governance kernel plus the EvidenceOS
pack only. The demo packs and experimental execution substrate enlarged the
maintenance and review surface without serving that scope. The web performance
kit included k6 API and Postgres pg_stat probes that do not measure this app.

## Decision

Retain the Rust governance kernel, EvidenceOS, its Tauri command surface, the
React UI, bundle validator, and kernel/EvidenceOS evaluation gates.

Remove:

- RedlineOS, IncidentOS, FinanceOS, and HealthcareOS: core modules, Tauri
  handlers, UI panels and samples, exclusive tests, corpora, and evaluation tools.
- The Docker local-execution qualification harness, its optional Cargo feature
  and binary, portable core execution contracts, schemas, fixture and seccomp
  profile, qualification fixtures, and feature-only documentation. No retained
  code consumes the core execution module.
- The k6 and Postgres pg_stat performance kit, its scripts, baselines, and two
  workflows. Keep Lighthouse, its configuration and CLI dependency, and the
  app's web-vitals monitoring.
- The uncalled EgressClient implementation and unused button type module.
  Keep the egress policy declarations, allowlist checks, adapter enforcement,
  and static egress gates.

Split the remaining Tauri entry points into `commands/` and the EvidenceOS
bundle path into `export/`, leaving `lib.rs` as wiring. Move tests beside the
implementation they exercise. This is a mechanical move; the retained command
inputs, outputs, export logic, authority hook, and kernel behavior are unchanged.

Git history preserves the removed implementations. Historical ADRs and release,
readiness, and closeout records remain historical evidence, not the current
supported surface. [The command surface](../command-surface.md) describes the
retained commands.

## Consequences

Subsequent waves work on a smaller codebase. The four demo workflows and
qualification binary are no longer available. No replacement execution backend
is introduced. The kernel's bundle format, audit chain, validation, vault, and
cryptography retain their existing behavior. Existing export encryption and
model stamps are deliberately unchanged; truthfulness fixes belong to wave 2.

## Alternatives Considered

- Keep the demos and harness behind feature flags: rejected because it leaves
  the maintenance surface in the current tree.
- Fold behavior corrections into the scope reduction: rejected to keep review
  of deletion and mechanical moves separate from wave 2 behavior changes.
