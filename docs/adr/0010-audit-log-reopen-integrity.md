# ADR 0010: Verify the audit chain before resuming a log

- Status: Accepted
- Date: 2026-09-10

## Context

`AuditLog::open_or_create` previously recovered the last `event_hash` from
the final non-empty NDJSON line without validating any preceding event. A
modified earlier line could therefore remain undetected while new events were
appended to the log. The resulting file would only fail later, when a bundle
validator happened to inspect it.

## Decision

Opening an existing audit log must verify every non-empty line before returning
an `AuditLog`. Verification requires the locked eight-key event envelope,
valid event deserialization and taxonomy, the expected `prev_event_hash`, and
the hash recomputed using the canonical event rules. Each append repeats this
verification and rejects a persisted chain whose final hash differs from the
hash captured at open time.

## Consequences

1. Tampering, malformed records, unsupported event types, and forbidden
   top-level fields fail closed before the runtime resumes the log.
2. A second writer or external edit detected between open and append cannot be
   silently extended by the in-memory writer.
3. This is an integrity and stale-writer check, not a filesystem lock; callers
   still need single-writer coordination for concurrent appends.
