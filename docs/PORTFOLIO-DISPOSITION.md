# AIGC Core — Portfolio Disposition

**Status:** Release Frozen at v0.1.0 — macOS unsigned release candidate
complete, full readiness closeout merged, awaiting operator-only Apple
signing + notarization credentials. Do not surface for routine review.

---

## Why this file exists

The portfolio operating system has been tracking AIGC Core as a row
needing review attention. The repo has been doing the opposite of
stalling — Phases 3, 4, and 5 closed out, v0.1.0 release ceremony
completed, ADRs landed, runbooks captured — but no disposition signal
told the portfolio OS what to do with the row given that the artifact
is shipped-but-unsigned.

This file is that signal. It does not duplicate the existing governance
docs (5 ADRs + readiness reports cover the technical state); it tells
the portfolio operating system how to treat the row.

---

## Closeout receipt

Full readiness closeout merged 2026-03-14 (see
`docs/full-readiness-closeout-2026-03-14.md`). What that closed:

- Local dev launch alignment (`pnpm dev` boots cleanly)
- Packaged macOS `.app` and DMG produce a visible, smoke-tested window
- Runtime ingestion audit contract corrected
- Pack export bundle correctness fix (artifact hashes validate)
- CI drift cleanup
- Top-level docs truthfulness pass

The v0.1.0 release evidence packet is captured at
`docs/release-evidence-v0.1.0.md` and the release ceremony sign-off at
`docs/release-ceremony-v0.1.0-signoff.md`.

Phases 4 and 5 hardening closed via PRs #26, #28, #34. Phase
remediation backlog tracked at `docs/security-remediation-backlog.md`.

---

## Current state in one paragraph

AIGC Core is a Tauri + Rust + React/TypeScript local-first governance
engine that enforces offline-by-default behavior, deterministic
outputs, hash-chained audit trails, and Evidence Bundle v1 exports.
Five Packs (EvidenceOS, RedlineOS, IncidentOS, FinanceOS, HealthcareOS)
pass pack-level happy-path command tests. Five ADRs cover pack export
runtime contract, release signing/gates, branch-protection deadlock
avoidance, audit-freshness/runtime-artifact security, and security
hardening cycle ownership. The only gate between "v0.1.0 packaged
locally" and "v0.1.0 distributed to a real user" is Apple signing
credentials.

For full detail, see (in priority order):

- `docs/release-evidence-v0.1.0.md`
- `docs/release-ceremony-v0.1.0-signoff.md`
- `docs/full-readiness-closeout-2026-03-14.md`
- `docs/release-checklist.md`
- `docs/adr/0002-release-signing-and-gates.md`

---

## Portfolio operating system instructions

| Aspect               | Posture                                                                                                                                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Portfolio status     | `Release Frozen`                                                                                                                                                                                                   |
| v0.1.0 release       | **Locally ceremonied**, unsigned                                                                                                                                                                                   |
| Review cadence       | Suspend overdue counting                                                                                                                                                                                           |
| Resurface conditions | (a) Apple signing credentials wired, (b) operator opens a v0.2.0 scope packet with a defined product reason (new Pack, new audit feature), or (c) glib remediation execution blocker (Linux path) becomes priority |
| Linux distribution   | Out of scope until macOS distribution is proven; glib blocker captured at `docs/glib-remediation-execution-2026-03-01.md` is **not** holding macOS                                                                 |

---

## Why "Release Frozen" instead of other dispositions

- **Active** — wrong. The product surface for v0.1.0 is done; adding
  features now competes with the unblock work without addressing it.
- **Cold Storage** — wrong. v0.1.0 has a captured release evidence
  packet and a sign-off ceremony. Calling that "cold" misrepresents
  months of work.
- **Archived / Wind-down** — wrong. The author has not decided to
  stop; the multi-Pack architecture has clear v0.2.0+ ambitions.
- **Release Frozen** — correct, and the same posture as DesktopPEt
  and ContentEngine. Three repos in this posture is a signal: when
  the operator opens an Apple credentials window, they should batch
  all three through signing in one session rather than one at a time.

---

## Unblock trigger (operator)

When the operator is ready to ship v0.1.0:

1. Add Apple Developer ID Application certificate + notarization
   credentials to CI per `docs/adr/0002-release-signing-and-gates.md`.
2. Re-run the release ceremony with signing enabled —
   `docs/release-checklist.md` lists the steps.
3. Verify the signed/notarized DMG opens on a clean macOS install
   without Gatekeeper warnings.
4. Publish v0.1.0 as a real GitHub release (currently it lives only
   as a local ceremony).
5. Cut a v0.2.0 scope packet if continuing.

Estimated operator time once credentials are in hand: ~3 hours
including notarization round-trip.

---

## Reactivation procedure (for the next code session)

When portfolio operating system flips this row to `Active`:

1. Reconcile the many `codex/*` branches — most are merged-history
   artifacts. Compare against `git log --merges` and delete the
   stale ones.
2. Re-run `pnpm install --frozen-lockfile && pnpm verify` to confirm
   the toolchain still works after the freeze.
3. Re-run the v0.1.0 packaged-app smoke (per
   `full-readiness-closeout-2026-03-14.md`) before adding any new
   scope — long pauses can invalidate prior evidence.
4. Only then proceed to whatever v0.2.0 packet motivated the flip
   (signing, new Pack, new audit feature, glib remediation, etc.).

---

## Last known reference

| Field                            | Value                                                             |
| -------------------------------- | ----------------------------------------------------------------- |
| Last meaningful commit on `main` | `e851e78` docs(agents): align communication contract labels (#36) |
| v0.1.0 release ceremony          | Locally completed (see signoff doc)                               |
| Public release                   | Not yet — pending signing                                         |
| Build verification status        | green                                                             |
| Pack happy-path tests            | 5/5 packs passing                                                 |
| Blocker                          | Apple signing + notarization (operator-only)                      |
| Open ADRs                        | 5 (0001–0005)                                                     |
| Linux distribution status        | Deferred; glib remediation noted but not a macOS blocker          |
