# OpenSSF Best Practices Badge Evidence Map

Date: 2026-08-27

## Status

AIGCCore is preparing an OpenSSF Best Practices Badge application, but the
project does not yet claim a passing, silver, gold, baseline, or in-progress
badge.

OpenSSF Scorecard's `CIIBestPracticesID` check is provider-backed: the badge
state must be created and read through the OpenSSF Best Practices application,
not inferred from this repository alone. This document is the repository-side
evidence map for that application.

## Repository evidence

| Badge area | Repository evidence | Notes |
| --- | --- | --- |
| Project description | `README.md` | Describes AIGCCore as a local-first governance and audit engine for privacy-first desktop AI applications. |
| Obtain and run | `README.md` | Documents clone, dependency installation, development mode, tests, build, and release commands. |
| License | `LICENSE` | MIT license. |
| Contribution process | `CONTRIBUTING.md` | Documents fork, branch, conventional commit, push, and pull request flow. |
| Issue reporting | `CONTRIBUTING.md` | Public issue reporting path for ordinary bugs and enhancements. |
| Vulnerability reporting | `SECURITY.md` | Private vulnerability reporting path, supported versions, response targets, disclosure process, and security ownership. |
| Code of conduct | `CODE_OF_CONDUCT.md` | Contributor Covenant 2.1. |
| Ownership | `.github/CODEOWNERS`, `SECURITY.md` | Code ownership and security owner/back-up owner are recorded. |
| Release process | `docs/release-checklist.md`, `docs/release-evidence-v0.1.0.md`, `docs/release-ceremony-v0.1.0-signoff.md` | Release gates, evidence, and signing/notarization expectations are documented. |
| Security hardening backlog | `docs/security-remediation-backlog.md` | Tracks completed and blocked security hardening work, including dependency findings. |
| Threat model | `docs/threat-model-local-execution-v1.md` | Documents local execution trust boundaries and security controls. |
| Architecture decisions | `docs/adr/` | Records security and release-signing architecture decisions. |
| CI and security workflows | `.github/workflows/` | Includes CI, CodeQL, release, and codex quality/security workflows. |

## External application gate

To move Scorecard `CIIBestPracticesID` from `0`, a repository owner must:

1. Sign in to the OpenSSF Best Practices Badge application.
2. Create or update the AIGCCore project entry for
   `https://github.com/saagpatel/AIGCCore`.
3. Use this evidence map to answer the Best Practices criteria honestly.
4. Read back the public project URL, badge tier/progress state, and Scorecard
   result after Scorecard's next run.

Until that external readback exists, the badge state remains `UNKNOWN` from
repository evidence alone.
