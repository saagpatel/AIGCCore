# OpenSSF Best Practices registration plan

AIGCCore tracks the OpenSSF Best Practices badge separately from repository
source changes because the Scorecard `CII-Best-Practices` check reads the
OpenSSF Best Practices badge API for the Git repository URL.

## Current status

- Repository URL: `https://github.com/saagpatel/AIGCCore`
- Badge registration: pending external OpenSSF Best Practices project creation
- Target first tier: passing
- Owner: `@saagpatel`

## Registration evidence to prepare

- Security reporting process: `SECURITY.md`
- Contribution process: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- License: `LICENSE`
- CI and security checks: `.github/workflows/`
- Fuzz/property-based testing: `tests/unit/security/authorityIntegrityFuzzing.spec.ts`

## Closure condition

Scorecard alert #40 should not be considered remediated by this repository
change alone. Closure requires creating or updating the OpenSSF Best Practices
project for the repository URL and then re-running the Scorecard check after
the badge API reports at least an in-progress project.
