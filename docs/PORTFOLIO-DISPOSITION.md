# AIGCCore current disposition

**Status:** Active development. The product is a local-first governance kernel
with EvidenceOS as its sole pack.

## Product state

The Rust core enforces policy, canonicalizes and verifies hash-chained audit
events, serializes deterministic artifacts, and assembles exports. The Tauri
shell is the frontend command boundary. EvidenceOS is the only supported pack;
the repository does not contain the five-pack product described in earlier
portfolio notes.

Exports are checked against the v3 validator checklist before finalization.
The bundle's content hashes support integrity verification, but they are not
cryptographic signatures. Deterministic serialization applies to equivalent
contents; runtime timestamps can change complete bundle hashes between runs.

## Release state

The changelog records 0.2.0 as unreleased. This work does not create a tag or
release. Older v0.1.0 ceremony and evidence documents are historical records;
they do not establish the state of a current build, installation, or public
release.

## Local entry points

- Setup and Rust check: `make setup && make check`
- Full local gate runner: `pnpm gate:all`
- Frontend checks and browser regressions: `pnpm ui:gate`
- Desktop build: `pnpm build`

Current machine or provider state is not inferred from this repository
document. Use fresh build, CI, signing, and installation evidence for release
claims.
