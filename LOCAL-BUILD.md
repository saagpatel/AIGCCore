# Local Build

This is the operator path for reproducible local setup, bounded development, verification, diagnostics, app review, release rehearsal, and rollback rehearsal. All commands run from the repository root. They prove local behavior only; they do not prove hosted CI, signing credentials, notarization, deployment, publication, provider state, or human adoption.

## Bootstrap

Use Node 22, pnpm 10.29.2, and the repository's Rust stable toolchain, then install the frozen dependency graph:

```sh
pnpm install --frozen-lockfile
```

Do not use a global fallback install. A clean bootstrap should begin from a clean clone and an empty, explicitly selected local pnpm store when measuring reproducibility.

## Develop

Run the bounded UI development smoke:

```sh
pnpm local:develop
```

It reserves a loopback port, starts Vite in a dedicated process group, reads back an HTTP 200 page, and terminates only that exact process group. Its cache defaults to `.local-build/vite-cache`. This path does not invoke `lean:dev`, `clean:heavy`, `clean:full-local`, or any cleanup trap.

For an interactive Tauri session, use `pnpm dev` only when an operator is prepared to own its lifecycle. The bounded smoke is the qualification path.

## Fast Check

```sh
pnpm local:fast
```

This invokes the lockfile-installed ESLint, Stylelint, TypeScript, Vitest, and Node test entrypoints directly. It retains the package-script coverage while avoiding duplicate lint and nested package-runner startup. It stops on the first failure and preserves the original exit code.

## Full Check and CI Parity

```sh
pnpm local:full
```

This reads `.codex/verify.commands` and executes every non-comment command in order under the caller's pinned local toolchain. A pass proves local command parity only. Hosted runners, CodeQL, external database or performance services, workflow token permissions, uploaded artifacts, and provider state remain `UNKNOWN` until separately observed.

## Fixtures

```sh
pnpm local:fixtures
```

This runs the repository gate bundle covering egress enforcement, Redline extraction parity, future-pack deterministic exports, artifact ingestion, and synthetic Rust gate-runner bundles. Compare emitted bundle digests across repetitions; do not accept a single successful run as determinism proof.

## Diagnose

```sh
AIGCCORE_EXPECT_REVISION="$(git rev-parse HEAD)" \
AIGCCORE_LOCAL_BUILD_ROOT="$PWD/.local-build" \
AIGCCORE_PREVIEW_APP="$CARGO_TARGET_DIR/release/bundle/macos/AIGC Core.app" \
AIGCCORE_CANONICAL_SNAPSHOT=/absolute/task-owned/canonical-snapshot.json \
pnpm local:doctor
```

The doctor is read-only. It reports revision and source cleanliness, Node, pnpm, Rust, Cargo, Xcode, dependency presence, repository-local build root, available disk, app codesign verification, absence of signing credential variables, and optional canonical-repository snapshot preservation. Ready exits `0`; degraded exits exactly `2` and names every failed check. To exercise bounded degradation without changing the machine, set `AIGCCORE_DOCTOR_MIN_DISK_GIB` above available disk.

The canonical snapshot format is:

```json
{
  "repositories": [
    { "path": "/absolute/read-only/repository", "revision": "40-hex-commit", "clean": true }
  ]
}
```

## Preview

First validate the exact app artifact:

```sh
AIGCCORE_PREVIEW_APP="/absolute/path/AIGC Core.app" pnpm local:preview:check
```

That command verifies the app's local code signature and deliberately reports `gui_verified: false`. A preview claim additionally requires launching that exact app through an approved deny-network sandbox, direct accessibility readback of a visible AIGC Core window, a captured screenshot, and termination of only the exact launched PID. Process survival, static HTML, or shell configuration is not visual proof.

## Release Check

Choose a fresh local target and a new manifest path for every sample:

```sh
CARGO_TARGET_DIR="$PWD/.local-build/release-01/cargo-target" \
AIGCCORE_RELEASE_MANIFEST="$PWD/.local-build/release-01/app-manifest.json" \
AIGCCORE_SOURCE_REVISION="$(git rev-parse HEAD)" \
pnpm local:release:check
```

The command builds the macOS `.app`, verifies it with `codesign --verify --deep --strict`, and writes a deterministic content manifest while refusing to overwrite an existing manifest. It does not sign with production credentials, notarize, create a publication claim, or mutate an installed app. Do not use `release:macos` for this local-only lane.

## Rollback

Prepare immutable prior and current task-local app generations, then use a fresh output directory:

```sh
pnpm local:rollback -- \
  --prior-app "/absolute/generations/prior/AIGC Core.app" \
  --current-app "/absolute/generations/current/AIGC Core.app" \
  --output "$PWD/.local-build/rollback-01" \
  --prior-revision 40-hex-prior-commit \
  --current-revision 40-hex-current-commit
```

The rehearsal creates append-only activation pointers and reads back prior → current → prior identity. It refuses to overwrite its output and never touches an installed application. Production rollback remains `UNKNOWN`.

## Controlled Failure

```sh
pnpm local:controlled-failure
```

This proves that the authorized loopback attempt is observable and that malformed or non-loopback adapter endpoints are rejected before an attempt. The test command exits `0` when those failure controls work. Doctor degradation is separate and exits exactly `2`.

## Cache and invalidation policy

- `node_modules` is reusable only while `pnpm-lock.yaml`, Node major, and pnpm exact version match.
- `.local-build/vite-cache` is reusable while Vite configuration and UI source inputs match.
- Cargo targets are reusable for fast iteration only while the Rust toolchain, `Cargo.lock`, features, target triple, and relevant source inputs match.
- Release and rollback qualification always use fresh target and output directories. Never delete an old receipt or generation to manufacture a clean sample.
- When any key changes, select a new local directory. Do not run `cargo clean`, `clean:heavy`, `clean:full-local`, or a broad cleanup command as part of qualification.

## Artifact locations and documentation

The default developer cache is `.local-build/`. Measured receipts, logs, manifests, screenshots, and rollback traces should live under a task-owned evidence root outside canonical repositories when a governed program supplies one. Keep failures and outliers. Record exact revision, command, cache mode, tool versions, wall time, peak RSS, exit status, and stdout/stderr digests for performance claims.

Update this guide whenever a local command, cache key, failure exit, artifact path, or claim boundary changes.
