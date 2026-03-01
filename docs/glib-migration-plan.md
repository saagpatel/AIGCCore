# Glib Advisory Migration Plan (Issue #31)

Date: 2026-03-01  
Owner: Runtime owner  
Tracking issue: https://github.com/saagar210/AIGCCore/issues/31  
Target decision date: 2026-04-15

## Objective

Produce a tested migration path that removes the current `glib` advisory exposure by moving the Linux runtime dependency chain off `glib 0.18.x`.

## Execution Status

- Execution attempt performed on 2026-03-01.
- Result: blocked by upstream stack constraints in current Tauri 2.x Linux dependency chain.
- Evidence: `docs/glib-remediation-execution-2026-03-01.md`.

## Baseline Evidence

Current dependency chain (captured 2026-03-01):

- `src-tauri/Cargo.toml` pins desktop shell to `tauri = 2.0.0`.
- `cargo tree -i glib --locked --target all` shows:
  - `glib v0.18.5`
  - consumed through `gtk v0.18.2`
  - transitively required by `tauri v2.10.2`/`tauri-runtime-wry` Linux stack.

Canonical verification baseline on current stack:

- `cargo test --workspace`: pass
- `pnpm gate:all`: pass

## Migration Options

1. In-place patching (`glib` only)  
   Status: rejected  
   Reason: blocked by `gtk 0.18.x` / Tauri Linux dependency chain compatibility.

2. Full desktop runtime stack uplift (recommended)  
   Status: selected for prototype  
   Reason: only credible path to land `glib >= 0.20` with supported dependency graph.

## Planned Execution (Prototype Then Rollout)

### Phase A: Prototype Branch

1. Create prototype branch from latest `master`.
2. Attempt coordinated uplift:
   - `tauri` / `tauri-build` to latest compatible `2.x`
   - Linux runtime/transitive stack (`tauri-runtime-wry`, `wry`, `webkit2gtk`, `gtk-rs` family)
3. Capture resulting `cargo tree -i glib --target all` output.
4. Run full required checks:
   - `bash .codex/scripts/run_verify_commands.sh`
   - `pnpm gate:all`
   - `cargo test --workspace`
5. Record pass/fail deltas and blocking incompatibilities.

### Phase B: Compatibility and Release Impact

1. Validate platform parity:
   - macOS and Windows build unchanged
   - Linux packaging unchanged (`deb`, `rpm`, `AppImage`)
2. Verify no command-surface breaking changes:
   - no rename to `run_redlineos`, `run_incidentos`, `run_financeos`, `run_healthcareos`
3. Confirm deterministic export gates remain stable.

### Phase C: Production Rollout

1. Merge uplift in isolated PR with:
   - dependency diff summary
   - gate evidence table
   - rollback instructions
2. Run release workflow for signed desktop artifacts.
3. Publish release evidence update with post-migration checksums.

## Risk Register

1. Linux webview stack breakage after uplift  
   Mitigation: branch-isolated prototype + full `pnpm gate:all` + packaging checks before merge.

2. Hidden transitive incompatibilities across `gtk-rs` family  
   Mitigation: upgrade as a coordinated set, avoid partial pin overrides.

3. Hash/determinism drift in generated bundles  
   Mitigation: keep determinism gates blocking and compare pre/post bundle hashes.

## Rollback Plan

If prototype or release candidate fails:

1. Revert uplift PR completely.
2. Restore last known-good tag (`v0.1.0-week1-stable`) for release lane.
3. Keep advisory tracked as planned remediation in backlog and issue #31 with next attempt window.

## Exit Criteria for Issue #31

1. Migration plan document exists (this document).
2. Prototype branch evidence includes:
   - dependency-chain output before/after
   - full verify + gate pass/fail results
3. Security backlog status reflects planned remediation execution (not accepted-risk).
