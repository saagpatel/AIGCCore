# Scorecard #47 RustSec disposition refresh

Date: 2026-08-26
Repository: `saagpatel/AIGCCore`
Baseline commit: `7c81961b4fbd7815a773b331844f3c5669b3eb2c`
Alert: GitHub code scanning #47, OpenSSF Scorecard `VulnerabilitiesID`

## Summary

PR #101 updated `Cargo.lock` to lift the remediable `quick-xml` vulnerability
path to:

- `anyhow 1.0.103`
- `plist 1.10.0`
- `quick-xml 0.41.0`

After that merge, Scorecard #47 still reports 17 RustSec advisories. Fresh
local verification showed the remaining items are not simple lockfile lifts in
the current Tauri 2.11.x dependency graph. They require either an upstream Tauri
Linux runtime migration, a future Tauri URL pattern dependency update, or a
time-boxed risk disposition while Linux distribution remains deferred.

## Current advisory groups

### Linux GTK runtime stack

The following advisories are present through target-specific Linux Tauri
runtime dependencies:

- `RUSTSEC-2024-0413` `atk`
- `RUSTSEC-2024-0416` `atk-sys`
- `RUSTSEC-2024-0412` `gdk`
- `RUSTSEC-2024-0418` `gdk-sys`
- `RUSTSEC-2024-0411` `gdkwayland-sys`
- `RUSTSEC-2024-0417` `gdkx11`
- `RUSTSEC-2024-0414` `gdkx11-sys`
- `RUSTSEC-2024-0415` `gtk`
- `RUSTSEC-2024-0420` `gtk-sys`
- `RUSTSEC-2024-0419` `gtk3-macros`
- `RUSTSEC-2024-0370` `proc-macro-error`
- `RUSTSEC-2024-0429` `glib`

Representative dependency path:

```text
aigc_core_tauri
└── tauri 2.11.5
    ├── tauri-runtime-wry 2.11.4
    │   ├── wry 0.55.1
    │   └── tao 0.35.3
    ├── muda 0.19.3
    └── gtk/webkit2gtk/gtk-rs Linux dependencies
```

`RUSTSEC-2024-0429` has a patched `glib >=0.20.0` range, but the current Linux
stack still requires `gtk 0.18.2`, which constrains `glib` to `^0.18`.

### Tauri URL pattern stack

The following advisories are present through Tauri URL pattern processing:

- `RUSTSEC-2025-0081` `unic-char-property`
- `RUSTSEC-2025-0075` `unic-char-range`
- `RUSTSEC-2025-0080` `unic-common`
- `RUSTSEC-2025-0100` `unic-ucd-ident`
- `RUSTSEC-2025-0098` `unic-ucd-version`

Representative dependency path:

```text
aigc_core_tauri
└── tauri 2.11.5
    └── tauri-utils 2.9.3
        └── urlpattern 0.3.0
            └── unic-* 0.9.0
```

`urlpattern 0.6.0` exists, but `tauri-utils 2.9.3` currently requires
`urlpattern ^0.3`.

## Resolver evidence

Fresh local commands on 2026-08-26:

```text
cargo update -p urlpattern --precise 0.6.0
```

Result: failed because `tauri-utils 2.9.3` requires `urlpattern = "^0.3"`.

```text
cargo update -p wry --precise 0.56.1
```

Result: failed because `tauri-runtime-wry 2.11.4` requires `wry = "^0.55.0"`.

```text
cargo update -p glib --precise 0.20.0
```

Result: failed because `gtk 0.18.2` requires `glib = "^0.18"`.

Static source search found no direct AIGCCore use of:

- `VariantStrIter`
- `glib::`
- `gtk::`
- `gdk::`
- `atk::`
- `gdkx11::`
- `urlpattern`
- `unic_`

The only local `urlpattern` text hits were generated Tauri schema descriptions.

## Disposition

The root `osv-scanner.toml` records time-boxed ignores for the 17 remaining
advisories. Its `ignoreUntil` fields use full RFC3339 timestamps because
OSV-Scanner rejects date-only values. This is a scanner disposition, not a
dependency fix:

- it does not claim the upstream GTK, glib, proc-macro-error, urlpattern, or
  unic crates are maintained or remediated;
- it does not prove Linux runtime exposure is impossible;
- it keeps each advisory ID visible with an expiry and a concrete upstream
  reassessment trigger;
- it should be removed or narrowed as soon as Tauri's compatible dependency
  graph can lift the affected crates.

## OSV-Scanner validation

Fresh local OSV-Scanner validation used `github.com/google/osv-scanner` version
`1.9.2` through an isolated Go cache.

Configured scan:

```text
osv-scanner scan --config osv-scanner.toml --lockfile Cargo.lock --format json
```

Result:

- exit status: `0`
- JSON result count: `0`
- vulnerability count: `0`
- scanner log: `Filtered 18 vulnerabilities from output`

Control scan with an explicit empty config:

```text
osv-scanner scan --config <empty-config> --lockfile Cargo.lock --format json
```

Result:

- exit status: `1`
- JSON result count: `1`
- vulnerability count: `18`
- IDs included the 17 RustSec advisories plus the `GHSA-wrw7-89jp-8q8g`
  alias for `RUSTSEC-2024-0429`.

## Required reassessment triggers

Reassess before 2026-11-26 or earlier if any of these become true:

1. `tauri` / `tauri-runtime-wry` can use `wry >=0.56`.
2. `tauri-utils` can use `urlpattern >=0.6`.
3. The Linux runtime stack can move to `gtk-rs` / `glib >=0.20`.
4. Linux distribution becomes an active release target.
5. A direct AIGCCore use of the affected GTK/glib/urlpattern/unic APIs is
   introduced.
