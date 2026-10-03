# Contributing

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `chore:`, etc.
5. Push and open a pull request

## Reporting Issues

Open a [GitHub Issue](../../issues) with a clear description and steps to reproduce.

## Code Style

Follow the existing conventions in the codebase.

## Verification

Run commands from the repository root. Use the [README prerequisites](README.md#prerequisites)
and `pnpm install --frozen-lockfile`; dependency installation needs registry access.
Installation runs the Husky `prepare` script, so use an isolated checkout for
verification when another worktree shares Git configuration.

Start with the lane relevant to the change:

```bash
# Small desktop-build invocation/configuration fixtures; no desktop app launch
pnpm test:build:desktop
# Focused authority request fixtures, with mocked Tauri invocation
pnpm test:unit tests/unit/security/authorityIntegrityFuzzing.spec.ts
# Broader JavaScript tests and static checks
pnpm test
pnpm ui:gate:static
# Rust core only; the native shell has additional Tauri platform prerequisites
cargo test --locked -p aigc_core
# Frontend build only
pnpm build:ui
```

`pnpm ui:gate:static` runs ESLint, Stylelint, and TypeScript (`pnpm ui:typecheck`).
There is no standalone formatter-check script. These fixture tests do not require
a live adapter or model service and do not prove desktop runtime or release behavior.

The complete required lane is [`.codex/verify.commands`](.codex/verify.commands),
run with `bash .codex/scripts/run_verify_commands.sh`. It includes workspace and
authority-integrity Rust tests and `pnpm build`, which builds native desktop bundles
and needs platform tooling. [Quality CI](.github/workflows/quality-gates.yml) also
runs `pnpm gate:all`, unit coverage, and diff coverage; its Python 3.12/hash-pinned
diff-cover prerequisites are defined there. Keep those gates intact when reporting
only a focused local check.

For changed UI behavior, install Chromium with `pnpm exec playwright install chromium`.
On Linux, use `pnpm exec playwright install --with-deps chromium`, matching the
[UI workflow](.github/workflows/ui-quality.yml), to install Chromium and its native
system libraries. That Linux command can require administrator privileges and
changes system packages; review those prerequisites before running it on a shared
host. Then run `pnpm ui:gate:regression`.
The [Playwright configuration](playwright.config.ts) starts the loopback UI on port
4102; use an unused port/configuration rather than another project's server.
Cover loading, empty, error, success, disabled, and keyboard-focus states; UI changes
also require the Lighthouse workflow in [AGENTS.md](AGENTS.md#ui-hard-gates-required-for-frontendui-changes).
Pure documentation changes do not require a browser walkthrough.

Do not run `release:macos`, cleanup scripts, rollback, or live local-execution
qualification to validate these instructions. Those operations have separate
credentials, data, signing, or deletion boundaries.
