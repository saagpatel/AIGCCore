.PHONY: setup check test build require-tools require-deps

# Toolchain selection comes from rust-toolchain.toml and .node-version.
require-tools:
	@for tool in node pnpm cargo rustup; do \
		command -v $$tool >/dev/null 2>&1 || { \
			echo "Missing $$tool. Install the README prerequisites, then run make setup." >&2; \
			exit 1; \
		}; \
	done

require-deps: require-tools
	@test -x node_modules/.bin/playwright || { \
		echo "Missing project dependencies. Run make setup." >&2; exit 1; \
	}

setup: require-tools
	pnpm install --frozen-lockfile
	pnpm exec playwright install chromium

check: require-deps
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --locked -- -D warnings
	pnpm ui:gate:static
	$(MAKE) test
	pnpm gate:all
	pnpm ui:gate:regression

test: require-deps
	cargo test --workspace --locked
	cargo test --locked -p aigc_core_tauri --features authority-integrity-test-hooks authority_integrity_tests -- --show-output
	pnpm test
	pnpm test:build:desktop

build: require-deps
	pnpm build
