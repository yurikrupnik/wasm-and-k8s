# wasm-and-k8s — task runner
#
# Run `just` to list recipes.

default:
    @just --list

# ─── Build / Test ─────────────────────────────────────────────────────────────

# Build everything (debug)
build:
    cargo build

# Build everything (release)
build-release:
    cargo build --release

# Run all tests
test:
    cargo test

# Run tests for a specific crate (e.g. `just test-crate pg-gen`)
test-crate name:
    cargo test -p {{ name }}

# ─── CLI install (system-wide) ────────────────────────────────────────────────
# Installs CLIs to ~/.cargo/bin (already on PATH).
# Other repos (e.g. nx-playground) can then call the binary by name.

# Install pg-cli to ~/.cargo/bin/pg-cli
install-pg-cli:
    cargo install --path apps/clis/pg-cli --force

# Install every CLI under apps/clis/
install-clis:
    #!/usr/bin/env bash
    set -euo pipefail
    for d in apps/clis/*/; do
      name=$(basename "$d")
      echo "==> installing $name"
      cargo install --path "$d" --force
    done

# Uninstall pg-cli
uninstall-pg-cli:
    cargo uninstall pg-cli

# Verify pg-cli is on PATH and runnable
verify-pg-cli:
    @command -v pg-cli >/dev/null && pg-cli --help | head -5 \
        || (echo "pg-cli not on PATH — run: just install-pg-cli" && exit 1)
