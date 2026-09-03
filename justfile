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

# ─── Examples ─────────────────────────────────────────────────────────────────

# Run the pg-cli consumer example against the workspace-built pg-cli (no install needed)
run-pg-cli-example: build
    PG_CLI=dist/target/debug/pg-cli cargo run -p pg-cli-example

# ─── Docs (generated; do not edit outputs by hand) ───────────────────────────
# docs/pg-cli.md          <- clap definition (pg-cli docs)
# libs/pg-gen/README.md   <- //! crate docs (cargo-readme; doctests keep it compiling)
# CLAUDE.md imports both so AI agents get exact flags/APIs. Requires: cargo install cargo-readme

# Regenerate all generated docs
docs:
    cargo run -q -p pg-cli -- docs > docs/pg-cli.md
    cargo readme -r libs/pg-gen --no-license -o libs/pg-gen/README.md

# Fail if generated docs are stale (run in CI)
docs-check:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp -d)
    cargo run -q -p pg-cli -- docs > "$tmp/pg-cli.md"
    cargo readme -r libs/pg-gen --no-license -o "$tmp/pg-gen-README.md"
    diff -u docs/pg-cli.md "$tmp/pg-cli.md" && diff -u libs/pg-gen/README.md "$tmp/pg-gen-README.md" \
        || { echo "Generated docs are stale — run: just docs"; exit 1; }
