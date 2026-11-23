#!/usr/bin/env bash
# Runs the checks the CI runs, so a green run here means a green pull request.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
