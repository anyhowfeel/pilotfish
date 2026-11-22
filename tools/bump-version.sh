#!/usr/bin/env bash
# Sets the version in Cargo.toml, Cargo.lock and the Arch PKGBUILD. Edit CHANGELOG.md by hand, then run check-version.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

new="${1:?usage: tools/bump-version.sh X.Y.Z}"
[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "'$new' is not a Semantic Version" >&2; exit 1; }

sed -i '/^\[workspace.package\]/,/^\[/s/^version = ".*"/version = "'"$new"'"/' Cargo.toml
sed -i 's/^pkgver=.*/pkgver='"$new"'/; s/^pkgrel=.*/pkgrel=1/' packaging/arch/PKGBUILD
cargo update --workspace --offline
echo "Now move the Unreleased notes of CHANGELOG.md under '## [$new] - $(date +%F)', fix its compare links, then run tools/check-version.sh."
