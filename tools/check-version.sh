#!/usr/bin/env bash
# Fails unless every file that carries the version agrees (and the tag does, when run on one).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
lock=$(awk '/^name = "wl-app"$/ { getline; print $3; exit }' Cargo.lock | tr -d '"')
pkgbuild=$(sed -n 's/^pkgver=//p' packaging/arch/PKGBUILD)
changelog=$(sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' CHANGELOG.md | head -n 1)

semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
status=0
check() {
  if [[ "$2" != "$cargo" ]]; then
    echo "::error::$1 says '$2' but Cargo.toml says '$cargo'" >&2
    status=1
  fi
}

[[ "$cargo" =~ $semver ]] || { echo "::error::Cargo.toml version '$cargo' is not a Semantic Version" >&2; status=1; }
check "Cargo.lock (wl-app)" "$lock"
check "packaging/arch/PKGBUILD pkgver" "$pkgbuild"
check "CHANGELOG.md (latest released section)" "$changelog"
if [[ "${GITHUB_REF_NAME:-}" == v* && "${GITHUB_REF_TYPE:-}" == tag ]]; then
  check "tag ${GITHUB_REF_NAME}" "${GITHUB_REF_NAME#v}"
fi

[[ $status -eq 0 ]] && echo "Version $cargo is consistent."
exit $status
