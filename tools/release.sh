#!/usr/bin/env bash
# Builds the release artifacts in containers and checks them. Nothing leaves the machine unless --publish is given.
#   tools/release.sh                  dry run: checks, container build into dist/, release notes in dist/NOTES.md
#   tools/release.sh --publish        after the dry run, push the tag and create the GitHub release with gh
set -euo pipefail
cd "$(dirname "$0")/.."

publish=false
for arg in "$@"; do
  case "$arg" in
    --publish) publish=true ;;
    *) echo "usage: tools/release.sh [--publish]" >&2; exit 1 ;;
  esac
done

version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
tag="v$version"

[[ -z "$(git status --porcelain)" ]] || { echo "error: the working tree is not clean" >&2; exit 1; }
tools/check-version.sh
tools/check.sh
docker/run.sh build

# The notes are the CHANGELOG.md section of this version.
awk -v v="$version" '$0 ~ "^## \\[" v "\\]" {on=1; next} /^## \[/ || /^\[[^]]+\]: / {on=0} on' CHANGELOG.md \
  | sed '/./,$!d' > dist/NOTES.md
[[ -s dist/NOTES.md ]] || { echo "error: CHANGELOG.md has no entry for $version" >&2; exit 1; }

if [[ "$publish" != true ]]; then
  echo "Dry run done: dist/ holds the artifacts and dist/NOTES.md the notes for $tag."
  echo "To publish: tools/release.sh --publish (pushes $tag, creates the release, then CI adds the macOS images)."
  exit 0
fi

git tag "$tag"
git push origin "$tag"
gh release create "$tag" dist/*.tar.gz dist/*.zip dist/*.deb dist/*.pkg.tar.zst dist/SHA256SUMS \
  --title "pilotfish $version" --notes-file dist/NOTES.md
