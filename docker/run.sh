#!/usr/bin/env bash
# Container side of the release: image (build the release images), run (a command in one), build (all artifacts).
# IMAGE=arch picks the Arch image. The Linux arm64 files are built by the release workflow on an arm runner.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }
version() { sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml; }

# The tag is a hash of the Dockerfile, so an image is rebuilt only when it changes.
image_ref() {
  echo "ghcr.io/anyhowfeel/pilotfish-$1:$(sha256sum "docker/$1.Dockerfile" | cut -c1-12)"
}

image() {
  local name="${1:?usage: docker/run.sh image builder|arch [--push]}" ref
  ref=$(image_ref "$name")
  docker build -f "docker/$name.Dockerfile" -t "$ref" docker
  echo "built $ref"
  [[ "${2:-}" == --push ]] && docker push "$ref"
  return 0
}

# One cache volume per checkout and image: checkouts never share a target dir.
run() {
  local ref
  ref=$(image_ref "${IMAGE:-builder}")
  docker image inspect "$ref" >/dev/null 2>&1 || docker pull -q "$ref" >/dev/null 2>&1 \
    || image "${IMAGE:-builder}" >&2
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" \
    -v "pilotfish-${IMAGE:-builder}-$(pwd | sha256sum | cut -c1-8):/cache" "$ref" "$@"
}

# Stage a release folder with the binary and the docs, then archive it.
package() {
  local name="$1" kind="$2" bin="$3"
  mkdir -p "dist/$name"
  cp "$bin" README.md LICENSE CHANGELOG.md "dist/$name/"
  if [[ "$kind" == zip ]]; then (cd dist && zip -qr "$name.zip" "$name"); else tar -C dist -czf "dist/$name.tar.gz" "$name"; fi
  rm -rf "dist/$name"
}

inside() {
  local tag="v$(version)" ver
  ver=$(version)
  case "$1" in
    linux)
      cargo build --release --locked
      package "pilotfish-$tag-linux-$(uname -m)" tar "$CARGO_TARGET_DIR/release/pilotfish"
      cargo deb -p wl-app --no-build --output dist/ ;;
    windows)
      cargo build --release --locked --target x86_64-pc-windows-gnu
      package "pilotfish-$tag-windows-x86_64" zip "$CARGO_TARGET_DIR/x86_64-pc-windows-gnu/release/pilotfish.exe" ;;
    arch)
      # makepkg finds the tarball next to the PKGBUILD and skips the download. The host made the tarball
      # (dist/src), since a git worktree's .git points outside the mounted folder.
      local work=/cache/arch
      rm -rf "$work" && mkdir -p "$work"
      cp "dist/src/pilotfish-$ver.tar.gz" packaging/arch/PKGBUILD "$work/"
      (cd "$work" && makepkg -f --nodeps --noconfirm)
      cp "$work"/*.pkg.tar.zst dist/ ;;
    *) die "unknown target $1" ;;
  esac
}

# Builds the working tree (including a version bump that is not committed yet) into dist/.
build() {
  local ref self="docker/run.sh"
  ref=$(git stash create || true)
  rm -rf dist && mkdir -p dist/src
  git archive --prefix="pilotfish-$(version)/" -o "dist/src/pilotfish-$(version).tar.gz" "${ref:-HEAD}"
  run "$self" inside linux
  run "$self" inside windows
  IMAGE=arch run "$self" inside arch
  rm -rf dist/src
  (cd dist && sha256sum -- * > SHA256SUMS)
  ls -l dist
}

cmd="${1:-}"
[[ $# -gt 0 ]] && shift
case "$cmd" in
  image | run | build | inside) "$cmd" "$@" ;;
  *) die "usage: docker/run.sh image|run|build|inside ..." ;;
esac
