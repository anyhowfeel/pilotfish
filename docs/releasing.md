# Releasing

Linux and Windows artifacts are built locally in containers, so a release does not depend on CI minutes. GitHub Actions checks pull requests and, once a release is published, adds the macOS images and the Windows installer.

## Prepare

1. `tools/bump-version.sh X.Y.Z`, then move the Unreleased notes of `CHANGELOG.md` under `## [X.Y.Z] - date` and fix its compare links.
2. `tools/check-version.sh` fails unless Cargo.toml, Cargo.lock, the PKGBUILD and the changelog agree.
3. Commit. The working tree must be clean.

## Build

`tools/release.sh` runs the version check, fmt, clippy and the tests, then builds in containers (`docker/run.sh build`) into `dist/`:

- `pilotfish-vX.Y.Z-linux-x86_64.tar.gz` and `-linux-aarch64.tar.gz` and a `.deb` for each, from the Debian builder image (glibc 2.36)
- `pilotfish-vX.Y.Z-windows-x86_64.zip`, cross-built with mingw
- the Arch package, from the Arch image
- `SHA256SUMS` and `NOTES.md` (the changelog section of this version)

The arm64 files are built under QEMU and take much longer; `--no-aarch64` skips them. They need the QEMU handler registered on the host: `docker run --privileged --rm tonistiigi/binfmt --install arm64` (it lasts until a reboot). The builder images are tagged with a hash of their Dockerfile and live on `ghcr.io/anyhowfeel/pilotfish-<name>`; `docker/run.sh image builder` builds one, `docker/run.sh image builder --push` uploads it.

## Publish

`tools/release.sh --publish` pushes the tag `vX.Y.Z` and creates the GitHub release with `gh`. Publishing the release starts `release-installers.yml`, which builds the arm64 and x86_64 macOS disk images, wraps the executable of the Windows zip in the Inno Setup installer (`packaging/windows/pilotfish.iss`), attaches them to the release and refreshes `SHA256SUMS` over every asset.

## macOS and Wireshark

A Finder-launched app does not inherit the shell PATH. pilotfish looks for the Wireshark tools in `/Applications/Wireshark.app/Contents/MacOS`, `/opt/homebrew/bin` and `/usr/local/bin`. Live capture also needs ChmodBPF, which the Wireshark installer sets up.
