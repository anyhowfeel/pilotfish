# Contributing

pilotfish is a prototype and a personal project; issues and small pull requests are welcome,
but there is no promise of fast replies.

## Building

You need a stable Rust toolchain and Wireshark's command-line tools (`tshark`, `dumpcap`).
See the README for details.

```sh
cargo build
cargo test --workspace
```

## Before sending a change

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Conventions used in the code:

- Source files stay under about 250 lines; split a file by responsibility rather than grow it.
- Shared UI helpers live in `wl-kit`, shared types in `wl-model`; avoid copying a helper into a
  second crate.
- Colours come from the theme (`Palette`), never from literals in the panels.
- Check UI changes in both the dark and the light theme.

## Pull requests and commits

Pull requests are squash-merged, so `main` has one commit per pull request and no merge commits.
The pull request title becomes that commit, and the description its body. The title follows
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) and is checked by the CI:

```
type(scope): short imperative summary
```

| Type | Use it for | Version bump (0.y.z) |
| :--- | :--- | :--- |
| `feat` | a new feature | minor |
| `fix` | a bug fix | patch |
| `perf` | a speed or memory improvement | patch |
| `refactor`, `docs`, `test`, `build`, `ci`, `chore` | no change in behaviour | none |
| `revert` | undoing an earlier change | as the reverted change |

A `!` before the colon (`feat(cli)!: drop --old-flag`) marks a breaking change, which also bumps the
minor version while the project is below 1.0. The scope is optional and names the area (`web`, `insights`,
`capture`, `packaging`...). Name branches after the type: `feat/diff-page`, `fix/flow-width`,
`release/0.5.0`.

## Versioning

pilotfish follows [Semantic Versioning](https://semver.org/). Below 1.0.0 a minor version (0.5.0) brings
features and may break things, and a patch version (0.5.1) only fixes bugs. Tags are `vX.Y.Z` and only
ever point at a commit of `main`. `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
with full sentences.

The version lives in `Cargo.toml`, `Cargo.lock`, `packaging/arch/PKGBUILD` and the latest released section of
`CHANGELOG.md`. `tools/check-version.sh` fails when they disagree, and the CI runs it on every pull request
and every release build.

## Releasing

1. Branch `release/X.Y.Z` from an up to date `main`.
2. `tools/bump-version.sh X.Y.Z` sets the version in `Cargo.toml`, `Cargo.lock` and the PKGBUILD.
3. In `CHANGELOG.md`, move the `Unreleased` notes under `## [X.Y.Z] - YYYY-MM-DD` and fix the compare links.
4. `tools/check-version.sh`, then open a pull request titled `chore(release): X.Y.Z`.
5. When the CI is green, squash-merge it and update `main`.
6. On `main`, run `tools/release.sh` to build and check the artifacts in containers (nothing leaves the
   machine), then `tools/release.sh --publish` to tag the commit, push the tag and create the release with the
   notes taken from `CHANGELOG.md`. The macOS images, the Windows installer and the Linux arm64 files are added by a workflow. See `docs/releasing.md`.
