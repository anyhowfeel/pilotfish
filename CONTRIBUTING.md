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

## Commits

Short, imperative subject line ("Fix the flow list width"), one logical change per commit, and
a few lines of explanation in the body when the reason is not obvious.
