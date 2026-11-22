## What and why

<!-- A few sentences. Link the issue if there is one. -->

## Checks

- [ ] The title follows Conventional Commits (`feat(scope): summary`): it becomes the commit on `main`
- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] UI changes: checked in the dark and the light theme
- [ ] User-visible changes: a line under `Unreleased` in `CHANGELOG.md`
