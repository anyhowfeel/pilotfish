# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-21

### Added
- Debian packages (`.deb`) for `amd64` and `arm64`, a Windows installer, macOS `.dmg` images
  (drag `wirelens` to Applications) and an Arch Linux `.pkg.tar.zst`, with a `PKGBUILD` in
  `packaging/arch`.
- `SHA256SUMS` published with each release.
- A synthetic demo capture (`tests/fixtures/demo.pcap`) and a screenshot table in the README.
- A short code of conduct.

### Changed
- New light theme: cooler paper greys with a stronger contrast for borders and muted text, and a
  deep blue accent.
- Release builds are stripped and use thin LTO, which makes the binaries about three times
  smaller.
- Updated `rfd` to 0.18, `dirs` to 7 and the GitHub Actions used by the CI.

### Fixed
- The Windows build no longer opens a console window.

## [0.1.0] - 2026-11-20

Initial public prototype release of `wirelens`, a desktop packet viewer built in Rust with `egui` on top of `tshark` and `dumpcap`.

### Added
- **Capture**: interface discovery grouped by type with live rates, BPF capture filters, promiscuous/monitor mode, snap length, ring buffer, auto-stop rules, and recent file history.
- **Packets**: virtualized packet list, display filter bar with field completion and quick-filter chips, search (string, regex, hex), dissection tree with click-to-filter, hex viewer, custom columns, time formats, bookmarks, stream following, and export (pcap subsets, CSV, JSON, HTML report).
- **Overview, Hosts & Conversations**: live and offline totals, throughput chart with time-window selection, protocol breakdown, and top talkers.
- **Graphs & Flows**: multi-series I/O graphs, conversation sequence diagrams, and TCP time-sequence, throughput, RTT, and window-size plots.
- **Map**: force-directed host-to-host traffic graph with volume-scaled links and encrypted flow highlighting.
- **Web & Insights**: HTTP request/response pairing with body preview and `curl` export, TLS session inspection (SNI, version, cipher, ALPN, optional `SSLKEYLOGFILE` decryption), extracted objects, expert info, protocol hierarchy, and DNS query log.
- **UI & CLI**: dark/light themes, detachable page windows, command palette (`Ctrl+K`), settings (`Ctrl+,`), and CLI options (`--live`, `--filter`, `--page`, `--detach`, `--decode-as`, `--scale`, `--size`, `--light`).
- **Release binaries**: CI builds for Linux (`x86_64`, `aarch64`, Arch Linux), macOS (`arm64`, `x86_64`), and Windows (`x86_64`).
