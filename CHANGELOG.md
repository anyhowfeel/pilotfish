# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-11-21

### Added
- Settings: a **Locations** page for the country and network databases. It proposes the DB-IP
  Country Lite and ASN Lite databases with a Download button (and Update once installed), lets you
  add your own `.mmdb` files and remove them, and opens their folder. A download is checked to be a
  valid database before it replaces the old one, and Hosts and Map pick it up without a restart.
- Filter boxes suggest the hosts and the service ports of the capture after a comparison operator
  (`ip.addr == 10.`, `tcp.port == `), instead of field names.
- Web: HTML responses can be read as text (a Preview with headings, lists and link targets, or the
  Source). The Pretty / Raw switch for JSON stays.

### Changed
- Filter autocomplete uses the real cursor position to find the token being edited, and long field
  names no longer run into their description.
- The Hosts hint tells where to add a location database (Settings > Locations).

### Fixed
- After accepting a suggestion the cursor was left in the middle of the text; it now moves to the
  end of the inserted text.

## [0.3.0] - 2026-11-21

### Added
- A new application icon (a split W on a rounded tile), in a blue and a dark version, used as the
  window icon, in the sidebar, in the `.deb` and Arch packages, in the macOS `.app` and on the
  Windows installer and executable. Sources and PNG, `.ico` and `.icns` exports are in
  `assets/logo`.
- Hosts: a **Location** column (country and, with an ASN database, the network operator) and the
  same details in the Map tooltips. It reads local MaxMind-format `.mmdb` files (GeoLite2, DB-IP
  Lite...) from `~/.local/share/wirelens/geo`, the qBittorrent `GeoDB` folder, `/usr/share/GeoIP`
  or the folder named by `WIRELENS_GEO_DIR`. The column is hidden when no database is found.
- Reverse DNS names for public hosts (they were limited to `localhost`).
- Web: JA3, JA4 and JA3S TLS fingerprints in the session details, searchable.
- Web: response bodies can be switched between pretty and raw text (JSON is formatted), the text
  preview grew from 4 KiB to 256 KiB, and PNG, JPEG and GIF bodies are shown as images.
- Insights: behavioural findings for TCP and UDP port scans, ping and host sweeps, regular
  connections or packets (beaconing) and unusually long DNS names. They are computed in one
  streamed pass whose memory follows the number of channels, not packets.
- Overview: the throughput chart has a step selector (Auto, 10 ms, 100 ms, 1 s, 10 s).

### Changed
- The throughput series now starts at 1 ms buckets and widens itself as the capture grows, and a
  selected time window is kept to the millisecond instead of whole seconds.
- Filter autocomplete loads every field known to tshark (it stopped at 25,000, so fields such as
  `ip.addr` were missing) and ranks the exact match, then common fields, then the shortest
  prefix. Enter accepts the suggestion and Tab / Shift+Tab move through the list.
- Case-insensitive searches in the filter boxes no longer allocate for each row.
- Insights results are delivered as soon as each analysis finishes.

### Fixed
- Flows: selecting hosts of both address families produced an invalid display filter.
- Flows: a TCP graph for ports reused by several connections plotted them all as one, with time
  running backwards. It now shows the first connection and says how many share the ports.

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
