# Changelog

All notable changes to wirelens are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **TLS keys can be loaded from the app.** The Web page has a TLS keys line: pick a key log file, or drop one on the
  window, and the capture is read again with it, so HTTPS shows up as ordinary HTTP. A dropped file is recognised as a
  key log by its content, anything else still opens as a capture. Embed into .pcapng saves a copy of the capture that
  carries the keys (it needs `editcap` and is greyed out without it); the original file is never overwritten.
- **Certificates can be inspected.** An HTTPS session lists the certificate chain the server sent: subject, issuer,
  validity dates, alternative names, key type and signature, with warnings for a self-signed, expired, not yet valid
  or mismatching (against the SNI) certificate. TLS 1.3 chains appear once the keys are loaded.
- **WebSocket, Server-Sent Events and gRPC have a Streams tab** in Web. Each conversation is one row with its
  endpoint, message counts and status (WebSocket close code, gRPC status); selecting it shows the timeline of
  messages with direction, opcode, event name or gRPC call, and a payload preview.
- **Packet comments of pcapng files are read and written.** Comments stored in a capture become bookmarks when it is
  opened, and the bookmark bar's Save to .pcapng writes the bookmark comments into a new capture. The HTML report now
  lists each bookmarked packet with its time, addresses, protocol and info next to your comment.

### Changed
- **New screenshots in the README.** It shows nine pages instead of six (Hosts with its locations, Insights and the
  Locations settings were added), in both themes, all taken on an invented home network.

## [0.4.0] - 2026-11-21

### Added
- **Location databases from the settings.** Settings > Locations lists the free DB-IP Country and ASN databases
  (about 4 and 5 MB) with a Download button, which becomes Update once one is installed. A download is checked to open
  as a valid database before it replaces the old file, so a failed one never breaks the lookups. Your own `.mmdb` files
  (GeoLite2, DB-IP...) are added from the same page and can be removed again, and the folder opens in the file
  manager. Hosts and Map use a new database at once, without a restart.
- **The filter box suggests values from the capture.** After a comparison operator, `ip.addr == 10.` offers the hosts
  that start with `10.` and `tcp.port == ` the service ports in use, the most active first, instead of matching field
  names. Enter or Tab accepts. It works in the Packets filter and in the Graphs series; names (DNS, SNI, hosts) are not
  suggested yet.
- **HTML responses can be read.** The Web details show a Preview of the page (title, headings, list items and link
  targets as plain text, scripts and styles left out) next to its Source, with a Preview / Source switch like the
  Pretty / Raw one of JSON.

### Changed
- **Suggestions follow the cursor.** Editing the middle of a filter completes the word under the cursor instead of
  assuming the end of the text, and a long field name is cut instead of running into its description.
- **The Hosts page says where to get a location database** when none is installed (Settings > Locations), on one line
  that is cut to the width of the toolbar.

### Fixed
- **The cursor lands after what a suggestion inserted.** It used to stay in the middle of the text.
- **Pretty-printed JSON keeps the order of its keys** as the server sent them, instead of sorting them alphabetically.

## [0.3.0] - 2026-11-21

### Added
- **A logo.** wirelens has an icon, a split W on a rounded tile, in a blue version for the light theme and a dark one
  for the dark theme. It is the window icon, heads the sidebar, and is in the `.deb` and Arch packages, the macOS app
  and the Windows installer and executable. The sources and the PNG, `.ico` and `.icns` exports are in `assets/logo`.
- **Where a host is.** Hosts gets a Location column with the country and, with an ASN database, the network operator
  of public addresses, and the Map tooltips show the same. It reads local MaxMind-format `.mmdb` files (GeoLite2, DB-IP
  Lite) from `~/.local/share/wirelens/geo`, the qBittorrent `GeoDB` folder, `/usr/share/GeoIP` or the folder in
  `WIRELENS_GEO_DIR`, and stays hidden when none is found. Hosts also show reverse DNS names, which were limited to
  `localhost`.
- **TLS fingerprints.** The session details in Web show the JA3, JA4 and JA3S of the handshake, which tell one client or
  server from another even when the traffic is encrypted, and the search box finds them.
- **Reading response bodies.** A Pretty / Raw switch formats JSON, text previews grow from 4 KiB to 256 KiB, and PNG,
  JPEG and GIF bodies are shown as images with their size.
- **Behaviour findings in Insights.** TCP and UDP port scans, ping and host sweeps, connections or packets that arrive at
  a steady rhythm (beaconing) and unusually long DNS names are reported, each with the filter that shows its packets.
  They come from a single pass whose memory follows the number of hosts and ports rather than the number of packets, so
  there is no cap on the capture. Many hosts contacted on a web port (80, 443...) are not counted as a sweep, since
  browsing does that.
- **A step for the throughput chart.** Auto, 10 ms, 100 ms, 1 s or 10 s.

### Changed
- **The throughput chart is finer.** Its buckets start at 1 ms and widen as the capture grows (a short capture used to
  be two points), and a selected time window is kept to the millisecond instead of whole seconds.
- **Filter autocomplete knows every field.** It loaded only the first 25,000 of tshark's 270,000 fields, so `ip.addr`
  was missing. It now loads them all, ranks the exact match, then the common fields, then the shortest, and Enter
  accepts while Tab and Shift+Tab move through the list.
- **Searches in the filter boxes are faster**: the case-insensitive match no longer allocates for each row.
- **Insights appear as each analysis finishes** instead of after the last one.

### Fixed
- **Flows with hosts of both IPv4 and IPv6** no longer build an invalid display filter.
- **A TCP graph for ports reused by several connections** drew them as one, with time running backwards. It shows the
  first connection and says how many share the ports.

## [0.2.0] - 2026-11-21

### Added
- **Packages.** `.deb` packages for `amd64` and `arm64`, a Windows installer, macOS `.dmg` images (drag wirelens to
  Applications) and an Arch Linux `.pkg.tar.zst` with a `PKGBUILD` in `packaging/arch`, and a `SHA256SUMS` file with
  every release.
- **A demo capture and screenshots.** `tests/fixtures/demo.pcap` and a table of screenshots in the README, and a short
  code of conduct.

### Changed
- **A cooler light theme.** Paper greys with a stronger contrast for borders and muted text, and a deep blue accent.
- **Smaller binaries.** Release builds are stripped and use thin LTO, which makes them about three times smaller.
- **Dependencies.** `rfd` 0.18, `dirs` 7 and newer GitHub Actions in the CI.

### Fixed
- **Windows:** the app no longer opens a console window behind it.

## [0.1.0] - 2026-11-20

First public prototype of wirelens, a desktop packet viewer written in Rust with `egui` on top of `tshark` and
`dumpcap`.

### Added
- **Capture:** interfaces grouped by type with live rates, BPF capture filters, promiscuous and monitor mode, snap
  length, ring buffer, auto-stop rules and a list of recent files.
- **Packets:** a virtualized packet list, the display filter bar with field completion and quick-filter chips, search
  (string, regex, hex), the dissection tree with click-to-filter, a hex view, custom columns, time formats, bookmarks,
  stream following and export (pcap subsets, CSV, JSON, HTML report).
- **Overview, Hosts and Conversations:** live and offline totals, a throughput chart with time-window selection, the
  protocol mix and the top talkers.
- **Graphs and Flows:** I/O graphs with several series, conversation sequence diagrams, and TCP time-sequence,
  throughput, RTT and window-size plots.
- **Map:** a force-directed graph of host-to-host traffic with links scaled by volume and encrypted flows highlighted.
- **Web and Insights:** HTTP requests paired with their responses, with a body preview and `curl` export; TLS sessions
  (SNI, version, cipher, ALPN, and decryption with `SSLKEYLOGFILE`); extracted objects; expert info, the protocol
  hierarchy and the DNS query log.
- **Interface and command line:** dark and light themes, pages that open in their own window, a command palette
  (`Ctrl+K`), settings (`Ctrl+,`) and the options `--live`, `--filter`, `--page`, `--detach`, `--decode-as`, `--scale`,
  `--size` and `--light`.
- **Release binaries** built by the CI for Linux (`x86_64`, `aarch64`, Arch Linux), macOS (`arm64`, `x86_64`) and
  Windows (`x86_64`).

[Unreleased]: https://github.com/anyhowfeel/wirelens/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/anyhowfeel/wirelens/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/anyhowfeel/wirelens/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/anyhowfeel/wirelens/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/anyhowfeel/wirelens/releases/tag/v0.1.0
