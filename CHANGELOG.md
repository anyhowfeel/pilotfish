# Changelog

All notable changes to pilotfish (formerly wirelens) are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- **Copying works with the system clipboard.** Ctrl+C on selected text and every Copy button only reached a
  clipboard inside pilotfish, because the build left out the clipboard support of the window library, so
  nothing could be pasted into another program. It is enabled again, on Wayland and X11.
### Added
- **Live captures are saved by default.** A capture is kept as `capture-<date>-<time>-<interface>.pcapng` in
  `Documents/pilotfish/captures`, appears in Recent files, and never overwrites an existing file. Settings >
  Capture > Saved captures sets the folder or turns it off, in which case the capture stays a temporary file
  as before. A path typed in Output > Save to still wins, and a ring buffer always keeps its files.
### Added
- **A Reset view button on the map** (key `R`). It fits the graph, frees the hosts you moved so the layout starts
  afresh, and clears the selection, the search and the filters. The layout mode and the Labels, Directions and
  Encrypted switches stay as you set them.

## [0.6.0] - 2026-11-23

### Added
- **Capture files open without Wireshark.** A pure-Rust reader and decoder (`wl-native`) read pcap and pcapng
  files and feed the Overview, Hosts, Map, Packets, Graphs and Properties pages, a layer summary in the packet
  detail pane, a subset of the display filter language, I/O graphs and file properties. `wl-hybrid` sends
  every other request (HTTP and TLS details, streams, objects, Decode As, export, live capture) to tshark, which
  now starts on first use instead of at launch. The missing-Wireshark banner is gone; a feature that needs
  Wireshark says so when it is used. The native rows, filters, series, properties and frame layers are checked
  against tshark on every fixture capture. On a synthetic 3 million packet capture the native read peaks at 15 MiB
  and takes 3.3 s, where tshark peaks at 2059 MiB and takes 67 s.
- **A Planar layout for the map.** The default layout draws the graph without crossing links when that is
  possible and keeps the crossings to a minimum when it is not. The map shows the number of crossings, or "No
  crossings". Force stays as the free-moving layout.
- **A time zone setting for the file properties.** Times show in local time by default and in UTC when
  chosen in Settings, on both the native and the tshark path.

### Changed
- **The Radial map layout is gone**, replaced by Planar.
- **Link arrows on the map end at the destination host.** The tip touches the host, the head is outlined and its
  size no longer grows with the width of the link.
- **The map colors private and public hosts with chart colors** (blue and magenta). Green and orange are the ok and
  warning colors, so every public host used to read as a warning.
- **Less interface copy.** The Network health page lost its subtitle, the hints that explained how to drag a chart
  selection or zoom were removed (the README describes the gestures), tooltips that repeated a button label are
  gone and the command palette uses sentence case.
- **Releases are built in containers.** `tools/release.sh` checks the tree, builds the Linux and Windows files and
  the Arch package in pinned containers (`docker/run.sh`) and prepares the notes from this changelog; it only
  publishes with `--publish`. The macOS disk images and the Windows installer (which wraps the same executable as
  the `.zip`) are built by a workflow when a release is published, and the CI only runs the version check, fmt,
  clippy and the tests. The Linux aarch64 files are built by the same workflow on an arm runner. See `docs/releasing.md`.
- **The packages recommend Wireshark instead of requiring it**: the `.deb` recommends `tshark` and the Arch package
  lists `wireshark-cli` as optional, since capture files open without it.

### Fixed
- **Wireshark is found on macOS and Windows when the app is not started from a shell.** The tools are looked for
  in the folder chosen in Settings > Capture (or `PILOTFISH_WIRESHARK_DIR`), on `PATH`, in the Wireshark app
  bundle, the Homebrew and MacPorts folders, `Program Files\Wireshark` and, on macOS, the `PATH` of the login
  shell. The missing-Wireshark message says what to install and where it looked, and a macOS capture permission
  failure lists the ChmodBPF steps.
- **Insights no longer reports a clean capture when an analysis failed or has not run.** A failed expert info,
  protocol hierarchy, behavior or credential scan now shows "Analysis failed" with the reason and a way to
  retry, the summary reads "Analysis incomplete", and exported reports leave out the all-clear card unless
  every analysis finished. Before, the failure was dropped and the page said "Nothing looks wrong".
- **A Python cache file is no longer tracked** in `tests/fixtures`, and Python caches are ignored.

## [0.5.0] - 2026-11-22

### Added
- **Offline threat lists.** Files dropped in the `intel` folder (opened from Settings > Locations, where files can also
  be added) are matched against the capture without any network call. A JA4DB `.json` export names the application
  behind a TLS fingerprint, and text or CSV blocklists (abuse.ch formats work) list addresses, domains and JA3 / JA4
  fingerprints. Hosts shows a Threat column, the Web TLS rows and details show the known client and any listing, and
  Insights reports blocklisted addresses and domains and malicious fingerprints.
- **Cleartext credentials in Insights.** HTTP Basic logins, bearer tokens, API keys in headers and query strings, FTP,
  POP3 and SMTP logins and NTLM authentications are reported with the secret masked. Settings > Insights can show the
  secrets, but the exported reports always mask them.
- **Tunable Insights.** Settings > Insights sets the thresholds of the port scan, sweep, steady rhythm and long DNS name
  findings. Right-clicking a finding mutes a host or a kind of finding, and the muted list is managed on the same page.
- **Capture Diff page.** It compares the open capture with a second one, picked from the page or given with `--diff`.
  It lists the hosts, services (endpoints and server port, so changing client ports do not count), mean HTTP and DNS
  latencies, HTTP hosts, status codes and TLS server names that are new, missing or changed, biggest change first.
- **Saved filters.** The filter bar has a Saved menu to keep the current filter under a name, apply it again, rename it
  or delete it. They are remembered between sessions.
- **The filter box suggests names.** After `ip.addr ==` typing a domain offers the addresses it resolved to in the DNS
  log or the TLS handshake, and each suggested address shows its name. `http.host`, `dns.qry.name` and the TLS server
  name field suggest the names seen in the capture.
- **Live captures name the process behind each connection (Linux).** While a local capture runs, the sockets listed in
  `/proc/net` are matched with the file descriptors of running processes every two seconds. Hosts and Conversations get a
  Process column, the Flows list shows the process name and the Map tooltip a Process line, all only once a process is
  known. Processes of other users cannot be inspected and stay unnamed.
- **Capture over SSH.** Capture options has a Remote capture (SSH) section: host, user, port, interface and an optional
  `sudo -n`, with the capture filter field as the filter. Pilotfish runs `tcpdump` on the remote host through the system
  `ssh` (never asking for a password, so a key or agent is needed) and feeds the stream to the same live view as a local
  capture. Every value is quoted for the remote shell, and failures such as a refused login, a missing `tcpdump` or a
  sudo that wants a password are reported in plain words. Stop ends the ssh process.
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
- **The app is now called pilotfish.** The binary, the window title, the packages, the icons and the environment
  variables (`PILOTFISH_CONFIG_DIR`, `PILOTFISH_GEO_DIR`, `PILOTFISH_INTEL_DIR`) carry the new name. The `wirelens`
  folders of your configuration and data are moved to `pilotfish` the first time it starts, and the `WIRELENS_*`
  variables are still read. The packages are called `pilotfish`, so remove an installed `wirelens` package yourself.
- **A new logo**: a fin and a school of pilot fish on a rounded tile, as the window icon, in the packages and in the
  README, with a new GitHub social preview image. The sidebar now shows only the name.
- **The Flows list is easier to read.** Each conversation shows its endpoints with the ports dimmed, the protocol as a
  pill, aligned packet, byte and duration figures (the least useful one is dropped first in a narrow pane) and a thin bar
  for its share of the traffic. Top talkers and Top services on the Overview use the same bar style.
- **Narrow windows behave.** The Capture Diff page has Before, After and Change columns and scrolls sideways instead of
  clipping, the Web TLS keys line keeps its buttons on one line, the Hosts table keeps a visible sideways scroll bar and
  the status bar hides the rate and the elapsed time first.
- **Insights says what it leaves out.** When a kind of finding is capped, for example to three cards per behaviour, a
  note tells how many more are not shown.
- **Opening a capture runs fewer `tshark` passes.** The TLS, HTTP, DNS and credential scans are shared between Web,
  Insights, Diff and the filter suggestions and run once per file version.
- **Releases follow a written convention.** Pull requests are squash-merged with a Conventional Commits title,
  versions follow Semantic Versioning, and `tools/check-version.sh` makes the CI fail when `Cargo.toml`,
  `Cargo.lock`, the Arch PKGBUILD, the changelog and the tag disagree. CONTRIBUTING.md describes the steps.
- **The Locations page writes your home folder as `~`**, so the folder of the databases reads
  `~/.local/share/pilotfish/geo` instead of a full path.
- **A richer demo capture.** `tests/fixtures/demo.pcap` now also holds a visitor scanning the NAS, a phone calling an
  address at a steady rhythm and very long DNS names, so Insights has something to show, and
  `tests/fixtures/gen_demo_capture.py` writes it.
- **The releases take their notes from this changelog**: the title is "pilotfish X.Y.Z" and the notes are the section of
  the tag, instead of a list of pull request titles.
- **New screenshots in the README.** It shows nine pages instead of six (Hosts with its locations, Insights and the
  Locations settings were added), in both themes, all taken on an invented home network.

### Fixed
- **The quick filters No broadcast and Not multicast** also work on captures taken with `tcpdump -i any`.
- **The long DNS name finding** gives a filter that matches the names that triggered it, including a single very long
  label.

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

[Unreleased]: https://github.com/anyhowfeel/pilotfish/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/anyhowfeel/pilotfish/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/anyhowfeel/pilotfish/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/anyhowfeel/pilotfish/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/anyhowfeel/pilotfish/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/anyhowfeel/pilotfish/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/anyhowfeel/pilotfish/releases/tag/v0.1.0
