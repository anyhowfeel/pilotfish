# Native fast path

pilotfish reads capture files with a pure-Rust reader first and starts tshark only for what needs
Wireshark's dissectors. Without Wireshark installed, a file still opens and the Overview, Hosts,
Map, Packets, Graphs and Properties pages work.

## Crates

| Crate | Role |
|---|---|
| `wl-native` | Reads pcap / pcapng, decodes link, network and transport layers into `PacketRow`, evaluates a small display-filter subset, builds I/O series and file properties. Not a `CaptureBackend`. |
| `wl-hybrid` | `HybridBackend`: the `CaptureBackend` the app uses. Routes each request to `wl-native` or to `wl-tshark`, which it starts on first use. |
| `wl-tshark` | Unchanged role: every request that needs dissection, live capture, or Wireshark's filter language. |

`wl-native` and `wl-tshark` do not know each other. `wl-hybrid` is the only place that does.

## Routing

| Request | Answered by |
|---|---|
| `start(File)` with no display filter, or a filter `wl_native::filter` supports, and no Decode As rule | native |
| `start(File)` with any other filter or with Decode As rules | tshark |
| `start(Live / Capture)`, `interfaces`, `check_capture_filter` | tshark (dumpcap) |
| `check_filter` | native when the filter is in the subset, else tshark |
| `capture_properties`, `file_sha256` | native |
| `io_series` when every spec's filter is in the subset | native, else tshark |
| `frame_detail` | tshark; without Wireshark, a native layer summary and the raw bytes |
| everything else (HTTP, TLS, DNS log, objects, credentials, streams, Decode As, export, comments) | tshark |

Without tshark a tshark-only request returns `CaptureError::ToolMissing`, and the UI says which
feature needs Wireshark. The native requests keep working.

## Time zone

Times in the file properties follow Settings > Display > Capture file > Time zone: local by
default, UTC on request. The hybrid backend holds the choice (`CaptureBackend::set_clock_zone`),
hands it to the native side with each request and replays it to tshark when that is started, which
runs `capinfos` with `TZ=UTC` for UTC and with its own environment for local time. Both paths
print the same text in either zone; `properties_vs_capinfos` checks it in both.

## Fidelity rule

The native rows must equal tshark's for the fields the statistics read: `no`, `epoch`, `rel`,
`src`, `dst`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `transport`, `len`, `stream`. That is
checked packet by packet against tshark on the fixture captures. `protocol` and `info` follow
Wireshark's wording for the cases the decoder recognises and are best effort elsewhere.

A native filter must select exactly the frames tshark selects. A filter that cannot be guaranteed
to is outside the subset.

## Filter subset

`wl_native::filter::parse` accepts `&&` `||` `!` (and `and` `or` `not`), parentheses, `==` `!=`
`<` `<=` `>` `>=` (and `eq` `ne` `lt` `le` `gt` `ge`), `field in {a, b}` and bare fields.
Anything else returns `None` and goes to tshark.

| Fields | Values |
|---|---|
| `eth` `ip` `ipv6` `tcp` `udp` `icmp` `icmpv6` `arp` `dns` `http` `tls` (presence) | none |
| `ip.addr` `ip.src` `ip.dst`, `ipv6.addr` `ipv6.src` `ipv6.dst` | address or `address/prefix` |
| `eth.addr` `eth.src` `eth.dst` | `aa:bb:cc:dd:ee:ff` |
| `tcp.port` `tcp.srcport` `tcp.dstport` `udp.port` `udp.srcport` `udp.dstport` | 0 to 65535 |
| `tcp.stream` `udp.stream` `frame.number` `frame.len` | unsigned 32-bit |
| `ip.ttl` `ip.proto` | 0 to 255 |
| `tcp.flags.syn` `.ack` `.fin` `.reset` `.push` | `1` `0` `true` `false` |

Numbers are decimal or `0x` hex. Set members are separated by commas, as Wireshark requires.
`!=` is true only when the field is present and no occurrence equals the value. `ip.addr` is both
the source and the destination, and an ICMP error also holds the addresses, ports and TCP flags
of the packet it quotes, as Wireshark's second IP layer does. `vlan` and `vlan.id` are left to
tshark because Wireshark ignores 802.1ad tags and the decoder keeps one VLAN id only.
An ICMP error numbers the TCP conversation it quotes only when the quote reaches the TCP flags byte (at least 14 bytes) and the message is not a redirect; the decoder applies that rule once, to the stream and to the quoted flags.
`dns`, `http` and `tls` read the protocol column, which agrees with tshark on every fixture.

Known limits, shared with the decoder: fragmented datagrams (Wireshark reports the transport on
the last fragment), and encapsulations Wireshark opens that the decoder does not (IP-in-IP, GRE,
VXLAN, GTP), where `ip.addr` also matches the inner header in tshark.
`tests/filter_vs_tshark.rs` checks the subset against tshark on every fixture. `tests/detail_vs_tshark.rs` checks the layer lines of the no-Wireshark detail pane against `tshark -V`.

## Memory

The native pass keeps a stream table, an interner and one packet buffer. It does not keep frames.
`crates/wl-native/tests/memory_flat.rs` streams 300k and then 600k packets and asserts that the
peak resident growth stays under a fixed bound and that doubling the packets raises it by less
than 25 %. Linux only.

## Measured

Synthetic capture of 3 000 000 packets (1257 MiB pcap; TCP, UDP, DNS and ICMP over 50 000
conversations and 5 000 hosts), rows drained and dropped as they arrive. Release build, tshark
4.7.4, one run each on one machine.

| Backend | Seconds | Rows/s | Peak resident |
|---|---|---|---|
| native (in process) | 3.3 | 915 000 | 15 MiB |
| tshark (child process) | 66.8 | 45 000 | 2059 MiB |

On 1 000 000 packets the figures are 15 MiB native and 889 MiB tshark, so the native peak is flat
and tshark's grows with the file. Holding every row, as the UI does, costs the same on both paths
because the rows are the same type: about 235 bytes per row native, 246 tshark (peak growth of the
process divided by the rows).

Reproduce:

```
cargo build --release -p wl-hybrid --features test-util --example measure
M=target/release/examples/measure
$M gen /tmp/big.pcap 3000000
$M native /tmp/big.pcap
$M tshark /tmp/big.pcap
$M native /tmp/big.pcap --keep
$M tshark /tmp/big.pcap --keep
```
