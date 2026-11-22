"""Writes tests/fixtures/web-bodies.pcap: three HTTP exchanges returning an HTML page, JSON and a PNG."""
import socket
import struct
import sys
from pathlib import Path

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
MSS = 1200

HTML = b"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>wirelens demo</title>
<style>body { color: #333; }</style><script>var tracking = "<p>ignored</p>";</script></head>
<body><h1>Directory listing for /</h1><p>Files &amp; folders:</p>
<ul><li><a href="docs/">docs/</a></li><li><a href="https://example.com/a">a link</a></li></ul>
</body></html>"""
JSON = b'{"name":"wirelens","version":"0.3","items":[1,2,3],"nested":{"ok":true,"tags":["a","b"]}}'


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    head = head[:10] + struct.pack("!H", checksum(head)) + head[12:]
    return head + tcp


def exchange(port, path, ctype, body, t0):
    """Handshake, request, response (split in segments) and close, as (time, packet) pairs."""
    req = f"GET {path} HTTP/1.1\r\nHost: demo.test\r\nAccept: */*\r\n\r\n".encode()
    resp = (f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
    c, s = 1000, 5000
    out, t = [], t0

    def add(pkt):
        nonlocal t
        out.append((t, pkt))
        t += 0.001

    add(packet(CLIENT, SERVER, port, 80, c, 0, 0x02))
    add(packet(SERVER, CLIENT, 80, port, s, c + 1, 0x12))
    c, s = c + 1, s + 1
    add(packet(CLIENT, SERVER, port, 80, c, s, 0x10))
    add(packet(CLIENT, SERVER, port, 80, c, s, 0x18, req))
    c += len(req)
    for i in range(0, len(resp), MSS):
        chunk = resp[i:i + MSS]
        add(packet(SERVER, CLIENT, 80, port, s, c, 0x18, chunk))
        s += len(chunk)
    add(packet(CLIENT, SERVER, port, 80, c, s, 0x11))
    add(packet(SERVER, CLIENT, 80, port, s, c + 1, 0x11))
    add(packet(CLIENT, SERVER, port, 80, c + 1, s + 1, 0x10))
    return out


def main(path):
    png = (Path(__file__).resolve().parents[2] / "assets/logo/pilotfish-64.png").read_bytes()
    events = []
    for i, (p, ct, body) in enumerate([("/index.html", "text/html; charset=utf-8", HTML),
                                       ("/data.json", "application/json", JSON),
                                       ("/logo.png", "image/png", png)]):
        events += exchange(50000 + i, p, ct, body, i * 0.1)
    events.sort(key=lambda e: e[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for t, pkt in events:
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(pkt), len(pkt)) + pkt)


main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/web-bodies.pcap")
