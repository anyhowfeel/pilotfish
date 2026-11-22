"""Writes comments-multi.pcapng: packet 1 has two comments (the second multi-line), packet 2 one,
packet 3 has a backslash, plus an interface statistics block and a capture filter option that editcap drops."""
import struct
import sys

from pcaplib import udp_packet


def pad(b):
    return b + b"\0" * (-len(b) % 4)


def option(code, value):
    return struct.pack("<HH", code, len(value)) + pad(value)


def block(kind, body):
    total = 12 + len(body)
    return struct.pack("<II", kind, total) + body + struct.pack("<I", total)


def main(path):
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 101, 0, 0) + option(11, b"\0udp port 9999") + option(0, b""))
    comments = [[b"first note", b"second\nnote with\ttab"], [b"only one"], [b"back\\slash \"q\""]]
    body = b""
    for i, cs in enumerate(comments):
        pkt = udp_packet("10.0.0.1", "10.0.0.2", 40000 + i, 40100, b"x")
        opts = b"".join(option(1, c) for c in cs) + (option(0, b"") if cs else b"")
        ts = 1_700_000_000_000_000 + i * 1000
        body += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(pkt), len(pkt)) + pad(pkt) + opts)
    isb = block(5, struct.pack("<III", 0, 0, 0) + option(0, b""))
    with open(path, "wb") as f:
        f.write(shb + idb + body + isb)


main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/comments-multi.pcapng")
