"""Writes tests/fixtures/behavior.pcap: a port scan, a 30 s beacon and a ping sweep."""
import socket
import struct
import sys


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def ip(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    head = head[:10] + struct.pack("!H", checksum(head)) + head[12:]
    return head + payload


def syn(src: str, dst: str, port: int) -> bytes:
    seg = struct.pack("!HHIIBBHHH", 40000, port, 1, 0, 5 << 4, 0x02, 8192, 0, 0)
    return ip(6, src, dst, seg)


def echo(src: str, dst: str) -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    return ip(1, src, dst, struct.pack("!BBH", 8, 0, checksum(body)) + body[4:])


def main(path: str) -> None:
    events = []
    for p in range(1, 41):
        events.append((p * 0.01, syn("10.0.0.9", "10.0.0.1", p)))
    for i in range(10):
        events.append((i * 30.0, syn("10.0.0.5", "8.8.8.8", 443)))
    for h in range(1, 26):
        events.append((h * 0.05, echo("10.0.0.7", f"10.0.1.{h}")))
    events.sort(key=lambda e: e[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for t, pkt in events:
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(pkt), len(pkt)) + pkt)


main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/behavior.pcap")
