"""Raw-IP pcap writer and protocol builders shared by the gen_*.py scripts that import it."""
import socket
import struct

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"
LINKTYPE_RAW = 101
LINKTYPE_SLL = 113


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def ip(src, dst, proto, body):
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    head = head[:10] + struct.pack("!H", checksum(head)) + head[12:]
    return head + body


def tcp_packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return ip(src, dst, 6, tcp)


def udp_packet(src, dst, sport, dport, payload):
    return ip(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


class Conn:
    """One TCP connection; `client`/`server` append a segment from either side."""

    def __init__(self, cport, sport, t0, handshake=True):
        self.cport, self.sport, self.t = cport, sport, t0
        self.c, self.s = 1000, 5000
        self.out = []
        if handshake:
            self._emit(CLIENT, SERVER, cport, sport, self.c, 0, 0x02)
            self._emit(SERVER, CLIENT, sport, cport, self.s, self.c + 1, 0x12)
            self.c, self.s = self.c + 1, self.s + 1
            self._emit(CLIENT, SERVER, cport, sport, self.c, self.s, 0x10)

    def _emit(self, src, dst, sp, dp, seq, ack, flags, payload=b""):
        self.out.append((self.t, tcp_packet(src, dst, sp, dp, seq, ack, flags, payload)))
        self.t += 0.01

    def client(self, data):
        self._emit(CLIENT, SERVER, self.cport, self.sport, self.c, self.s, 0x18, data)
        self.c += len(data)

    def server(self, data):
        self._emit(SERVER, CLIENT, self.sport, self.cport, self.s, self.c, 0x18, data)
        self.s += len(data)

    def fin_server(self):
        self._emit(SERVER, CLIENT, self.sport, self.cport, self.s, self.c, 0x11)

    def close(self):
        self._emit(CLIENT, SERVER, self.cport, self.sport, self.c, self.s, 0x11)
        self._emit(SERVER, CLIENT, self.sport, self.cport, self.s, self.c + 1, 0x11)
        self._emit(CLIENT, SERVER, self.cport, self.sport, self.c + 1, self.s + 1, 0x10)


def chunk(data):
    return f"{len(data):x}\r\n".encode() + data + b"\r\n"


def ws_frame(opcode, payload, mask, fin=True):
    head = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    mbit = 0x80 if mask else 0
    head += bytes([mbit | n]) if n < 126 else bytes([mbit | 126]) + struct.pack("!H", n)
    if not mask:
        return head + payload
    key = b"\x01\x02\x03\x04"
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def hpack(headers):
    out = b""
    for k, v in headers:
        out += b"\x00" + bytes([len(k)]) + k.encode() + bytes([len(v)]) + v.encode()
    return out


def h2_frame(kind, flags, stream, payload):
    n = len(payload)
    return bytes([n >> 16, (n >> 8) & 255, n & 255, kind, flags]) + struct.pack("!I", stream) + payload


def grpc_message(payload):
    return b"\x00" + struct.pack("!I", len(payload)) + payload


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_rr(name, rtype, rdata):
    return dns_name(name) + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata


def write_pcap(path, events, linktype=LINKTYPE_RAW):
    events = sorted(events, key=lambda e: e[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for t, pkt in events:
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(pkt), len(pkt)) + pkt)
