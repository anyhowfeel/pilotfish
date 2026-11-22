"""Writes tests/fixtures/web-streams.pcap: a WebSocket chat, a Server-Sent Events feed and a gRPC call (h2c)."""
import socket
import struct
import sys

CLIENT, SERVER = "10.0.0.1", "10.0.0.2"


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


class Conn:
    """One TCP connection; `send` appends a segment from either side."""

    def __init__(self, cport, sport, t0):
        self.cport, self.sport, self.t = cport, sport, t0
        self.c, self.s = 1000, 5000
        self.out = []
        self._emit(CLIENT, SERVER, cport, sport, self.c, 0, 0x02)
        self._emit(SERVER, CLIENT, sport, cport, self.s, self.c + 1, 0x12)
        self.c, self.s = self.c + 1, self.s + 1
        self._emit(CLIENT, SERVER, cport, sport, self.c, self.s, 0x10)

    def _emit(self, src, dst, sp, dp, seq, ack, flags, payload=b""):
        self.out.append((self.t, packet(src, dst, sp, dp, seq, ack, flags, payload)))
        self.t += 0.01

    def client(self, data):
        self._emit(CLIENT, SERVER, self.cport, self.sport, self.c, self.s, 0x18, data)
        self.c += len(data)

    def server(self, data):
        self._emit(SERVER, CLIENT, self.sport, self.cport, self.s, self.c, 0x18, data)
        self.s += len(data)

    def close(self):
        self._emit(CLIENT, SERVER, self.cport, self.sport, self.c, self.s, 0x11)
        self._emit(SERVER, CLIENT, self.sport, self.cport, self.s, self.c + 1, 0x11)
        self._emit(CLIENT, SERVER, self.cport, self.sport, self.c + 1, self.s + 1, 0x10)


def ws_frame(opcode, payload, mask):
    head = bytes([0x80 | opcode])
    n = len(payload)
    mbit = 0x80 if mask else 0
    head += bytes([mbit | n]) if n < 126 else bytes([mbit | 126]) + struct.pack("!H", n)
    if not mask:
        return head + payload
    key = b"\x01\x02\x03\x04"
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def websocket(t0):
    c = Conn(50001, 8080, t0)
    c.client(b"GET /chat HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    c.server(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
    c.client(ws_frame(1, b"hello server", True))
    c.server(ws_frame(1, b'{"reply":"hello client"}', False))
    c.client(ws_frame(9, b"ping", True))
    c.server(ws_frame(10, b"ping", False))
    c.server(ws_frame(2, bytes([1, 2, 3, 4]), False))
    c.client(ws_frame(8, struct.pack("!H", 1000), True))
    c.server(ws_frame(8, struct.pack("!H", 1000), False))
    c.close()
    return c.out


def chunk(data):
    return f"{len(data):x}\r\n".encode() + data + b"\r\n"


def sse(t0):
    c = Conn(50002, 8080, t0)
    c.client(b"GET /events HTTP/1.1\r\nHost: sse.test\r\nAccept: text/event-stream\r\n\r\n")
    c.server(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n"
             b"Transfer-Encoding: chunked\r\n\r\n")
    c.server(chunk(b"data: welcome\n\n"))
    c.server(chunk(b"event: tick\nid: 1\ndata: {\"n\":1}\n\n"))
    c.server(chunk(b"event: tick\nid: 2\ndata: {\"n\":2}\n\n"))
    c.server(chunk(b": keep-alive\n\ndata: line one\ndata: line two\n\n"))
    c.server(b"0\r\n\r\n")
    c.close()
    return c.out


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


def grpc(t0):
    c = Conn(50003, 50051, t0)
    c.client(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4, 0, 0, b""))
    c.server(h2_frame(4, 0, 0, b"") + h2_frame(4, 1, 0, b""))
    c.client(h2_frame(4, 1, 0, b""))
    req = hpack([(":method", "POST"), (":scheme", "http"), (":path", "/helloworld.Greeter/SayHello"),
                 (":authority", "grpc.test:50051"), ("content-type", "application/grpc"), ("te", "trailers")])
    c.client(h2_frame(1, 0x04, 1, req) + h2_frame(0, 0x01, 1, grpc_message(b"\x0a\x05world")))
    c.server(h2_frame(1, 0x04, 1, hpack([(":status", "200"), ("content-type", "application/grpc")])) +
             h2_frame(0, 0, 1, grpc_message(b"\x0a\x0bHello world")) +
             h2_frame(1, 0x05, 1, hpack([("grpc-status", "0"), ("grpc-message", "OK")])))
    c.close()
    return c.out


def main(path):
    events = websocket(0.0) + sse(0.5) + grpc(1.0)
    events.sort(key=lambda e: e[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for t, pkt in events:
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(pkt), len(pkt)) + pkt)


main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/web-streams.pcap")
