"""Writes streams-edge.pcap: SSE streams that never terminate (open chunked, close-delimited),
a fragmented WebSocket message, and gRPC calls (two messages each way, one cancelled by RST_STREAM)."""
import struct
import sys

from pcaplib import Conn, chunk, grpc_message, h2_frame, hpack, ws_frame, write_pcap

SSE_HEAD = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n")


def sse_open(t0):
    c = Conn(51001, 8080, t0)
    c.client(b"GET /open HTTP/1.1\r\nHost: open.test\r\nAccept: text/event-stream\r\n\r\n")
    c.server(SSE_HEAD + b"Transfer-Encoding: chunked\r\n\r\n")
    c.server(chunk(b"data: first\n\n"))
    c.server(chunk(b"data: second\n\n"))
    return c.out


def sse_close_delimited(t0):
    c = Conn(51002, 8080, t0)
    c.client(b"GET /plain HTTP/1.1\r\nHost: plain.test\r\nAccept: text/event-stream\r\n\r\n")
    c.server(SSE_HEAD + b"Connection: close\r\n\r\ndata: one\n\ndata: two\n\n")
    c.fin_server()
    return c.out


def websocket_fragmented(t0):
    c = Conn(51003, 8080, t0)
    c.client(b"GET /frag HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    c.server(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
    c.client(ws_frame(1, b"hel", True, fin=False))
    c.client(ws_frame(0, b"lo ", True, fin=False))
    c.client(ws_frame(0, b"world", True))
    c.server(ws_frame(1, b"ok", False))
    return c.out


def grpc_call(t0, cport, path, cancel):
    c = Conn(cport, 50051, t0)
    c.client(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4, 0, 0, b""))
    c.server(h2_frame(4, 0, 0, b"") + h2_frame(4, 1, 0, b""))
    c.client(h2_frame(4, 1, 0, b""))
    req = hpack([(":method", "POST"), (":scheme", "http"), (":path", path),
                 (":authority", "grpc.test:50051"), ("content-type", "application/grpc"), ("te", "trailers")])
    c.client(h2_frame(1, 0x04, 1, req) + h2_frame(0, 0, 1, grpc_message(b"\x0a\x01a")) +
             h2_frame(0, 0, 1, grpc_message(b"\x0a\x01b")))
    c.server(h2_frame(1, 0x04, 1, hpack([(":status", "200"), ("content-type", "application/grpc")])) +
             h2_frame(0, 0, 1, grpc_message(b"\x0a\x01x")) + h2_frame(0, 0, 1, grpc_message(b"\x0a\x01y")))
    if cancel:
        c.client(h2_frame(3, 0, 1, struct.pack("!I", 8)))
    else:
        c.server(h2_frame(1, 0x05, 1, hpack([("grpc-status", "0")])))
    return c.out


def main(path):
    events = (sse_open(0.0) + sse_close_delimited(0.5) + websocket_fragmented(1.0)
              + grpc_call(1.5, 51004, "/svc.Chat/Talk", False) + grpc_call(2.0, 51005, "/svc.Chat/Cancelled", True))
    write_pcap(path, events)


main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/streams-edge.pcap")
