"""Writes tests/fixtures/credentials.pcap: cleartext logins over HTTP, FTP, SMTP, POP3 and NTLM."""
import base64
import socket
import struct
import sys

PSH_ACK = 0x18


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def ip(src: str, dst: str, payload: bytes) -> bytes:
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, 6, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    head = head[:10] + struct.pack("!H", checksum(head)) + head[12:]
    return head + payload


class Stream:
    def __init__(self, client: str, server: str, sport: int, dport: int):
        self.ends = {"c": (client, sport), "s": (server, dport)}
        self.seq = {"c": 1000, "s": 5000}
        self.packets = []

    def send(self, side: str, data: bytes) -> None:
        other = "s" if side == "c" else "c"
        (src, sp), (dst, dp) = self.ends[side], self.ends[other]
        seg = struct.pack("!HHIIBBHHH", sp, dp, self.seq[side], self.seq[other], 5 << 4,
                          PSH_ACK, 8192, 0, 0) + data
        self.seq[side] += len(data)
        self.packets.append(ip(src, dst, seg))


def http(client: str, server: str, sport: int, requests: list) -> list:
    s = Stream(client, server, sport, 80)
    for path, headers in requests:
        lines = [f"GET {path} HTTP/1.1", f"Host: {server}", *headers, "", ""]
        s.send("c", "\r\n".join(lines).encode())
        s.send("s", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    return s.packets


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def ntlm_authenticate() -> bytes:
    def field(length: int, offset: int) -> bytes:
        return struct.pack("<HHI", length, length, offset)

    domain, user, host = "CORP".encode("utf-16le"), "alice".encode("utf-16le"), "PC1".encode("utf-16le")
    proof = bytes(range(1, 25))
    base = 64
    off_domain, off_user, off_host = base, base + len(domain), base + len(domain) + len(user)
    off_resp = off_host + len(host)
    head = b"NTLMSSP\0" + struct.pack("<I", 3)
    head += field(24, off_resp) + field(24, off_resp)
    head += field(len(domain), off_domain) + field(len(user), off_user) + field(len(host), off_host)
    head += field(0, off_resp + 24) + struct.pack("<I", 0x00088201)
    head += b"\0" * (base - len(head))
    return head + domain + user + host + proof + proof


def main(path: str) -> None:
    pkts = []
    pkts += http("10.0.0.2", "10.0.0.80", 41001, [
        ("/private", [f"Authorization: Basic {b64('alice:s3cretPass')}"]),
        ("/api/me", ["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"]),
        ("/api/items", ["X-API-Key: sk_live_abcdef123456"]),
        ("/search?q=cats&api_key=KEY123456789&page=2", []),
        ("/login", [f"Authorization: NTLM {base64.b64encode(ntlm_authenticate()).decode()}"]),
        ("/public?q=hello", []),
    ])
    ftp = Stream("10.0.0.3", "10.0.0.21", 41002, 21)
    ftp.send("s", b"220 ready\r\n")
    ftp.send("c", b"USER bob\r\n")
    ftp.send("s", b"331 password\r\n")
    ftp.send("c", b"PASS hunter2\r\n")
    ftp.send("s", b"230 ok\r\n")
    pkts += ftp.packets
    smtp = Stream("10.0.0.4", "10.0.0.25", 41003, 25)
    smtp.send("s", b"220 mail ready\r\n")
    smtp.send("c", b"EHLO client\r\n")
    smtp.send("s", b"250-mail\r\n250 AUTH PLAIN LOGIN\r\n")
    smtp.send("c", f"AUTH PLAIN {b64(chr(0) + 'carol' + chr(0) + 'mailpass1')}\r\n".encode())
    smtp.send("s", b"235 ok\r\n")
    pkts += smtp.packets
    login = Stream("10.0.0.4", "10.0.0.25", 41004, 25)
    login.send("s", b"220 mail ready\r\n")
    login.send("c", b"EHLO client\r\n")
    login.send("s", b"250 AUTH LOGIN\r\n")
    login.send("c", b"AUTH LOGIN\r\n")
    login.send("s", f"334 {b64('Username:')}\r\n".encode())
    login.send("c", f"{b64('dave')}\r\n".encode())
    login.send("s", f"334 {b64('Password:')}\r\n".encode())
    login.send("c", f"{b64('davepass')}\r\n".encode())
    login.send("s", b"235 ok\r\n")
    pkts += login.packets
    pop = Stream("10.0.0.5", "10.0.0.110", 41005, 110)
    pop.send("s", b"+OK ready\r\n")
    pop.send("c", b"USER erin\r\n")
    pop.send("s", b"+OK\r\n")
    pop.send("c", b"PASS letmein99\r\n")
    pop.send("s", b"+OK logged in\r\n")
    pkts += pop.packets
    pkts += http("10.0.0.6", "10.0.0.80", 41006, [
        ("/ka", [f"Authorization: Basic {b64('ops:keepalive1')}"]),
        ("/ka", [f"Authorization: Basic {b64('ops:keepalive1')}"]),
        ("/ka", [f"Authorization: Basic {b64('ops:keepalive1')}"]),
        ("/s?key=name&token=next_page_abc&password=p%40ss%20word", []),
        ("/s3", ["Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240101/us-east-1/s3/aws4_request, Signature=abc123"]),
        ("/proxy", [f"Proxy-Authorization: Basic {b64('proxy:proxypw')}"]),
        ("/empty", [f"Authorization: Basic {b64('token123:')}"]),
    ])
    logins = []
    for port, user, password in [(41007, "u1", "p1pass"), (41008, "u2", "p2pass")]:
        ftp = Stream("10.0.0.3", "10.0.0.22", port, 21)
        ftp.send("c", f"USER {user}\r\n".encode())
        ftp.send("s", b"331 password\r\n")
        ftp.send("c", f"PASS {password}\r\n".encode())
        ftp.send("s", b"230 ok\r\n")
        logins.append(ftp.packets)
    for pair in zip(*logins):
        pkts += pair
    lower = Stream("10.0.0.7", "10.0.0.25", 41009, 25)
    lower.send("s", b"220 mail ready\r\n")
    lower.send("c", f"auth plain {b64(chr(0) + 'frank' + chr(0) + 'lowerpass')}\r\n".encode())
    lower.send("s", b"235 ok\r\n")
    pkts += lower.packets
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for i, pkt in enumerate(pkts):
            f.write(struct.pack("<IIII", i, 0, len(pkt), len(pkt)) + pkt)


main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/credentials.pcap")
