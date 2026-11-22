"""Writes dns-glue.pcap (raw IP: a DNS answer with an additional-section glue record and a query
name containing a double quote) and sll-cast.pcap (Linux cooked: unicast, broadcast, multicast)."""
import socket
import struct
import sys

from pcaplib import LINKTYPE_SLL, dns_name, dns_rr, ip, udp_packet, write_pcap


def dns_query(txid, name):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(txid, name, answers, additional):
    head = struct.pack("!HHHHHH", txid, 0x8180, 1, len(answers), 0, len(additional))
    return head + dns_name(name) + struct.pack("!HH", 1, 1) + b"".join(answers + additional)


def dns_events():
    a = lambda s: socket.inet_aton(s)
    out = []
    for i, (name, ans, glue) in enumerate([
        ("a.test", "1.1.1.1", ("ns.glue.test", "9.9.9.9")),
        ('we"ird.test', "2.2.2.2", None),
    ]):
        t = i * 0.1
        out.append((t, udp_packet("10.0.0.1", "10.0.0.53", 4000 + i, 53, dns_query(i + 1, name))))
        extra = [dns_rr(glue[0], 1, a(glue[1]))] if glue else []
        resp = dns_response(i + 1, name, [dns_rr(name, 1, a(ans))], extra)
        out.append((t + 0.01, udp_packet("10.0.0.53", "10.0.0.1", 53, 4000 + i, resp)))
    return out


def sll(pkttype, payload):
    return struct.pack("!HHH8sH", pkttype, 1, 6, b"\x02\0\0\0\0\x01", 0x0800) + payload


def sll_events():
    # pkttype 0 host, 1 broadcast, 2 multicast, 4 outgoing
    cases = [(0, "10.0.0.2", 1000), (1, "255.255.255.255", 1001), (2, "224.0.0.251", 1002), (4, "10.0.0.9", 1003)]
    return [(i * 0.1, sll(kind, udp_packet("10.0.0.1", dst, port, 9999, b"x"))) for i, (kind, dst, port) in enumerate(cases)]


dns_path = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/dns-glue.pcap"
sll_path = sys.argv[2] if len(sys.argv) > 2 else "tests/fixtures/sll-cast.pcap"
write_pcap(dns_path, dns_events())
write_pcap(sll_path, sll_events(), LINKTYPE_SLL)
