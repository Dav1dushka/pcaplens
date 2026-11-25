"""Builds packets byte by byte, and a synthetic demo capture of a small office
network where a few things are going wrong.

Every address is either private (192.168.1.0/24) or from the ranges reserved
for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and every
domain ends in .example, so the demo points at nothing real.
"""
from __future__ import annotations

import base64
import ipaddress
import random
import struct
from pathlib import Path

from .capture import Frame, write_pcap, write_pcapng
from .decode import ACK, FIN, PSH, RST, SYN

MAC = {}


def _mac(ip: str) -> bytes:
    if ip not in MAC:
        MAC[ip] = bytes([0x02, 0x00]) + ipaddress.ip_address(ip).packed[-4:]
    return MAC[ip]


def checksum(data: bytes) -> int:
    """The Internet checksum (RFC 1071): one's complement sum of 16-bit words."""
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, ttl, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + struct.pack("!BBH", 0, proto, length)


def tcp(src: str, dst: str, sport: int, dport: int, flags: int, payload: bytes = b"", seq: int = 1,
        ack: int = 0) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    csum = checksum(_pseudo(src, dst, 6, len(seg)) + seg)
    return ipv4(src, dst, 6, seg[:16] + struct.pack("!H", csum) + seg[18:])


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    dgram = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = checksum(_pseudo(src, dst, 17, len(dgram)) + dgram) or 0xFFFF
    return ipv4(src, dst, 17, dgram[:6] + struct.pack("!H", csum) + dgram[8:])


def ethernet(src_ip: str, dst_ip: str, packet: bytes) -> bytes:
    return _mac(dst_ip) + _mac(src_ip) + struct.pack("!H", 0x0800) + packet


def arp_reply(sender_mac: bytes, sender_ip: str, target_mac: bytes, target_ip: str) -> bytes:
    """An Ethernet frame carrying an ARP reply: "sender_ip is at sender_mac"."""
    arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + sender_mac + ipaddress.IPv4Address(sender_ip).packed
           + target_mac + ipaddress.IPv4Address(target_ip).packed)
    return target_mac + sender_mac + struct.pack("!H", 0x0806) + arp


# -- application payloads -----------------------------------------------------------------------
def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"


def dns_query(qid: int, name: str, qtype: int = 1) -> bytes:
    return struct.pack("!6H", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(qid: int, name: str, qtype: int, answers: list[bytes], rcode: int = 0) -> bytes:
    msg = struct.pack("!6H", qid, 0x8180 | rcode, 1, len(answers), 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)
    for rdata in answers:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata   # name: pointer to the question
    return msg


BROWSER_CIPHERS = [0x1A1A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030]   # starts with a GREASE value
SCRIPT_CIPHERS = [0xC030, 0xC02C, 0xC028, 0xC024, 0x009F, 0x006B, 0x0039, 0x0035]    # an older TLS library


def client_hello(sni: str, alpn: tuple[str, ...] = ("h2", "http/1.1"), ciphers: list[int] = BROWSER_CIPHERS) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    alpn_list = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    exts = [
        (0x2A2A, b""),                                                   # GREASE extension
        (0, sni_ext),
        (23, b""),                                                       # extended_master_secret
        (65281, b"\0"),                                                  # renegotiation_info
        (10, struct.pack("!H4H", 8, 0x0A0A, 29, 23, 24)),                # supported_groups (with GREASE)
        (11, b"\x01\x00"),                                               # ec_point_formats: uncompressed
        (16, struct.pack("!H", len(alpn_list)) + alpn_list),
    ]
    ext_bytes = b"".join(struct.pack("!HH", t, len(b)) + b for t, b in exts)
    body = (struct.pack("!H", 0x0303) + bytes(32) + b"\x20" + bytes(32)
            + struct.pack("!H", 2 * len(ciphers)) + struct.pack(f"!{len(ciphers)}H", *ciphers)
            + b"\x01\x00" + struct.pack("!H", len(ext_bytes)) + ext_bytes)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# -- the demo scenario ----------------------------------------------------------------------------
class Capture:
    def __init__(self, seed: int = 7, start: float = 1_764_000_000.0):
        self.rng = random.Random(seed)
        self.start = start
        self.frames: list[Frame] = []

    def add(self, t: float, src: str, dst: str, packet: bytes) -> None:
        data = ethernet(src, dst, packet)
        self.frames.append(Frame(self.start + t, 1, data, len(data)))

    def add_frame(self, t: float, data: bytes) -> None:
        self.frames.append(Frame(self.start + t, 1, data, len(data)))

    def port(self) -> int:
        return self.rng.randint(49152, 65000)

    def tcp_session(self, t: float, client: str, server: str, dport: int, request: bytes = b"",
                    response_size: int = 0) -> float:
        """A full TCP conversation: handshake, one request, a response, then FIN."""
        sp, r = self.port(), self.rng
        rtt = r.uniform(0.01, 0.06)
        self.add(t, client, server, tcp(client, server, sp, dport, SYN, seq=1000))
        self.add(t + rtt, server, client, tcp(server, client, dport, sp, SYN | ACK, seq=5000, ack=1001))
        self.add(t + rtt * 1.5, client, server, tcp(client, server, sp, dport, ACK, seq=1001, ack=5001))
        t += rtt * 2
        if request:
            self.add(t, client, server, tcp(client, server, sp, dport, PSH | ACK, request, 1001, 5001))
            t += rtt
        if response_size:
            for i in range(0, response_size, 1400):
                n = min(1400, response_size - i)
                self.add(t, server, client, tcp(server, client, dport, sp, ACK, bytes(n), 5001 + i, 1001))
                t += 0.002
        self.add(t + rtt, client, server, tcp(client, server, sp, dport, FIN | ACK, seq=1001 + len(request)))
        self.add(t + rtt * 2, server, client, tcp(server, client, dport, sp, FIN | ACK, seq=5001 + response_size))
        return t + rtt * 2

    def lookup(self, t: float, client: str, name: str, answer: str | None, qtype: int = 1) -> None:
        qid, sp = self.rng.randint(1, 65535), self.port()
        resolver = "192.168.1.1"
        self.add(t, client, resolver, udp(client, resolver, sp, 53, dns_query(qid, name, qtype)))
        if answer is None:
            resp = dns_response(qid, name, qtype, [], rcode=3)
        elif qtype == 16:
            txt = answer.encode()
            resp = dns_response(qid, name, qtype, [bytes([len(txt)]) + txt])
        else:
            resp = dns_response(qid, name, qtype, [ipaddress.ip_address(answer).packed])
        self.add(t + self.rng.uniform(0.005, 0.03), resolver, client, udp(resolver, client, 53, sp, resp))


SITES = {   # name -> address, all fictional
    "www.news.example": "203.0.113.10", "mail.office.example": "203.0.113.20", "cdn.assets.example": "203.0.113.30",
    "api.weather.example": "198.51.100.40", "docs.wiki.example": "198.51.100.41", "store.shop.example": "203.0.113.44",
}


def demo_capture(seed: int = 7, attacks: bool = True) -> list[Frame]:
    c = Capture(seed)
    r = c.rng
    workstations = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.23"]
    infected = "192.168.1.23"
    rogue = "192.168.1.66"
    fileserver = "192.168.1.50"

    # The gateway answers ARP for itself now and then, as it should.
    gateway = "192.168.1.1"
    for t in (1.0, 180.0, 360.0, 540.0):
        c.add_frame(t, arp_reply(_mac(gateway), gateway, _mac(r.choice(workstations)), "192.168.1.10"))

    # Ten minutes of ordinary browsing: look the name up, then talk TLS to it.
    t = 0.0
    while t < 600:
        host = r.choice(workstations)
        name = r.choice(list(SITES))
        c.lookup(t, host, name, SITES[name])
        c.tcp_session(t + 0.05, host, SITES[name], 443, client_hello(name), r.randint(2000, 40000))
        t += r.uniform(2, 9)

    if not attacks:
        c.frames.sort(key=lambda f: f.ts)
        return c.frames

    # An old intranet page that still uses HTTP Basic authentication.
    creds = base64.b64encode(b"jsmith:Summer2026!").decode()
    req = (f"GET /reports/q3 HTTP/1.1\r\nHost: intranet.office.example\r\nUser-Agent: Mozilla/5.0\r\n"
           f"Authorization: Basic {creds}\r\n\r\n").encode()
    c.lookup(95, "192.168.1.11", "intranet.office.example", "192.168.1.40")
    c.tcp_session(95.1, "192.168.1.11", "192.168.1.40", 80, req, 6000)

    # A backup script logging in to FTP.
    backup, sp, t = "192.168.1.12", 51515, 140.0
    c.add(t, backup, fileserver, tcp(backup, fileserver, sp, 21, SYN))
    c.add(t + 0.01, fileserver, backup, tcp(fileserver, backup, 21, sp, SYN | ACK))
    c.add(t + 0.02, backup, fileserver, tcp(backup, fileserver, sp, 21, ACK))
    dialogue = [(False, b"220 FTP ready"), (True, b"USER backup"), (False, b"331 Password required"),
                (True, b"PASS b4ckup-2026"), (False, b"230 Logged in")]
    for i, (from_client, line) in enumerate(dialogue):
        src, dst = (backup, fileserver) if from_client else (fileserver, backup)
        ports = (sp, 21) if from_client else (21, sp)
        c.add(t + 0.05 * (i + 1), src, dst, tcp(src, dst, *ports, PSH | ACK, line + b"\r\n"))

    # A device nobody recognises tells everyone that it is the gateway (ARP cache poisoning)...
    for i in range(20):
        victim = workstations[i % len(workstations)]
        c.add_frame(190.0 + i * 2.0, arp_reply(_mac(rogue), gateway, _mac(victim), victim))

    # ...and scans the file server.
    t = 200.0
    open_ports = {21, 22, 80, 445}
    for port in r.sample([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900,
                          6379, 8080, 8443, 9200, 11211, 27017, 111, 2049, 389, 636, 88, 464], 30):
        sp = c.port()
        c.add(t, rogue, fileserver, tcp(rogue, fileserver, sp, port, SYN))
        reply = SYN | ACK if port in open_ports else RST | ACK
        c.add(t + 0.0004, fileserver, rogue, tcp(fileserver, rogue, port, sp, reply))
        t += r.uniform(0.01, 0.05)

    # The infected workstation checks in with its server every 30 seconds...
    t = 20.0
    while t < 590:
        hello = client_hello("update-check.example", ("http/1.1",), SCRIPT_CIPHERS)
        c.tcp_session(t, infected, "198.51.100.77", 443, hello, 300)
        t += 30 * r.uniform(0.98, 1.02)

    # ...hides data in DNS questions...
    secret = bytes(r.getrandbits(8) for _ in range(900))
    chunks = base64.b32encode(secret).decode().rstrip("=").lower()
    t = 300.0
    for i in range(0, len(chunks), 45):
        c.lookup(t, infected, f"{chunks[i:i + 45]}.{i // 45}.t.exfil-tunnel.example", "ok", qtype=16)
        t += r.uniform(0.2, 0.6)

    # ...tries a list of generated domains, most of which do not exist...
    t = 420.0
    for _ in range(14):
        name = "".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(r.randint(10, 16))) + ".example"
        c.lookup(t, infected, name, None)
        t += r.uniform(0.5, 2.5)

    # ...uploads a large archive over HTTPS...
    sp, t, server = c.port(), 540.0, "203.0.113.150"
    c.add(t, infected, server, tcp(infected, server, sp, 443, SYN, seq=1000))
    c.add(t + 0.03, server, infected, tcp(server, infected, 443, sp, SYN | ACK, seq=9000, ack=1001))
    c.add(t + 0.05, infected, server, tcp(infected, server, sp, 443, ACK, seq=1001, ack=9001))
    hello = client_hello("files.storage-drop.example", ("http/1.1",), SCRIPT_CIPHERS)
    c.add(t + 0.06, infected, server, tcp(infected, server, sp, 443, PSH | ACK, hello, seq=1001, ack=9001))
    seq = 1001 + len(hello)
    for i in range(1800):                    # about 2.5 MB of encrypted data going out
        t += 0.004
        c.add(t, infected, server, tcp(infected, server, sp, 443, ACK, bytes(1400), seq=seq, ack=9001))
        seq += 1400
        if i % 20 == 0:
            c.add(t + 0.002, server, infected, tcp(server, infected, 443, sp, ACK, seq=9001, ack=seq))

    # ...and opens a shell to a classic listener port.
    c.tcp_session(500.0, infected, "203.0.113.99", 4444, b"id\n", 120)

    c.frames.sort(key=lambda f: f.ts)
    return c.frames


def write_demo(path: str | Path, fmt: str = "pcap", seed: int = 7) -> int:
    frames = demo_capture(seed)
    (write_pcapng if fmt == "pcapng" else write_pcap)(path, frames)
    return len(frames)
