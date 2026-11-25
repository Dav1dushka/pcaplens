"""One pass over the capture: decode every frame, keep what the report and the
detectors need (conversations, DNS, HTTP, TLS, connection attempts).
"""
from __future__ import annotations

import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .apps import METHODS, ClientHello, Dns, HttpRequest, ftp_command, parse_client_hello, parse_dns, parse_http_request
from .capture import CaptureInfo, read_capture
from .decode import FIN, RST, Packet, decode


@dataclass
class Conversation:
    proto: str
    client: str
    cport: int
    server: str
    sport: int
    first: float
    last: float
    packets: int = 0
    bytes: int = 0
    upload: int = 0      # bytes from client to server
    download: int = 0    # bytes from server to client


STREAM_LIMIT = 16 * 1024   # bytes kept per direction while waiting for a complete first message


@dataclass
class _Stream:
    """The first bytes of one direction of a TCP connection, put back in order.

    Only the opening message matters here (an HTTP request, a TLS ClientHello), so
    reassembly stops once it is complete or after STREAM_LIMIT bytes.
    """
    base: int                                   # sequence number of the first payload byte
    chunks: dict[int, bytes] = field(default_factory=dict)
    done: bool = False

    def add(self, seq: int, data: bytes) -> None:
        offset = (seq - self.base) % 2**32      # sequence numbers wrap around
        if offset < STREAM_LIMIT:
            self.chunks[offset] = data[: STREAM_LIMIT - offset]

    def contiguous(self) -> bytes:
        """The bytes from the start up to the first gap; retransmissions and overlaps are fine."""
        buf, pos = bytearray(), 0
        for off in sorted(self.chunks):
            if off > pos:
                break
            data = self.chunks[off]
            if off + len(data) > pos:
                buf += data[pos - off:]
                pos = off + len(data)
        return bytes(buf)


@dataclass
class Analysis:
    path: str
    info: CaptureInfo
    packets: int = 0
    bytes: int = 0
    first: float = 0.0
    last: float = 0.0
    protocols: Counter = field(default_factory=Counter)
    host_bytes: Counter = field(default_factory=Counter)        # bytes sent + received per address
    per_second: Counter = field(default_factory=Counter)        # packets per whole second
    conversations: dict[tuple, Conversation] = field(default_factory=dict)
    syns: list[tuple[float, str, str, int]] = field(default_factory=list)        # (ts, src, dst, dport)
    syn_acks: set[tuple[str, int, str]] = field(default_factory=set)            # (server, port, client)
    dns: list[tuple[float, str, str, Dns]] = field(default_factory=list)        # (ts, src, dst, message)
    http: list[tuple[float, str, str, int, HttpRequest]] = field(default_factory=list)
    tls: list[tuple[float, str, str, int, ClientHello]] = field(default_factory=list)
    ftp_logins: list[tuple[float, str, str, str, str]] = field(default_factory=list)  # (ts, client, server, user, pw)
    arp_claims: list[tuple[float, int, str, str]] = field(default_factory=list)       # (ts, op, ip, mac)
    mac_ips: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))   # IPs each MAC sent from

    @property
    def duration(self) -> float:
        return max(0.0, self.last - self.first)


def analyze(path: str | Path) -> Analysis:
    info = CaptureInfo()
    a = Analysis(str(path), info)
    ftp_user: dict[tuple[str, str, int], str] = {}
    streams: dict[tuple, _Stream] = {}
    syn_seq: dict[tuple, int] = {}
    for frame in read_capture(path, info):
        p = decode(frame)
        _count(a, p)
        if p.arp:
            a.arp_claims.append((p.ts, *p.arp))
        elif p.mac and p.l3 == "IPv4":
            a.mac_ips[p.mac].add(p.src)
        if p.proto == "TCP":
            _tcp(a, p, ftp_user, streams, syn_seq)
        elif p.proto == "UDP" and 53 in (p.sport, p.dport):
            msg = parse_dns(p.payload)
            if msg:
                a.protocols["DNS"] += 1
                a.dns.append((p.ts, p.src, p.dst, msg))
    return a


def _count(a: Analysis, p: Packet) -> None:
    a.packets += 1
    a.bytes += p.length
    if a.packets == 1 or p.ts < a.first:
        a.first = p.ts
    a.last = max(a.last, p.ts)
    a.per_second[int(p.ts)] += 1
    a.protocols[p.l3 or "other"] += 1
    if p.proto:
        a.protocols[p.proto] += 1
    if not p.src:
        return
    a.host_bytes[p.src] += p.length
    a.host_bytes[p.dst] += p.length
    if p.proto in ("TCP", "UDP"):
        key = (p.proto, *sorted([(p.src, p.sport), (p.dst, p.dport)]))
        conv = a.conversations.get(key)
        if conv is None:
            # The client is whoever sent the first packet, unless that packet is a SYN-ACK.
            client, server = ((p.dst, p.dport), (p.src, p.sport)) if p.syn_ack else ((p.src, p.sport), (p.dst, p.dport))
            conv = a.conversations[key] = Conversation(p.proto, client[0], client[1], server[0], server[1], p.ts, p.ts)
        conv.packets += 1
        conv.bytes += p.length
        if p.src == conv.client and p.sport == conv.cport:
            conv.upload += p.length
        else:
            conv.download += p.length
        conv.last = max(conv.last, p.ts)


def _tcp(a: Analysis, p: Packet, ftp_user: dict, streams: dict, syn_seq: dict) -> None:
    key = (p.src, p.sport, p.dst, p.dport)
    if p.syn_only:
        a.syns.append((p.ts, p.src, p.dst, p.dport))
        syn_seq[key] = p.seq
    elif p.syn_ack:
        a.syn_acks.add((p.src, p.sport, p.dst))
        syn_seq[key] = p.seq
    data = p.payload
    if p.flags & (FIN | RST):
        # The connection is closing: whatever was not parsed by now never will be. Free the state,
        # so a long capture with millions of connections does not keep them all in memory.
        streams.pop(key, None)
        syn_seq.pop(key, None)
    if not data:
        return
    if 53 in (p.sport, p.dport) and len(data) > 2:
        msg = parse_dns(data[2:2 + struct.unpack_from("!H", data)[0]])   # DNS over TCP has a length prefix
        if msg:
            a.protocols["DNS"] += 1
            a.dns.append((p.ts, p.src, p.dst, msg))
        return
    if p.dport == 21:
        cmd = ftp_command(data)
        if cmd:
            a.protocols["FTP"] += 1
            flow = (p.src, p.dst, p.sport)
            if cmd[0] == "USER":
                ftp_user[flow] = cmd[1]
            elif flow in ftp_user:
                a.ftp_logins.append((p.ts, p.src, p.dst, ftp_user.pop(flow), cmd[1]))
        return
    stream = streams.get(key)
    if stream is None:
        # The first payload byte follows the SYN; without a SYN (capture started late) use this packet.
        base = (syn_seq[key] + 1) % 2**32 if key in syn_seq else p.seq
        stream = streams[key] = _Stream(base)
    if stream.done:
        return
    stream.add(p.seq, data)
    _first_message(a, p, stream)


def _first_message(a: Analysis, p: Packet, stream: _Stream) -> None:
    """Parse the opening message of a stream once enough of it has arrived."""
    buf = stream.contiguous()
    if not buf:
        return
    complete = len(buf) >= STREAM_LIMIT
    if buf[:1] == b"\x16":                                    # TLS handshake record
        if len(buf) >= 5:
            need = 5 + struct.unpack_from("!H", buf, 3)[0]
            if len(buf) >= need or complete:
                hello = parse_client_hello(buf[:need])
                if hello:
                    a.protocols["TLS"] += 1
                    a.tls.append((p.ts, p.src, p.dst, p.dport, hello))
                stream.done = True
        return
    if any(m.startswith(buf[:8]) or buf.startswith(m + b" ") for m in METHODS):   # HTTP, maybe still partial
        if b"\r\n\r\n" in buf or complete:
            req = parse_http_request(buf)
            if req:
                a.protocols["HTTP"] += 1
                a.http.append((p.ts, p.src, p.dst, p.dport, req))
            stream.done = True
        return
    stream.done = True                                         # some other protocol: stop collecting
    stream.chunks.clear()
