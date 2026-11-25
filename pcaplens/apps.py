"""Application protocols: DNS, HTTP, TLS ClientHello (SNI and JA3), FTP.

These look only at single packets, which covers what matters for a quick
investigation: a DNS message fits in one UDP datagram, the first line and
headers of an HTTP request usually arrive in the first segment, and so does
a TLS ClientHello.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import struct
from dataclasses import dataclass, field

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
             65: "HTTPS", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


# -- DNS ------------------------------------------------------------------------------
@dataclass
class Dns:
    id: int
    response: bool
    rcode: str
    questions: list[tuple[str, str]] = field(default_factory=list)       # (name, type)
    answers: list[tuple[str, str, str]] = field(default_factory=list)    # (name, type, data)


def parse_dns(msg: bytes) -> Dns | None:
    """Parse a DNS message; None if it is not one."""
    if len(msg) < 12:
        return None
    qid, flags, qd, an, _ns, _ar = struct.unpack_from("!6H", msg)
    if qd > 64 or an > 256 or (flags >> 11) & 0xF > 5:   # opcode beyond the defined ones
        return None
    dns = Dns(qid, bool(flags & 0x8000), RCODES.get(flags & 0xF, str(flags & 0xF)))
    try:
        pos = 12
        for _ in range(qd):
            name, pos = _name(msg, pos)
            qtype = struct.unpack_from("!H", msg, pos)[0]
            dns.questions.append((name, DNS_TYPES.get(qtype, str(qtype))))
            pos += 4
        for _ in range(an):
            name, pos = _name(msg, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", msg, pos)
            pos += 10
            rdata = msg[pos:pos + rdlen]
            if len(rdata) < rdlen:
                break
            dns.answers.append((name, DNS_TYPES.get(rtype, str(rtype)), _rdata(msg, pos, rtype, rdata)))
            pos += rdlen
    except (struct.error, ValueError, IndexError):
        if not dns.questions:
            return None
    return dns


def _name(msg: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    end = None
    jumps = 0
    while True:
        n = msg[pos]
        if n & 0xC0 == 0xC0:                       # compression pointer
            jumps += 1
            if jumps > 20:
                raise ValueError("compression loop")
            if end is None:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | msg[pos + 1]
            continue
        if n & 0xC0:
            raise ValueError("bad label")
        pos += 1
        if n == 0:
            break
        labels.append(msg[pos:pos + n].decode("ascii", "replace"))
        pos += n
        if len(labels) > 127:
            raise ValueError("too many labels")
    return ".".join(labels) or ".", end if end is not None else pos


def _rdata(msg: bytes, pos: int, rtype: int, rdata: bytes) -> str:
    if rtype == 1 and len(rdata) == 4:
        return str(ipaddress.IPv4Address(rdata))
    if rtype == 28 and len(rdata) == 16:
        return str(ipaddress.IPv6Address(rdata))
    if rtype in (2, 5, 12):
        return _name(msg, pos)[0]
    if rtype == 16:
        parts, i = [], 0
        while i < len(rdata):
            n = rdata[i]
            parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return " ".join(parts)
    return f"{len(rdata)} bytes"


# -- HTTP -------------------------------------------------------------------------------
METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH")


@dataclass
class HttpRequest:
    method: str
    path: str
    host: str
    user_agent: str
    basic_auth: tuple[str, str] | None   # (user, password) from an Authorization: Basic header
    form_password: bool                  # a body field named like a password


def parse_http_request(payload: bytes) -> HttpRequest | None:
    if not payload.startswith(METHODS):
        return None
    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or not parts[2].startswith(b"HTTP/"):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        k, sep, v = line.partition(b":")
        if sep:
            headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    auth = None
    scheme, _, value = headers.get("authorization", "").partition(" ")
    if scheme.lower() == "basic":
        try:
            user, _, pw = base64.b64decode(value, validate=True).decode("utf-8", "replace").partition(":")
            auth = (user, pw)
        except (binascii.Error, ValueError):
            pass
    lowered = body.lower()
    form_pw = any(k in lowered for k in (b"password=", b"passwd=", b"pwd=", b"pass="))
    return HttpRequest(parts[0].decode(), parts[1].decode("latin-1"), headers.get("host", ""),
                       headers.get("user-agent", ""), auth, form_pw)


# -- TLS ----------------------------------------------------------------------------------
GREASE = {0x0A0A + 0x1010 * i for i in range(16)}   # RFC 8701 values, ignored by JA3


@dataclass
class ClientHello:
    version: int
    sni: str
    alpn: list[str]
    ja3: str          # the JA3 string: version,ciphers,extensions,groups,point formats
    ja3_hash: str     # its MD5, the form threat-intel feeds use


def parse_client_hello(payload: bytes) -> ClientHello | None:
    """Parse a TLS ClientHello at the start of a TCP payload."""
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] != 0x01:
        return None
    try:
        pos = 9                                       # record header (5) + handshake header (4)
        version = struct.unpack_from("!H", payload, pos)[0]
        pos += 2 + 32                                 # client_version, random
        pos += 1 + payload[pos]                       # session id
        clen = struct.unpack_from("!H", payload, pos)[0]
        ciphers = [c for c in struct.unpack_from(f"!{clen // 2}H", payload, pos + 2) if c not in GREASE]
        pos += 2 + clen
        pos += 1 + payload[pos]                       # compression methods
        ext_end = pos + 2 + struct.unpack_from("!H", payload, pos)[0]
        pos += 2
        exts, groups, points, alpn = [], [], [], []
        sni = ""
        while pos + 4 <= min(ext_end, len(payload)):
            etype, elen = struct.unpack_from("!HH", payload, pos)
            body = payload[pos + 4:pos + 4 + elen]
            pos += 4 + elen
            if etype in GREASE:
                continue
            exts.append(etype)
            if etype == 0 and len(body) >= 5 and body[2] == 0:            # server_name, host_name
                n = struct.unpack_from("!H", body, 3)[0]
                sni = body[5:5 + n].decode("ascii", "replace")
            elif etype == 10 and len(body) >= 2:                          # supported_groups
                n = struct.unpack_from("!H", body)[0] // 2
                groups = [g for g in struct.unpack_from(f"!{n}H", body, 2) if g not in GREASE]
            elif etype == 11 and body:                                    # ec_point_formats
                points = list(body[1:1 + body[0]])
            elif etype == 16 and len(body) >= 2:                          # ALPN
                i = 2
                while i < len(body):
                    n = body[i]
                    alpn.append(body[i + 1:i + 1 + n].decode("ascii", "replace"))
                    i += 1 + n
    except (struct.error, IndexError):
        return None
    ja3 = ",".join([str(version), "-".join(map(str, ciphers)), "-".join(map(str, exts)),
                    "-".join(map(str, groups)), "-".join(map(str, points))])
    return ClientHello(version, sni, alpn, ja3, hashlib.md5(ja3.encode()).hexdigest())  # noqa: S324 (JA3 is defined with MD5)


# -- FTP -------------------------------------------------------------------------------------
def ftp_command(payload: bytes) -> tuple[str, str] | None:
    """('USER', 'alice') for a client command line, else None."""
    line = payload.split(b"\r\n", 1)[0]
    verb, _, arg = line.partition(b" ")
    if verb.upper() in (b"USER", b"PASS") and arg:
        return verb.upper().decode(), arg.decode("utf-8", "replace")
    return None
