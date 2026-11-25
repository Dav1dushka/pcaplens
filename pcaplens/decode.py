"""From raw frames to packets: link layer, IP, TCP/UDP/ICMP.

Every length field comes from the capture and may be wrong (truncated
captures, corrupt or hostile traffic), so each step checks that the bytes it
needs are really there and returns what it could decode instead of raising.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from .capture import Frame

LINK_ETHERNET, LINK_RAW, LINK_RAW_ALT, LINK_NULL, LINK_SLL, LINK_SLL2 = 1, 101, 12, 0, 113, 276
ETH_IPV4, ETH_IPV6, ETH_ARP, ETH_VLAN, ETH_QINQ = 0x0800, 0x86DD, 0x0806, 0x8100, 0x88A8

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass(slots=True)
class Packet:
    ts: float
    length: int                 # bytes on the wire
    l3: str = ""                # "IPv4", "IPv6", "ARP" or "" if unknown
    src: str = ""
    dst: str = ""
    proto: str = ""             # "TCP", "UDP", "ICMP", "ICMPv6" or "IP:<n>"
    sport: int = 0
    dport: int = 0
    flags: int = 0              # TCP flags
    payload: bytes = b""        # transport payload
    ttl: int = 0
    seq: int = 0                # TCP sequence number
    mac: str = ""               # Ethernet source address
    arp: tuple[int, str, str] | None = None   # (operation, sender IP, sender MAC) for ARP packets

    @property
    def syn_only(self) -> bool:
        return self.proto == "TCP" and self.flags & (SYN | ACK) == SYN

    @property
    def syn_ack(self) -> bool:
        return self.proto == "TCP" and self.flags & (SYN | ACK) == SYN | ACK


def decode(frame: Frame) -> Packet:
    p = Packet(ts=frame.ts, length=frame.orig_len)
    data = frame.data
    lt = frame.linktype
    if lt == LINK_ETHERNET:
        if len(data) < 14:
            return p
        p.mac = data[6:12].hex(":")
        etype = struct.unpack_from("!H", data, 12)[0]
        off = 14
        while etype in (ETH_VLAN, ETH_QINQ) and len(data) >= off + 4:   # 802.1Q / 802.1ad tags
            etype = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
        _network(p, etype, data[off:])
    elif lt in (LINK_RAW, LINK_RAW_ALT):
        if data:
            _network(p, ETH_IPV4 if data[0] >> 4 == 4 else ETH_IPV6, data)
    elif lt == LINK_SLL and len(data) >= 16:
        _network(p, struct.unpack_from("!H", data, 14)[0], data[16:])
    elif lt == LINK_SLL2 and len(data) >= 20:
        _network(p, struct.unpack_from("!H", data, 0)[0], data[20:])
    elif lt == LINK_NULL and len(data) >= 4:
        family = struct.unpack_from("<I", data)[0]   # host byte order of the capturing machine
        if family > 0xFFFF:
            family = struct.unpack_from(">I", data)[0]
        _network(p, ETH_IPV4 if family == 2 else ETH_IPV6, data[4:])
    return p


def _network(p: Packet, etype: int, data: bytes) -> None:
    if etype == ETH_IPV4 and len(data) >= 20 and data[0] >> 4 == 4:
        ihl = (data[0] & 0x0F) * 4
        total = struct.unpack_from("!H", data, 2)[0]
        if ihl < 20 or len(data) < ihl:
            return
        frag = struct.unpack_from("!H", data, 6)[0] & 0x1FFF
        p.l3, p.ttl = "IPv4", data[8]
        p.src = socket.inet_ntoa(data[12:16])   # several times faster than the ipaddress module
        p.dst = socket.inet_ntoa(data[16:20])
        body = data[ihl:total] if ihl <= total <= len(data) else data[ihl:]   # drop Ethernet padding
        if frag:
            p.proto = _proto_name(data[9])   # a later fragment: no transport header in it
            return
        _transport(p, data[9], body)
    elif etype == ETH_IPV6 and len(data) >= 40 and data[0] >> 4 == 6:
        plen = struct.unpack_from("!H", data, 4)[0]
        nxt, off = data[6], 40
        p.l3, p.ttl = "IPv6", data[7]
        p.src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        p.dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
        end = min(len(data), 40 + plen) if plen else len(data)
        for _ in range(8):   # skip a bounded number of extension headers
            if nxt in (0, 43, 60) and off + 2 <= end:
                nxt, off = data[off], off + (data[off + 1] + 1) * 8
            elif nxt == 44 and off + 8 <= end:
                fragoff = struct.unpack_from("!H", data, off + 2)[0] >> 3
                nxt, off = data[off], off + 8
                if fragoff:
                    p.proto = _proto_name(nxt)
                    return
            else:
                break
        _transport(p, nxt, data[off:end])
    elif etype == ETH_ARP:
        p.l3 = "ARP"
        # Ethernet + IPv4 ARP: op at 6, sender MAC at 8, sender IP at 14.
        if len(data) >= 28 and data[2:4] == b"\x08\x00" and data[4] == 6 and data[5] == 4:
            op = struct.unpack_from("!H", data, 6)[0]
            p.arp = (op, socket.inet_ntoa(data[14:18]), data[8:14].hex(":"))


def _transport(p: Packet, proto: int, body: bytes) -> None:
    p.proto = _proto_name(proto)
    if proto == 6 and len(body) >= 20:
        p.sport, p.dport, p.seq = struct.unpack_from("!HHI", body)
        doff = (body[12] >> 4) * 4
        p.flags = body[13]
        p.payload = body[doff:] if 20 <= doff <= len(body) else b""
    elif proto == 17 and len(body) >= 8:
        p.sport, p.dport, ulen = struct.unpack_from("!HHH", body)
        p.payload = body[8:ulen] if 8 <= ulen <= len(body) else body[8:]
    elif proto in (1, 58) and len(body) >= 4:
        p.sport, p.dport = body[0], body[1]   # ICMP type and code, kept in the port fields
        p.payload = body[4:]


def _proto_name(n: int) -> str:
    return {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(n, f"IP:{n}")
