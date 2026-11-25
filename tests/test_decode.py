import ipaddress
import struct

from pcaplens.capture import Frame
from pcaplens.decode import ACK, SYN, decode
from pcaplens.synth import checksum, ethernet, ipv4, tcp


def eth(src, dst, pkt):
    data = ethernet(src, dst, pkt)
    return decode(Frame(5.0, 1, data, len(data)))


def test_rfc1071_checksum_example():
    # The worked example in RFC 1071: these words sum to 0xddf2, so the checksum is its complement.
    assert checksum(bytes.fromhex("0001f203f4f5f6f7")) == 0x220D


def test_generated_headers_have_valid_checksums():
    pkt = tcp("192.0.2.1", "198.51.100.2", 40000, 443, SYN, b"hello")
    assert checksum(pkt[:20]) == 0                       # IPv4 header checksum verifies to zero
    pseudo = pkt[12:20] + struct.pack("!BBH", 0, 6, len(pkt) - 20)
    assert checksum(pseudo + pkt[20:]) == 0              # so does the TCP checksum


def test_tcp_fields():
    p = eth("192.0.2.1", "198.51.100.2", tcp("192.0.2.1", "198.51.100.2", 40000, 443, SYN | ACK, b"abc"))
    assert (p.l3, p.proto, p.sport, p.dport, p.payload) == ("IPv4", "TCP", 40000, 443, b"abc")
    assert p.syn_ack and not p.syn_only


def test_ethernet_padding_is_not_payload():
    # TCP has no length field of its own: only the IP total length says where the segment ends.
    pkt = tcp("10.0.0.1", "10.0.0.2", 1, 2, ACK, b"hi")
    data = ethernet("10.0.0.1", "10.0.0.2", pkt) + b"\x00" * 16   # frames shorter than 60 bytes get padded
    assert decode(Frame(0, 1, data, len(data))).payload == b"hi"


def test_ipv6_with_extension_header():
    src, dst = ipaddress.IPv6Address("2001:db8::1"), ipaddress.IPv6Address("2001:db8::2")
    seg = struct.pack("!HHIIBBHHH", 5555, 443, 1, 0, 5 << 4, SYN, 1000, 0, 0)
    hop = bytes([6, 0]) + b"\x00" * 6                    # hop-by-hop options, next header TCP
    ip6 = struct.pack("!IHBB", 6 << 28, len(hop) + len(seg), 0, 64) + src.packed + dst.packed + hop + seg
    data = b"\x02" * 12 + b"\x86\xdd" + ip6
    p = decode(Frame(0, 1, data, len(data)))
    assert (p.l3, p.src, p.proto, p.dport) == ("IPv6", "2001:db8::1", "TCP", 443)
    assert p.syn_only


def test_later_fragments_have_no_ports():
    pkt = bytearray(ipv4("10.0.0.1", "10.0.0.2", 17, b"\x00" * 40))
    pkt[6:8] = struct.pack("!H", 185)                    # fragment offset 185 × 8 bytes
    p = eth("10.0.0.1", "10.0.0.2", bytes(pkt))
    assert p.proto == "UDP" and p.sport == 0 and p.payload == b""


def test_truncated_packets_never_raise():
    full = ethernet("10.0.0.1", "10.0.0.2", tcp("10.0.0.1", "10.0.0.2", 1, 80, SYN, b"x" * 50))
    for n in range(len(full)):
        decode(Frame(0, 1, full[:n], len(full)))         # must simply decode less
