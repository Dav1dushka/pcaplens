"""Reading capture files: classic pcap and pcapng.

Both formats are a header followed by records, each holding one captured
frame and its timestamp. pcap is a fixed 24-byte header plus 16-byte record
headers; pcapng (Wireshark's default) is a sequence of typed blocks, and can
mix several interfaces with different link types and clock resolutions.

The byte order is whatever the capturing machine used, so it is detected
from the magic number instead of assumed.
"""
from __future__ import annotations

import mmap
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

PCAP_MAGIC_US = 0xA1B2C3D4   # timestamps in microseconds
PCAP_MAGIC_NS = 0xA1B23C4D   # timestamps in nanoseconds
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BOM = 0x1A2B3C4D

MAX_FRAME = 256 * 1024       # anything bigger is a corrupt length field, not a packet


class CaptureError(ValueError):
    pass


@dataclass(slots=True)
class Frame:
    ts: float          # seconds since the epoch
    linktype: int      # 1 = Ethernet, 101 = raw IP, 113 = Linux cooked, ...
    data: bytes        # captured bytes (may be shorter than the original frame)
    orig_len: int      # length of the frame on the wire


@dataclass
class CaptureInfo:
    format: str = ""
    truncated: bool = False   # file ends in the middle of a record


def read_capture(path: str | Path, info: CaptureInfo | None = None) -> Iterator[Frame]:
    """Yield every frame of a pcap or pcapng file."""
    info = info if info is not None else CaptureInfo()
    with open(path, "rb") as fh:
        if Path(path).stat().st_size < 4:
            raise CaptureError("file is too short to be a capture")
        # mmap lets the parser slice a multi-gigabyte capture without reading it all into memory.
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as data:
            yield from _read(data, info)


def _read(data, info: CaptureInfo) -> Iterator[Frame]:
    magic_le = struct.unpack_from("<I", data)[0]
    magic_be = struct.unpack_from(">I", data)[0]
    if magic_le == PCAPNG_SHB:
        info.format = "pcapng"
        yield from _pcapng(data, info)
    elif PCAP_MAGIC_US in (magic_le, magic_be) or PCAP_MAGIC_NS in (magic_le, magic_be):
        info.format = "pcap"
        yield from _pcap(data, info)
    else:
        raise CaptureError(f"not a pcap or pcapng file (magic {data[:4].hex()})")


def _pcap(data: bytes, info: CaptureInfo) -> Iterator[Frame]:
    if len(data) < 24:
        raise CaptureError("pcap header is truncated")
    magic = struct.unpack_from("<I", data)[0]
    end = "<" if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS) else ">"
    magic = struct.unpack_from(end + "I", data)[0]
    divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6
    _major, _minor, _zone, _sigfigs, _snaplen, linktype = struct.unpack_from(end + "HHiIII", data, 4)
    linktype &= 0xFFFF   # the upper bits can carry FCS information
    pos = 24
    while pos < len(data):
        if pos + 16 > len(data):
            info.truncated = True
            return
        sec, frac, incl, orig = struct.unpack_from(end + "IIII", data, pos)
        if incl > MAX_FRAME:
            raise CaptureError(f"record at offset {pos} claims {incl} bytes")
        pos += 16
        if pos + incl > len(data):
            info.truncated = True
            return
        yield Frame(sec + frac / divisor, linktype, bytes(data[pos:pos + incl]), orig)
        pos += incl


def _pcapng(data: bytes, info: CaptureInfo) -> Iterator[Frame]:
    pos = 0
    end = "<"
    interfaces: list[tuple[int, float, int]] = []   # (linktype, seconds per tick, snaplen)
    while pos < len(data):
        if pos + 12 > len(data):
            info.truncated = True
            return
        btype = struct.unpack_from(end + "I", data, pos)[0]
        if btype == PCAPNG_SHB:
            # A new section: the byte-order magic decides how to read everything after it.
            bom_le = struct.unpack_from("<I", data, pos + 8)[0]
            end = "<" if bom_le == PCAPNG_BOM else ">"
            if struct.unpack_from(end + "I", data, pos + 8)[0] != PCAPNG_BOM:
                raise CaptureError("bad pcapng byte-order magic")
            interfaces = []
        blen = struct.unpack_from(end + "I", data, pos + 4)[0]
        if blen < 12 or blen % 4:
            raise CaptureError(f"bad pcapng block length {blen} at offset {pos}")
        if pos + blen > len(data):
            info.truncated = True
            return
        body = bytes(data[pos + 8:pos + blen - 4])
        if btype == 1:                                   # Interface Description Block
            linktype, _reserved, snaplen = struct.unpack_from(end + "HHI", body)
            interfaces.append((linktype, _tsresol(body[8:], end), snaplen))
        elif btype == 6:                                 # Enhanced Packet Block
            iface, hi, lo, caplen, orig = struct.unpack_from(end + "IIIII", body)
            if iface >= len(interfaces):
                raise CaptureError(f"packet refers to unknown interface {iface}")
            if caplen > len(body) - 20:
                raise CaptureError(f"packet at offset {pos} is longer than its block")
            linktype, tick, _ = interfaces[iface]
            yield Frame(((hi << 32) | lo) * tick, linktype, body[20:20 + caplen], orig)
        elif btype == 3:                                 # Simple Packet Block (no timestamp)
            if not interfaces:
                raise CaptureError("simple packet before any interface")
            orig = struct.unpack_from(end + "I", body)[0]
            linktype, _, snaplen = interfaces[0]
            caplen = min(orig, snaplen or orig, len(body) - 4)
            yield Frame(0.0, linktype, body[4:4 + caplen], orig)
        pos += blen


def _tsresol(options: bytes, end: str) -> float:
    """Seconds per timestamp tick, from the if_tsresol option (default: microseconds)."""
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack_from(end + "HH", options, pos)
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = options[pos + 4]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        pos += 4 + length + (-length % 4)
    return 1e-6


# -- writing (used by the demo generator and the tests) ---------------------------------
def write_pcap(path: str | Path, frames: list[Frame], linktype: int = 1) -> None:
    out = bytearray(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 65535, linktype))
    for f in frames:
        sec = int(f.ts)
        usec = int(round((f.ts - sec) * 1e6))
        if usec == 1_000_000:
            sec, usec = sec + 1, 0
        out += struct.pack("<IIII", sec, usec, len(f.data), f.orig_len) + f.data
    Path(path).write_bytes(out)


def write_pcapng(path: str | Path, frames: list[Frame], linktype: int = 1) -> None:
    def block(btype: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        n = len(body) + 12
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    out = block(PCAPNG_SHB, struct.pack("<IHHq", PCAPNG_BOM, 1, 0, -1))
    # if_tsresol = 9 (nanoseconds), to exercise non-default clock resolutions
    opts = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)
    out += block(1, struct.pack("<HHI", linktype, 0, 65535) + opts)
    for f in frames:
        ticks = int(round(f.ts * 1e9))
        out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(f.data), f.orig_len) + f.data)
    Path(path).write_bytes(out)
