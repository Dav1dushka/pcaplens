import struct

import pytest

from pcaplens.capture import CaptureError, CaptureInfo, Frame, read_capture, write_pcap, write_pcapng
from pcaplens.decode import decode
from pcaplens.synth import tcp, udp

FRAMES = [Frame(1_700_000_000.123456, 1, b"\x00" * 60, 60), Frame(1_700_000_001.5, 1, b"\x01" * 42, 1514)]


def test_pcap_round_trip(tmp_path):
    path = tmp_path / "a.pcap"
    write_pcap(path, FRAMES)
    info = CaptureInfo()
    got = list(read_capture(path, info))
    assert info.format == "pcap" and not info.truncated
    assert [f.data for f in got] == [f.data for f in FRAMES]
    assert got[1].orig_len == 1514                      # snapped frame keeps its real length
    assert got[0].ts == pytest.approx(FRAMES[0].ts, abs=1e-6)


def test_pcapng_round_trip_with_nanosecond_clock(tmp_path):
    path = tmp_path / "a.pcapng"
    write_pcapng(path, FRAMES)
    info = CaptureInfo()
    got = list(read_capture(path, info))
    assert info.format == "pcapng"
    assert [f.data for f in got] == [f.data for f in FRAMES]
    assert got[0].ts == pytest.approx(FRAMES[0].ts, abs=1e-6)


def _pcap_bytes(endian: str, magic: int, frac: int, linktype: int = 1, data: bytes = b"\xaa" * 20) -> bytes:
    head = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    return head + struct.pack(endian + "IIII", 100, frac, len(data), len(data)) + data


@pytest.mark.parametrize("endian", ["<", ">"])
def test_both_byte_orders_and_nanosecond_pcap(tmp_path, endian):
    path = tmp_path / "x.pcap"
    path.write_bytes(_pcap_bytes(endian, 0xA1B2C3D4, 250_000))
    assert next(read_capture(path)).ts == pytest.approx(100.25)
    path.write_bytes(_pcap_bytes(endian, 0xA1B23C4D, 250_000_000))
    assert next(read_capture(path)).ts == pytest.approx(100.25)


def test_truncated_capture_yields_complete_records_only(tmp_path):
    path = tmp_path / "t.pcap"
    write_pcap(path, FRAMES)
    path.write_bytes(path.read_bytes()[:-10])            # the capture was cut while writing
    info = CaptureInfo()
    assert len(list(read_capture(path, info))) == 1
    assert info.truncated


@pytest.mark.parametrize("content,message", [
    (b"", "too short"),
    (b"GIF89a....", "not a pcap"),
    (struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 0, 0, 10**7, 10**7), "claims"),
])
def test_invalid_files(tmp_path, content, message):
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(CaptureError, match=message):
        list(read_capture(path))


@pytest.mark.parametrize("linktype,prefix", [
    (101, b""),                                          # raw IP
    (113, b"\x00" * 14 + b"\x08\x00"),                   # Linux cooked capture (tcpdump -i any)
    (276, b"\x08\x00" + b"\x00" * 18),                   # Linux cooked v2
    (0, struct.pack("<I", 2)),                           # BSD loopback
])
def test_link_types(linktype, prefix):
    ip = tcp("10.0.0.1", "10.0.0.2", 1234, 443, 0x02)
    p = decode(Frame(0, linktype, prefix + ip, len(prefix + ip)))
    assert (p.src, p.dst, p.proto, p.dport) == ("10.0.0.1", "10.0.0.2", "TCP", 443)


def test_vlan_tagged_ethernet():
    ip = udp("10.0.0.1", "10.0.0.53", 5000, 53, b"x")
    frame = b"\x02" * 12 + b"\x81\x00\x00\x64" + b"\x08\x00" + ip   # 802.1Q, VLAN 100
    p = decode(Frame(0, 1, frame, len(frame)))
    assert (p.proto, p.dport, p.payload) == ("UDP", 53, b"x")
