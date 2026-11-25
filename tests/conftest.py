import pytest

from pcaplens.capture import Frame, write_pcap
from pcaplens.synth import demo_capture, ethernet


@pytest.fixture(scope="session")
def demo_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("cap") / "demo.pcap"
    write_pcap(path, demo_capture())
    return path


def frames_of(*packets, t0=1000.0, step=1.0):
    """Wrap (src, dst, ip_packet) tuples into Ethernet frames, one per second."""
    out = []
    for i, (src, dst, pkt) in enumerate(packets):
        data = ethernet(src, dst, pkt)
        out.append(Frame(t0 + i * step, 1, data, len(data)))
    return out
