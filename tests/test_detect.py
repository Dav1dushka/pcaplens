import base64

from pcaplens.analyze import analyze
from pcaplens.capture import Frame, write_pcap
from pcaplens.decode import ACK, RST, SYN
from pcaplens.detect import detect_all, entropy
from pcaplens.synth import arp_reply, client_hello, demo_capture, dns_query, tcp, udp

from .conftest import frames_of


def run(tmp_path, frames):
    path = tmp_path / "c.pcap"
    write_pcap(path, frames)
    a = analyze(path)
    return a, detect_all(a)


def test_demo_capture_finds_every_planted_problem(demo_path):
    findings = detect_all(analyze(demo_path))
    titles = sorted(f.title for f in findings)
    assert titles == sorted([
        "HTTP Basic credentials over plain HTTP",
        "FTP login in clear text",
        "Port scan of 192.168.1.50",
        "Possible DNS tunnel via exfil-tunnel.example",
        "Regular check-ins to update-check.example",
        "Burst of failed DNS lookups",
        "Connection to port 4444",
        "TLS to 198.51.100.77 without a DNS lookup",   # the beacon uses a hard-coded address
        "ARP spoofing: 192.168.1.1 claimed by 2 devices",
        "Large upload to files.storage-drop.example",
        "TLS to 203.0.113.150 without a DNS lookup",
    ])
    scan = next(f for f in findings if f.title.startswith("Port scan"))
    assert "21, 22, 80, 445" in scan.evidence[1]          # the open ports were found
    arp = next(f for f in findings if f.title.startswith("ARP"))
    assert "also sent IP traffic as 192.168.1.66" in arp.evidence[-1]   # the spoofer is the scanner
    assert [f.severity for f in findings] == sorted((f.severity for f in findings),
                                                     key=["high", "medium", "low"].index)


def test_normal_traffic_is_quiet(tmp_path):
    for seed in range(5):
        _, findings = run(tmp_path, demo_capture(seed=seed, attacks=False))
        assert findings == [], [f.title for f in findings]


def test_scan_threshold(tmp_path):
    def scan(n):
        probes = [("10.0.0.9", "10.0.0.5", tcp("10.0.0.9", "10.0.0.5", 40000 + p, p, SYN)) for p in range(1, n + 1)]
        return frames_of(*probes, step=0.01)
    assert run(tmp_path, scan(14))[1] == []               # 14 ports: could be an application, stay quiet
    assert run(tmp_path, scan(15))[1][0].title == "Port scan of 10.0.0.5"


def test_horizontal_sweep(tmp_path):
    frames = frames_of(*[("10.0.0.9", f"10.0.1.{i}", tcp("10.0.0.9", f"10.0.1.{i}", 40000 + i, 3389, SYN))
                         for i in range(1, 25)], step=0.01)
    assert [f.title for f in run(tmp_path, frames)[1]] == ["Sweep for port 3389"]


def test_beacon_needs_regularity(tmp_path):
    def beacons(gaps):
        t, pkts = 0.0, []
        for g in gaps:
            pkts.append(("10.0.0.7", "203.0.113.5", tcp("10.0.0.7", "203.0.113.5", 50000 + len(pkts), 443, SYN)))
            t += g
        times = [sum(gaps[:i]) for i in range(len(gaps))]
        frames = frames_of(*pkts)
        for f, ts in zip(frames, times, strict=True):
            f.ts = 1000 + ts
        return frames
    regular = [60.0, 61.0, 59.5, 60.2, 60.4, 59.8, 60.1, 60.0, 59.9]
    human = [5.0, 140.0, 33.0, 2.0, 300.0, 47.0, 12.0, 90.0, 61.0]
    assert [f.title for f in run(tmp_path, beacons(regular))[1]] == ["Regular check-ins to 203.0.113.5"]
    assert run(tmp_path, beacons(human))[1] == []


def test_entropy():
    assert entropy("aaaaaaaa") == 0
    assert entropy("mail") < 2.1
    assert entropy("x7k2q9vmz4lp8w3c") > 3.8


def test_tls_names_attach_to_beacons(tmp_path):
    frames = []
    for i in range(10):
        frames += frames_of(("10.0.0.7", "203.0.113.5", tcp("10.0.0.7", "203.0.113.5", 50000 + i, 443, SYN)),
                            ("10.0.0.7", "203.0.113.5", tcp("10.0.0.7", "203.0.113.5", 50000 + i, 443, ACK,
                                                            client_hello("c2.example"), seq=2)),
                            t0=1000 + i * 45.0, step=0.1)
    finding = run(tmp_path, frames)[1][0]
    assert finding.title == "Regular check-ins to c2.example"


def test_dns_and_rst_do_not_count_as_connections(tmp_path):
    queries = [("10.0.0.2", "10.0.0.1", udp("10.0.0.2", "10.0.0.1", 5000 + i, 53, dns_query(i, "a.example")))
               for i in range(30)]
    resets = [("10.0.0.5", "10.0.0.2", tcp("10.0.0.5", "10.0.0.2", 80, 6000 + i, RST | ACK)) for i in range(30)]
    frames = frames_of(*queries, *resets)
    a, findings = run(tmp_path, frames)
    assert findings == [] and a.protocols["DNS"] == 30


def test_http_request_split_across_segments_out_of_order(tmp_path):
    req = (b"GET /admin HTTP/1.1\r\nHost: router.example\r\nAuthorization: Basic "
           + base64.b64encode(b"admin:admin") + b"\r\n\r\n")
    a_, b_ = 20, 45
    parts = [(101, req[:a_]), (101 + a_, req[a_:b_]), (101 + b_, req[b_:])]
    c, s = "10.0.0.2", "10.0.0.1"
    frames = frames_of(
        (c, s, tcp(c, s, 5000, 80, SYN, seq=100)),
        (c, s, tcp(c, s, 5000, 80, ACK, parts[1][1], seq=parts[1][0])),   # second piece first
        (c, s, tcp(c, s, 5000, 80, ACK, parts[0][1], seq=parts[0][0])),
        (c, s, tcp(c, s, 5000, 80, ACK, parts[0][1], seq=parts[0][0])),   # a retransmission
        (c, s, tcp(c, s, 5000, 80, ACK, parts[2][1], seq=parts[2][0])),
    )
    a, findings = run(tmp_path, frames)
    assert a.protocols["HTTP"] == 1
    assert [f.title for f in findings] == ["HTTP Basic credentials over plain HTTP"]


def test_client_hello_split_in_two(tmp_path):
    hello = client_hello("split.example")
    c, s = "10.0.0.2", "203.0.113.9"
    frames = frames_of((c, s, tcp(c, s, 5001, 443, SYN, seq=7)),
                       (c, s, tcp(c, s, 5001, 443, ACK, hello[:30], seq=8)),
                       (c, s, tcp(c, s, 5001, 443, ACK, hello[30:], seq=8 + 30)))
    a, _ = run(tmp_path, frames)
    assert [h.sni for *_, h in a.tls] == ["split.example"]


def test_capture_starting_mid_connection_is_ignored(tmp_path):
    c, s = "10.0.0.2", "10.0.0.1"
    frames = frames_of((c, s, tcp(c, s, 5002, 80, ACK, b"rest of an earlier request body", seq=999)),
                       (c, s, tcp(c, s, 5002, 80, ACK, b"GET / HTTP/1.1\r\n\r\n", seq=1030)))
    a, _ = run(tmp_path, frames)
    assert a.protocols["HTTP"] == 0      # the stream did not start with a request: no guessing


def test_arp_spoofing(tmp_path):
    gw, mac_gw, mac_evil, mac_pc = "192.168.1.1", b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x66", b"\x02" * 6

    def frames(*senders):
        return [Frame(1000.0 + i, 1, d, len(d))
                for i, d in enumerate(arp_reply(m, ip, mac_pc, "192.168.1.10") for m, ip in senders)]

    assert run(tmp_path, frames((mac_gw, gw), (mac_gw, gw), (mac_gw, gw)))[1] == []
    # Hosts checking whether an address is free send probes from 0.0.0.0: many MACs, but no claim.
    assert run(tmp_path, frames((mac_gw, "0.0.0.0"), (mac_evil, "0.0.0.0")))[1] == []
    finding = run(tmp_path, frames((mac_gw, gw), (mac_evil, gw), (mac_evil, gw)))[1][0]
    assert finding.title == "ARP spoofing: 192.168.1.1 claimed by 2 devices"
    assert finding.src == "02:00:00:00:00:66"


def test_internal_means_lan_ranges_not_documentation_ranges():
    from pcaplens.detect import _internal
    assert _internal("192.168.1.5") and _internal("10.1.2.3") and _internal("fe80::1")
    # Python's ipaddress calls these "private"; for exfiltration they are outside.
    assert not _internal("203.0.113.150") and not _internal("192.0.2.1") and not _internal("8.8.8.8")


def test_uploads_need_volume_and_imbalance(tmp_path):
    def session(up_packets, down_packets):
        c, s = "192.168.1.9", "198.51.100.200"
        pkts = [(c, s, tcp(c, s, 6000, 443, SYN, seq=1))]
        pkts += [(c, s, tcp(c, s, 6000, 443, ACK, bytes(1400), seq=2 + i * 1400)) for i in range(up_packets)]
        pkts += [(s, c, tcp(s, c, 443, 6000, ACK, bytes(1400), seq=9 + i * 1400)) for i in range(down_packets)]
        return frames_of(*pkts, step=0.001)
    assert [f.title for f in run(tmp_path, session(800, 10))[1]] == ["Large upload to 198.51.100.200"]
    assert run(tmp_path, session(800, 400))[1] == []     # a lot both ways: a sync or a video call
    assert run(tmp_path, session(300, 0))[1] == []       # too little to matter
