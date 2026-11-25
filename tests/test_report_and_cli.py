import json
import random

import pytest

from pcaplens.__main__ import main
from pcaplens.analyze import analyze
from pcaplens.capture import CaptureError, write_pcap
from pcaplens.decode import ACK, PSH
from pcaplens.detect import detect_all
from pcaplens.report import to_html, to_json, to_text
from pcaplens.synth import client_hello, tcp

from .conftest import frames_of

PASSWORDS = ["Summer2026!", "b4ckup-2026"]   # planted in the demo capture


def test_passwords_never_appear_in_any_output(demo_path):
    a = analyze(demo_path)
    findings = detect_all(a)
    for out in (to_text(a, findings), to_json(a, findings), to_html(a, findings)):
        for pw in PASSWORDS:
            assert pw not in out


def test_html_escapes_hostile_capture_content(tmp_path):
    evil = '<script>alert(1)</script>.example'
    # Basic auth makes this request a finding, so the hostile host and path reach the finding card too.
    http = f"GET /<img/src=x/onerror=alert(1)> HTTP/1.1\r\nHost: {evil}\r\nAuthorization: Basic YTpi\r\n\r\n".encode()
    frames = frames_of(("10.0.0.2", "10.0.0.3", tcp("10.0.0.2", "10.0.0.3", 5000, 443, PSH | ACK, client_hello(evil))),
                       ("10.0.0.2", "10.0.0.3", tcp("10.0.0.2", "10.0.0.3", 5001, 80, PSH | ACK, http)))
    path = tmp_path / "evil.pcap"
    write_pcap(path, frames)
    a = analyze(path)
    findings = detect_all(a)
    assert any(evil in f.summary for f in findings)
    page = to_html(a, findings)
    assert "<script" not in page and "<img" not in page
    assert "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page and "default-src 'none'" in page


def test_json_is_valid_and_complete(demo_path):
    a = analyze(demo_path)
    data = json.loads(to_json(a, detect_all(a)))
    assert data["packets"] == a.packets and len(data["findings"]) == 11
    assert data["findings"][0]["attack"].startswith("T")
    assert {"domain", "distinct_names", "queries"} <= set(data["dns_domains"][0])


def test_cli(tmp_path, demo_path, capsys):
    html, js = tmp_path / "r.html", tmp_path / "r.json"
    assert main([str(demo_path), "--html", str(html), "--json", str(js), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "11 findings: 5 high, 4 medium, 2 low" in out
    assert html.read_text().startswith("<!doctype html>")
    assert json.loads(js.read_text())["format"] == "pcap"
    assert main([str(demo_path), "--fail-on", "high"]) == 3
    assert main([str(tmp_path / "missing.pcap")]) == 2
    assert main(["demo", str(tmp_path / "d.pcapng")]) == 0
    assert "pcapng" in capsys.readouterr().out


def test_fuzzed_captures_never_crash(tmp_path, demo_path):
    """A capture is untrusted input. Corrupt it in many ways: the analyzer must either
    work or report a CaptureError, and never fail with anything else."""
    original = demo_path.read_bytes()
    rng = random.Random(1234)
    path = tmp_path / "fuzz.pcap"
    for _ in range(150):
        data = bytearray(original[: rng.randint(24, len(original))])
        for _ in range(rng.randint(1, 40)):
            pos = rng.randrange(len(data))
            data[pos] = rng.randrange(256)
        path.write_bytes(bytes(data))
        try:
            a = analyze(path)
        except CaptureError:
            continue
        findings = detect_all(a)
        to_html(a, findings)
        to_json(a, findings)


@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_both_formats_give_the_same_analysis(tmp_path, fmt):
    path = tmp_path / f"d.{fmt}"
    assert main(["demo", str(path)]) == 0
    a = analyze(path)
    assert len(detect_all(a)) == 11 and a.protocols["ARP"] == 24
