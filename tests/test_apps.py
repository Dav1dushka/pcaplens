import base64
import hashlib
import struct
import time

from pcaplens.apps import ftp_command, parse_client_hello, parse_dns, parse_http_request
from pcaplens.synth import BROWSER_CIPHERS, client_hello, dns_query, dns_response


def test_dns_query_and_compressed_answer():
    q = parse_dns(dns_query(0x1234, "www.example.org", 28))
    assert not q.response and q.questions == [("www.example.org", "AAAA")]
    r = parse_dns(dns_response(0x1234, "www.example.org", 1, [bytes([192, 0, 2, 7])]))
    assert r.response and r.rcode == "NOERROR"
    assert r.answers == [("www.example.org", "A", "192.0.2.7")]   # the answer name is a pointer back


def test_dns_nxdomain_and_txt():
    assert parse_dns(dns_response(1, "nope.example", 1, [], rcode=3)).rcode == "NXDOMAIN"
    txt = parse_dns(dns_response(1, "t.example", 16, [b"\x05hello\x05world"]))
    assert txt.answers[0][2] == "hello world"


def test_dns_pointer_loop_does_not_hang():
    msg = struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"   # name points at itself
    start = time.perf_counter()
    assert parse_dns(msg) is None
    assert time.perf_counter() - start < 0.05            # rejected at once, not after a long spin


def test_garbage_is_not_dns():
    assert parse_dns(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03") is None
    assert parse_dns(b"short") is None


def test_http_basic_auth_and_form():
    creds = base64.b64encode(b"alice:s3cret").decode()
    req = parse_http_request(f"GET /admin HTTP/1.1\r\nHost: intranet\r\nAuthorization: Basic {creds}\r\n\r\n".encode())
    assert (req.method, req.path, req.host, req.basic_auth) == ("GET", "/admin", "intranet", ("alice", "s3cret"))
    post = parse_http_request(b"POST /login HTTP/1.1\r\nHost: x\r\n\r\nuser=a&password=b")
    assert post.form_password and post.basic_auth is None
    assert parse_http_request(b"GET nonsense") is None
    assert parse_http_request(b"\x16\x03\x01") is None


def test_client_hello_sni_alpn_and_ja3():
    h = parse_client_hello(client_hello("login.bank.example"))
    assert h.sni == "login.bank.example"
    assert h.alpn == ["h2", "http/1.1"]
    # JA3: version, ciphers, extensions, groups, point formats; GREASE values are left out.
    ciphers = "-".join(str(c) for c in BROWSER_CIPHERS if c != 0x1A1A)
    assert h.ja3 == f"771,{ciphers},0-23-65281-10-11-16,29-23-24,0"
    assert h.ja3_hash == hashlib.md5(h.ja3.encode()).hexdigest()


def test_truncated_client_hello_is_ignored():
    full = client_hello("a.example")
    for n in range(len(full)):
        parse_client_hello(full[:n])                     # never raises


def test_ftp_commands():
    assert ftp_command(b"USER backup\r\n") == ("USER", "backup")
    assert ftp_command(b"pass hunter2\r\n") == ("PASS", "hunter2")
    assert ftp_command(b"LIST\r\n") is None
