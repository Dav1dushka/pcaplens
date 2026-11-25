"""Detectors: patterns in the analysed traffic that deserve a closer look.

Each detector explains its evidence and maps to a MITRE ATT&CK technique,
so a finding can be looked up and discussed in the usual vocabulary.
Thresholds are deliberately conservative: a quiet report on normal traffic
matters as much as catching attacks.
"""
from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .analyze import Analysis

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

SUSPICIOUS_PORTS = {
    4444: "Metasploit's default listener",
    1337: "a port popular with backdoors",
    31337: "Back Orifice and other old backdoors",
    6667: "IRC, used by old botnets for command and control",
}


@dataclass
class Finding:
    severity: str            # high, medium, low
    title: str
    summary: str
    attack: str              # MITRE ATT&CK technique, e.g. "T1046 Network Service Discovery"
    src: str = ""
    dst: str = ""
    first: float = 0.0
    evidence: list[str] = field(default_factory=list)


def detect_all(a: Analysis) -> list[Finding]:
    findings: list[Finding] = []
    for detector in (port_scans, cleartext_credentials, dns_tunneling, nxdomain_bursts, beaconing, suspicious_ports,
                     tls_without_lookup, arp_spoofing, large_uploads):
        findings += detector(a)
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.first))


# -- port scans ----------------------------------------------------------------------------
SCAN_PORTS = 15      # distinct ports on one host
SWEEP_HOSTS = 20     # distinct hosts on one port


def port_scans(a: Analysis) -> list[Finding]:
    ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    hosts: dict[tuple[str, int], set[str]] = defaultdict(set)
    first: dict[tuple, float] = {}
    for ts, src, dst, dport in a.syns:
        ports[(src, dst)].add(dport)
        hosts[(src, dport)].add(dst)
        first.setdefault((src, dst), ts)
        first.setdefault((src, dport), ts)
    out = []
    for (src, dst), tried in ports.items():
        if len(tried) < SCAN_PORTS:
            continue
        open_ports = sorted(p for p in tried if (dst, p, src) in a.syn_acks)
        out.append(Finding(
            "high", f"Port scan of {dst}",
            f"{src} tried {len(tried)} different TCP ports on {dst}; {len(open_ports)} answered.",
            "T1046 Network Service Discovery", src, dst, first[(src, dst)],
            [f"Ports tried: {_ports(sorted(tried))}",
             f"Open (answered with SYN-ACK): {_ports(open_ports) if open_ports else 'none'}"]))
    for (src, dport), targets in hosts.items():
        if len(targets) >= SWEEP_HOSTS:
            out.append(Finding(
                "high", f"Sweep for port {dport}",
                f"{src} tried port {dport} on {len(targets)} different hosts.",
                "T1046 Network Service Discovery", src, "", first[(src, dport)],
                [f"Hosts: {', '.join(sorted(targets)[:12])}{' …' if len(targets) > 12 else ''}"]))
    return out


def _ports(ports: list[int], limit: int = 25) -> str:
    shown = ", ".join(map(str, ports[:limit]))
    return shown + (f" … (+{len(ports) - limit})" if len(ports) > limit else "")


# -- credentials in clear text ---------------------------------------------------------------
def mask(secret: str) -> str:
    """Never print a captured password: show only its length."""
    return f"{'•' * min(len(secret), 8)} ({len(secret)} characters)"


def cleartext_credentials(a: Analysis) -> list[Finding]:
    out = []
    for ts, client, server, user, pw in a.ftp_logins:
        out.append(Finding(
            "high", "FTP login in clear text",
            f"{client} logged in to the FTP server {server} as '{user}'. Anyone on the path can read the password.",
            "T1040 Network Sniffing (credentials exposed)", client, server, ts,
            [f"USER {user}", f"PASS {mask(pw)}", "Use SFTP or FTPS instead."]))
    for ts, client, server, port, req in a.http:
        if req.basic_auth:
            user, pw = req.basic_auth
            out.append(Finding(
                "high", "HTTP Basic credentials over plain HTTP",
                f"{client} sent a username and password to http://{req.host or server}{req.path} without TLS.",
                "T1040 Network Sniffing (credentials exposed)", client, server, ts,
                [f"{req.method} {req.path} (port {port})",
                 f"Authorization: Basic → user '{user}', password {mask(pw)}"]))
        elif req.form_password and req.method == "POST":
            out.append(Finding(
                "high", "Login form posted over plain HTTP",
                f"{client} posted a form with a password field to http://{req.host or server}{req.path}.",
                "T1040 Network Sniffing (credentials exposed)", client, server, ts,
                [f"{req.method} {req.path} (port {port})", "Body contains a password field (value not shown)."]))
    return out


# -- DNS tunnelling --------------------------------------------------------------------------------
def entropy(text: str) -> float:
    """Shannon entropy in bits per character: ~2.5-3.5 for words, ~4-5 for encoded data."""
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def base_domain(name: str) -> str:
    labels = name.rstrip(".").split(".")
    return ".".join(labels[-2:])


TUNNEL_NAMES = 15        # distinct suspicious names under one domain


def dns_tunneling(a: Analysis) -> list[Finding]:
    names: dict[tuple[str, str], set[str]] = defaultdict(set)
    types: dict[tuple[str, str], Counter] = defaultdict(Counter)
    first: dict[tuple[str, str], float] = {}
    for ts, src, _dst, msg in a.dns:
        if msg.response:
            continue
        for name, qtype in msg.questions:
            base = base_domain(name)
            sub = name.rstrip(".")[: -len(base)].rstrip(".")
            if len(sub) >= 25 or (len(sub) >= 12 and entropy(sub.replace(".", "")) >= 3.8):
                key = (src, base)
                names[key].add(name)
                types[key][qtype] += 1
                first.setdefault(key, ts)
    out = []
    for (src, base), found in names.items():
        if len(found) < TUNNEL_NAMES:
            continue
        subs = [n.rstrip(".")[: -len(base)].rstrip(".") for n in found]
        encoded = sum(len(s.replace(".", "")) for s in subs)
        out.append(Finding(
            "high", f"Possible DNS tunnel via {base}",
            f"{src} asked for {len(found)} long, random-looking names under {base}: "
            f"about {encoded:,} characters of data hidden in DNS queries.",
            "T1071.004 Application Layer Protocol: DNS", src, base, first[(src, base)],
            [f"Examples: {', '.join(sorted(found)[:3])}",
             f"Average subdomain length {encoded / len(found):.0f} characters, "
             f"entropy {statistics.mean(entropy(s.replace('.', '')) for s in subs):.1f} bits/char",
             "Record types: " + ", ".join(f"{t} ×{n}" for t, n in types[(src, base)].most_common())]))
    return out


# -- many NXDOMAIN answers (domain generation algorithms) -------------------------------------------
NXDOMAIN_BURST = 10      # distinct failing names for one client within a minute


def nxdomain_bursts(a: Analysis) -> list[Finding]:
    failures: dict[str, list[tuple[float, str]]] = defaultdict(list)
    for ts, _src, dst, msg in a.dns:
        if msg.response and msg.rcode == "NXDOMAIN" and msg.questions:
            failures[dst].append((ts, msg.questions[0][0]))
    out = []
    for client, items in failures.items():
        # Sliding 60-second window with a count per name: O(n) instead of rebuilding the window
        # for every answer, which matters when an infected host fails thousands of lookups.
        items.sort()
        in_window: Counter = Counter()
        best_size, best_range = 0, (0, 0)
        start = 0
        for end, (t_end, name) in enumerate(items):
            in_window[name] += 1
            while t_end - items[start][0] > 60:
                old = items[start][1]
                in_window[old] -= 1
                if not in_window[old]:
                    del in_window[old]
                start += 1
            if len(in_window) > best_size:
                best_size, best_range = len(in_window), (start, end + 1)
        first_seen: dict[str, float] = {}
        for t, n in items[best_range[0]:best_range[1]]:
            first_seen.setdefault(n, t)
        best = sorted((t, n) for n, t in first_seen.items())
        if len(best) >= NXDOMAIN_BURST:
            out.append(Finding(
                "medium", "Burst of failed DNS lookups",
                f"{client} got NXDOMAIN for {len(best)} different names within a minute. Malware that uses a domain "
                "generation algorithm tries many random names until one is registered.",
                "T1568.002 Dynamic Resolution: Domain Generation Algorithms", client, "", best[0][0],
                [f"Examples: {', '.join(n for _, n in best[:4])}"]))
    return out


# -- beaconing ---------------------------------------------------------------------------------------
BEACON_MIN = 8           # connections needed to call it regular
BEACON_JITTER = 0.15     # standard deviation / mean of the intervals


def beaconing(a: Analysis) -> list[Finding]:
    starts: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    for ts, src, dst, dport in a.syns:
        starts[(src, dst, dport)].append(ts)
    sni = {(src, dst): h.sni for _, src, dst, _, h in a.tls if h.sni}
    out = []
    for (src, dst, dport), times in starts.items():
        if len(times) < BEACON_MIN:
            continue
        times.sort()
        gaps = [b - a_ for a_, b in zip(times, times[1:], strict=False)]
        mean = statistics.mean(gaps)
        if mean < 2:
            continue   # bursts (a browser opening many connections) are not beacons
        jitter = statistics.pstdev(gaps) / mean
        if jitter > BEACON_JITTER:
            continue
        name = sni.get((src, dst))
        out.append(Finding(
            "medium", f"Regular check-ins to {name or dst}",
            f"{src} connected to {dst}:{dport} {len(times)} times, every {mean:.1f} s "
            f"(±{jitter * 100:.0f}%). People are not that regular; malware checking in with its server is.",
            "T1071.001 Application Layer Protocol: Web Protocols (C2 beaconing)", src, dst, times[0],
            [f"Interval {mean:.1f} s, standard deviation {statistics.pstdev(gaps):.2f} s",
             f"TLS server name: {name}" if name else "No TLS server name seen"]))
    return out


# -- ports associated with malware ------------------------------------------------------------------
def suspicious_ports(a: Analysis) -> list[Finding]:
    seen: dict[tuple[str, str, int], float] = {}
    for ts, src, dst, dport in a.syns:
        if dport in SUSPICIOUS_PORTS:
            seen.setdefault((src, dst, dport), ts)
    return [Finding(
        "medium", f"Connection to port {dport}",
        f"{src} opened a connection to {dst}:{dport}, {SUSPICIOUS_PORTS[dport]}.",
        "T1571 Non-Standard Port", src, dst, ts,
        ["Answered" if (dst, dport, src) in a.syn_acks else "Not answered"])
        for (src, dst, dport), ts in seen.items()]


# -- TLS to an address nobody looked up ---------------------------------------------------------------
def tls_without_lookup(a: Analysis) -> list[Finding]:
    """A browser resolves a name, then connects to the answer. Malware often carries a hard-coded
    address and puts any name it likes in the SNI. Low severity: the lookup may simply predate
    the capture, so this is a lead, not a verdict."""
    resolved = {data for _, _, _, msg in a.dns if msg.response for _, t, data in msg.answers if t in ("A", "AAAA")}
    if not a.dns:
        return []   # no DNS in the capture at all (filtered out, or DNS over HTTPS): nothing to compare with
    seen: dict[tuple[str, str], tuple[float, str, int]] = {}
    for ts, src, dst, port, hello in a.tls:
        if dst not in resolved:
            seen.setdefault((src, dst), (ts, hello.sni, port))
    return [Finding(
        "low", f"TLS to {dst} without a DNS lookup",
        f"{src} opened TLS to {dst}:{port}{f' claiming the name {sni}' if sni else ''}, but no DNS answer in the "
        "capture pointed to that address.",
        "T1071.001 Application Layer Protocol: Web Protocols", src, dst, ts,
        [f"Server name sent: {sni or '(none)'}", "The lookup may have happened before the capture started."])
        for (src, dst), (ts, sni, port) in seen.items()]


# -- ARP spoofing ----------------------------------------------------------------------------------------
def arp_spoofing(a: Analysis) -> list[Finding]:
    """On a LAN, ARP maps an IP address to a MAC address. An attacker who answers "the router's
    IP is at my MAC" receives everyone's traffic. Two MACs claiming one IP is the tell-tale sign."""
    claims: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for ts, _op, ip, mac in a.arp_claims:
        if ip != "0.0.0.0":   # ARP probes use 0.0.0.0 as the sender address
            claims[ip][mac].append(ts)
    out = []
    for ip, macs in claims.items():
        if len(macs) < 2:
            continue
        # The newcomer is the MAC seen last for the first time; it is usually also the loudest.
        ordered = sorted(macs.items(), key=lambda kv: min(kv[1]))
        newcomer, times = ordered[-1]
        evidence = [f"{mac}: {len(seen)} ARP message{'' if len(seen) == 1 else 's'}, "
                    f"first at +{min(seen) - a.first:.0f}s" for mac, seen in ordered]
        if a.mac_ips.get(newcomer):
            evidence.append(f"{newcomer} also sent IP traffic as {', '.join(sorted(a.mac_ips[newcomer]))}")
        out.append(Finding(
            "high", f"ARP spoofing: {ip} claimed by {len(macs)} devices",
            f"{len(macs)} different MAC addresses announced that they are {ip}. If {ip} is the gateway, the device at "
            f"{newcomer} can now read and change traffic meant for it (man in the middle).",
            "T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning", newcomer, ip, min(times), evidence))
    return out


# -- large uploads to the internet --------------------------------------------------------------------------
UPLOAD_BYTES = 1_000_000     # per internal host and external server
UPLOAD_RATIO = 5             # sent at least five times more than received


# Python's is_private is True for documentation and benchmarking ranges too (203.0.113.0/24, ...),
# which would hide uploads to them. "Internal" here means the address ranges a LAN actually uses.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "fc00::/7", "fe80::/10", "::1/128")]


def _internal(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in INTERNAL_NETS)


def large_uploads(a: Analysis) -> list[Finding]:
    """Normal users download far more than they upload. A workstation pushing megabytes to an outside
    server, and getting little back, is what data theft looks like on the wire."""
    totals: dict[tuple[str, str], list] = defaultdict(lambda: [0, 0, 0, float("inf"), set()])
    for c in a.conversations.values():
        if c.proto == "TCP" and _internal(c.client) and not _internal(c.server):
            t = totals[(c.client, c.server)]
            t[0] += c.upload
            t[1] += c.download
            t[2] += 1
            t[3] = min(t[3], c.first)
            t[4].add(c.sport)
    sni = {(src, dst): h.sni for _, src, dst, _, h in a.tls if h.sni}
    out = []
    for (client, server), (up, down, conns, first, ports) in totals.items():
        if up >= UPLOAD_BYTES and up >= UPLOAD_RATIO * max(down, 1):
            name = sni.get((client, server))
            web = ports <= {80, 443, 8080, 8443}
            technique = "T1567 Exfiltration Over Web Service" if web else "T1048 Exfiltration Over Alternative Protocol"
            out.append(Finding(
                "high" if up >= 10 * UPLOAD_BYTES else "medium",
                f"Large upload to {name or server}",
                f"{client} sent {up / 1e6:.1f} MB to {server} and received only {down / 1e6:.2f} MB back. "
                "Exfiltration looks like this: much more going out than coming in.",
                technique, client, server, first,
                [f"{conns} connection{'s' if conns != 1 else ''} to port{'s' if len(ports) != 1 else ''} "
                 f"{', '.join(map(str, sorted(ports)))}",
                 f"Upload {up:,} bytes, download {down:,} bytes (ratio {up / max(down, 1):.0f}:1)"]
                + ([f"TLS server name: {name}"] if name else [])))
    return out
