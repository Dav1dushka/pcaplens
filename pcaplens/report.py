"""Turning an analysis into something to read: terminal text, JSON, or a
self-contained HTML page.

Everything in a capture is attacker-controlled: host names, URLs, user agents.
The HTML report escapes every value and ships a Content-Security-Policy that
forbids scripts, so a hostile capture cannot run code in the analyst's browser.
"""
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyze import Analysis
from .detect import Finding, base_domain

SEV_COLOR = {"high": "#ff4d6d", "medium": "#ffb020", "low": "#4cc9f0"}


def _time(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def summary(a: Analysis, findings: list[Finding]) -> dict:
    """Everything the report shows, as plain data (this is also the JSON output)."""
    dns_names: dict[tuple[str, str], dict] = {}
    for _ts, _src, _dst, msg in a.dns:
        for name, qtype in msg.questions:
            row = dns_names.setdefault((name, qtype), {"name": name, "type": qtype, "queries": 0, "answers": set(),
                                                       "rcodes": Counter()})
            if msg.response:
                row["rcodes"][msg.rcode] += 1
                row["answers"].update(d for n, t, d in msg.answers if t == qtype)
            else:
                row["queries"] += 1
    domains: dict[str, dict] = {}
    for _ts, _src, _dst, msg in a.dns:
        if msg.response:
            continue
        for name, qtype in msg.questions:
            d = domains.setdefault(base_domain(name), {"domain": base_domain(name), "names": set(), "queries": 0,
                                                       "types": Counter()})
            d["names"].add(name)
            d["queries"] += 1
            d["types"][qtype] += 1
    tls: dict[tuple[str, str], dict] = {}
    for _ts, src, dst, port, h in a.tls:
        row = tls.setdefault((h.sni, h.ja3_hash), {"sni": h.sni, "ja3": h.ja3_hash, "servers": set(), "clients": set(),
                                                   "alpn": h.alpn, "count": 0})
        row["servers"].add(f"{dst}:{port}")
        row["clients"].add(src)
        row["count"] += 1
    convs = sorted(a.conversations.values(), key=lambda c: c.bytes, reverse=True)
    hosts: dict[str, dict] = defaultdict(lambda: {"sent": 0, "received": 0, "peers": set(), "findings": 0})
    for c in a.conversations.values():
        for me, peer in ((c.client, c.server), (c.server, c.client)):
            hosts[me]["peers"].add(peer)
    for c in a.conversations.values():
        hosts[c.client]["sent"] += c.upload
        hosts[c.client]["received"] += c.download
        hosts[c.server]["sent"] += c.download
        hosts[c.server]["received"] += c.upload
    for f in findings:
        for addr in {f.src, f.dst}:
            if addr in hosts:
                hosts[addr]["findings"] += 1
    return {
        "tool": f"pcaplens {__version__}",
        "file": Path(a.path).name,
        "format": a.info.format,
        "truncated": a.info.truncated,
        "packets": a.packets,
        "bytes": a.bytes,
        "start": _time(a.first) if a.packets else None,
        "end": _time(a.last) if a.packets else None,
        "duration_s": round(a.duration, 3),
        "protocols": dict(a.protocols.most_common()),
        "findings": [f.__dict__ | {"offset_s": round(f.first - a.first, 1)} for f in findings],
        "top_hosts": [{"address": h, "bytes": b} for h, b in a.host_bytes.most_common(10)],
        "hosts": sorted(({"address": h, "sent_bytes": d["sent"], "received_bytes": d["received"],
                          "peers": len(d["peers"]), "findings": d["findings"]} for h, d in hosts.items()),
                        key=lambda d: (-d["findings"], -d["peers"]))[:25],
        "conversations": [{"proto": c.proto, "client": f"{c.client}:{c.cport}", "server": f"{c.server}:{c.sport}",
                           "packets": c.packets, "bytes": c.bytes, "duration_s": round(c.last - c.first, 3)}
                          for c in convs[:15]],
        "dns_domains": sorted(({"domain": d["domain"], "distinct_names": len(d["names"]), "queries": d["queries"],
                                "types": dict(d["types"]), "example": sorted(d["names"], key=len)[0]}
                               for d in domains.values()), key=lambda d: -d["queries"])[:40],
        "dns": sorted(({**r, "answers": sorted(r["answers"])[:5], "rcodes": dict(r["rcodes"])}
                       for r in dns_names.values()), key=lambda r: -r["queries"])[:40],
        "tls": sorted(({**r, "servers": sorted(r["servers"]), "clients": sorted(r["clients"])} for r in tls.values()),
                      key=lambda r: -r["count"]),
        "http": [{"time_s": round(ts - a.first, 1), "client": src, "server": f"{dst}:{port}", "method": r.method,
                  "host": r.host, "path": r.path, "user_agent": r.user_agent} for ts, src, dst, port, r in a.http],
    }


def to_json(a: Analysis, findings: list[Finding]) -> str:
    return json.dumps(summary(a, findings), indent=2, ensure_ascii=False)


# -- terminal --------------------------------------------------------------------------------------
def to_text(a: Analysis, findings: list[Finding], color: bool = False) -> str:
    def c(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    s = summary(a, findings)
    lines = [c(f"pcaplens · {s['file']}", "1"),
             f"{s['packets']:,} packets, {_size(s['bytes'])} over {a.duration:.0f} s ({s['format']}"
             f"{', truncated' if s['truncated'] else ''})",
             "Protocols: " + ", ".join(f"{k} {v:,}" for k, v in s["protocols"].items()), ""]
    counts = Counter(f.severity for f in findings)
    lines.append(c(f"{len(findings)} findings", "1") + (": " + ", ".join(f"{counts[k]} {k}" for k in
                                                                       ("high", "medium", "low") if counts[k])
                                                        if findings else " — nothing suspicious found"))
    codes = {"high": "31;1", "medium": "33;1", "low": "36"}
    for f in findings:
        lines += ["", c(f"[{f.severity.upper()}] {f.title}", codes[f.severity]) + c(f"  +{f.first - a.first:.0f}s", "2"),
                  f"  {f.summary}", c(f"  ATT&CK {f.attack}", "2")]
        lines += [f"  · {e}" for e in f.evidence]
    if s["tls"]:
        lines += ["", c("TLS servers by name", "1")]
        lines += [f"  {r['sni'] or '(no SNI)':<32} {r['count']:>5}×  JA3 {r['ja3']}" for r in s["tls"][:10]]
    return "\n".join(lines)


# -- HTML ----------------------------------------------------------------------------------------------
CSS = """
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a33;--line:rgba(220,228,255,.1);--ink:#e6ebff;--mute:#96a0c8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 20px 60px}h1{font-size:26px;margin:0}h2{font-size:17px;margin:34px 0 12px}
.mute{color:var(--mute)}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.head{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:flex-end;border-bottom:1px solid var(--line);padding-bottom:18px}
.logo{font:700 13px ui-monospace,monospace;letter-spacing:.12em;color:#4cc9f0;text-transform:uppercase}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:18px 0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}.stat b{display:block;font-size:20px}
.badge{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700;color:#0b1020}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid;border-radius:12px;padding:14px 16px;margin-bottom:10px}
.finding h3{margin:0 0 4px;font-size:15px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.finding p{margin:4px 0}.finding ul{margin:8px 0 0;padding-left:18px;color:#cdd5f5}.finding li{overflow-wrap:anywhere}
.attack{font-size:12px;color:var(--mute)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{color:var(--mute);font-weight:600;font-size:12px}tr:last-child td{border-bottom:0}td.n{text-align:right;white-space:nowrap}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:800px){.grid{grid-template-columns:1fr}}
.bar{height:8px;border-radius:4px;background:#4cc9f0}.chart{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px}
footer{margin-top:40px;color:var(--mute);font-size:12px}
"""


def _timeline(a: Analysis, findings: list[Finding]) -> str:
    if not a.packets:
        return ""
    w, h, bins = 1100, 120, 120
    span = max(a.duration, 1.0)
    counts = [0] * bins
    for sec, n in a.per_second.items():
        counts[min(bins - 1, int((sec - int(a.first)) / span * bins))] += n
    peak = max(counts) or 1
    bw = w / bins
    bars = "".join(f'<rect x="{i * bw:.1f}" y="{h - 22 - (c / peak) * (h - 40):.1f}" width="{bw - 1:.1f}" '
                   f'height="{(c / peak) * (h - 40):.1f}" fill="#4cc9f0" opacity=".75"/>' for i, c in enumerate(counts))
    marks = ""
    for f in findings:
        x = (f.first - a.first) / span * w
        marks += (f'<line x1="{x:.1f}" x2="{x:.1f}" y1="6" y2="{h - 22}" stroke="{SEV_COLOR[f.severity]}" stroke-width="2"/>'
                  f'<circle cx="{x:.1f}" cy="8" r="5" fill="{SEV_COLOR[f.severity]}"><title>{html.escape(f.title)}</title></circle>')
    axis = "".join(f'<text x="{i / 4 * w:.0f}" y="{h - 4}" fill="#96a0c8" font-size="11" '
                   f'text-anchor="{"start" if i == 0 else "end" if i == 4 else "middle"}">+{span * i / 4:.0f}s</text>'
                   for i in range(5))
    return (f'<div class="chart"><svg viewBox="0 0 {w} {h}" width="100%" role="img" '
            f'aria-label="Packets over time with findings marked">{bars}{marks}{axis}</svg></div>')


def to_html(a: Analysis, findings: list[Finding]) -> str:
    e = html.escape
    s = summary(a, findings)
    counts = Counter(f.severity for f in findings)
    badges = " ".join(f'<span class="badge" style="background:{SEV_COLOR[k]}">{counts[k]} {k}</span>'
                      for k in ("high", "medium", "low") if counts[k]) or '<span class="badge" style="background:#4ade80">clean</span>'

    cards = []
    for f in findings:
        evidence = "".join(f"<li>{e(x)}</li>" for x in f.evidence)
        cards.append(f'<div class="finding" style="border-left-color:{SEV_COLOR[f.severity]}">'
                     f'<h3><span class="badge" style="background:{SEV_COLOR[f.severity]}">{f.severity}</span>{e(f.title)}'
                     f'<span class="mute mono">+{f.first - a.first:.0f}s</span></h3>'
                     f'<p>{e(f.summary)}</p><p class="attack">MITRE ATT&amp;CK: {e(f.attack)}</p><ul>{evidence}</ul></div>')

    def table(head: list[str], rows: list[list], numeric: set[int] = frozenset()) -> str:
        th = "".join(f"<th>{e(x)}</th>" for x in head)
        body = "".join("<tr>" + "".join(f'<td class="{"n" if i in numeric else ""}">{e(str(v))}</td>'
                                        for i, v in enumerate(r)) + "</tr>" for r in rows)
        return f"<table><thead><tr>{th}</tr></thead><tbody>{body or '<tr><td>none</td></tr>'}</tbody></table>"

    total = sum(v for k, v in s["protocols"].items() if k in ("TCP", "UDP", "ICMP", "ICMPv6")) or 1
    protos = "".join(f'<tr><td>{e(k)}</td><td class="n">{v:,}</td><td style="width:45%"><div class="bar" '
                     f'style="width:{min(100, v / total * 100):.1f}%"></div></td></tr>' for k, v in s["protocols"].items())

    sections = [
        f'<div class="head"><div><div class="logo">pcaplens report</div><h1>{e(s["file"])}</h1>'
        f'<div class="mute">{e(s["start"] or "")} → {e(s["end"] or "")}</div></div><div>{badges}</div></div>',
        '<div class="stats">' + "".join(f'<div class="stat"><span class="mute">{k}</span><b>{v}</b></div>' for k, v in [
            ("Packets", f"{s['packets']:,}"), ("Data", _size(s["bytes"])), ("Duration", f"{a.duration:.0f} s"),
            ("Conversations", f"{len(a.conversations):,}"), ("Hosts", f"{len(a.host_bytes):,}"),
            ("Format", e(s["format"] + (" (truncated)" if s["truncated"] else "")))]) + "</div>",
        "<h2>Timeline</h2>" + _timeline(a, findings),
        f"<h2>Findings ({len(findings)})</h2>" + ("".join(cards) or '<p class="mute">Nothing suspicious found.</p>'),
        '<div class="grid"><div><h2>Protocols</h2><table><tbody>' + protos + "</tbody></table></div>"
        "<div><h2>Busiest hosts</h2>" + table(["Address", "Bytes"], [[h["address"], _size(h["bytes"])] for h in s["top_hosts"]], {1})
        + "</div></div>",
        "<h2>Hosts</h2>" + table(
            ["Address", "Findings", "Peers", "Sent", "Received"],
            [[h["address"], h["findings"] or "", h["peers"], _size(h["sent_bytes"]), _size(h["received_bytes"])]
             for h in s["hosts"]], {1, 2, 3, 4}),
        "<h2>TLS: who talked to which server name</h2>" + table(
            ["Server name (SNI)", "Clients", "Servers", "ALPN", "JA3", "Hellos"],
            [[r["sni"] or "(none)", ", ".join(r["clients"]), ", ".join(r["servers"][:3]), ", ".join(r["alpn"]), r["ja3"], r["count"]]
             for r in s["tls"]], {5}),
        "<h2>DNS by domain</h2>" + table(
            ["Domain", "Distinct names", "Queries", "Types", "Example"],
            [[d["domain"], d["distinct_names"], d["queries"], ", ".join(f"{t} ×{n}" for t, n in d["types"].items()),
              d["example"]] for d in s["dns_domains"]], {1, 2}),
        "<h2>HTTP requests (unencrypted)</h2>" + table(
            ["Time", "Client", "Server", "Request", "User agent"],
            [[f"+{r['time_s']}s", r["client"], r["server"], f"{r['method']} {r['host']}{r['path']}", r["user_agent"]] for r in s["http"]]),
        "<h2>Largest conversations</h2>" + table(
            ["Protocol", "Client", "Server", "Packets", "Bytes", "Duration"],
            [[c["proto"], c["client"], c["server"], c["packets"], _size(c["bytes"]), f"{c['duration_s']:.1f} s"] for c in s["conversations"]],
            {3, 4, 5}),
        f'<footer>Generated by {e(s["tool"])}. Captured passwords are never shown, only their length.</footer>',
    ]
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>pcaplens · {e(s['file'])}</title><style>{CSS}</style></head><body><main>"
            + "".join(sections) + "</main></body></html>")
