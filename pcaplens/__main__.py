"""Command line.

    pcaplens capture.pcapng                       summary and findings in the terminal
    pcaplens capture.pcap --html report.html      plus a self-contained HTML report
    pcaplens capture.pcap --json -                findings and statistics as JSON
    pcaplens demo demo.pcap                       write the synthetic demo capture
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyze import analyze
from .capture import CaptureError
from .detect import detect_all
from .report import to_html, to_json, to_text
from .synth import write_demo


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["demo"]:
        p = argparse.ArgumentParser(prog="pcaplens demo", description="Write the synthetic demo capture.")
        p.add_argument("out", nargs="?", default="demo.pcap")
        p.add_argument("--format", choices=["pcap", "pcapng"], default=None, help="default: from the file extension")
        args = p.parse_args(argv[1:])
        fmt = args.format or ("pcapng" if args.out.endswith(".pcapng") else "pcap")
        n = write_demo(args.out, fmt)
        print(f"wrote {n} packets to {args.out} ({fmt})")
        return 0

    p = argparse.ArgumentParser(prog="pcaplens", description="Find attacks in a packet capture (pcap or pcapng).",
                                epilog="Run 'pcaplens demo demo.pcap' to create a capture to try it on.")
    p.add_argument("capture", help="a .pcap or .pcapng file")
    p.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    p.add_argument("--json", metavar="FILE", help="write JSON ('-' for standard output)")
    p.add_argument("--fail-on", choices=["high", "medium", "low"],
                   help="exit with status 3 if a finding of this severity or worse is present (for scripts and CI)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"pcaplens {__version__}")
    args = p.parse_args(argv)

    try:
        a = analyze(args.capture)
    except FileNotFoundError:
        print(f"pcaplens: no such file: {args.capture}", file=sys.stderr)
        return 2
    except CaptureError as exc:
        print(f"pcaplens: {args.capture}: {exc}", file=sys.stderr)
        return 2
    findings = detect_all(a)

    if args.json == "-":
        print(to_json(a, findings))
    else:
        print(to_text(a, findings, color=sys.stdout.isatty() and not args.no_color))
        if args.json:
            Path(args.json).write_text(to_json(a, findings), encoding="utf-8")
    if args.html:
        Path(args.html).write_text(to_html(a, findings), encoding="utf-8")
        if args.json != "-":
            print(f"\nHTML report: {args.html}")

    if args.fail_on:
        rank = {"high": 0, "medium": 1, "low": 2}
        if any(rank[f.severity] <= rank[args.fail_on] for f in findings):
            return 3
    return 0


def run() -> int:
    try:
        return main()
    except BrokenPipeError:      # e.g. `pcaplens x.pcap | head`: the reader went away, which is fine
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    sys.exit(run())
