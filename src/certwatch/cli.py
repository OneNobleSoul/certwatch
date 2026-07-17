"""Command line entry point.

Two modes:
  certwatch host [host:port ...] [--targets file]   -> probe live hosts
  certwatch inspect cert.pem                         -> decode a local file
"""

from __future__ import annotations

import argparse
import ssl
import sys
from collections.abc import Callable
from pathlib import Path

from certwatch import __version__
from certwatch.certinfo import CertInfo, decode_cert_file
from certwatch.probe import ProbeResult, probe_host
from certwatch.report import exit_code, render_json, render_table, to_entries

ProbeFn = Callable[..., ProbeResult]


def parse_target(text: str) -> tuple[str, int]:
    text = text.strip()
    if text.startswith("["):
        # bracketed IPv6 literal, optionally with a port: [::1] or [::1]:8443
        host, sep, rest = text[1:].partition("]")
        if not sep:
            raise ValueError(f"invalid target {text!r}: missing closing ']'")
        if not host:
            raise ValueError(f"invalid target {text!r}: empty host in brackets")
        if rest.startswith(":"):
            return host, _parse_port(rest[1:], text)
        if rest:
            raise ValueError(f"invalid target {text!r}: unexpected text after ']'")
        return host, 443
    if text.count(":") > 1:
        # bare IPv6 literal, no brackets means no unambiguous place for a port
        return text, 443
    if ":" in text:
        host, _, port = text.rpartition(":")
        return host, _parse_port(port, text)
    return text, 443


def _parse_port(raw: str, target: str) -> int:
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"invalid target {target!r}: {raw!r} is not a valid port") from None


def collect_targets(hosts: list[str], targets_file: str | None) -> list[tuple[str, int]]:
    out = [parse_target(h) for h in hosts]
    if targets_file:
        for line in Path(targets_file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(parse_target(line))
    return out


def _build_watch_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certwatch",
        description="check when TLS certificates expire",
    )
    parser.add_argument("hosts", nargs="*", help="host or host:port (default port 443)")
    parser.add_argument("--targets", metavar="FILE", help="file with one host per line")
    parser.add_argument("--warn", type=int, default=21, help="warn threshold in days")
    parser.add_argument("--critical", type=int, default=7, help="critical threshold in days")
    parser.add_argument("--timeout", type=float, default=10.0, help="connect timeout seconds")
    parser.add_argument("--json", action="store_true", help="print json instead of a table")
    return parser


def run_watch(argv: list[str], probe_fn: ProbeFn | None = None) -> int:
    parser = _build_watch_parser()
    args = parser.parse_args(argv)

    try:
        targets = collect_targets(args.hosts, args.targets)
    except OSError as exc:
        parser.error(f"can't read targets file: {exc}")
    except ValueError as exc:
        parser.error(str(exc))

    if not targets:
        parser.error("no targets given (pass hosts or --targets FILE)")

    probe_fn = probe_fn or probe_host
    results = [probe_fn(host, port, timeout=args.timeout) for host, port in targets]
    entries = to_entries(results, warn=args.warn, critical=args.critical)

    if args.json:
        print(render_json(entries))
    else:
        render_table(entries)
    return exit_code(entries)


def run_inspect(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="certwatch inspect")
    parser.add_argument("path", help="path to a PEM certificate")
    parser.add_argument("--warn", type=int, default=21)
    parser.add_argument("--critical", type=int, default=7)
    parser.add_argument("--json", action="store_true", help="print json instead of a table")
    args = parser.parse_args(argv)

    try:
        cert = decode_cert_file(args.path)
    except (OSError, ValueError, ssl.SSLError) as exc:
        result = ProbeResult(args.path, 0, error=str(exc))
    else:
        info = CertInfo.from_cert_dict(cert, args.path, port=0)
        result = ProbeResult(args.path, 0, cert=info)

    entries = to_entries([result], warn=args.warn, critical=args.critical)
    if args.json:
        print(render_json(entries))
    else:
        render_table(entries)
    return exit_code(entries)


def main(argv: list[str] | None = None, probe_fn: ProbeFn | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if "--version" in argv or "-V" in argv:
        print(f"certwatch {__version__}")
        return 0

    if argv and argv[0] == "inspect":
        return run_inspect(argv[1:])

    return run_watch(argv, probe_fn=probe_fn)
