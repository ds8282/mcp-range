"""mcpscan CLI.

Commands
--------
Static scan of source code::

    mcpscan static <path> [--sarif out.sarif] [--json] [--fail-on high]

Live scan of a running server (Milestone 5)::

    mcpscan live --url http://127.0.0.1:8731/mcp
"""

from __future__ import annotations

import argparse
import json
import sys

from .findings import SEVERITY_ORDER
from .report import render_text, summary_counts
from .static.engine import scan_path


def _fail(findings, threshold: str | None) -> int:
    if not threshold:
        return 0
    cutoff = SEVERITY_ORDER.index(threshold)
    worst = min((SEVERITY_ORDER.index(f.rule.severity) for f in findings), default=len(SEVERITY_ORDER))
    return 1 if worst <= cutoff else 0


def _emit(findings, args, target: str) -> None:
    if args.json:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        print(render_text(findings, color=not args.no_color, target=target))
    if getattr(args, "sarif", None):
        from .sarif import write_sarif
        write_sarif(findings, args.sarif)
        print(f"\nSARIF written to {args.sarif}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcpscan", description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--sarif", metavar="FILE", help="also write SARIF to FILE")
    parser.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None,
                        help="exit non-zero if a finding at/above this severity exists")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_static = sub.add_parser("static", help="scan source code")
    p_static.add_argument("path")

    p_live = sub.add_parser("live", help="scan a running MCP server")
    p_live.add_argument("--url", help="streamable-http MCP URL, e.g. http://127.0.0.1:8731/mcp")
    p_live.add_argument("--stdio", help="shell command to launch a stdio MCP server")

    args = parser.parse_args(argv)

    if args.cmd == "static":
        findings = scan_path(args.path)
        _emit(findings, args, target=args.path)
        return _fail(findings, args.fail_on)

    if args.cmd == "live":
        import asyncio
        from .live.engine import scan_live
        findings = asyncio.run(scan_live(url=args.url, stdio_cmd=args.stdio))
        _emit(findings, args, target=args.url or args.stdio or "")
        return _fail(findings, args.fail_on)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
