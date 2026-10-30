"""dvmcp command-line entry point.

Examples
--------
Run over stdio (default, safest)::

    dvmcp

Run the patched variants to diff against the vulnerable ones::

    dvmcp --patched

Serve over loopback HTTP for the live scanner::

    dvmcp --transport streamable-http --port 8731

Print the scoreboard / challenge catalogue::

    dvmcp list
    dvmcp score 'DVMCP{c03_path_traversal_2d9c}'
"""

from __future__ import annotations

import argparse
import sys

from . import challenges
from .config import DEFAULT_PORT, Settings, _parse_ids
from .safety import assert_loopback, print_banner
from .scoring import check_flag, render_scoreboard
from .server import build_server, mounted_summary


def _build_settings(args: argparse.Namespace) -> Settings:
    return Settings(
        transport=args.transport,
        host=args.host,
        port=args.port,
        allow_nonloopback=args.i_know_this_is_dangerous,
        patched_all=args.patched,
        patched_ids=_parse_ids(args.patched_ids),
        enabled_ids=_parse_ids(args.only),
        real_exec=args.real_exec,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dvmcp", description=__doc__)
    sub = parser.add_subparsers(dest="cmd")

    # default (serve) flags live on the top-level parser too
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--patched", action="store_true", help="mount patched variants of all challenges")
    parser.add_argument("--patched-ids", default="", help="space/comma list of challenge ids to patch")
    parser.add_argument("--only", default="", help="space/comma list of challenge ids to mount")
    parser.add_argument("--i-know-this-is-dangerous", action="store_true",
                        help="permit binding to a non-loopback host (off by default)")
    parser.add_argument("--real-exec", action="store_true",
                        help="c05: run the genuine shell sink (container use only)")

    sub.add_parser("list", help="list the challenge catalogue")
    p_score = sub.add_parser("score", help="check a captured flag")
    p_score.add_argument("flag")
    sub.add_parser("solve", help="run every exploit against a fresh server and report")

    args = parser.parse_args(argv)

    if args.cmd == "list":
        print(render_scoreboard(captured=set()))
        return 0

    if args.cmd == "score":
        result = check_flag(args.flag)
        print(result.message)
        return 0 if result.ok else 1

    if args.cmd == "solve":
        import asyncio
        from .solver import render_outcomes, solve_all
        outcomes = asyncio.run(solve_all(_build_settings(args)))
        print(render_outcomes(outcomes))
        return 0 if all(o.solved for o in outcomes) else 1

    # default action: serve
    settings = _build_settings(args)
    print_banner()
    for line in mounted_summary(settings):
        print("  mount:", line, file=sys.stderr)

    server = build_server(settings)

    if settings.transport == "stdio":
        server.run("stdio")
    else:
        assert_loopback(settings.host, settings.allow_nonloopback)
        print(f"  serving streamable-http on http://{settings.host}:{settings.port}/mcp",
              file=sys.stderr)
        server.run("streamable-http", host=settings.host, port=settings.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
