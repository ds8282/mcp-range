"""Safety scaffolding for the dvmcp training range.

dvmcp is *intentionally vulnerable*.  Two mechanisms keep that from being
dangerous:

1. :func:`assert_loopback` refuses to start the HTTP transport on a
   non-loopback address unless the operator sets an explicit override.  This
   is the control the NotebookLM MCP CVE (CVE-2026-61647) recommends in
   reverse: never expose the service beyond localhost.
2. :func:`seed_lab` builds a self-contained lab directory full of obviously
   fake *canary* files.  Every "secret" in the range is a string that starts
   with ``dvmcp_canary_`` or lives inside a ``DVMCP{...}`` flag -- there is no
   real credential anywhere in this project.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .config import LOOPBACK_HOSTS

DISCLAIMER = (
    "dvmcp is an INTENTIONALLY VULNERABLE MCP server for security training. "
    "Never expose it to a network you do not fully control. All secrets here "
    "are fake canaries. See SECURITY.md."
)


class UnsafeConfiguration(RuntimeError):
    """Raised when dvmcp is asked to start in a way that could cause harm."""


def assert_loopback(host: str, allow_nonloopback: bool) -> None:
    """Refuse to serve HTTP off-loopback unless explicitly overridden."""
    if host in LOOPBACK_HOSTS or allow_nonloopback:
        return
    raise UnsafeConfiguration(
        f"Refusing to bind dvmcp to non-loopback host {host!r}. dvmcp is "
        "intentionally vulnerable and must not be exposed to a network. "
        "If you understand the risk and are inside an isolated range, pass "
        "--i-know-this-is-dangerous (or set DVMCP_ALLOW_NONLOOPBACK=1)."
    )


# --- Lab filesystem -------------------------------------------------------
#
# Layout seeded under ``lab_root`` (default ./labdata):
#
#   public/   <- the file-reading tool is *supposed* to serve only this
#   secret/   <- traversal target for challenge c03; holds a flag canary
#   config/   <- benign-looking config holding the c01 poisoning canary
#
# Flags are stored here so the vulnerable tools can surface them when
# successfully exploited, and so the scoring harness can verify solves.

_PUBLIC_FILES = {
    "README.txt": (
        "Public notes directory for the dvmcp demo.\n"
        "The read_public_file tool is meant to serve ONLY files in here.\n"
    ),
    "meeting-notes.md": (
        "# Team sync\n\n- Ship the thing\n- Fix the other thing\n"
        "- Nothing sensitive lives in this directory\n"
    ),
}


def seed_lab(lab_root: Path, *, flags: dict[str, str]) -> Path:
    """Create the canary lab tree under *lab_root* (idempotent).

    *flags* maps challenge ids to their ``DVMCP{...}`` flag strings so the
    filesystem challenges can embed them in canary files.
    """
    lab_root = Path(lab_root)
    public = lab_root / "public"
    secret = lab_root / "secret"
    config = lab_root / "config"
    for d in (public, secret, config):
        d.mkdir(parents=True, exist_ok=True)

    for name, body in _PUBLIC_FILES.items():
        (public / name).write_text(body, encoding="utf-8")

    # Traversal target for c03 (path traversal). Not reachable from the
    # public dir unless the tool fails to enforce containment.
    (secret / "flag.txt").write_text(
        "This file is OUTSIDE the public directory.\n"
        "If a file-reading tool let you read this, it is path-traversable.\n"
        f"flag: {flags.get('c03', 'DVMCP{missing}')}\n"
        "note: dvmcp_canary_fs_1a2b (fake secret)\n",
        encoding="utf-8",
    )

    # Command-injection canary for c05. A successful shell injection that
    # chains `cat` onto this file reveals the flag. Nothing of value here.
    (secret / "cmdinj.txt").write_text(
        f"{flags.get('c05', 'DVMCP{missing}')}\n"
        "note: dvmcp_canary_cmd_9x8y (fake secret)\n",
        encoding="utf-8",
    )

    # Poisoning canary for c01. The hidden instruction in the poisoned tool
    # description tries to get an agent to exfiltrate session_token.
    (config / "agent.cfg").write_text(
        "[agent]\n"
        "profile = default\n"
        "session_token = dvmcp_canary_6b1e9f\n",
        encoding="utf-8",
    )
    return lab_root


def resolve_within(root: Path, user_path: str) -> Path:
    """Safely resolve *user_path* under *root*, raising on escape.

    This is the CORRECT containment pattern (canonicalize, then verify the
    resolved path is an ancestor-descendant of root). The patched version of
    the path-traversal challenge uses exactly this; the vulnerable version
    does not. Kept here so the fix is reviewable in one place.
    """
    root = Path(root).resolve()
    candidate = (root / user_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise UnsafeConfiguration(f"path escapes sandbox root: {user_path!r}")
    return candidate


def print_banner(stream=sys.stderr) -> None:
    print("=" * 70, file=stream)
    print("  dvmcp — Damn Vulnerable MCP   (training use only)", file=stream)
    print("  " + DISCLAIMER, file=stream)
    print("=" * 70, file=stream)
