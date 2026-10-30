"""Challenge 03 — Path Traversal in a file-reading tool (MCP05 / ASI02 / CWE-22).

Learning objective: a file-reading tool that joins user input onto a base
directory without canonicalising and verifying containment can be walked out
of its sandbox with ``../`` sequences — the exact root cause of
CVE-2026-61647 (NotebookLM MCP) and the Anthropic Git MCP path-validation
bypasses.

Vulnerable ``read_public_file`` naively joins ``base / path`` and opens it, so
``../secret/flag.txt`` escapes the public directory. The patched version uses
canonicalize-then-verify-ancestor containment (``Path.resolve()`` +
``is_relative_to``), which is a correctness check, not a substring blocklist.
"""

from __future__ import annotations

from pathlib import Path

from ..config import Settings
from .base import ChallengeMeta

META = ChallengeMeta(
    id="c03",
    slug="path-traversal",
    title="Path Traversal (file read)",
    objective="Escape a file-reading tool's base directory with ../ to read a file outside it.",
    difficulty="Easy",
    mcp_category="MCP05",
    asi_category="ASI02",
    cwe="CWE-22",
    flag="DVMCP{c03_path_traversal_2d9c}",
)


def register(server, settings: Settings) -> None:
    patched = settings.is_patched(META.id)
    public_root = (settings.lab_root / "public").resolve()

    if not patched:
        def read_public_file(path: str) -> str:
            """Read a file from the public notes directory by relative path."""
            # VULNERABLE: no canonicalisation, no containment check. The join
            # happily resolves ``../`` out of public_root.
            target = public_root / path
            try:
                return target.open("r", encoding="utf-8", errors="replace").read()
            except FileNotFoundError:
                return f"[not found: {path}]"
            except IsADirectoryError:
                return f"[is a directory: {path}]"
    else:
        def read_public_file(path: str) -> str:
            """Read a file from the public notes directory by relative path."""
            # PATCHED: canonicalize then verify the resolved path stays under
            # public_root. Rejects absolute paths and ../ escapes alike.
            candidate = (public_root / path).resolve()
            if candidate != public_root and public_root not in candidate.parents:
                return "[access denied: path escapes the public directory]"
            try:
                return candidate.open("r", encoding="utf-8", errors="replace").read()
            except FileNotFoundError:
                return f"[not found: {path}]"
            except IsADirectoryError:
                return f"[is a directory: {path}]"

    server.add_tool(
        read_public_file,
        name="read_public_file",
        description="Read a file from the public notes directory by relative path.",
    )


async def exploit(server) -> str | None:
    """Traverse out of the public directory into the sibling secret file."""
    res = await server.call_tool("read_public_file", {"path": "../secret/flag.txt"})
    text = " ".join(getattr(c, "text", "") for c in (res.content or []))
    return text if META.flag in text else None
