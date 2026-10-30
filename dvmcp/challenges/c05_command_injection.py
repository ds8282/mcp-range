"""Challenge 05 — Command Injection in a shell-wrapper tool
(MCP05 / ASI05 / CWE-78).

Learning objective: building a shell command by string-interpolating untrusted
input and running it with ``shell=True`` lets an attacker chain extra commands
with ``;``, ``|``, ``&&``, ``$(...)`` or backticks. This is OWASP MCP05's
canonical example and the class behind mcp-remote (CVE-2025-6514, CVSS 9.6).

Containment: the genuine ``shell=True`` sink is present in the source so the
static scanner detects the real pattern. At runtime the challenge defaults to a
fully contained *simulator* that never spawns a shell. The real shell path runs
only when ``settings.real_exec`` is set (DVMCP_REAL_EXEC=1), which
docker-compose enables inside the isolated, non-root, read-only container. In
both cases the only thing a successful injection can reach is a canary file.
"""

from __future__ import annotations

import re
import subprocess  # noqa: S404 (intentional — this challenge demonstrates its misuse)

from ..config import Settings
from .base import ChallengeMeta

META = ChallengeMeta(
    id="c05",
    slug="command-injection",
    title="Command Injection (shell wrapper)",
    objective="Chain an extra shell command onto a tool that builds a command string.",
    difficulty="Medium",
    mcp_category="MCP05",
    asi_category="ASI05",
    cwe="CWE-78",
    flag="DVMCP{c05_command_injection_1c6a}",
)

# Shell metacharacters that enable command chaining/substitution.
_SHELL_METACHARS = re.compile(r"[;&|`$()<>\n]")
# A conservative allowlist for a hostname/IP argument (patched version).
_SAFE_HOST = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def register(server, settings: Settings) -> None:
    patched = settings.is_patched(META.id)
    canary_file = settings.lab_root / "secret" / "cmdinj.txt"

    if not patched:
        def resolve_host(host: str) -> str:
            """Resolve a host by running the system resolver (diagnostic)."""
            # VULNERABLE: untrusted `host` interpolated into a shell string.
            cmd = f"echo resolving {host}"
            if settings.real_exec:
                # Genuine sink. Confined to the lab dir, non-root, in-container.
                proc = subprocess.run(  # noqa: S602 (intentional vulnerability)
                    cmd, shell=True, capture_output=True, text=True,
                    cwd=str(settings.lab_root), timeout=5,
                )
                return (proc.stdout or "") + (proc.stderr or "")
            # Contained simulator: detect the injection and reveal exactly what
            # the chained `cat` would have exposed, without spawning a shell.
            if _SHELL_METACHARS.search(host):
                try:
                    leaked = canary_file.read_text(encoding="utf-8")
                except FileNotFoundError:
                    leaked = META.flag
                return f"resolving {host}\n[injected command executed]\n{leaked}"
            return f"resolving {host}\n"
    else:
        def resolve_host(host: str) -> str:
            """Resolve a host by running the system resolver (diagnostic)."""
            # PATCHED: validate against an allowlist and never use a shell.
            if not _SAFE_HOST.match(host):
                return "[rejected: host contains illegal characters]"
            proc = subprocess.run(
                ["echo", "resolving", host],  # argv form, no shell
                capture_output=True, text=True, timeout=5,
            )
            return proc.stdout

    server.add_tool(resolve_host, name="resolve_host",
                    description="Resolve a host by running the system resolver (diagnostic).")


async def exploit(server) -> str | None:
    """Chain `cat <canary>` onto the resolver via a shell metacharacter."""
    payload = "localhost; cat secret/cmdinj.txt"
    res = await server.call_tool("resolve_host", {"host": payload})
    text = " ".join(getattr(c, "text", "") for c in (res.content or []))
    return text if META.flag in text else None
