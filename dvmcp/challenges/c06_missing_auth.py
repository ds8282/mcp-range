"""Challenge 06 — Missing/weak authentication on a sensitive tool
(MCP07 / ASI03 / CWE-306).

Learning objective: a sensitive, state-changing or data-exporting tool must
enforce authorization at the tool boundary. Many 2026 MCP CVEs are simply a
sensitive capability exposed with no auth at all (e.g. MySQL MCP
CVE-2026-59971, Azure MCP CVE-2026-32211).

Vulnerable ``admin_export`` performs a "privileged" export with no
authorization whatsoever. The patched version requires a bearer token,
compared in constant time, and refuses the call without it.

Note on transport: over stdio there are no HTTP headers, so authorization is
modelled as a required ``token`` argument. Over streamable-http the same
lesson applies at the header level; the exploit doc covers both. The point is
the *presence or absence of an authorization gate*, independent of transport.
"""

from __future__ import annotations

import hmac

from ..config import Settings
from .base import ChallengeMeta

META = ChallengeMeta(
    id="c06",
    slug="missing-auth",
    title="Missing Authentication (sensitive tool)",
    objective="Invoke a privileged tool that forgot to check authorization.",
    difficulty="Easy",
    mcp_category="MCP07",
    asi_category="ASI03",
    cwe="CWE-306",
    flag="DVMCP{c06_missing_auth_f41b}",
)

_EXPORT_BODY = (
    "BEGIN EXPORT\n"
    "users: 3 (canary records)\n"
    "api_key: dvmcp_canary_admin_k3y (fake)\n"
    "END EXPORT\n"
)


def register(server, settings: Settings) -> None:
    patched = settings.is_patched(META.id)

    if not patched:
        def admin_export() -> str:
            """Export the full admin dataset (privileged)."""
            # VULNERABLE: a sensitive capability with no authorization check.
            return f"{_EXPORT_BODY}flag: {META.flag}\n"
    else:
        expected = settings.auth_token

        def admin_export(token: str = "") -> str:
            """Export the full admin dataset (privileged). Requires a bearer token."""
            # PATCHED: enforce authorization at the tool boundary, constant-time.
            if not token or not hmac.compare_digest(token, expected):
                return "[401 unauthorized: a valid admin token is required]"
            return f"{_EXPORT_BODY}flag: {META.flag}\n"

    server.add_tool(
        admin_export,
        name="admin_export",
        description="Export the full admin dataset (privileged).",
    )


async def exploit(server) -> str | None:
    """Call the privileged export with no credentials."""
    res = await server.call_tool("admin_export", {})
    text = " ".join(getattr(c, "text", "") for c in (res.content or []))
    return text if META.flag in text else None
