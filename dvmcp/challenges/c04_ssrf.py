"""Challenge 04 — SSRF in a URL-fetching tool (ASI02 / CWE-918).

Learning objective: a tool that fetches a user-supplied URL without validating
the destination can be pointed at internal-only services and cloud metadata
endpoints. In MCP this is frequently reached by indirect prompt injection and
shows up as DNS-rebinding / redirect bypasses (CVE-2026-77242, -61612).

To stay *realistic but fully contained*, fetching is routed through a lab
resolver that knows a small, fixed set of canary targets and never touches the
real internet:

  * http://public.canary.range/      -> benign public content
  * http://internal.canary.range/flag-> an "internal-only" service (flag)
  * http://169.254.169.254/...       -> a cloud-metadata stand-in (canary creds)

The vulnerable tool fetches any requested host. The patched tool blocks
private, loopback, and link-local destinations and anything off the public
allowlist before fetching. (docker-compose also ships a real loopback canary
service so the same exploit works over HTTP; see docs.)
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from ..config import Settings
from .base import ChallengeMeta

META = ChallengeMeta(
    id="c04",
    slug="ssrf",
    title="Server-Side Request Forgery (URL fetch)",
    objective="Make a URL-fetching tool reach an internal-only / metadata endpoint.",
    difficulty="Medium",
    mcp_category="MCP05",
    asi_category="ASI02",
    cwe="CWE-918",
    flag="DVMCP{c04_ssrf_9b22}",
)

# Simulated, fully offline targets. Keyed by host. Returned verbatim.
_LAB_TARGETS = {
    "public.canary.range": "200 OK: public marketing page (nothing sensitive)",
    "internal.canary.range": (
        "200 OK: INTERNAL admin service — should never be reachable from a "
        f"user-supplied URL. {META.flag}"
    ),
    "169.254.169.254": (
        "200 OK: metadata stand-in: {'AccessKeyId':'dvmcp_canary_AKIA', "
        "'SecretAccessKey':'dvmcp_canary_secret'}"
    ),
}

# Public allowlist used by the patched version.
_PUBLIC_ALLOWLIST = {"public.canary.range"}


def _lab_fetch(host: str) -> str:
    """Offline stand-in for an HTTP GET against the lab targets."""
    return _LAB_TARGETS.get(host, f"000: no route to {host!r} in lab")


def _is_private_host(host: str) -> bool:
    """True if host is an IP in a private/loopback/link-local range, or
    resolves to one. Hostnames not in DNS are treated by name below."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        # Not a literal IP. In a real resolver we'd resolve and re-check to
        # defend against DNS rebinding; the lab's link-local name is explicit.
        return host in {"internal.canary.range"} or host.endswith(".internal")


def register(server, settings: Settings) -> None:
    patched = settings.is_patched(META.id)

    if not patched:
        def fetch_url(url: str) -> str:
            """Fetch a URL and return its body."""
            host = (urlparse(url).hostname or "").lower()
            # VULNERABLE: no destination validation whatsoever.
            return _lab_fetch(host)
    else:
        def fetch_url(url: str) -> str:
            """Fetch a URL and return its body. Public hosts only."""
            host = (urlparse(url).hostname or "").lower()
            if not host:
                return "[blocked: unparseable URL]"
            if _is_private_host(host):
                return "[blocked SSRF: destination is internal/link-local]"
            if host not in _PUBLIC_ALLOWLIST:
                return "[blocked SSRF: host not on the public allowlist]"
            return _lab_fetch(host)

    server.add_tool(fetch_url, name="fetch_url",
                    description="Fetch a URL and return its body.")


async def exploit(server) -> str | None:
    """Point the fetcher at the internal-only canary service."""
    res = await server.call_tool("fetch_url", {"url": "http://internal.canary.range/flag"})
    text = " ".join(getattr(c, "text", "") for c in (res.content or []))
    return text if META.flag in text else None
