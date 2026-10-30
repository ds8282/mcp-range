"""Challenge 08 — Secrets exposure via an over-permissive resource
(MCP01 / ASI03 / CWE-538).

Learning objective: MCP *resources* are addressable data the model can read.
A resource that over-shares — returning secret material inline where only
public status was intended — leaks credentials directly into the agent's
context. Corroborating pattern: netlicensing-mcp, where a REST path bypassed
token redaction.

Vulnerable ``dvmcp://service/status`` returns a status blob that also embeds
API keys and a session token (canaries) plus the flag. The patched resource
returns only the public fields and redacts everything secret.
"""

from __future__ import annotations

import json

from ..config import Settings
from .base import ChallengeMeta

META = ChallengeMeta(
    id="c08",
    slug="secrets-exposure",
    title="Secrets Exposure (over-permissive resource)",
    objective="Read a resource that over-shares and leaks secrets into context.",
    difficulty="Medium",
    mcp_category="MCP01",
    asi_category="ASI03",
    cwe="CWE-538",
    flag="DVMCP{c08_secrets_exposure_a0d5}",
)

RESOURCE_URI = "dvmcp://service/status"

_PUBLIC = {"service": "dvmcp-demo", "status": "ok", "uptime_s": 1234}
_SECRETS = {
    "api_key": "dvmcp_canary_sk_live_0ldfaKe",
    "session_token": "dvmcp_canary_6b1e9f",
    "flag": META.flag,
}


def register(server, settings: Settings) -> None:
    patched = settings.is_patched(META.id)

    if not patched:
        def service_status() -> str:
            """Return service status."""
            # VULNERABLE: the resource over-shares, inlining secret material
            # that has no business being in a status resource.
            return json.dumps({**_PUBLIC, **_SECRETS}, indent=2)
    else:
        def service_status() -> str:
            """Return service status."""
            # PATCHED: public fields only; secrets never enter the response.
            return json.dumps(_PUBLIC, indent=2)

    server.resource(
        RESOURCE_URI,
        name="service-status",
        description="Service status resource.",
        mime_type="application/json",
    )(service_status)


def _extract_resource(result) -> str:
    """Flatten read_resource output across SDK content shapes."""
    parts = []
    for item in (result or []):
        for attr in ("text", "content", "blob", "data"):
            val = getattr(item, attr, None)
            if isinstance(val, str):
                parts.append(val)
                break
        else:
            parts.append(str(item))
    return " ".join(parts)


async def exploit(server) -> str | None:
    """Read the over-permissive status resource and capture the leaked flag."""
    result = await server.read_resource(RESOURCE_URI)
    text = _extract_resource(result)
    return text if META.flag in text else None
