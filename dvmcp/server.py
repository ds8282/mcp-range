"""Assemble the dvmcp MCPServer from the enabled challenges."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from . import challenges
from .config import Settings
from .safety import DISCLAIMER, seed_lab

SERVER_INSTRUCTIONS = (
    "dvmcp is a deliberately vulnerable MCP training server. " + DISCLAIMER
)


def build_server(settings: Settings) -> MCPServer:
    """Seed the lab and build a server with the enabled challenges mounted."""
    seed_lab(settings.lab_root, flags=challenges.flags())

    server = MCPServer(
        name="dvmcp",
        version="0.1.0",
        instructions=SERVER_INSTRUCTIONS,
    )

    for mod in challenges.ALL:
        if settings.is_enabled(mod.META.id):
            mod.register(server, settings)

    return server


def mounted_summary(settings: Settings) -> list[str]:
    """Human-readable list of what will be mounted, for the startup banner."""
    out = []
    for mod in challenges.ALL:
        if not settings.is_enabled(mod.META.id):
            continue
        m = mod.META
        mode = "patched" if settings.is_patched(m.id) else "VULNERABLE"
        out.append(f"{m.id} {m.title} [{mode}] {m.mcp_category}/{m.asi_category} {m.cwe}")
    return out
