"""Shared pytest fixtures for the dvmcp test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from dvmcp.config import Settings
from dvmcp.server import build_server


def _extract(result) -> str:
    """Flatten a CallToolResult into its text content."""
    return " ".join(getattr(c, "text", str(c)) for c in (result.content or []))


@pytest.fixture
def make_server(tmp_path: Path):
    """Factory: build a dvmcp server in vulnerable or patched mode."""

    def _factory(*, patched: bool = False, **kwargs) -> object:
        settings = Settings(patched_all=patched, lab_root=tmp_path / "labdata", **kwargs)
        return build_server(settings)

    return _factory


@pytest.fixture
def call():
    """Helper to call a tool and return flattened text."""

    async def _call(server, name: str, arguments: dict | None = None) -> str:
        res = await server.call_tool(name, arguments or {})
        return _extract(res)

    return _call
