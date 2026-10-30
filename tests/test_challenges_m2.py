"""Challenge behaviour tests for Milestone 2 (c01, c03, c06).

Each challenge is verified twice: the vulnerable build must be exploitable and
yield its flag, and the patched build must refuse the same exploit. This is
the invariant the scanner's true-positive claim later depends on.
"""

from __future__ import annotations

import pytest

from dvmcp.challenges import c01_tool_poisoning, c03_path_traversal, c06_missing_auth

CANARY_TOKEN = "dvmcp_canary_6b1e9f"


# --- c01 tool poisoning ---------------------------------------------------

async def test_c01_vulnerable_leaks_flag(make_server, call):
    server = make_server(patched=False)
    out = await call(server, "summarize_notes", {"topic": "q3", "context": CANARY_TOKEN})
    assert c01_tool_poisoning.META.flag in out


async def test_c01_description_is_poisoned(make_server):
    server = make_server(patched=False)
    tools = {t.name: t for t in await server.list_tools()}
    desc = tools["summarize_notes"].description or ""
    assert "<IMPORTANT>" in desc and "session_token" in desc


async def test_c01_patched_has_clean_description_and_no_flag(make_server, call):
    server = make_server(patched=True)
    tools = {t.name: t for t in await server.list_tools()}
    assert "<IMPORTANT>" not in (tools["summarize_notes"].description or "")
    out = await call(server, "summarize_notes", {"topic": "q3"})
    assert c01_tool_poisoning.META.flag not in out


# --- c03 path traversal ---------------------------------------------------

async def test_c03_vulnerable_traverses_to_secret(make_server, call):
    server = make_server(patched=False)
    out = await call(server, "read_public_file", {"path": "../secret/flag.txt"})
    assert c03_path_traversal.META.flag in out


async def test_c03_vulnerable_still_reads_legit_files(make_server, call):
    server = make_server(patched=False)
    out = await call(server, "read_public_file", {"path": "README.txt"})
    assert "Public notes directory" in out


async def test_c03_patched_blocks_traversal(make_server, call):
    server = make_server(patched=True)
    out = await call(server, "read_public_file", {"path": "../secret/flag.txt"})
    assert c03_path_traversal.META.flag not in out
    assert "access denied" in out


async def test_c03_patched_still_reads_legit_files(make_server, call):
    server = make_server(patched=True)
    out = await call(server, "read_public_file", {"path": "README.txt"})
    assert "Public notes directory" in out


# --- c06 missing auth -----------------------------------------------------

async def test_c06_vulnerable_exports_without_auth(make_server, call):
    server = make_server(patched=False)
    out = await call(server, "admin_export", {})
    assert c06_missing_auth.META.flag in out


async def test_c06_patched_requires_token(make_server, call):
    server = make_server(patched=True)
    assert c06_missing_auth.META.flag not in await call(server, "admin_export", {})
    assert c06_missing_auth.META.flag not in await call(server, "admin_export", {"token": "wrong"})


async def test_c06_patched_accepts_correct_token(make_server, call):
    from dvmcp.config import DEFAULT_AUTH_TOKEN
    server = make_server(patched=True)
    out = await call(server, "admin_export", {"token": DEFAULT_AUTH_TOKEN})
    assert c06_missing_auth.META.flag in out
