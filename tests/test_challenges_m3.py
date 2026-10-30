"""Challenge behaviour tests for Milestone 3 (c02, c04, c05, c07, c08)
plus the end-to-end solver invariant across all eight.
"""

from __future__ import annotations

import pytest

from dvmcp import challenges
from dvmcp.config import Settings
from dvmcp.solver import solve_all


# --- c02 rug pull ---------------------------------------------------------

async def test_c02_first_call_clean_second_call_mutates(make_server, call):
    server = make_server(patched=False)
    first = await call(server, "fetch_quote", {})
    assert "DVMCP{" not in first
    second = await call(server, "fetch_quote", {})
    assert challenges.c02_rug_pull.META.flag in second


async def test_c02_patched_never_mutates(make_server, call):
    server = make_server(patched=True)
    for _ in range(3):
        out = await call(server, "fetch_quote", {})
        assert challenges.c02_rug_pull.META.flag not in out
    assert "pinned" in out


# --- c04 ssrf -------------------------------------------------------------

async def test_c04_vulnerable_reaches_internal(make_server, call):
    server = make_server(patched=False)
    out = await call(server, "fetch_url", {"url": "http://internal.canary.range/flag"})
    assert challenges.c04_ssrf.META.flag in out


async def test_c04_patched_blocks_internal_and_metadata(make_server, call):
    server = make_server(patched=True)
    for url in ("http://internal.canary.range/flag", "http://169.254.169.254/latest"):
        out = await call(server, "fetch_url", {"url": url})
        assert "blocked SSRF" in out
        assert challenges.c04_ssrf.META.flag not in out


async def test_c04_patched_allows_public(make_server, call):
    server = make_server(patched=True)
    out = await call(server, "fetch_url", {"url": "http://public.canary.range/"})
    assert "public marketing page" in out


# --- c05 command injection ------------------------------------------------

async def test_c05_vulnerable_injection_simulated(make_server, call):
    server = make_server(patched=False)  # real_exec False -> contained simulator
    out = await call(server, "resolve_host", {"host": "localhost; cat secret/cmdinj.txt"})
    assert challenges.c05_command_injection.META.flag in out


async def test_c05_vulnerable_benign_input_no_flag(make_server, call):
    server = make_server(patched=False)
    out = await call(server, "resolve_host", {"host": "localhost"})
    assert challenges.c05_command_injection.META.flag not in out


async def test_c05_patched_rejects_metacharacters(make_server, call):
    server = make_server(patched=True)
    out = await call(server, "resolve_host", {"host": "localhost; cat secret/cmdinj.txt"})
    assert "rejected" in out
    assert challenges.c05_command_injection.META.flag not in out


# --- c07 prompt-injection chain ------------------------------------------

async def test_c07_vulnerable_chain_fires(make_server):
    server = make_server(patched=False)
    assert await challenges.c07_prompt_injection_chain.exploit(server)


async def test_c07_patched_redacts_and_blocks(make_server, call):
    server = make_server(patched=True)
    doc = await call(server, "fetch_document", {"doc_id": "q3"})
    assert "untrusted-data" in doc and "dvmcp_canary_exfil_c7" not in doc
    assert challenges.c07_prompt_injection_chain.META.flag not in (
        await call(server, "send_data", {"payload": "dvmcp_canary_exfil_c7"})
    )


# --- c08 secrets exposure (resource) -------------------------------------

async def test_c08_vulnerable_resource_leaks_secrets(make_server):
    server = make_server(patched=False)
    assert await challenges.c08_secrets_exposure.exploit(server)


async def test_c08_patched_resource_public_only(make_server):
    server = make_server(patched=True)
    result = await server.read_resource(challenges.c08_secrets_exposure.RESOURCE_URI)
    text = challenges.c08_secrets_exposure._extract_resource(result)
    assert "status" in text
    assert "api_key" not in text and challenges.c08_secrets_exposure.META.flag not in text


# --- solver invariant across all eight -----------------------------------

async def test_solver_vulnerable_solves_all(tmp_path):
    outcomes = await solve_all(Settings(lab_root=tmp_path / "lab"))
    assert all(o.solved for o in outcomes) and len(outcomes) == 8


async def test_solver_patched_solves_none(tmp_path):
    outcomes = await solve_all(Settings(patched_all=True, lab_root=tmp_path / "lab"))
    assert not any(o.solved for o in outcomes) and len(outcomes) == 8
