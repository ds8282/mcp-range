"""Live scanner tests, run in-process against a built dvmcp server.

The high-level mcp.Client accepts an MCPServer instance, so these exercise the
real client/transport path without opening a socket.
"""

from __future__ import annotations

import pytest

from dvmcp.config import Settings
from dvmcp.server import build_server
from mcpscan.live.engine import scan_live
from mcpscan.sarif import build_sarif


@pytest.fixture
def vuln_server(tmp_path):
    return build_server(Settings(lab_root=tmp_path / "lab"))


@pytest.fixture
def patched_server(tmp_path):
    return build_server(Settings(patched_all=True, lab_root=tmp_path / "lab"))


async def test_live_scan_detects_every_category(vuln_server):
    findings = await scan_live(target=vuln_server)
    categories = {f.rule_id for f in findings}
    expected = {
        "MCPSCAN-TOOL-POISONING", "MCPSCAN-RUG-PULL", "MCPSCAN-PATH-TRAVERSAL",
        "MCPSCAN-SSRF", "MCPSCAN-SHELL-TRUE", "MCPSCAN-MISSING-AUTH",
        "MCPSCAN-INJECTION-TEXT", "MCPSCAN-SECRET-RESOURCE",
    }
    assert expected <= categories, f"missed: {expected - categories}"


async def test_live_scan_clean_against_patched(patched_server):
    findings = await scan_live(target=patched_server)
    assert findings == [], f"patched server produced findings: {[f.rule_id for f in findings]}"


async def test_live_scan_has_no_false_positive_duplicates(vuln_server):
    findings = await scan_live(target=vuln_server)
    # one finding per tool/category pair — no runaway duplicates
    keys = [(f.rule_id, f.file) for f in findings]
    assert len(keys) == len(set(keys))


async def test_live_findings_render_to_sarif(vuln_server):
    findings = await scan_live(target=vuln_server)
    sarif = build_sarif(findings)
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == len(findings)
    for r in results:
        assert r["ruleId"] and r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
