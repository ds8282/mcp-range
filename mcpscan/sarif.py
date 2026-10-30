"""SARIF 2.1.0 output so findings upload to GitHub code scanning.

GitHub's code-scanning ingester expects SARIF 2.1.0 with a tool driver, a
``rules`` array, and ``results`` that reference those rules by ``ruleId`` and
carry a physical location. Static findings point at a file and line; live
findings have no file, so they use a synthetic ``mcp://tool/<name>`` URI.
"""

from __future__ import annotations

import json

from . import __version__
from .findings import RULES, SARIF_LEVEL, Finding

SARIF_VERSION = "2.1.0"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _rules_block() -> list[dict]:
    rules = []
    for r in RULES.values():
        rules.append({
            "id": r.id,
            "name": r.name.replace(" ", ""),
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.remediation},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {
                "security-severity": _security_severity(r.severity),
                "asi": r.asi, "mcp": r.mcp, "cwe": r.cwe,
                "tags": ["security", r.asi, r.mcp, r.cwe],
            },
            "help": {"text": r.remediation},
        })
    return rules


def _security_severity(severity: str) -> str:
    # GitHub uses a 0-10 numeric scale for ordering.
    return {"critical": "9.5", "high": "8.0", "medium": "5.0",
            "low": "3.0", "info": "1.0"}[severity]


def _result(f: Finding) -> dict:
    r = f.rule
    return {
        "ruleId": r.id,
        "level": SARIF_LEVEL[r.severity],
        "message": {"text": f"{f.message} [{r.asi}/{r.mcp}, {r.cwe}] Fix: {r.remediation}"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": max(1, f.line)},
            }
        }],
        "properties": {"source": f.source, "severity": r.severity, **f.evidence},
    }


def build_sarif(findings: list[Finding]) -> dict:
    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "mcpscan",
                "informationUri": "https://github.com/ds8282/mcp-range",
                "version": __version__,
                "rules": _rules_block(),
            }},
            "results": [_result(f) for f in findings],
        }],
    }


def write_sarif(findings: list[Finding], path: str) -> None:
    # path is an operator-supplied output file, not untrusted tool input.
    with open(path, "w", encoding="utf-8") as fh:  # mcpscan: ignore[MCPSCAN-PATH-TRAVERSAL]
        json.dump(build_sarif(findings), fh, indent=2)
