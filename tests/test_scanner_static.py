"""Static scanner tests.

Two invariants matter for the project's headline claim:
1. Every planted challenge is flagged with the expected rule category.
2. The scanner does not cry wolf on the (non-vulnerable) core modules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpscan.static.checks import analyze_source
from mcpscan.static.engine import scan_path

CHALLENGES = Path("dvmcp/challenges")

# challenge file stem -> the rule we expect the static scanner to raise
EXPECTED = {
    "c01_tool_poisoning": "MCPSCAN-TOOL-POISONING",
    "c02_rug_pull": "MCPSCAN-RUG-PULL",
    "c03_path_traversal": "MCPSCAN-PATH-TRAVERSAL",
    "c04_ssrf": "MCPSCAN-SSRF",
    "c05_command_injection": "MCPSCAN-SHELL-TRUE",
    "c06_missing_auth": "MCPSCAN-MISSING-AUTH",
    "c07_prompt_injection_chain": "MCPSCAN-INJECTION-TEXT",
    "c08_secrets_exposure": "MCPSCAN-SECRET-RESOURCE",
}


@pytest.mark.parametrize("stem,rule", EXPECTED.items())
def test_each_challenge_flagged_with_expected_rule(stem, rule):
    path = CHALLENGES / f"{stem}.py"
    findings = analyze_source(str(path), path.read_text(encoding="utf-8"))
    rules = {f.rule_id for f in findings}
    assert rule in rules, f"{stem}: expected {rule}, got {sorted(rules)}"


def test_scanner_catches_all_eight_challenge_files():
    findings = scan_path(CHALLENGES)
    files = {f.file for f in findings}
    assert len(files) == 8


def test_no_false_positives_on_core_modules():
    for module in ("dvmcp/config.py", "dvmcp/safety.py", "dvmcp/server.py",
                   "dvmcp/solver.py", "dvmcp/scoring.py"):
        findings = scan_path(module)
        assert findings == [], f"unexpected findings in {module}: {findings}"


def test_scanner_is_clean_on_itself():
    assert scan_path("mcpscan") == []


def test_patched_pattern_not_flagged():
    """A correctly-guarded file-reader must not raise path traversal."""
    safe = '''
from pathlib import Path
def read(root: Path, p: str):
    cand = (root / p).resolve()
    if cand != root and root not in cand.parents:
        return "denied"
    return cand.open().read()
'''
    findings = analyze_source("safe.py", safe)
    assert not any(f.rule_id == "MCPSCAN-PATH-TRAVERSAL" for f in findings)


def test_shell_true_detected_generically():
    src = 'import subprocess\ndef f(x):\n    subprocess.run(f"ls {x}", shell=True)\n'
    findings = analyze_source("t.py", src)
    assert any(f.rule_id == "MCPSCAN-SHELL-TRUE" for f in findings)


def test_inline_suppression_silences_finding():
    noisy = 'import subprocess\ndef f(x):\n    subprocess.run(x, shell=True)\n'
    assert any(f.rule_id == "MCPSCAN-SHELL-TRUE" for f in analyze_source("t.py", noisy))
    hushed = ('import subprocess\ndef f(x):\n'
              '    subprocess.run(x, shell=True)  # mcpscan: ignore[MCPSCAN-SHELL-TRUE]\n')
    assert not any(f.rule_id == "MCPSCAN-SHELL-TRUE" for f in analyze_source("t.py", hushed))


def test_bare_suppression_silences_any_rule():
    hushed = 'import subprocess\ndef f(x):\n    subprocess.run(x, shell=True)  # mcpscan: ignore\n'
    assert analyze_source("t.py", hushed) == []
