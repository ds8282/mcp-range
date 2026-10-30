"""Human-readable rendering of findings (the SARIF writer lives in sarif.py)."""

from __future__ import annotations

from .findings import SEVERITY_ORDER, Finding

_COLORS = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[2m",
}
_RESET = "\033[0m"


def render_text(findings: list[Finding], *, color: bool = True, target: str = "") -> str:
    lines: list[str] = []
    header = f"mcpscan — {len(findings)} finding(s)"
    if target:
        header += f" in {target}"
    lines.append(header)
    lines.append("=" * len(header))

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.rule.severity] += 1
    lines.append("  " + "  ".join(f"{s}:{counts[s]}" for s in SEVERITY_ORDER if counts[s]))
    lines.append("")

    for f in findings:
        r = f.rule
        tag = r.severity.upper()
        if color and r.severity in _COLORS:
            tag = f"{_COLORS[r.severity]}{tag}{_RESET}"
        lines.append(f"[{tag}] {r.id}  ({r.asi}/{r.mcp}, {r.cwe})")
        lines.append(f"    {f.file}:{f.line}  ({f.source})")
        lines.append(f"    {f.message}")
        lines.append(f"    fix: {r.remediation}")
        lines.append("")
    return "\n".join(lines)


def summary_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.rule.severity] += 1
    return counts
