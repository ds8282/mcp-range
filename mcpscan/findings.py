"""Finding model and the rule catalogue shared by every scanner backend.

A :class:`Finding` is one reported issue. Each finding references a rule in
:data:`RULES`, which carries the fixed metadata for that rule: severity, the
OWASP Agentic (ASI) and MCP Top 10 mappings, the CWE, and a remediation note.
Keeping the mapping in one table means the static checks, the live checks, and
the SARIF writer all agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Severity ordering, most to least severe. Used for sorting and SARIF levels.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# SARIF only has error/warning/note/none; map our severities onto them.
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    asi: str          # OWASP Agentic Top 10 id
    mcp: str          # OWASP MCP Top 10 id
    cwe: str
    remediation: str


RULES: dict[str, Rule] = {
    "MCPSCAN-SHELL-TRUE": Rule(
        "MCPSCAN-SHELL-TRUE", "subprocess with shell=True", "critical",
        "ASI05", "MCP05", "CWE-78",
        "Never pass shell=True with interpolated input. Use an argv list "
        "(subprocess.run(['cmd', arg])) and validate arguments against an allowlist.",
    ),
    "MCPSCAN-OS-SYSTEM": Rule(
        "MCPSCAN-OS-SYSTEM", "os.system call", "critical",
        "ASI05", "MCP05", "CWE-78",
        "Replace os.system with subprocess.run([...]) using an argv list; never "
        "build the command by string concatenation.",
    ),
    "MCPSCAN-EVAL-EXEC": Rule(
        "MCPSCAN-EVAL-EXEC", "eval/exec on dynamic input", "high",
        "ASI05", "MCP05", "CWE-95",
        "Do not eval/exec untrusted input. Parse with a safe, explicit parser "
        "or dispatch on an allowlist of permitted operations.",
    ),
    "MCPSCAN-PATH-TRAVERSAL": Rule(
        "MCPSCAN-PATH-TRAVERSAL", "file access on user-controlled path", "high",
        "ASI02", "MCP05", "CWE-22",
        "Canonicalize then verify containment: candidate = (root / p).resolve(); "
        "reject unless candidate is root or a descendant (is_relative_to).",
    ),
    "MCPSCAN-SSRF": Rule(
        "MCPSCAN-SSRF", "outbound request to user-controlled URL", "high",
        "ASI02", "MCP05", "CWE-918",
        "Validate the destination before fetching: block private/loopback/"
        "link-local addresses, require a public allowlist, and re-check after redirects.",
    ),
    "MCPSCAN-MISSING-AUTH": Rule(
        "MCPSCAN-MISSING-AUTH", "sensitive tool without authorization", "medium",
        "ASI03", "MCP07", "CWE-306",
        "Gate sensitive tools behind an authorization check (token verified in "
        "constant time, or transport-level auth). Default-deny.",
    ),
    "MCPSCAN-TOOL-POISONING": Rule(
        "MCPSCAN-TOOL-POISONING", "suspicious instructions in tool/resource description",
        "high", "ASI01", "MCP03", "CWE-1384",
        "Tool descriptions are read by the model as instructions. Remove hidden "
        "directives; pin and review tool definitions; alert on instruction-like text.",
    ),
    "MCPSCAN-INJECTION-TEXT": Rule(
        "MCPSCAN-INJECTION-TEXT", "embedded agent-instruction text in a string", "medium",
        "ASI01", "MCP06", "CWE-77",
        "Treat tool output / fetched content as untrusted data, fenced and never "
        "re-interpreted as instructions. Gate sensitive follow-on tools.",
    ),
    "MCPSCAN-RUG-PULL": Rule(
        "MCPSCAN-RUG-PULL", "tool definition mutated at runtime", "high",
        "ASI04", "MCP03", "CWE-494",
        "Do not re-register tools at runtime without re-approval. Pin tool "
        "definition hashes and re-verify on list_changed.",
    ),
    "MCPSCAN-SECRET-RESOURCE": Rule(
        "MCPSCAN-SECRET-RESOURCE", "resource exposes secret-shaped fields", "high",
        "ASI03", "MCP01", "CWE-538",
        "Never return secrets from a model-readable resource. Allowlist public "
        "fields explicitly; hand back opaque handles, not secret values.",
    ),
}


@dataclass
class Finding:
    rule_id: str
    message: str
    file: str
    line: int
    source: str = "static"              # "static" | "live"
    snippet: str | None = None
    evidence: dict = field(default_factory=dict)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    def key(self) -> tuple:
        return (self.rule_id, self.file, self.line, self.message)

    def as_dict(self) -> dict:
        r = self.rule
        return {
            "rule_id": r.id, "rule": r.name, "severity": r.severity,
            "asi": r.asi, "mcp": r.mcp, "cwe": r.cwe,
            "message": self.message, "file": self.file, "line": self.line,
            "source": self.source, "remediation": r.remediation,
            "snippet": self.snippet, "evidence": self.evidence,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (
        SEVERITY_ORDER.index(f.rule.severity), f.file, f.line, f.rule_id))


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.key() not in seen:
            seen.add(f.key())
            out.append(f)
    return out
