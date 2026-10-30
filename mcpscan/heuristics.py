"""Text heuristics shared by the live scanner (and reusable elsewhere).

These operate on strings pulled from a running server — tool descriptions and
resource contents — rather than on source code.
"""

from __future__ import annotations

import re

_POISON_PATTERNS = [
    re.compile(r"<\s*important\s*>", re.I),
    re.compile(r"ignore\s+(all\s+)?previous", re.I),
    re.compile(r"do\s+not\s+(tell|mention|inform|reveal)", re.I),
    re.compile(r"session_token|api[_-]?key|password|secret\b", re.I),
    re.compile(r"\.ssh|\.env\b|\.cursor|/etc/passwd", re.I),
    re.compile(r"system\s+instruction", re.I),
    re.compile(r"you\s+must\s+(first\s+)?call", re.I),
    re.compile(r"(call|invoke)\s+(the\s+)?`?\w+`?\s+tool", re.I),
]
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")

_SECRET_KEY = re.compile(
    r"(api[_-]?key|secret|token|password|access[_-]?key|private[_-]?key)", re.I)
# Obvious credential-value shapes (incl. this project's canaries).
_SECRET_VALUE = re.compile(
    r"(dvmcp_canary_|sk_live_|AKIA[0-9A-Z]{4,}|-----BEGIN [A-Z ]*PRIVATE KEY)")


# Imperative, agent-directed text — stronger than a lone secret keyword. Used
# to flag tool OUTPUT that reads as instructions (indirect prompt injection).
_DIRECTIVE = re.compile(
    r"<\s*important\s*>|system\s+instruction|"
    r"do\s+not\s+(tell|mention|inform|reveal)|"
    r"you\s+must\s+(first\s+)?call|(call|invoke)\s+(the\s+)?`?\w+`?\s+tool", re.I)


def reads_as_instructions(text: str | None) -> bool:
    """True if *text* contains imperative, agent-directed instructions."""
    return bool(text and _DIRECTIVE.search(text))


def describe_poisoning(text: str | None) -> str | None:
    """Return a short reason if *text* looks like a poisoned description."""
    if not text:
        return None
    if _INVISIBLE.search(text):
        return "contains invisible/BiDi characters"
    hits = [p.pattern for p in _POISON_PATTERNS if p.search(text)]
    if hits:
        return f"instruction-like markers ({len(hits)} matched)"
    return None


def find_secret_markers(text: str | None) -> list[str]:
    """Return secret-shaped keys/values found in *text* (deduped, capped)."""
    if not text:
        return []
    found = set()
    for m in _SECRET_KEY.finditer(text):
        found.add(m.group(0).lower())
    for m in _SECRET_VALUE.finditer(text):
        found.add(m.group(0)[:12])
    return sorted(found)[:8]
