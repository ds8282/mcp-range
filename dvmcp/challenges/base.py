"""Challenge metadata model and shared helpers.

Each challenge module defines a module-level :data:`META` describing the
vulnerability (ids, difficulty, taxonomy mapping, learning objective, and the
canary flag it yields when solved) and a ``register(server, settings)``
function that mounts either the vulnerable or the patched implementation
depending on the feature flag in ``settings``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChallengeMeta:
    id: str            # short id, e.g. "c01"
    slug: str          # kebab slug, e.g. "tool-poisoning"
    title: str         # human title
    objective: str     # one-line learning objective
    difficulty: str    # "Easy" | "Medium" | "Hard"
    mcp_category: str  # OWASP MCP Top 10 id, e.g. "MCP03"
    asi_category: str  # OWASP Agentic Top 10 id, e.g. "ASI01"
    cwe: str           # e.g. "CWE-22"
    flag: str          # canary flag yielded on successful exploit

    @property
    def name(self) -> str:
        return f"{self.id}-{self.slug}"


def mode_tag(patched: bool) -> str:
    return "patched" if patched else "vulnerable"
