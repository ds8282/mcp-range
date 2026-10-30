"""Active solver harness.

Runs each challenge's canonical ``exploit`` against a freshly built server and
reports which flags were captured. This is the CTF "confirm solved" mechanism,
and it is also the ground-truth oracle the scanner validation reuses: against a
*vulnerable* build every exploit should fire; against a *patched* build none
should.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import challenges
from .config import Settings
from .server import build_server


@dataclass
class SolveOutcome:
    id: str
    title: str
    solved: bool
    captured_flag: str | None


async def solve_all(settings: Settings) -> list[SolveOutcome]:
    """Build a server with *settings* and attempt every exploit against it."""
    server = build_server(settings)
    outcomes: list[SolveOutcome] = []
    for mod in challenges.ALL:
        if not settings.is_enabled(mod.META.id):
            continue
        flag_text = None
        try:
            flag_text = await mod.exploit(server)
        except Exception as exc:  # a patched build may legitimately raise
            flag_text = None
            _ = exc
        solved = bool(flag_text and mod.META.flag in flag_text)
        outcomes.append(SolveOutcome(mod.META.id, mod.META.title, solved,
                                     mod.META.flag if solved else None))
    return outcomes


def render_outcomes(outcomes: list[SolveOutcome]) -> str:
    solved = sum(1 for o in outcomes if o.solved)
    lines = [f"dvmcp solver — {solved}/{len(outcomes)} challenges solved", "-" * 56]
    for o in outcomes:
        mark = "✔ solved " if o.solved else "· not solved"
        lines.append(f" {mark}  {o.id}  {o.title}")
    return "\n".join(lines)
