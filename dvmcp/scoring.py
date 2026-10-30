"""CTF-style scoring harness.

Flags are the canary strings each challenge yields when successfully
exploited. ``check_flag`` validates a submitted flag against the registry and
returns the matching challenge metadata. ``scoreboard`` renders the known
challenges and their solved state given a set of captured flags.

Milestone 3 extends this with an active solver that drives each challenge over
a live session to confirm it is exploitable end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import challenges


@dataclass
class CheckResult:
    ok: bool
    challenge_id: str | None
    title: str | None
    message: str


def check_flag(submitted: str) -> CheckResult:
    submitted = (submitted or "").strip()
    for mod in challenges.ALL:
        if submitted == mod.META.flag:
            return CheckResult(True, mod.META.id, mod.META.title,
                               f"Correct — solved {mod.META.name}")
    return CheckResult(False, None, None, "No challenge matches that flag.")


def scoreboard(captured: set[str]) -> list[dict]:
    rows = []
    for mod in challenges.ALL:
        m = mod.META
        rows.append({
            "id": m.id,
            "title": m.title,
            "difficulty": m.difficulty,
            "mcp": m.mcp_category,
            "asi": m.asi_category,
            "cwe": m.cwe,
            "solved": m.flag in captured,
        })
    return rows


def render_scoreboard(captured: set[str]) -> str:
    rows = scoreboard(captured)
    solved = sum(1 for r in rows if r["solved"])
    lines = [f"dvmcp scoreboard — {solved}/{len(rows)} solved", "-" * 60]
    for r in rows:
        mark = "✔" if r["solved"] else "·"
        lines.append(
            f" {mark} {r['id']}  {r['title']:<34} "
            f"{r['difficulty']:<6} {r['mcp']}/{r['asi']} {r['cwe']}"
        )
    return "\n".join(lines)
