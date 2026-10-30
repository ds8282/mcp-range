#!/usr/bin/env python3
"""Validate mcpscan against dvmcp and print a real detection report.

This is the single source of truth for the true-positive numbers quoted in the
README. It runs three independent checks and exits non-zero if any regresses,
so CI fails the build rather than letting the headline rate drift:

1. solver   — every challenge is exploitable vulnerable (8/8) and fixed patched (0/8)
2. static   — the static scanner flags all 8 challenge modules
3. live     — the live scanner detects all 8 categories against a running
              vulnerable server and nothing against the patched one

Nothing here is hard-coded: the counts come from actually running the tools.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dvmcp import challenges                     # noqa: E402
from dvmcp.config import Settings                # noqa: E402
from dvmcp.server import build_server            # noqa: E402
from dvmcp.solver import solve_all               # noqa: E402
from mcpscan.live.engine import scan_live        # noqa: E402
from mcpscan.static.engine import scan_path      # noqa: E402

CHALLENGES_DIR = Path(__file__).resolve().parent.parent / "dvmcp" / "challenges"


def _lab() -> Path:
    return Path(tempfile.mkdtemp()) / "lab"


def run_solver() -> tuple[int, int]:
    vuln = asyncio.run(solve_all(Settings(lab_root=_lab())))
    patched = asyncio.run(solve_all(Settings(patched_all=True, lab_root=_lab())))
    return sum(o.solved for o in vuln), sum(o.solved for o in patched)


def run_static() -> set[str]:
    findings = scan_path(CHALLENGES_DIR)
    # map a flagged file back to its challenge id (c01..c08)
    return {Path(f.file).name.split("_")[0] for f in findings}


def run_live() -> tuple[int, int]:
    vuln = asyncio.run(scan_live(target=build_server(Settings(lab_root=_lab()))))
    patched = asyncio.run(scan_live(target=build_server(
        Settings(patched_all=True, lab_root=_lab()))))
    return len({f.rule_id for f in vuln}), len(patched)


def main() -> int:
    total = len(challenges.ALL)
    print("=" * 64)
    print(" mcpscan vs dvmcp — validation report")
    print("=" * 64)

    solved_v, solved_p = run_solver()
    static_ids = run_static()
    live_v_cats, live_p = run_live()

    static_hits = len(static_ids & set(challenges.BY_ID))

    rows = [
        ("solver: challenges exploitable (vulnerable)", solved_v, total),
        ("solver: challenges exploitable (patched)", solved_p, 0),
        ("static: challenge modules flagged", static_hits, total),
        ("live:   vuln categories detected", live_v_cats, total),
        ("live:   findings against patched server", live_p, 0),
    ]
    for label, got, want in rows:
        ok = "OK " if got == want else "!! "
        print(f" [{ok}] {label:<48} {got}/{want if want else got}")

    tp_static = 100.0 * static_hits / total
    tp_live = 100.0 * live_v_cats / total
    print("-" * 64)
    print(f" static true-positive rate: {static_hits}/{total} = {tp_static:.0f}%")
    print(f" live   true-positive rate: {live_v_cats}/{total} = {tp_live:.0f}%")
    print(f" patched false-positive rate (static+live): {solved_p + live_p} findings")
    print("=" * 64)

    ok = (solved_v == total and solved_p == 0 and static_hits == total
          and live_v_cats == total and live_p == 0)
    print(" RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
