"""Tests for the loopback guard, lab seeding, and scoring harness."""

from __future__ import annotations

import pytest

from dvmcp import challenges
from dvmcp.safety import (
    UnsafeConfiguration,
    assert_loopback,
    resolve_within,
    seed_lab,
)
from dvmcp.scoring import check_flag, scoreboard


def test_loopback_guard_refuses_nonloopback():
    with pytest.raises(UnsafeConfiguration):
        assert_loopback("0.0.0.0", allow_nonloopback=False)


def test_loopback_guard_allows_override_and_loopback():
    assert_loopback("0.0.0.0", allow_nonloopback=True)  # explicit override
    assert_loopback("127.0.0.1", allow_nonloopback=False)
    assert_loopback("::1", allow_nonloopback=False)


def test_resolve_within_blocks_escape(tmp_path):
    (tmp_path / "ok.txt").write_text("hi")
    assert resolve_within(tmp_path, "ok.txt").name == "ok.txt"
    with pytest.raises(UnsafeConfiguration):
        resolve_within(tmp_path, "../etc/passwd")


def test_seed_lab_creates_canary_tree(tmp_path):
    root = seed_lab(tmp_path / "labdata", flags=challenges.flags())
    assert (root / "public" / "README.txt").exists()
    assert (root / "secret" / "flag.txt").exists()
    assert (root / "config" / "agent.cfg").exists()
    # secrets are fake canaries
    assert "dvmcp_canary_" in (root / "config" / "agent.cfg").read_text()


def test_scoring_recognises_real_flags():
    for mod in challenges.ALL:
        res = check_flag(mod.META.flag)
        assert res.ok and res.challenge_id == mod.META.id


def test_scoring_rejects_bad_flag():
    assert not check_flag("DVMCP{not-a-flag}").ok


def test_scoreboard_marks_captured():
    one = challenges.ALL[0].META.flag
    rows = {r["id"]: r for r in scoreboard({one})}
    assert rows[challenges.ALL[0].META.id]["solved"] is True
    assert rows[challenges.ALL[1].META.id]["solved"] is False
