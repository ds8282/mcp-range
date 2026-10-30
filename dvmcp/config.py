"""Runtime configuration for the dvmcp training server.

Settings come from CLI flags (see ``dvmcp.__main__``) and environment
variables.  The important security-relevant settings are:

* ``transport``          -- ``stdio`` (default) or ``streamable-http``.
* ``host`` / ``port``    -- HTTP bind address; guarded to loopback (see
  :mod:`dvmcp.safety`) unless ``allow_nonloopback`` is explicitly set.
* ``patched_all`` / ``patched_ids`` -- the feature flag that swaps each
  challenge between its *vulnerable* and *patched* implementation so a
  learner can diff the two.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Loopback addresses the HTTP transport is allowed to bind to without an
# explicit override.  Binding dvmcp to anything else exposes intentionally
# vulnerable code to the network and is refused by :func:`dvmcp.safety`.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", ""})

DEFAULT_PORT = 8731
# A dot-dir so the generated lab (public/ secret/ config/ subdirs) never
# collides with real project folders and is trivially git-ignored.
DEFAULT_LAB_ROOT = Path(os.environ.get("DVMCP_LAB_ROOT", ".dvmcp-lab")).resolve()

# A deliberately fake "secret" used by the auth challenge in *patched* mode.
# It authorises nothing real; it only gates a canary flag inside the lab.
DEFAULT_AUTH_TOKEN = os.environ.get("DVMCP_AUTH_TOKEN", "dvmcp-lab-token-please-change")


def _parse_ids(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {part.strip().lower() for part in raw.replace(",", " ").split() if part.strip()}


@dataclass
class Settings:
    """Immutable-ish settings bag assembled once at startup."""

    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    allow_nonloopback: bool = False

    # Feature flag: vulnerable (default) vs patched.
    patched_all: bool = False
    patched_ids: set[str] = field(default_factory=set)

    # Which challenges to mount. Empty set => all registered challenges.
    enabled_ids: set[str] = field(default_factory=set)

    lab_root: Path = field(default_factory=lambda: DEFAULT_LAB_ROOT)
    auth_token: str = DEFAULT_AUTH_TOKEN

    # c05: when False (default) the command-injection challenge uses a fully
    # contained simulator that never spawns a shell. When True (set only
    # inside the isolated container, via DVMCP_REAL_EXEC=1) the genuine
    # shell=True sink runs, confined to the lab dir as a non-root user.
    real_exec: bool = False

    def is_patched(self, challenge_id: str) -> bool:
        """True if *challenge_id* should mount its patched implementation."""
        return self.patched_all or challenge_id.lower() in self.patched_ids

    def is_enabled(self, challenge_id: str) -> bool:
        return not self.enabled_ids or challenge_id.lower() in self.enabled_ids

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from environment variables (used by Docker)."""
        return cls(
            transport=os.environ.get("DVMCP_TRANSPORT", "stdio"),
            host=os.environ.get("DVMCP_HOST", "127.0.0.1"),
            port=int(os.environ.get("DVMCP_PORT", DEFAULT_PORT)),
            allow_nonloopback=os.environ.get("DVMCP_ALLOW_NONLOOPBACK", "") == "1",
            patched_all=os.environ.get("DVMCP_PATCHED", "") == "1",
            patched_ids=_parse_ids(os.environ.get("DVMCP_PATCHED_IDS")),
            enabled_ids=_parse_ids(os.environ.get("DVMCP_ENABLED_IDS")),
            real_exec=os.environ.get("DVMCP_REAL_EXEC", "") == "1",
        )
