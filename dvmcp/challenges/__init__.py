"""Challenge registry.

Modules are listed explicitly (not auto-discovered) so the set of mounted
challenges is deterministic and reviewable. Each module exposes:

* ``META``                       -- :class:`~dvmcp.challenges.base.ChallengeMeta`
* ``register(server, settings)`` -- mounts vulnerable or patched implementation
* ``async exploit(server)``      -- the canonical exploit, returns the flag text
  when it fires (used by the active solver and the scanner validation).
"""

from __future__ import annotations

from . import (
    c01_tool_poisoning,
    c02_rug_pull,
    c03_path_traversal,
    c04_ssrf,
    c05_command_injection,
    c06_missing_auth,
    c07_prompt_injection_chain,
    c08_secrets_exposure,
)

# Ordered list of challenge modules.
ALL = [
    c01_tool_poisoning,
    c02_rug_pull,
    c03_path_traversal,
    c04_ssrf,
    c05_command_injection,
    c06_missing_auth,
    c07_prompt_injection_chain,
    c08_secrets_exposure,
]

BY_ID = {mod.META.id: mod for mod in ALL}


def flags() -> dict[str, str]:
    """Map challenge id -> canary flag, for lab seeding and scoring."""
    return {mod.META.id: mod.META.flag for mod in ALL}
