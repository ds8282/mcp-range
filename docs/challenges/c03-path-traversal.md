# c03 — Path Traversal (file-reading tool)

| | |
|---|---|
| **Difficulty** | Easy |
| **MCP Top 10** | MCP05 — Command Injection & Execution (file-path operations) |
| **Agentic Top 10** | ASI02 — Tool Misuse & Exploitation |
| **CWE** | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory |
| **Flag** | `DVMCP{c03_path_traversal_2d9c}` |

## Learning objective
A file-reading tool that joins user input onto a base directory without
canonicalising and checking containment can be walked out of its sandbox with
`../`. This is the exact root cause of CVE-2026-61647 (NotebookLM MCP) and the
Anthropic Git MCP path-validation bypasses (CVE-2025-68143/68145).

## Where the bug is
`read_public_file` is meant to serve only `labdata/public/`:

```python
target = public_root / path          # VULNERABLE: no resolve(), no containment
return target.open("r").read()
```

`public_root / "../secret/flag.txt"` resolves straight out of the public
directory. There is no canonicalisation and no ancestor check.

## Trigger it (in your lab)
```python
await server.call_tool("read_public_file", {"path": "../secret/flag.txt"})
# -> contents of labdata/secret/flag.txt, including DVMCP{c03_path_traversal_2d9c}
```

`labdata/secret/` sits outside the intended `public/` root; reaching it proves
the traversal. All files there are canaries — no real host data is involved.

## The fix (`--patched` or `DVMCP_PATCHED_IDS=c03`)
Canonicalize first, then verify the resolved path stays under the root. This is
a *correctness* check, not a substring blocklist (blocklists miss encodings,
symlinks, and absolute paths):

```python
candidate = (public_root / path).resolve()
if candidate != public_root and public_root not in candidate.parents:
    return "[access denied: path escapes the public directory]"
```

The shared helper `dvmcp.safety.resolve_within` implements the same pattern.

## Defensive takeaways
- Never trust a path join. Resolve, then assert `is_relative_to(root)` (or the
  `commonpath`/`parents` equivalent).
- Reject absolute paths and drive-letter prefixes explicitly.
- Run the tool as an unprivileged user confined to the data directory (defence
  in depth — the patched NotebookLM CVE fix is inert unless its vault-root env
  var is also set, a good lesson in configure-the-patch).

## References
- CVE-2026-61647 (NotebookLM MCP). See NOTES.md [S15].
- OWASP MCP05. See NOTES.md [S13].
