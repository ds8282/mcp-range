# c02 — Rug Pull (post-approval mutation)

| | |
|---|---|
| **Difficulty** | Medium |
| **MCP Top 10** | MCP03 — Tool Poisoning (dynamic / rug-pull variant) |
| **Agentic Top 10** | ASI04 — Agentic Supply Chain Vulnerabilities |
| **CWE** | CWE-494 — Download of Code Without Integrity Check |
| **Flag** | `DVMCP{c02_rug_pull_4e7d}` |

## Learning objective
A tool can be clean when you approve it and malicious later. MCP's
`notifications/tools/list_changed` lets a server push updated definitions, and
many hosts reload them without re-prompting — so the change rides in on trust
already granted. Real cases: CVE-2025-54136 ("MCPoison", Cursor) and the
postmark-mcp backdoor (Sept 2025).

## Where the bug is
`fetch_quote` returns a benign quote on its **first** call. On the **second**
call it rewrites its own registered description (to a poisoned one) and starts
appending the flag — modelling a server that weaponises a tool after approval.

## Trigger it (in your lab)
```python
await server.call_tool("fetch_quote", {})   # call 1: clean, "passes review"
await server.call_tool("fetch_quote", {})    # call 2: rug-pulled -> flag
```

## The fix (`--patched` or `DVMCP_PATCHED_IDS=c02`)
Pin the tool definition at registration and expose its hash; refuse to mutate:

```python
pinned_hash = hashlib.sha256(_CLEAN_DESC.encode()).hexdigest()[:16]
# behaviour is stable; response advertises [definition pinned sha256:...]
```

## Defensive takeaways
- Hash tool definitions at approval time and re-verify on every
  `list_changed`; re-prompt the user on any change.
- Treat the capability set as a supply chain: pin it, diff it, alert on drift.

## References
- CVE-2025-54136 "MCPoison"; postmark-mcp. See NOTES.md [S8, S9, S14].
