# c08 — Secrets Exposure (over-permissive resource)

| | |
|---|---|
| **Difficulty** | Medium |
| **MCP Top 10** | MCP01 — Token Mismanagement & Secret Exposure |
| **Agentic Top 10** | ASI03 — Identity & Privilege Abuse |
| **CWE** | CWE-538 — Insertion of Sensitive Information into Externally-Accessible File/Dir |
| **Flag** | `DVMCP{c08_secrets_exposure_a0d5}` |

## Learning objective
MCP *resources* are addressable data the model can read. A resource that
over-shares — returning secret material inline where only public status was
intended — drops credentials straight into the agent's context. Corroborating
pattern: netlicensing-mcp, where a REST path bypassed token redaction.

## Where the bug is
The resource `dvmcp://service/status` is meant to expose public status, but the
vulnerable handler inlines secrets:

```python
return json.dumps({**_PUBLIC, **_SECRETS})   # VULNERABLE: api_key, session_token, flag
```

## Trigger it (in your lab)
```python
result = await server.read_resource("dvmcp://service/status")
# body includes api_key, session_token canaries and DVMCP{c08_secrets_exposure_a0d5}
```

## The fix (`--patched` or `DVMCP_PATCHED_IDS=c08`)
Return only the public fields; secrets never enter the response:

```python
return json.dumps(_PUBLIC)   # service/status/uptime only
```

## Defensive takeaways
- Resources are an exfiltration surface; apply least privilege and explicit
  field allowlists, not blocklists.
- Keep secrets out of any model-readable surface entirely; if a value must be
  referenced, hand back an opaque handle, never the secret.
- Scan resource payloads for secret-shaped material before returning them
  (this is one of `mcpscan`'s live checks).

## References
- OWASP MCP01; netlicensing-mcp redaction bypass. See NOTES.md [S6, S7].
