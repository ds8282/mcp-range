# c06 — Missing Authentication on a sensitive tool

| | |
|---|---|
| **Difficulty** | Easy |
| **MCP Top 10** | MCP07 — Insufficient Authentication & Authorization |
| **Agentic Top 10** | ASI03 — Identity & Privilege Abuse |
| **CWE** | CWE-306 — Missing Authentication for Critical Function |
| **Flag** | `DVMCP{c06_missing_auth_f41b}` |

## Learning objective
A sensitive, data-exporting or state-changing tool must enforce authorization
at its own boundary. A large share of 2026 MCP CVEs are simply a privileged
capability exposed with no auth at all — e.g. MySQL MCP (CVE-2026-59971,
unauthenticated SQL execution over insecure SSE) and Azure MCP
(CVE-2026-32211, no-auth).

## Where the bug is
`admin_export` performs a "privileged" export and checks nothing:

```python
def admin_export() -> str:        # VULNERABLE: no authorization gate
    return f"{_EXPORT_BODY}flag: {META.flag}\n"
```

Anyone who can reach the tool gets the export.

## Trigger it (in your lab)
```python
await server.call_tool("admin_export", {})
# -> admin export dump + DVMCP{c06_missing_auth_f41b}
```

## The fix (`--patched` or `DVMCP_PATCHED_IDS=c06`)
Require a bearer token and compare it in constant time; refuse without it:

```python
if not token or not hmac.compare_digest(token, expected):
    return "[401 unauthorized: a valid admin token is required]"
```

## A note on transport
Over **stdio** there are no HTTP headers, so authorization is modelled here as a
required `token` argument. Over **streamable-http** the identical lesson applies
at the transport layer — a sensitive endpoint must sit behind authenticated
transport, and MCP's `TransportSecuritySettings` (allowed hosts/origins) should
be set to block DNS-rebinding. The vulnerability is the *absence of an
authorization gate*, which is transport-independent; the token-argument model
keeps the challenge runnable under both transports.

## Defensive takeaways
- Default-deny on sensitive tools; make the auth check impossible to forget
  (decorator / middleware), not a per-tool afterthought.
- Constant-time comparison for secrets.
- Log every privileged call with caller identity (ASI03 audit guidance).

## References
- OWASP MCP07; CVE-2026-59971, CVE-2026-32211. See NOTES.md [S6, S8].
