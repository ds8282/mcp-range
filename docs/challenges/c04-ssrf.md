# c04 — Server-Side Request Forgery (URL-fetching tool)

| | |
|---|---|
| **Difficulty** | Medium |
| **MCP Top 10** | MCP05 — Command Injection & Execution (network destination) |
| **Agentic Top 10** | ASI02 — Tool Misuse & Exploitation |
| **CWE** | CWE-918 — Server-Side Request Forgery |
| **Flag** | `DVMCP{c04_ssrf_9b22}` |

## Learning objective
A tool that fetches a user-supplied URL without validating the destination can
be pointed at internal-only services and cloud-metadata endpoints. In MCP this
is often reached by indirect prompt injection and appears as DNS-rebinding /
redirect bypasses (CVE-2026-77242, CVE-2026-61612).

## Where the bug is
`fetch_url` parses the URL and fetches whatever host it names — no check for
private, loopback, or link-local destinations:

```python
host = urlparse(url).hostname
return _lab_fetch(host)      # VULNERABLE: any host, including internal
```

## Trigger it (in your lab)
```python
await server.call_tool("fetch_url", {"url": "http://internal.canary.range/flag"})
# -> internal admin service body, including DVMCP{c04_ssrf_9b22}
# also reachable: http://169.254.169.254/...  (cloud-metadata stand-in)
```
All targets are offline canaries baked into the lab resolver; the tool never
touches the real internet. docker-compose also ships a loopback canary service
so the same exploit works over HTTP.

## The fix (`--patched` or `DVMCP_PATCHED_IDS=c04`)
Validate the destination before fetching: block private/loopback/link-local IPs
and require a public allowlist. In production, also re-resolve after any
redirect to defeat DNS rebinding and TOCTOU.

```python
if _is_private_host(host):          return "[blocked SSRF: internal/link-local]"
if host not in _PUBLIC_ALLOWLIST:   return "[blocked SSRF: not allowlisted]"
```

## Defensive takeaways
- Allowlist egress; deny RFC1918, loopback, link-local (169.254/16), and ULA.
- Re-validate on redirects; pin the resolved IP across the request.
- Give the fetcher no ambient cloud credentials (metadata theft is the prize).

## References
- OWASP MCP05; CVE-2026-77242 / -61612. See NOTES.md [S12, S13].
