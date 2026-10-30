# c05 — Command Injection (shell-wrapper tool)

| | |
|---|---|
| **Difficulty** | Medium |
| **MCP Top 10** | MCP05 — Command Injection & Execution |
| **Agentic Top 10** | ASI05 — Unexpected Code Execution (RCE) |
| **CWE** | CWE-78 — OS Command Injection |
| **Flag** | `DVMCP{c05_command_injection_1c6a}` |

## Learning objective
Building a shell command by interpolating untrusted input and running it with
`shell=True` lets an attacker chain commands with `;`, `|`, `&&`, `$(...)`, or
backticks. This is OWASP MCP05's canonical scenario and the class behind
mcp-remote (CVE-2025-6514, CVSS 9.6).

## Where the bug is
```python
cmd = f"echo resolving {host}"       # untrusted host in a shell string
subprocess.run(cmd, shell=True, ...)  # VULNERABLE sink (CWE-78)
```

## Trigger it (in your lab)
```python
await server.call_tool("resolve_host", {"host": "localhost; cat secret/cmdinj.txt"})
# -> "resolving localhost" + the contents of the canary file + the flag
```

## Containment (important)
The genuine `shell=True` sink is present in the source so the static scanner
detects the real pattern. At runtime the challenge defaults to a **contained
simulator** that recognises the injection and reveals the canary file *without
spawning a shell*. The real shell path runs only when `--real-exec`
(`DVMCP_REAL_EXEC=1`) is set, which docker-compose enables inside the isolated,
non-root, read-only container. Either way the only reachable target is a canary
file in the lab directory.

## The fix (`--patched` or `DVMCP_PATCHED_IDS=c05`)
Validate against an allowlist and never use a shell — pass argv:

```python
if not _SAFE_HOST.match(host):   return "[rejected: illegal characters]"
subprocess.run(["echo", "resolving", host], ...)   # argv, no shell
```

## Defensive takeaways
- Never `shell=True` with interpolated input; use argv lists.
- Allowlist/validate arguments; reject shell metacharacters.
- Sandbox tool execution (container, non-root, read-only FS, timeouts).

## References
- OWASP MCP05 Scenario 1; CVE-2025-6514. See NOTES.md [S13].
