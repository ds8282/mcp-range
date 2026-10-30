"""Live scanner: connect to a running MCP server and probe it.

Checks performed against the live server:

* **Passive** — enumerate tools and flag poisoned descriptions; read resources
  and flag secret-shaped content.
* **Active (safe canaries)** — drive candidate tools with benign payloads:
  path-traversal reads, SSRF to internal/metadata canaries, a harmless ``echo``
  command-injection marker, an unauthenticated call to sensitive tools, and a
  before/after description diff to catch rug pulls. No payload is destructive;
  nothing writes, deletes, or exfiltrates real data.

The target may be a Streamable-HTTP URL, a ``StdioServerParameters`` to launch,
or (in tests) an in-process ``MCPServer`` instance — the high-level
:class:`mcp.Client` accepts all three.
"""

from __future__ import annotations

import uuid

from mcp import Client

from ..findings import Finding, dedupe, sort_findings
from ..heuristics import describe_poisoning, find_secret_markers, reads_as_instructions

# keyword sets for classifying tools by name/parameter
_FILE_HINTS = ("path", "file", "filename", "dir", "read", "document", "cat")
# A URL-fetch tool is identified by an explicit URL-shaped PARAMETER, not just a
# name, so host-style command tools aren't mistaken for URL fetchers.
_URL_PARAM_NAMES = ("url", "uri", "endpoint", "target", "address")
_CMD_HINTS = ("cmd", "command", "exec", "run", "shell", "ping", "resolve", "host")
_SENSITIVE = ("admin", "export", "delete", "drop", "destroy", "write", "deploy",
              "grant", "secret", "credential", "dump")
# Tool names we never call with dummy args during output inspection (side effects).
_DESTRUCTIVE = ("delete", "drop", "destroy", "remove", "write", "deploy", "send",
                "kill", "truncate", "purge", "reset", "revoke")

_DENY_MARKERS = ("denied", "unauthor", "401", "403", "blocked", "forbidden",
                 "not allowed", "rejected", "escape")


def _loc(tool_name: str) -> str:
    return f"mcp://tool/{tool_name}"


def _text(result) -> str:
    return " ".join(getattr(b, "text", "") for b in (getattr(result, "content", None) or []))


def _schema(tool) -> dict:
    # mcp 2.x exposes input_schema (snake_case); older builds used inputSchema.
    schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {}
    return schema if isinstance(schema, dict) else {}


def _props(tool) -> dict:
    return _schema(tool).get("properties", {})


def _required(tool) -> list[str]:
    return _schema(tool).get("required", [])


def _string_params(tool) -> list[str]:
    return [k for k, v in _props(tool).items()
            if not isinstance(v, dict) or v.get("type", "string") == "string"]


def _looks_like(name: str, params: list[str], hints: tuple[str, ...]) -> bool:
    hay = (name + " " + " ".join(params)).lower()
    return any(h in hay for h in hints)


def _denied(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _DENY_MARKERS)


async def scan_live(url: str | None = None, stdio_cmd: str | None = None,
                    target=None) -> list[Finding]:
    """Scan a running server. Pass exactly one of url / stdio_cmd / target."""
    if target is None:
        if url:
            target = url
        elif stdio_cmd:
            from mcp.client.stdio import StdioServerParameters
            parts = stdio_cmd.split()
            target = StdioServerParameters(command=parts[0], args=parts[1:])
        else:
            raise ValueError("scan_live needs url, stdio_cmd, or target")

    findings: list[Finding] = []
    async with Client(target) as client:
        tools = list((await client.list_tools()).tools)

        # passive: descriptions
        for t in tools:
            reason = describe_poisoning(t.description)
            if reason:
                findings.append(Finding(
                    "MCPSCAN-TOOL-POISONING",
                    f"tool '{t.name}' description shows poisoning signals: {reason}.",
                    _loc(t.name), 0, "live", evidence={"reason": reason}))

        # passive: resources
        try:
            resources = list((await client.list_resources()).resources)
        except Exception:
            resources = []
        for r in resources:
            uri = str(getattr(r, "uri", r))
            try:
                body = _read_resource_text(await client.read_resource(uri))
            except Exception:
                continue
            markers = find_secret_markers(body)
            if markers:
                findings.append(Finding(
                    "MCPSCAN-SECRET-RESOURCE",
                    f"resource {uri} returns secret-shaped content: {markers}.",
                    uri, 0, "live", evidence={"markers": markers}))

        # active probes
        findings += await _probe_path_traversal(client, tools)
        findings += await _probe_ssrf(client, tools)
        findings += await _probe_command_injection(client, tools)
        findings += await _probe_missing_auth(client, tools)
        findings += await _probe_tool_output(client, tools)
        findings += await _probe_rug_pull(client, tools)

    return sort_findings(dedupe(findings))


def _read_resource_text(result) -> str:
    # Client.read_resource() returns a ReadResourceResult with .contents;
    # a raw server read returns an iterable directly. Handle both.
    items = getattr(result, "contents", None)
    if items is None:
        items = result if isinstance(result, (list, tuple)) else []
    parts = []
    for item in items:
        for attr in ("text", "content", "blob", "data"):
            val = getattr(item, attr, None)
            if isinstance(val, str):
                parts.append(val)
                break
    return " ".join(parts)


async def _call(client, name, args):
    try:
        return _text(await client.call_tool(name, args))
    except Exception as exc:
        return f"__error__: {exc}"


async def _probe_path_traversal(client, tools) -> list[Finding]:
    out = []
    payloads = ["../secret/flag.txt", "../../config/agent.cfg",
                "../../../../../../etc/hostname"]
    for t in tools:
        params = _string_params(t)
        if not _looks_like(t.name, params, _FILE_HINTS):
            continue
        path_param = next((p for p in params
                           if any(h in p.lower() for h in ("path", "file", "dir"))), None)
        if not path_param:
            continue
        for payload in payloads:
            resp = await _call(client, t.name, {path_param: payload})
            if resp.startswith("__error__") or _denied(resp) or "not found" in resp.lower():
                continue
            if resp.strip() and ("DVMCP{" in resp or "OUTSIDE" in resp
                                 or "canary" in resp.lower()):
                out.append(Finding(
                    "MCPSCAN-PATH-TRAVERSAL",
                    f"tool '{t.name}' returned out-of-scope content for traversal "
                    f"payload {payload!r}.", _loc(t.name), 0, "live",
                    evidence={"payload": payload, "snippet": resp[:120]}))
                break
    return out


async def _probe_ssrf(client, tools) -> list[Finding]:
    out = []
    payloads = ["http://internal.canary.range/flag",
                "http://169.254.169.254/latest/meta-data/"]
    # specific signatures that a fetch actually reached an internal/metadata target
    markers = ("INTERNAL", "AccessKeyId", "SecretAccessKey", "meta-data",
               "metadata", "169.254", "DVMCP{c04")
    for t in tools:
        params = _string_params(t)
        url_param = next((p for p in params
                          if any(h in p.lower() for h in _URL_PARAM_NAMES)), None)
        if not url_param:
            continue
        for payload in payloads:
            resp = await _call(client, t.name, {url_param: payload})
            if resp.startswith("__error__") or _denied(resp):
                continue
            if any(m in resp for m in markers):
                out.append(Finding(
                    "MCPSCAN-SSRF",
                    f"tool '{t.name}' fetched internal/metadata target {payload!r}.",
                    _loc(t.name), 0, "live",
                    evidence={"payload": payload, "snippet": resp[:120]}))
                break
    return out


async def _probe_command_injection(client, tools) -> list[Finding]:
    out = []
    nonce = f"mcpscan_canary_{uuid.uuid4().hex[:8]}"
    for t in tools:
        params = _string_params(t)
        if not _looks_like(t.name, params, _CMD_HINTS):
            continue
        param = params[0] if params else None
        if not param:
            continue
        # benign echo marker + metacharacters; never a destructive command
        for payload in (f"localhost; echo {nonce}", f"localhost && echo {nonce}",
                        "localhost; cat secret/cmdinj.txt"):
            resp = await _call(client, t.name, {param: payload})
            if resp.startswith("__error__") or _denied(resp):
                continue
            if nonce in resp or "DVMCP{" in resp or "injected" in resp.lower():
                out.append(Finding(
                    "MCPSCAN-SHELL-TRUE",
                    f"tool '{t.name}' executed a chained command from input "
                    f"(payload {payload!r}).", _loc(t.name), 0, "live",
                    evidence={"payload": payload, "snippet": resp[:120]}))
                break
    return out


async def _probe_missing_auth(client, tools) -> list[Finding]:
    out = []
    for t in tools:
        if not any(s in t.name.lower() for s in _SENSITIVE):
            continue
        if _required(t):
            continue  # needs args; skip to avoid guessing credentials
        resp = await _call(client, t.name, {})
        if resp.startswith("__error__") or _denied(resp):
            continue
        if resp.strip():
            out.append(Finding(
                "MCPSCAN-MISSING-AUTH",
                f"sensitive tool '{t.name}' returned data with no authorization.",
                _loc(t.name), 0, "live", evidence={"snippet": resp[:120]}))
    return out


async def _probe_tool_output(client, tools) -> list[Finding]:
    """Call read-only tools with benign dummy args; flag output that reads as
    agent instructions (indirect prompt injection via tool output)."""
    out = []
    for t in tools:
        if any(d in t.name.lower() for d in _DESTRUCTIVE):
            continue
        # fill required string params with a harmless dummy
        args = {k: "test" for k in _required(t) if k in _string_params(t)}
        if len(args) != len(_required(t)):
            continue  # a non-string required param we won't guess
        resp = await _call(client, t.name, args)
        if resp.startswith("__error__"):
            continue
        if reads_as_instructions(resp):
            out.append(Finding(
                "MCPSCAN-INJECTION-TEXT",
                f"tool '{t.name}' returns content that reads as agent instructions "
                "(indirect prompt-injection vector).", _loc(t.name), 0, "live",
                evidence={"snippet": resp[:120]}))
    return out


async def _probe_rug_pull(client, tools) -> list[Finding]:
    """Call no-arg tools a couple of times, then diff descriptions."""
    before = {t.name: (t.description or "") for t in tools}
    for t in tools:
        if _required(t):
            continue
        await _call(client, t.name, {})
        await _call(client, t.name, {})
    after = {t.name: (t.description or "") for t in (await client.list_tools()).tools}
    out = []
    for name, desc in before.items():
        if name in after and after[name] != desc:
            out.append(Finding(
                "MCPSCAN-RUG-PULL",
                f"tool '{name}' changed its definition after being called "
                "(rug-pull / dynamic mutation).", _loc(name), 0, "live",
                evidence={"before": desc[:80], "after": after[name][:80]}))
    return out
