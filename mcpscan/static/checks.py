"""AST-based static checks for a single Python module.

The analyzer makes one pass to collect module context (constant dicts and
strings, and MCP tool/resource registrations) and then inspects every function
definition — including nested ones, which matters because dvmcp defines its
vulnerable and patched variants as sibling nested functions.

Design choices that keep false positives low:

* Sinks that are dangerous regardless of input (``shell=True``, ``os.system``)
  are reported wherever they appear.
* Input-shape checks (path traversal, SSRF) require the value to be *tainted*
  by a function parameter AND the absence of a recognised guard in the same
  function. The guard check uses ``ast.unparse`` of the function body, so a fix
  in the same scope suppresses the finding.
"""

from __future__ import annotations

import ast
import re

from ..findings import Finding

# --- suspicious-text patterns for poisoning / injection -------------------

_POISON_PATTERNS = [
    re.compile(r"<\s*important\s*>", re.I),
    re.compile(r"ignore\s+(all\s+)?previous", re.I),
    re.compile(r"do\s+not\s+(tell|mention|inform|reveal)", re.I),
    re.compile(r"session_token|api[_-]?key|password|secret\b", re.I),
    re.compile(r"\.ssh|\.env\b|\.cursor|/etc/passwd", re.I),
    re.compile(r"system\s+instruction", re.I),
    re.compile(r"you\s+must\s+(first\s+)?call", re.I),
    re.compile(r"append\s+.*\bto\s+(every|all|each)", re.I),
]
# Zero-width / BiDi characters often used to hide poisoning from humans.
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")

_SECRET_KEY = re.compile(r"(api[_-]?key|secret|token|password|access[_-]?key|private[_-]?key)", re.I)
_SENSITIVE_TOOL = re.compile(
    r"(admin|export|delete|drop|destroy|write|deploy|grant|shell|exec|secret|credential)", re.I)

_GUARD_TOKENS_PATH = ("resolve(", "is_relative_to", "commonpath", "commonprefix",
                      "realpath", "abspath", "startswith", "access denied", "escapes")
_GUARD_TOKENS_SSRF = ("is_private", "is_loopback", "is_link_local", "ip_address",
                      "allowlist", "allow_list", "169.254", "blocked", "deny")
_AUTH_TOKENS = ("token", "compare_digest", "authoriz", "authentic", "api_key",
                "permission", "role", "401", "unauthor", "bearer")
_URL_SINKS = ("urlparse", "urlsplit", "requests", "httpx", "urlopen", "aiohttp")


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _static_text(node: ast.AST) -> str | None:
    """Literal text of a string Constant or an f-string (JoinedStr).

    For an f-string the interpolated ``{...}`` parts are dropped and the
    literal segments concatenated, which is enough for pattern matching.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values
                       if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return None


def _func_params(fn: ast.AST) -> set[str]:
    a = fn.args
    names = set()
    for group in (a.posonlyargs, a.args, a.kwonlyargs):
        names.update(arg.arg for arg in group)
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


class ModuleAnalyzer:
    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source
        self.tree = ast.parse(source)
        self.const_dicts: dict[str, set[str]] = {}
        self.const_strings: dict[str, str] = {}
        self.tool_regs: list[tuple] = []      # (description, fn_name, lineno, is_resource)
        self.findings: list[Finding] = []

    # -- pass 1: module context -------------------------------------------
    def _collect_context(self) -> None:
        for node in self.tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                val = node.value
                if isinstance(val, ast.Dict):
                    keys = {k.value for k in val.keys
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                    self.const_dicts[name] = keys
                else:
                    text = _static_text(val)
                    if text is not None:
                        self.const_strings[name] = text

        for call in [n for n in ast.walk(self.tree) if isinstance(n, ast.Call)]:
            self._maybe_registration(call)

    def _maybe_registration(self, call: ast.Call) -> None:
        func = call.func
        # add_tool(fn, ..., description=...)
        if isinstance(func, ast.Attribute) and func.attr == "add_tool":
            fn_name = self._first_callable_name(call.args)
            desc = self._kwarg_str(call, "description")
            self.tool_regs.append((desc, fn_name, call.lineno, False))
        # X.tool(...) / X.resource(uri, ...) used as decorator-call: Call(func=Call(...))
        elif isinstance(func, ast.Call) and isinstance(func.func, ast.Attribute) \
                and func.func.attr in ("tool", "resource"):
            is_res = func.func.attr == "resource"
            fn_name = self._first_callable_name(call.args)
            desc = self._kwarg_str(func, "description")
            self.tool_regs.append((desc, fn_name, call.lineno, is_res))

    def _first_callable_name(self, args: list[ast.AST]) -> str | None:
        for a in args:
            if isinstance(a, ast.Name):
                return a.id
        return None

    def _kwarg_str(self, call: ast.Call, key: str) -> str | None:
        for kw in call.keywords:
            if kw.arg == key:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    return kw.value.value
                if isinstance(kw.value, ast.Name):
                    return self.const_strings.get(kw.value.id)
        return None

    # -- helpers -----------------------------------------------------------
    def _add(self, rule_id: str, message: str, line: int, snippet: str | None = None,
             evidence: dict | None = None) -> None:
        self.findings.append(Finding(rule_id, message, self.path, line, "static",
                                     snippet, evidence or {}))

    def _tool_fns(self) -> dict[str, bool]:
        """Map registered function name -> is_resource."""
        return {fn: is_res for (_d, fn, _l, is_res) in self.tool_regs if fn}

    @staticmethod
    def _owned_nodes(fn: ast.AST) -> list[ast.AST]:
        """Nodes belonging to fn but NOT to any nested function/lambda.

        dvmcp defines its vulnerable and patched variants as sibling nested
        functions inside register(); analysing each function on its own body
        keeps a fix in the patched variant from masking the vulnerable one,
        and stops the enclosing register() from inheriting both.
        """
        owned: list[ast.AST] = []
        stack = list(fn.body)
        while stack:
            node = stack.pop()
            owned.append(node)
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    continue
                stack.append(child)
        return owned

    @staticmethod
    def _owned_src(fn: ast.AST, owned: list[ast.AST]) -> str:
        return "\n".join(ast.unparse(n) for n in fn.body)

    # -- pass 2: per-function checks --------------------------------------
    def _check_functions(self) -> None:
        tool_fns = self._tool_fns()
        for fn in [n for n in ast.walk(self.tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            params = _func_params(fn)
            owned = self._owned_nodes(fn)
            body_src = self._owned_src(fn, owned)
            taint = self._taint_set(owned, params)
            self._check_sinks(owned, taint)
            self._check_path_traversal(owned, taint, body_src)
            self._check_ssrf(fn, owned, params, body_src)
            self._check_rug_pull(fn, owned)
            if fn.name in tool_fns:
                if tool_fns[fn.name]:
                    self._check_secret_resource(fn, owned)
                else:
                    self._check_missing_auth(fn, body_src)

    def _taint_set(self, owned: list[ast.AST], params: set[str]) -> set[str]:
        taint = set(params)
        for stmt in owned:
            if isinstance(stmt, ast.Assign):
                rhs = _names_in(stmt.value)
                if rhs & taint:
                    for tgt in stmt.targets:
                        taint |= {n.id for n in ast.walk(tgt) if isinstance(n, ast.Name)}
        return taint

    def _check_sinks(self, owned: list[ast.AST], taint: set[str]) -> None:
        for call in [n for n in owned if isinstance(n, ast.Call)]:
            f = call.func
            # subprocess.* with shell=True
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                    and f.value.id == "subprocess":
                for kw in call.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) \
                            and kw.value.value is True:
                        self._add("MCPSCAN-SHELL-TRUE",
                                  f"subprocess.{f.attr}(..., shell=True) builds a shell "
                                  "command; interpolated input enables command injection.",
                                  call.lineno)
            # os.system
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                    and f.value.id == "os" and f.attr == "system":
                self._add("MCPSCAN-OS-SYSTEM", "os.system() executes a shell command line.",
                          call.lineno)
            # eval / exec with a tainted argument
            if isinstance(f, ast.Name) and f.id in ("eval", "exec"):
                if call.args and (_names_in(call.args[0]) & taint):
                    self._add("MCPSCAN-EVAL-EXEC",
                              f"{f.id}() on input derived from a parameter.", call.lineno)

    def _check_path_traversal(self, owned: list[ast.AST], taint: set[str], body_src: str) -> None:
        if any(g in body_src for g in _GUARD_TOKENS_PATH):
            return  # a containment guard is present in this scope
        for call in [n for n in owned if isinstance(n, ast.Call)]:
            f = call.func
            opens_file = (isinstance(f, ast.Name) and f.id == "open") or \
                         (isinstance(f, ast.Attribute) and f.attr == "open")
            if not opens_file:
                continue
            # receiver (x.open) or first arg (open(x)) tainted?
            tainted = False
            if isinstance(f, ast.Attribute):
                tainted = bool(_names_in(f.value) & taint)
            if call.args:
                tainted = tainted or bool(_names_in(call.args[0]) & taint)
            if tainted:
                self._add("MCPSCAN-PATH-TRAVERSAL",
                          "file opened on a path derived from a parameter without a "
                          "containment check (resolve()+is_relative_to).", call.lineno)

    def _check_ssrf(self, fn: ast.AST, owned: list[ast.AST], params: set[str], body_src: str) -> None:
        if not any(s in body_src for s in _URL_SINKS):
            return
        if any(g in body_src for g in _GUARD_TOKENS_SSRF):
            return  # destination validation present
        # URL-ish parameter present?
        url_param = any(re.search(r"url|uri|endpoint|host|target|address", p, re.I)
                        for p in params)
        if url_param or ("requests" in body_src or "httpx" in body_src or "urlopen" in body_src):
            line = fn.lineno
            for call in [n for n in owned if isinstance(n, ast.Call)]:
                seg = ast.unparse(call.func)
                if any(s in seg for s in _URL_SINKS):
                    line = call.lineno
                    break
            self._add("MCPSCAN-SSRF",
                      "a user-controlled URL/host is fetched or parsed without "
                      "destination validation (no private/loopback/allowlist check).",
                      line)

    def _check_rug_pull(self, fn: ast.AST, owned: list[ast.AST]) -> None:
        calls = [n for n in owned if isinstance(n, ast.Call)]
        attrs = {c.func.attr for c in calls if isinstance(c.func, ast.Attribute)}
        if ("remove_tool" in attrs or "remove" in attrs) and \
                ("add_tool" in attrs or "add" in attrs):
            self._add("MCPSCAN-RUG-PULL",
                      "tool is removed and re-registered at runtime (definition "
                      "mutation / rug-pull pattern).", fn.lineno)

    def _check_missing_auth(self, fn: ast.AST, body_src: str) -> None:
        if not _SENSITIVE_TOOL.search(fn.name):
            return
        if any(tok in body_src.lower() for tok in _AUTH_TOKENS):
            return
        self._add("MCPSCAN-MISSING-AUTH",
                  f"tool '{fn.name}' looks sensitive but performs no authorization "
                  "check.", fn.lineno)

    def _check_secret_resource(self, fn: ast.AST, owned: list[ast.AST]) -> None:
        # inline secret-shaped keys, or a referenced constant dict with such keys
        referenced = set()
        for n in owned:
            referenced |= {x.id for x in ast.walk(n) if isinstance(x, ast.Name)}
        leaked_keys: set[str] = set()
        for name in referenced:
            if name in self.const_dicts:
                leaked_keys |= {k for k in self.const_dicts[name] if _SECRET_KEY.search(k)}
        # inline dicts in the function body
        for d in [n for n in owned if isinstance(n, ast.Dict)]:
            for k in d.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str) \
                        and _SECRET_KEY.search(k.value):
                    leaked_keys.add(k.value)
        if leaked_keys:
            self._add("MCPSCAN-SECRET-RESOURCE",
                      f"resource '{fn.name}' can return secret-shaped fields: "
                      f"{sorted(leaked_keys)}.", fn.lineno,
                      evidence={"keys": sorted(leaked_keys)})

    # -- pass 3: suspicious strings ---------------------------------------
    def _check_strings(self) -> None:
        reg_descs = {d for (d, _f, _l, _r) in self.tool_regs if d}
        # tool/resource descriptions -> poisoning
        for (desc, _fn, lineno, _is_res) in self.tool_regs:
            if desc and self._looks_poisoned(desc):
                self._add("MCPSCAN-TOOL-POISONING",
                          "tool/resource description contains hidden or instruction-"
                          "like text the model will treat as commands.", lineno or 1)
        # other module string literals (incl. f-strings) with strong instruction
        # markers -> injection text. Constants inside an f-string are scanned as
        # one combined string, not individually.
        in_fstring: set[int] = set()
        for js in [n for n in ast.walk(self.tree) if isinstance(n, ast.JoinedStr)]:
            for child in ast.walk(js):
                if isinstance(child, ast.Constant):
                    in_fstring.add(id(child))

        candidates: list[tuple[str, int]] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.JoinedStr):
                candidates.append((_static_text(node) or "", getattr(node, "lineno", 1)))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and id(node) not in in_fstring:
                candidates.append((node.value, getattr(node, "lineno", 1)))

        for s, lineno in candidates:
            if not s or s in reg_descs:
                continue
            if _INVISIBLE.search(s):
                self._add("MCPSCAN-TOOL-POISONING",
                          "string contains invisible/BiDi characters often used to "
                          "hide poisoning.", lineno)
            elif self._strong_instruction(s):
                self._add("MCPSCAN-INJECTION-TEXT",
                          "string literal reads as embedded agent instructions "
                          "(possible poisoning payload or injectable tool output).",
                          lineno)

    def _looks_poisoned(self, s: str) -> bool:
        if _INVISIBLE.search(s):
            return True
        return sum(1 for p in _POISON_PATTERNS if p.search(s)) >= 1

    def _strong_instruction(self, s: str) -> bool:
        if len(s) < 20:
            return False
        hits = sum(1 for p in _POISON_PATTERNS if p.search(s))
        has_directive = bool(re.search(r"<\s*important\s*>|system\s+instruction|"
                                       r"do\s+not\s+(tell|mention|reveal)|you\s+must", s, re.I))
        return has_directive and hits >= 2

    # -- suppression -------------------------------------------------------
    def _suppressed(self, f: Finding) -> bool:
        """Honor an inline ``# mcpscan: ignore`` / ``ignore[RULE]`` comment on
        the finding's line (same convention as mainstream SAST tools)."""
        lines = self.source.splitlines()
        if not (1 <= f.line <= len(lines)):
            return False
        comment = lines[f.line - 1]
        m = re.search(r"#\s*mcpscan:\s*ignore(\[([A-Z0-9\-]+)\])?", comment)
        if not m:
            return False
        scoped = m.group(2)
        return scoped is None or scoped == f.rule_id

    # -- entry -------------------------------------------------------------
    def analyze(self) -> list[Finding]:
        self._collect_context()
        self._check_functions()
        self._check_strings()
        return [f for f in self.findings if not self._suppressed(f)]


def analyze_source(path: str, source: str) -> list[Finding]:
    try:
        return ModuleAnalyzer(path, source).analyze()
    except SyntaxError:
        return []
