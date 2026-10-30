"""Static scan engine: walk a path, analyse each Python file, collect findings."""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding, dedupe, sort_findings
from .checks import analyze_source

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "build", "dist",
              ".pytest_cache", ".mypy_cache", "node_modules"}


def iter_python_files(root: Path):
    root = Path(root)
    if root.is_file():
        if root.suffix == ".py":
            yield root
        return
    for p in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def scan_path(root: str | Path, *, repo_root: str | Path | None = None) -> list[Finding]:
    """Scan a file or directory tree and return sorted, de-duplicated findings."""
    root = Path(root)
    base = Path(repo_root) if repo_root else (root if root.is_dir() else root.parent)
    findings: list[Finding] = []
    for py in iter_python_files(root):
        try:
            source = py.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            rel = str(py.relative_to(base))
        except ValueError:
            rel = str(py)
        findings.extend(analyze_source(rel, source))
    return sort_findings(dedupe(findings))
