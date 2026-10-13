"""Bounded, passive filesystem traversal and optional git-diff filtering."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Iterator

from .detectors import inspect
from .models import Finding, SEVERITIES

IGNORED = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".next", ".nuxt",
                     "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor", ".terraform"})
MAX_BYTES = 512 * 1024
MAX_DEPTH = 16
MAX_FILES = 100_000


class ScanError(Exception):
    pass


def recognized(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    if not parts:
        return False
    basename = parts[-1]
    return (basename == "package.json" or
            (basename == "tasks.json" and ".vscode" in parts[:-1]) or
            (basename == "devcontainer.json" and ".devcontainer" in parts[:-1]) or
            (basename in ("mcp.json", ".mcp.json") or basename.endswith(".mcp.json")))


def changed_paths(root: Path, ref: str) -> set[str]:
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_./~^-]*", ref) or ref.startswith("-") or ".." in ref:
        raise ScanError("Invalid git ref; use a branch, tag or SHA")
    try:
        proc = subprocess.run(["git", "-C", str(root), "diff", "--name-only", "-z", "--diff-filter=ACMR", ref, "--"],
                              capture_output=True, timeout=15, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ScanError(f"git diff is unavailable: {exc}") from exc
    if proc.returncode != 0:
        raise ScanError("git diff failed: " + proc.stderr.decode("utf-8", "replace")[:300])
    return {p.decode("utf-8", "surrogateescape").replace("\\", "/") for p in proc.stdout.split(b"\0") if p}


def walk(root: Path) -> Iterator[tuple[str, Path]]:
    seen = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        path = Path(base)
        try:
            depth = len(path.relative_to(root).parts)
        except ValueError:
            continue
        dirs[:] = sorted(d for d in dirs if d not in IGNORED and not (path / d).is_symlink() and depth < MAX_DEPTH)
        for name in sorted(files):
            seen += 1
            if seen > MAX_FILES:
                raise ScanError(f"Scan exceeds {MAX_FILES:,} files; narrow the project root")
            file_path = path / name
            if file_path.is_symlink():
                continue
            relative = file_path.relative_to(root).as_posix()
            if recognized(relative):
                yield relative, file_path


def scan(root: Path, since: str | None = None) -> tuple[list[Finding], int, int]:
    if not root.is_dir() or root.is_symlink():
        raise ScanError(f"Not a directory (or symlink root): {root}")
    root = root.resolve()
    changed = changed_paths(root, since) if since else None
    findings: list[Finding] = []
    scanned = skipped = 0
    for relative, path in walk(root):
        if changed is not None and relative not in changed:
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                skipped += 1
                findings.append(Finding.make(rule="oversize-config", severity="medium", path=relative,
                                             line=1, trigger="Static analysis", title="Config too large to scan",
                                             evidence=f"Maximum supported size: {MAX_BYTES} bytes",
                                             why="A possibly executable configuration was skipped.",
                                             advice="Review this file manually or reduce its size.", identity="oversize"))
                continue
            content = path.read_text(encoding="utf-8-sig")
            scanned += 1
            findings.extend(inspect(relative, content))
        except (OSError, UnicodeError) as exc:
            skipped += 1
            findings.append(Finding.make(rule="unreadable-config", severity="medium", path=relative,
                                         line=1, trigger="Static analysis", title="Config could not be read",
                                         evidence=type(exc).__name__, why="The file was not inspected.",
                                         advice="Inspect it manually and confirm its encoding and permissions.",
                                         identity="unreadable"))
    findings.sort(key=lambda f: (-SEVERITIES[f.severity], f.path, f.line, f.rule, f.fingerprint))
    return findings, scanned, skipped
