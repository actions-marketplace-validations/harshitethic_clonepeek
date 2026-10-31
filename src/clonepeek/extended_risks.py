"""Additional high-confidence execution signatures for first-run configuration commands.

These are conservative static indicators, not proof that code ran. Keep each
signature narrow and regression-tested: configuration strings are untrusted and
can contain both real instructions and explanatory prose.
"""
from __future__ import annotations

import re


# Each entry is (stable rule label, compiled expression). The order is
# deliberate: fetch-and-execute signatures outrank destructive commands.
CRITICAL_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("powershell-restmethod-eval", re.compile(
        r"(?is)\b(?:iex|invoke-expression)\s*\(\s*(?:irm|invoke-restmethod)\b"
    )),
    ("shell-curl-substitution", re.compile(
        r"""(?is)\b(?:sh|bash|zsh)\s+-c\s+["']?\$\(\s*curl\b"""
    )),
    ("shell-wget-substitution", re.compile(
        r"""(?is)\b(?:sh|bash|zsh)\s+-c\s+["']?\$\(\s*wget\b"""
    )),
    ("eval-curl-substitution", re.compile(
        r"""(?is)\beval\s+["']?\$\(\s*curl\b"""
    )),
    ("eval-wget-substitution", re.compile(
        r"""(?is)\beval\s+["']?\$\(\s*wget\b"""
    )),
    ("python-curl-substitution", re.compile(
        r"""(?is)\bpython(?:\d+(?:\.\d+)?)?\s+-c\s+["']?\$\(\s*curl\b"""
    )),
    ("node-curl-substitution", re.compile(
        r"""(?is)\bnode\s+-e\s+["']?\$\(\s*curl\b"""
    )),
    ("perl-curl-substitution", re.compile(
        r"""(?is)\bperl\s+-e\s+["']?\$\(\s*curl\b"""
    )),
    ("ruby-curl-substitution", re.compile(
        r"""(?is)\bruby\s+-e\s+["']?\$\(\s*curl\b"""
    )),
    ("powershell-webclient-eval", re.compile(
        r"""(?is)\b(?:iex|invoke-expression)\s*\(?\s*\(?\s*new-object\s+net\.webclient\b.{0,250}\bdownloadstring\s*\("""
    )),
)

HIGH_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = ()


def classify_additional_risk(command: str) -> tuple[str, str, str] | None:
    """Classify dangerous commands not covered by the core signatures."""
    for label, pattern in CRITICAL_SIGNATURES:
        if pattern.search(command):
            return (
                "critical",
                f"Fetch-and-execute signature ({label}) may run unverified remote code.",
                "Download, verify, and pin external code before executing it.",
            )
    for label, pattern in HIGH_SIGNATURES:
        if pattern.search(command):
            return (
                "high",
                f"Destructive or opaque execution signature ({label}) requires review.",
                "Review the exact command, targets, and privileges before allowing execution.",
            )
    return None
