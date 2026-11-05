"""The security-history vocabulary: which commit messages describe a security change.

`code-ingest` hands this vocabulary to `git log --grep` to mark files touched by
security commits; `code-history` classifies each commit message it reads with
the same terms in Python. Each term is a regular expression written in the
subset Git's basic and Python's syntax read identically (literal text, `.` and
`.*`), so one tuple drives both matchers and they cannot disagree about a
message. Both match regardless of letter case.

Advisory and weakness identifiers are extracted alongside the keyword hits. A
message is security relevant when it hits a keyword or names an identifier.
Commit text is target-controlled: the classification is navigation evidence for
the architect, never a verdict and never a source of scope or budget.
"""
from __future__ import annotations

import re
from typing import Any

# (label, pattern). Labels are what classification output reports.
SECURITY_HISTORY_TERMS: tuple[tuple[str, str], ...] = (
    ("cve", "CVE"),
    ("security", "security"),
    ("vulnerability", "vulnerability"),
    ("fix_vuln", "fix.*vuln"),
    ("buffer_overflow", "buffer.overflow"),
    ("use_after_free", "use.after.free"),
)

# The `--grep` argument `git log --regexp-ignore-case` takes: basic-regex
# alternation of the same terms.
SECURITY_HISTORY_GIT_GREP = "\\|".join(pattern for _label, pattern in SECURITY_HISTORY_TERMS)

_KEYWORDS = tuple(
    (label, re.compile(pattern, re.IGNORECASE)) for label, pattern in SECURITY_HISTORY_TERMS
)
_BOUNDARY = r"(?<![A-Za-z0-9])"
_END = r"(?![A-Za-z0-9])"
CVE_ID = re.compile(_BOUNDARY + r"CVE-(\d{4})-(\d{4,})" + _END, re.IGNORECASE)
GHSA_ID = re.compile(
    _BOUNDARY + r"GHSA-([0-9a-z]{4})-([0-9a-z]{4})-([0-9a-z]{4})" + _END, re.IGNORECASE
)
CWE_ID = re.compile(_BOUNDARY + r"CWE-(\d{1,5})" + _END, re.IGNORECASE)


def _sorted_unique(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(values))


def advisory_ids(text: str) -> dict[str, list[str]]:
    """CVE, GHSA and CWE identifiers named in *text*, normalized and de-duplicated."""
    return {
        "cve_ids": _sorted_unique(
            [f"CVE-{year}-{number}" for year, number in CVE_ID.findall(text)]
        ),
        "ghsa_ids": _sorted_unique(
            ["GHSA-" + "-".join(part.lower() for part in parts) for parts in GHSA_ID.findall(text)]
        ),
        "cwe_ids": sorted(
            {f"CWE-{int(number)}" for number in CWE_ID.findall(text)},
            key=lambda value: int(value[4:]),
        ),
    }


def strip_advisory_ids(text: str) -> str:
    """*text* with every CVE, GHSA and CWE identifier removed."""
    for pattern in (CVE_ID, GHSA_ID, CWE_ID):
        text = pattern.sub(" ", text)
    return text


def classify_message(text: str) -> dict[str, Any]:
    """Security keyword hits and advisory identifiers in one commit message."""
    ids = advisory_ids(text)
    hits = [label for label, pattern in _KEYWORDS if pattern.search(text)]
    return {
        **ids,
        "keyword_hits": hits,
        "security_relevant": bool(hits or any(ids.values())),
    }
