"""The `code-history` contract: vocabularies, budgets, and pure helpers.

`vigil assess code-history` reads the history of an ingested Git repository
from the HEAD its sealed snapshot recorded, through `trusted_exec.TargetGit`
(ADR 0040), within explicit budgets (ADR 0041). This module owns what the
command and the contract registry both need to agree on; the command module
owns the I/O.

Commit messages, author identities, paths and patches are target-controlled
text (ADR 0018). They are stored verbatim: UTF-8 as a JSON string, anything
else as a base64 `<field>_b64` value. Nothing read from history widens a
budget, a path filter or the commits walked.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .security_history import strip_advisory_ids

RECEIPT_SCHEMA = "code-history-receipt/v1"
COMMIT_SCHEMA = "code-history-commit/v1"
SHAPE_CHECK_SCHEMA = "code-history-shape-check/v1"
HISTORY_ARTIFACT_DIR = ("tools", "analysis-state", "code-history")

DEFAULT_MAX_COMMITS = 500
MAX_COMMITS_CEILING = 20_000
DEFAULT_MAX_DIFF_BYTES = 256 * 1024
MAX_DIFF_BYTES_CEILING = 16 * 1024 * 1024
DEFAULT_MAX_DIFF_FILES = 50
MAX_DIFF_FILES_CEILING = 2_000
# Fixed per-commit bounds on what one hostile commit can make a walk read.
MAX_COMMIT_OBJECT_BYTES = 1024 * 1024
MAX_CHANGED_PATHS = 200
GIT_TIMEOUT_SECONDS = 120

MATCH_MODES = ("security", "all")
HISTORY_STATUSES = ("available", "partial_shallow", "unavailable")
UNAVAILABLE_REASONS: tuple[tuple[str, str], ...] = (
    ("directory_source", "the repository was ingested from a directory without Git metadata"),
    ("origin_missing", "the snapshot's source_origin_path no longer exists"),
    ("origin_not_git", "the origin has no usable Git metadata directory"),
    ("head_object_missing", "the origin's object store does not contain the recorded HEAD commit"),
    ("git_unavailable", "no trusted Git executable on absolute non-repository PATH entries"),
)
DIFF_STATUSES: tuple[tuple[str, str], ...] = (
    ("available", "patch against the commit's first parent"),
    ("root_commit", "the commit has no parent; the patch adds its whole tree"),
    ("first_parent_unavailable", "the first parent lies beyond a shallow boundary or is missing; no patch"),
)

_HEX_OBJECT_ID = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_IDENT_TIME = re.compile(rb">\s*(\d+)\s+[+-]\d{4}\s*$")
_SHORT_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{7,64}(?![0-9A-Za-z])")
_DESCRIPTIVE_WORD = re.compile(r"[^\W\d_]{2,}")
# A semantic bug shape names what the code did and what the fix guarded. Fewer
# words than this, once identifiers and hashes are removed, is a label.
MIN_DESCRIPTIVE_WORDS = 3


def full_object_id(value: str) -> str | None:
    """*value* lowercased when it is a full SHA-1 or SHA-256 object id, else None."""
    return value.lower() if _HEX_OBJECT_ID.match(value or "") else None


def repo_relative_path(value: str) -> str:
    """Validate a repository-relative path filter; Git reads it as a literal pathspec."""
    if not value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError("path filters must be non-empty and free of control characters")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"..", ".git"} for part in path.parts):
        raise ValueError(f"path filter must stay inside the repository: {value!r}")
    normalized = path.as_posix()
    if normalized in {"", "."}:
        raise ValueError("path filter must name a path inside the repository")
    return normalized


def text_field(name: str, raw: bytes | None) -> dict[str, Any]:
    """`{name: text}` for UTF-8 bytes, `{name_b64: ...}` otherwise; verbatim either way."""
    if raw is None:
        return {name: None}
    try:
        return {name: raw.decode("utf-8")}
    except UnicodeDecodeError:
        return {f"{name}_b64": base64.b64encode(raw).decode("ascii")}


def readable(raw: bytes) -> str:
    """Display/classification text for possibly non-UTF-8 bytes."""
    return raw.decode("utf-8", errors="replace")


def ident_time(ident: bytes | None) -> int | None:
    match = _IDENT_TIME.search(ident or b"")
    return int(match.group(1)) if match else None


@dataclass(frozen=True)
class CommitObject:
    tree: str
    parents: tuple[str, ...]
    author: bytes | None
    committer: bytes | None
    encoding: bytes | None
    message: bytes
    truncated: bool


def parse_commit_object(raw: bytes, *, truncated: bool) -> CommitObject:
    """Split a raw commit object into the headers history reports and its message."""
    header, separator, message = raw.partition(b"\n\n")
    if not separator:
        header, message = raw, b""
    values: dict[bytes, list[bytes]] = {}
    for line in header.split(b"\n"):
        if not line or line.startswith(b" "):
            continue  # continuation of a multi-line header (gpgsig, mergetag)
        key, _space, value = line.partition(b" ")
        values.setdefault(key, []).append(value)

    def first(key: bytes) -> bytes | None:
        found = values.get(key)
        return found[0] if found else None

    return CommitObject(
        tree=(first(b"tree") or b"").decode("ascii", errors="replace"),
        parents=tuple(value.decode("ascii", errors="replace") for value in values.get(b"parent", [])),
        author=first(b"author"),
        committer=first(b"committer"),
        encoding=first(b"encoding"),
        message=message,
        truncated=truncated,
    )


def request_digest(request: dict[str, Any]) -> str:
    """Short content address of a request, so the same request names the same artifact."""
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def encode_json_line(record: dict[str, Any]) -> bytes:
    """One record per physical line. ASCII escaping keeps U+2028, NEL and other
    separators a line splitter honours inside the JSON string."""
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def encode_receipt(receipt: dict[str, Any]) -> bytes:
    return (json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def descriptive_word_count(text: str) -> int:
    """Words left in *text* once advisory identifiers and hex hashes are removed."""
    return len(_DESCRIPTIVE_WORD.findall(_SHORT_HEX.sub(" ", strip_advisory_ids(text))))
