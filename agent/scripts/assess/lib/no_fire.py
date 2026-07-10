"""Canonical per-engagement URL no-fire matching and crawler exclusions."""
from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import Any
from urllib.parse import unquote, urlsplit


class NoFirePolicyError(ValueError):
    """Raised when authored no-fire policy cannot be enforced unambiguously."""


def patterns(scope_doc: dict[str, Any]) -> tuple[str, ...]:
    raw = scope_doc.get("off_limits_paths", [])
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise NoFirePolicyError("scope.json off_limits_paths must be a list of URL patterns")
    normalized: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise NoFirePolicyError(
                "scope.json off_limits_paths entries must be non-empty strings"
            )
        value = item.strip()
        if not value.startswith(("/", "http://", "https://")):
            raise NoFirePolicyError(
                "scope.json off_limits_paths entries must start with /, http://, or https://"
            )
        normalized.append(value)
    return tuple(normalized)


def _matches_component(pattern: str, value: str) -> bool:
    if any(char in pattern for char in "*["):
        return fnmatch.fnmatchcase(value, pattern)
    return value == pattern


_ENCODED_OCTET = re.compile(r"%[0-9A-Fa-f]{2}")
_INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_DECODE_PASSES = 3


def _canonical_path(value: str) -> str:
    """Decode transport encodings and normalize the server-visible URL path.

    Two ordinary encoding layers are supported; a third pass permits a stable
    decoded result, while any remaining encoded octet fails closed as an
    ambiguous/excessively nested representation.
    """
    current = value or "/"
    for _ in range(_MAX_DECODE_PASSES):
        if _INVALID_PERCENT.search(current):
            raise NoFirePolicyError(
                "URL path contains invalid percent encoding; refusing ambiguous no-fire match"
            )
        try:
            decoded = unquote(current, errors="strict")
        except UnicodeDecodeError as exc:
            raise NoFirePolicyError(
                "URL path contains invalid percent encoding; refusing ambiguous no-fire match"
            ) from exc
        if decoded == current:
            break
        current = decoded
    if _ENCODED_OCTET.search(current):
        raise NoFirePolicyError(
            "URL path contains excessive nested percent encoding; refusing ambiguous no-fire match"
        )
    current = current.replace("\\", "/")
    normalized = posixpath.normpath(current)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def match_url(scope_doc: dict[str, Any], value: str) -> str | None:
    """Return the matching no-fire pattern for an HTTP(S) URL, else ``None``."""
    raw = str(value or "").strip()
    if not raw.startswith(("http://", "https://")):
        return None
    parsed = urlsplit(raw)
    if not parsed.hostname:
        return None
    target_path = _canonical_path(parsed.path or "/")
    target_path_query = target_path + (f"?{parsed.query}" if parsed.query else "")
    for pattern in patterns(scope_doc):
        if pattern.startswith("/"):
            candidate = target_path_query if "?" in pattern else target_path
            if _matches_component(pattern, candidate):
                return pattern
            continue
        authored = urlsplit(pattern)
        if authored.scheme != parsed.scheme:
            continue
        if not authored.hostname or not fnmatch.fnmatchcase(
            parsed.hostname.lower(), authored.hostname.lower()
        ):
            continue
        authored_path = authored.path or "/"
        authored_value = authored_path + (
            f"?{authored.query}" if authored.query else ""
        )
        candidate = target_path_query if authored.query else target_path
        if _matches_component(authored_value, candidate):
            return pattern
    return None


def _glob_regex(value: str) -> str:
    return re.escape(value).replace(r"\*", ".*")


def crawl_exclusion_regex(scope_doc: dict[str, Any]) -> str:
    """Compile no-fire URL globs into one Katana ``-cos`` regular expression."""
    expressions: list[str] = []
    encoded_reserved = r"[^?#]*%(?:25)*(?:2f|2e|5c)[^?#]*"
    for pattern in patterns(scope_doc):
        if pattern.startswith("/"):
            host_prefix = r"https?://[^/]+"
            expressions.append(host_prefix + _glob_regex(pattern))
            expressions.append(host_prefix + r"/" + encoded_reserved)
        else:
            parsed = urlsplit(pattern)
            host_prefix = _glob_regex(
                f"{parsed.scheme}://{parsed.netloc}"
            )
            expressions.append(_glob_regex(pattern))
            expressions.append(host_prefix + r"/" + encoded_reserved)
    if not expressions:
        return ""
    # Katana applies -cos to full URLs. Match query/fragment variants too; an
    # exact authored endpoint remains exact with respect to the path itself.
    return "(?:" + "|".join(expressions) + r")(?:[?#].*)?$"
