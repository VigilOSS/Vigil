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


def _encoded_byte_regex(value: int) -> str:
    octet = "".join(
        f"[{char.lower()}{char.upper()}]" if char.isalpha() else char
        for char in f"{value:02x}"
    )
    return rf"%(?:25){{0,{_MAX_DECODE_PASSES - 1}}}{octet}"


def _path_character_regex(value: str) -> str:
    alternatives = [re.escape(value)]
    alternatives.append("".join(_encoded_byte_regex(octet) for octet in value.encode("utf-8")))
    if value == "/":
        # Backslashes become slashes in the canonical path.
        alternatives.extend((r"\\", _encoded_byte_regex(ord("\\"))))
    return "(?:" + "|".join(alternatives) + ")"


def _path_glob_regex(value: str, *, raw_leading_slash: bool = False) -> str:
    expressions: list[str] = []
    for index, char in enumerate(value):
        if char == "*":
            expressions.append(r"[^?#]*")
        elif raw_leading_slash and index == 0 and char == "/":
            # A valid absolute URL has a literal slash between authority and path.
            expressions.append("/")
        else:
            expressions.append(_path_character_regex(char))
    return "".join(expressions)


def _crawl_path_expressions(
    host_prefix: str, path: str, query: str | None
) -> list[str]:
    query_suffix = (
        r"(?:[?#].*)?$"
        if query is None
        else r"\?" + _glob_regex(query) + r"(?:#.*)?$"
    )
    direct = host_prefix + _glob_regex(path)
    encoded = host_prefix + _path_glob_regex(path, raw_leading_slash=True)

    # A transport-encoded `..` prefix can normalize onto the authored path.
    # Keep this conservative case scoped to that exact authored suffix instead
    # of excluding every encoded URL on the host.
    separator = _path_character_regex("/")
    dot = _path_character_regex(".")
    tail = path[1:] if path.startswith("/") else path
    traversal = (
        host_prefix
        + r"/[^?#]*"
        + dot
        + dot
        + separator
        + _path_glob_regex(tail)
    )
    return [
        direct + query_suffix,
        encoded + query_suffix,
        traversal + query_suffix,
    ]


def crawl_exclusion_regex(scope_doc: dict[str, Any]) -> str:
    """Compile no-fire URL globs into one Katana ``-cos`` regular expression."""
    expressions: list[str] = []
    for pattern in patterns(scope_doc):
        if pattern.startswith("/"):
            host_prefix = r"https?://[^/]+"
            path, has_query, query = pattern.partition("?")
            expressions.extend(
                _crawl_path_expressions(
                    host_prefix, path, query if has_query else None
                )
            )
        else:
            parsed = urlsplit(pattern)
            host_prefix = _glob_regex(f"{parsed.scheme}://{parsed.netloc}")
            expressions.extend(
                _crawl_path_expressions(
                    host_prefix,
                    parsed.path or "/",
                    parsed.query if parsed.query else None,
                )
            )
    if not expressions:
        return ""
    return "(?:" + "|".join(expressions) + ")"
