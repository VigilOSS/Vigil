"""Canonical syntax, normalization, and classification for authored scope entries."""
from __future__ import annotations

import ipaddress
import re
import sys
from urllib.parse import SplitResult, urlsplit, urlunsplit

_DNS_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
_warned_scope_keys: set[str] = set()


class ScopeEntryError(ValueError):
    """An authored authorization root is syntactically ambiguous or invalid."""


def is_dns_label(value: str) -> bool:
    return bool(value and _DNS_LABEL_RE.fullmatch(value))


def ip_literal(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("[") != candidate.endswith("]"):
        return ""
    if candidate.startswith("["):
        candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def parse_cidr(
    value: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def to_a_label(value: str) -> str:
    cleaned = value.strip().rstrip(".").lower()
    if not cleaned:
        return ""
    try:
        return cleaned.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""


def normalize_host(value: str, *, allow_single_label: bool = True) -> str:
    literal = ip_literal(value)
    if literal:
        return literal
    host = to_a_label(value)
    if not host or len(host) > 253:
        return ""
    labels = host.split(".")
    if any(not is_dns_label(label) for label in labels):
        return ""
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        return ""
    if len(labels) == 1 and not allow_single_label:
        return ""
    return host


def _authority_host(value: str) -> tuple[str, int | None]:
    try:
        parsed = urlsplit("//" + value)
        port = parsed.port
    except ValueError as exc:
        raise ScopeEntryError("malformed host authority") from exc
    if parsed.username is not None or parsed.password is not None:
        raise ScopeEntryError("credentials are not valid in a scope host")
    if parsed.path or parsed.query or parsed.fragment or not parsed.hostname:
        raise ScopeEntryError("malformed host authority")
    host = normalize_host(parsed.hostname)
    if not host:
        raise ScopeEntryError("invalid host labels")
    return host, port


def _canonical_url(parsed: SplitResult, host: str, port: int | None) -> str:
    authority_host = f"[{host}]" if ":" in host else host
    netloc = authority_host if port is None else f"{authority_host}:{port}"
    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _parse_scope_entry(raw: str) -> tuple[str, str, str, bool]:
    stripped = raw.strip()
    if not stripped or any(character.isspace() for character in stripped):
        raise ScopeEntryError("scope entries must be one non-empty token")

    if stripped.startswith("*."):
        if stripped.count("*") != 1:
            raise ScopeEntryError("wildcard is only valid as one leading '*.'")
        host = normalize_host(stripped[2:], allow_single_label=False)
        if not host or ip_literal(host):
            raise ScopeEntryError("wildcard requires a valid DNS suffix")
        return f"*.{host}", "wildcard", host, False
    if "*" in stripped:
        raise ScopeEntryError("wildcard is only valid as one leading '*.'")

    if "://" in stripped:
        try:
            parsed = urlsplit(stripped)
            port = parsed.port
        except ValueError as exc:
            raise ScopeEntryError("malformed URL scope entry") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ScopeEntryError("scope URL must be absolute HTTP(S)")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeEntryError("credentials are not valid in a scope URL")
        host = normalize_host(parsed.hostname)
        if not host:
            raise ScopeEntryError("scope URL contains an invalid host")
        return _canonical_url(parsed, host, port), "url", host, bool(parsed.path.strip("/"))

    if "/" in stripped:
        network = parse_cidr(stripped)
        if network is None:
            raise ScopeEntryError("slash-bearing scope entry is not a valid CIDR")
        return str(network), "cidr", str(network), False

    literal = ip_literal(stripped)
    if literal:
        return literal, "bare_host", literal, False
    host, _port = _authority_host(stripped)
    return host, "bare_host", host, False


def canonicalize_scope_entry(raw: str) -> str:
    canonical, _kind, _host, _path_warning = _parse_scope_entry(raw)
    return canonical


def classify_scope_entry(raw: str) -> dict[str, str] | None:
    try:
        _canonical, kind, host, path_warning = _parse_scope_entry(raw)
    except ScopeEntryError:
        return None
    stripped = raw.strip()
    if path_warning and stripped not in _warned_scope_keys:
        _warned_scope_keys.add(stripped)
        print(
            f"scope: entry '{stripped}' carries a path; scope is matched at host "
            f"granularity, so this admits the whole host '{host}'. The path boundary "
            "is not enforced — narrow the engagement in-band if it matters.",
            file=sys.stderr,
        )
    return {"scope_entry": stripped, "entry_kind": kind, "host": host}


def normalize_host_for_match(value: str) -> str:
    return normalize_host(value)
