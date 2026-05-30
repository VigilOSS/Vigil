"""Shared, pure helpers for the composable discovery pipelines.

Single source of truth for the host de-noise filter (§8/§10): passive/CT/PTR
enumeration inflates a host list ~10x with non-host artifacts (DNS service
records, DHCP/MAC reverse-DNS, workstation names) that each cost a full probe
timeout for ~0 yield. Dropping them BEFORE httpx/dnsx is the difference between
spending the budget on real origins and grinding a tar-pit.

These functions are pure (no I/O, no tool execution) so they are trivially
unit-tested and reused by `dns-discovery` and any caller that needs the same
filter the subdomain-enumeration skill documents.
"""
from __future__ import annotations

import re

# DNS service / control records — never a live web origin.
_SERVICE_RECORD_RE = re.compile(r"(^|\.)(_dmarc|_dkim|_domainkey|_acme-challenge|_spf|_mta-sts)\.", re.IGNORECASE)
# DHCP / workstation / reverse-DNS noise (the bulk of resolved .mil names in §8).
_DHCP_RE = re.compile(r"(^|\.)(dhcp[-.]|dha-\d+-\d+|dhpcile\d+)", re.IGNORECASE)
_WORKSTATION_RE = re.compile(r"(-laptop|-desktop|-kw|-pc)(\.|$)", re.IGNORECASE)
# Leading MAC-octet PTR names, e.g. 00-08-74-xx... or 00:08:74:...
_MAC_PTR_RE = re.compile(r"^[0-9a-f]{2}[-:][0-9a-f]{2}[-:]", re.IGNORECASE)
# Generic reverse-DNS zone marker.
_REV_RE = re.compile(r"(^|\.)rev\.", re.IGNORECASE)


def normalize_host(value: str) -> str:
    """Canonical host key: lowercased, scheme/path/port-stripped authority.

    Mirrors the backend ``state_manager._normalize_liveness_host`` so a CLI-side
    lookup matches the stored ``assessment_host_liveness.host`` key. (The two
    live in different processes and cannot share an import, so they must agree by
    algorithm — keep them in sync.)
    """
    h = (value or "").strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    if h.startswith("["):  # [ipv6](:port)?
        end = h.find("]")
        if end != -1:
            h = h[: end + 1]
    elif ":" in h:
        h = h.split(":", 1)[0]
    return h


def is_noise_host(host: str) -> bool:
    """True when *host* matches a known non-origin noise pattern (§8)."""
    h = (host or "").strip().lower()
    if not h:
        return True
    return bool(
        _SERVICE_RECORD_RE.search(h)
        or _DHCP_RE.search(h)
        or _WORKSTATION_RE.search(h)
        or _MAC_PTR_RE.search(h)
        or _REV_RE.search(h)
    )


def _normalize_host_line(line: str) -> str:
    """Strip scheme/path/whitespace so a mixed list (URLs + bare hosts) dedupes
    cleanly. Port is preserved (a host:port is a distinct probe target)."""
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    return s.lower()


def denoise_hosts(lines: list[str]) -> tuple[list[str], int]:
    """Return (clean_sorted_unique_hosts, dropped_count).

    Normalizes each line to a bare host, drops blanks/comments and every
    :func:`is_noise_host` match, and returns a sorted de-duplicated list plus how
    many entries were dropped as noise (for an auditable "dropped N noise" line).
    """
    kept: set[str] = set()
    seen = 0
    dropped = 0
    for raw in lines:
        host = _normalize_host_line(raw)
        if not host:
            continue
        seen += 1
        if is_noise_host(host):
            dropped += 1
            continue
        kept.add(host)
    return sorted(kept), dropped
