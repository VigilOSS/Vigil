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
# Leading MAC-octet PTR names, e.g. 00-08-74-ab-... — require >=3 hex-octet
# groups so real hosts like `ad-01-portal` / `fe-80-gw` are NOT dropped (a real
# MAC PTR has 6 octets; two leading hex pairs is too common in corporate naming).
_MAC_PTR_RE = re.compile(r"^([0-9a-f]{2}[-:]){3,}", re.IGNORECASE)
# Generic reverse-DNS zone marker.
_REV_RE = re.compile(r"(^|\.)rev\.", re.IGNORECASE)


def normalize_host(value: str) -> str:
    """Canonical host key: lowercased, scheme/path/port-stripped authority.

    Mirrors the backend ``state_manager._normalize_liveness_host`` so a CLI-side
    lookup matches the stored ``assessment_host_liveness.host`` key. (The two
    live in different processes and cannot share an import, so they must agree by
    algorithm — keep them in sync.)
    """
    h = (value or "").strip().lower().rstrip(".")
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    if h.startswith("["):  # [ipv6](:port)?
        end = h.find("]")
        if end != -1:
            h = h[: end + 1]
    elif h.count(":") == 1:
        # exactly one colon → host:port (a bare IPv6 has >=2 colons; leave intact)
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


# --------------------------------------------------------------------------- #
# CR-19 — brute the WORDLIST HEAD (frequency-ordered lists have junk tails)
# --------------------------------------------------------------------------- #


def wordlist_head(lines: list[str], cap: int) -> list[str]:
    """Return the first ``cap`` entries of a frequency-ordered wordlist (CR-19).

    CT-derived / frequency-ordered huge lists (e.g. n0kovo_subdomains, 3M) put the
    real labels in the HEAD and CT-hash / one-off junk in the TAIL — so bruting
    only the head recovers nearly all real hosts at a fraction of the DNS spend.
    This is the pure head-slice the brute path applies before puredns; it assumes
    the input is already frequency-ordered (it does NOT sort — sorting would
    destroy that order). Identity (returns ``lines`` unchanged-by-content) when the
    list is at or under ``cap``; ``cap <= 0`` yields an empty list.
    """
    if cap <= 0:
        return []
    if len(lines) <= cap:
        return list(lines)
    return list(lines[:cap])


# --------------------------------------------------------------------------- #
# CR-17 / CR-20 — parent clustering (wildcard pre-strip + productive-parent axis)
# --------------------------------------------------------------------------- #


def _norm_host_token(host: str) -> str:
    """Lowercase, strip a trailing dot and any port; '' for blanks/comments."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or h.startswith("#"):
        return ""
    # Drop a host:port suffix (single colon; bare IPv6 has >=2 colons — leave it).
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h


def _immediate_parent(host: str) -> str:
    """The parent one label up from *host* (drop the leftmost label).

    ``a.origin.api.t.com`` → ``origin.api.t.com``. A 2-label host (``t.com``) has
    no deeper parent → ''.
    """
    labels = [p for p in host.split(".") if p]
    if len(labels) <= 2:
        return ""
    return ".".join(labels[1:])


def cluster_productive_parents(
    resolved_hosts: list[str],
    *,
    min_children: int = 5,
    bruted_apexes: list[str],
) -> list[str]:
    """Cluster resolved hosts by immediate parent; return productive parents (CR-20).

    Groups resolved hosts by the parent ONE label below each host (e.g. both
    ``a.origin.api.t.com`` and ``b.origin.api.t.com`` cluster under
    ``origin.api.t.com``) and returns the parents with at least ``min_children``
    distinct child hosts — the "productive parents" worth re-bruting a wordlist
    against (``<word>.origin.api.t.com``), the biggest depth win in the convergence
    loop. The bruted apexes themselves are excluded (re-bruting an apex you already
    bruted yields nothing); a parent equal to a bruted apex is skipped.

    Pure (no I/O), deterministic (sorted output), so it is unit-tested like
    :func:`denoise_hosts`.

    Args:
        resolved_hosts: the hosts resolved so far this pass.
        min_children: minimum distinct children for a parent to count as productive.
        bruted_apexes: apexes already bruted (excluded from the returned parents).
    """
    apex_set = {a for a in (_norm_host_token(x) for x in bruted_apexes) if a}
    children: dict[str, set[str]] = {}
    for raw in resolved_hosts:
        host = _norm_host_token(raw)
        if not host:
            continue
        parent = _immediate_parent(host)
        if not parent or parent in apex_set:
            continue
        children.setdefault(parent, set()).add(host)
    productive = [p for p, kids in children.items() if len(kids) >= min_children]
    return sorted(productive)


def wildcard_parent_candidates(hosts: list[str]) -> list[str]:
    """Cluster hosts by 2nd/3rd-level parent → candidate parents to wildcard-probe (CR-17).

    Before a permutation brute, each discovered parent that has children should be
    random-label probed for a wildcard sink (I-010: ``*.review.acme-media.example`` — a
    non-apex parent that apex-only detection misses). This pure helper returns the
    distinct candidate parents (the immediate parent of every multi-label host that
    actually has a child in the set), so a probe stage can test each one and strip
    permutations under any that wildcards. Deterministic (sorted, de-duped).
    """
    candidates: set[str] = set()
    for raw in hosts:
        host = _norm_host_token(raw)
        if not host:
            continue
        parent = _immediate_parent(host)
        if parent:
            candidates.add(parent)
    return sorted(candidates)
