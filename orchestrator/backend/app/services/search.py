"""Shared FTS5 helpers.

Extracted from ``state_manager._fts_escape`` so every list endpoint that
needs to feed a user-supplied string into an ``FTS5 MATCH`` expression has a
single safe helper to import. Kept intentionally tiny — this module is the
home for any future FTS5 utilities (rank parsing, snippet helpers, etc.).
"""
from __future__ import annotations

import re

# FTS5 treats ``"``, ``'``, and ``\`` specially inside MATCH expressions; the
# tokeniser itself copes fine but the query parser blows up on unbalanced
# quotes. Strip them and run every remaining token through phrase quotes so
# operators like ``AND``/``OR``/``NOT`` or leading ``-`` are treated as data.
_FTS_SPECIAL_RE = re.compile(r"[\"'\\]")


def fts_escape(term: str) -> str:
    """Return a safe FTS5 MATCH expression for ``term``.

    Each word becomes a quoted phrase so punctuation and FTS keywords are
    treated as data rather than query operators. Returns ``""`` when the
    input normalises to nothing, which callers should treat as "no match
    filter requested".
    """
    cleaned = _FTS_SPECIAL_RE.sub(" ", term).strip()
    if not cleaned:
        return ""
    tokens = [tok for tok in cleaned.split() if tok]
    if not tokens:
        return ""
    return " ".join(f'"{tok}"' for tok in tokens)


CANONICAL_FINDING_SLUG_RE = re.compile(r"^[A-Z]{2}-\d{3,}$")
_FINDING_ALIAS_FULL_RE = re.compile(r"^(?:FINDING[-\s]*)?([A-Za-z]{2})[-\s]?(\d{3,})$")
_FINDING_ALIAS_SEARCH_RE = re.compile(r"\b(?:FINDING[-\s]*)?([A-Za-z]{2})[-\s]?(\d{3,})\b")


def is_canonical_finding_slug(value: str | None) -> bool:
    """Return True for the write-time canonical finding ID shape.

    Lookup and search callers may accept aliases, but mutating paths use this
    strict check so backend rows do not accumulate spelling variants.
    """

    return bool(value and CANONICAL_FINDING_SLUG_RE.fullmatch(str(value)))


def canonical_finding_alias(value: str | None) -> str | None:
    """Normalize a single finding alias for lookup/search.

    Accepts ``VA-047``, ``VA047``, ``VA 047``, and ``FINDING-VA-047`` variants.
    Returns ``None`` when the whole value is not a finding reference.
    """

    if value is None:
        return None
    match = _FINDING_ALIAS_FULL_RE.fullmatch(str(value).strip())
    if not match:
        return None
    return f"{match.group(1).upper()}-{match.group(2)}"


def finding_aliases(canonical_slug: str) -> list[str]:
    """Return stable search aliases for a canonical finding slug."""

    canonical = canonical_finding_alias(canonical_slug)
    if canonical is None:
        return []
    prefix, number = canonical.split("-", 1)
    return [
        canonical,
        f"{prefix}{number}",
        f"{prefix} {number}",
        f"FINDING-{canonical}",
    ]


def finding_aliases_in_text(value: str | None) -> dict[str, list[str]]:
    """Return canonical finding refs detected in free text with their aliases."""

    if value is None:
        return {}
    found: dict[str, list[str]] = {}
    for match in _FINDING_ALIAS_SEARCH_RE.finditer(str(value)):
        canonical = f"{match.group(1).upper()}-{match.group(2)}"
        found.setdefault(canonical, finding_aliases(canonical))
    return found


def fts_or_expression(terms: list[str]) -> str:
    """Return a safe FTS5 OR expression for user-controlled terms."""

    expressions: list[str] = []
    seen: set[str] = set()
    for term in terms:
        expression = fts_escape(term)
        if not expression or expression in seen:
            continue
        seen.add(expression)
        expressions.append(expression)
    if not expressions:
        return ""
    if len(expressions) == 1:
        return expressions[0]
    return " OR ".join(f"({expression})" for expression in expressions)


def expanded_fts_query(value: str, *, exact: bool = False, require_all: bool = False) -> str:
    """Build a command/artifact search expression with finding alias expansion.

    - ``exact``: skip alias expansion; return only the raw escaped phrase.
      The strictest mode — useful when the caller knows the exact spelling.
    - ``require_all``: keep alias expansion but intersect every non-alias
      token (AND) instead of unioning the user's input with the aliases.
      Use when the user wants "VA-047 AND OIDC" semantics: rows must mention
      VA-047 (in any alias form) AND mention OIDC.
    - default: union the raw input with all alias forms (OR). Loose; surfaces
      anything related to the finding even if the topic token is missing.
    """

    if exact:
        return fts_escape(value)
    aliases_by_canonical = finding_aliases_in_text(value)
    if require_all:
        # Strip finding identifiers out of the user's free text and AND every
        # remaining token with an alias-OR group per canonical finding.
        residual = _strip_finding_refs(value)
        clauses: list[str] = []
        for canonical, aliases in aliases_by_canonical.items():
            alias_expr = fts_or_expression(aliases)
            if alias_expr:
                clauses.append(f"({alias_expr})")
        residual_expr = fts_escape(residual)
        if residual_expr:
            clauses.append(residual_expr)
        if not clauses:
            return ""
        return " AND ".join(clauses) if len(clauses) > 1 else clauses[0]
    terms = [value]
    for aliases in aliases_by_canonical.values():
        terms.extend(aliases)
    return fts_or_expression(terms)


def _strip_finding_refs(value: str) -> str:
    """Return ``value`` with any embedded finding aliases removed."""

    return _FINDING_ALIAS_SEARCH_RE.sub(" ", str(value or "")).strip()
