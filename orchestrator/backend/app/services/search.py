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
