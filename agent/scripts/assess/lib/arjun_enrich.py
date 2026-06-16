"""Pure helpers for folding Arjun discovery output into the work buffer.

Kept separate from ``commands/ingest_arjun.py`` (the same lib/command split as
``candidate_records.py`` / ``ingest_candidates.py``) so the param-slot routing,
the sqlmap-suggestion rule, and the Arjun-JSON parsing are unit-testable
without a DB or a backend.

Arjun is a *discovery producer*; the existing ``classify_buckets`` machinery is
the *router*. This module never re-implements classification — it only decides
WHICH field a discovered param belongs in (GET -> query_params, POST/XML/JSON ->
body_params), records header-mode params as a signal, and builds the
LLM-facing ``triage_rationale`` (naming sqlmap when the param routes to a
DB-class surface). The caller then re-runs ``classify_from_fields`` so routing
recomputes for free.
"""
from __future__ import annotations

import json
from typing import Any

# Methods whose discovered params land in the request BODY rather than the
# query string. Mirrors kali_arjun._BODY_METHODS — keep the two in lockstep.
_BODY_METHODS = frozenset({"POST", "XML", "JSON"})

# Param keys / bucket names that signal a DB-backed surface where the right
# next move is sqlmap confirmation + extraction. The classifier routes id/uid/
# numeric-id params to gf:sqli (weight 40) which beats gf:idor (35); this set
# lets the enricher name sqlmap in the rationale BEFORE re-classification by
# recognising the same param vocabulary the sqli bucket keys on.
_SQLI_PARAM_KEYS = frozenset(
    {
        "id", "uid", "pid", "sid", "tid", "order", "sort", "filter",
        "q", "search", "query", "category",
    }
)


def slot_for_method(method: str) -> str:
    """Return the work-item field a discovered param belongs in for ``method``.

    GET -> ``query_params``; POST / XML / JSON -> ``body_params``. Case- and
    whitespace-insensitive; unknown methods default to query (the GET-like
    safe choice).
    """
    return "body_params" if (method or "").strip().upper() in _BODY_METHODS else "query_params"


def routes_to_sqli(params: list[str]) -> bool:
    """True when any discovered param matches the sqli bucket's key vocabulary.

    Used to decide whether the triage rationale should name sqlmap. The match
    is lowercase exact against ``_SQLI_PARAM_KEYS`` — the same keys
    ``classify_buckets._BUCKETS['sqli']`` fires on, so the rationale agrees with
    where the row will actually route after re-classification.
    """
    lowered = {str(p).strip().lower() for p in params if str(p).strip()}
    return bool(lowered & _SQLI_PARAM_KEYS)


def build_signals(params: list[str], *, header_params: list[str] | None = None) -> list[str]:
    """Build the ``signals`` list recorded on an enriched/created row.

    Each discovered param becomes ``arjun:<param>``. Header-mode params (found
    via ``--headers`` auth-aware discovery, which Arjun cannot write to a
    classifier field) are recorded as ``arjun-header:<param>`` so the signal is
    not lost. A short evidence note is appended so the work-buffer row carries
    why it was selected.
    """
    signals: list[str] = [f"arjun:{p}" for p in params if str(p).strip()]
    for hp in header_params or []:
        if str(hp).strip():
            signals.append(f"arjun-header:{hp}")
    if params or header_params:
        signals.append("arjun-discovered-hidden-param")
    return signals


def build_triage_rationale(
    *,
    method: str,
    params: list[str],
    url_path: str = "",
    header_params: list[str] | None = None,
) -> str:
    """Build the one-line LLM-facing instruction stamped as ``triage_rationale``.

    Names the discovered params and the slot they were written to. When a param
    routes to the sqli surface (or an id=/numeric param on a DB-ish route),
    NAMES sqlmap as the recommended operator-invoked confirmation/extraction
    step (the sqlmap doctrine). sqlmap is suggested, never auto-fired.
    """
    slot = "query" if slot_for_method(method) == "query_params" else "body"
    parts: list[str] = []
    if params:
        param_list = ", ".join(f"`{p}`" for p in params)
        parts.append(
            f"arjun-discovered hidden {slot} param(s) {param_list} on a "
            f"{(method or 'GET').upper()} request — test the matching vuln class"
        )
    if header_params:
        hdr_list = ", ".join(f"`{p}`" for p in header_params)
        parts.append(
            f"header-mode param(s) {hdr_list} surfaced via --headers (auth-aware); "
            "no classifier field maps to a header, recorded as a signal"
        )
    if routes_to_sqli(params):
        parts.append(
            "param routes to a DB-backed (gf:sqli) surface — hand the isolated "
            "param to `vigil assess kali sqlmap` for blind/time-based confirmation "
            "+ extraction (operator-invoked, never auto-fired)"
        )
    if not parts:
        return "arjun run produced no discovered params for this endpoint"
    return "; ".join(parts)


def _normalize_param_list(raw: Any) -> list[str]:
    """Coerce an Arjun param payload into a clean ``list[str]``.

    Accepts a list, a single string, or a dict (param-name keys). Dedupes while
    preserving first-seen order; drops blanks.
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(value: Any) -> None:
        token = str(value).strip()
        if token and token not in seen:
            seen.add(token)
            out.append(token)

    if isinstance(raw, list):
        for item in raw:
            _add(item)
    elif isinstance(raw, dict):
        for key in raw.keys():
            _add(key)
    elif raw not in (None, ""):
        _add(raw)
    return out


def parse_arjun_json(text: str, *, default_method: str = "GET") -> list[dict[str, Any]]:
    """Parse Arjun ``-oJ`` JSON into a list of ``{endpoint, method, params}`` dicts.

    Arjun's JSON shape has varied across versions; this parser is defensive and
    accepts all observed forms:

    1. ``{ "<url>": ["p1", "p2"] }`` — flat url -> param list.
    2. ``{ "<url>": {"params": [...], "method": "POST", "headers": {...}} }`` —
       per-endpoint object with method/headers metadata.
    3. ``[{"url": "...", "method": "...", "params": [...]}]`` — list of records.

    ``default_method`` (the ``-m`` the verb ran with) is used when a record does
    not carry its own method. Records with no endpoint are dropped. Returns one
    dict per endpoint: ``{"endpoint", "method", "params", "header_params"}``.
    """
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return []

    records: list[dict[str, Any]] = []

    def _emit(endpoint: str, method: str, params: list[str], header_params: list[str]) -> None:
        endpoint = (endpoint or "").strip()
        if not endpoint:
            return
        records.append(
            {
                "endpoint": endpoint,
                "method": (method or default_method or "GET").strip().upper(),
                "params": params,
                "header_params": header_params,
            }
        )

    if isinstance(data, dict):
        for endpoint, payload in data.items():
            if isinstance(payload, dict):
                params = _normalize_param_list(payload.get("params") or payload.get("parameters"))
                method = str(payload.get("method") or default_method)
                # Arjun's per-endpoint `headers` echoes the REQUEST headers that were
                # sent (e.g. our own auth/identification headers), not discovered
                # parameters — so it is never a findings source.
                _emit(endpoint, method, params, [])
            else:
                _emit(endpoint, default_method, _normalize_param_list(payload), [])
    elif isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            endpoint = str(entry.get("url") or entry.get("endpoint") or "")
            method = str(entry.get("method") or default_method)
            params = _normalize_param_list(entry.get("params") or entry.get("parameters"))
            _emit(endpoint, method, params, [])

    return records


def merge_params_into_field(existing_json: str | None, new_params: list[str]) -> str:
    """Merge ``new_params`` into an existing JSON param-field value.

    The work-item param columns store a JSON object ``{name: value}``. We add
    each discovered param with an empty-string value (Arjun finds the NAME, not
    a value), preserving any params already present. Returns a JSON string.
    """
    base: dict[str, Any] = {}
    if existing_json:
        try:
            decoded = json.loads(existing_json)
            if isinstance(decoded, dict):
                base = decoded
        except (TypeError, ValueError):
            base = {}
    for name in new_params:
        token = str(name).strip()
        if token and token not in base:
            base[token] = ""
    return json.dumps(base, sort_keys=True)


def merge_signal_lists(existing_json: str | None, new_signals: list[str]) -> list[str]:
    """Merge ``new_signals`` into an existing JSON signals list, dedup, order-preserving.

    Enrichment must ADD its discovered-param signals without erasing whatever the
    row already carried (e.g. a curated source's signals). Malformed/empty input
    is treated as no prior signals.
    """
    base: list[str] = []
    if existing_json:
        try:
            decoded = json.loads(existing_json)
            if isinstance(decoded, list):
                base = [str(x) for x in decoded]
        except (TypeError, ValueError):
            base = []
    out = list(base)
    for sig in new_signals:
        if sig not in out:
            out.append(sig)
    return out
