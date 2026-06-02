"""Response anomaly oracle — deterministic, no-LLM population outlier scoring.

Scores a *population* of HTTP response records (dicts) to surface the odd-one-
out(s). Ported from the reference-project ``pkg/anomaly`` approach (engine.go /
weights.go):

1. Build per-attribute frequency tables over the population.
2. An attribute only contributes signal when it VARIES (>= 2 distinct values).
3. Rare values score higher; as an attribute accrues more distinct values its
   weight is *degraded* so a near-unique column (like a per-response nonce)
   cannot dominate the ranking.
4. Numeric attributes (content_length) are bucketed so near-equal lengths
   cluster together instead of every value being unique.

Design: pure functions, deterministic output, no regex compilation needed,
no network, no LLM, no new dependencies (stdlib only).
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any

# ---------------------------------------------------------------------------
# Attribute extraction helpers
# ---------------------------------------------------------------------------

_LENGTH_BUCKET_BOUNDARIES = (0, 1, 64, 512, 4096, 32768, 131072, 1048576)


def _bucket_length(n: int) -> str:
    """Map a content-length integer into a coarse size bucket label.

    Boundaries chosen so small/empty responses (0-1 bytes), typical JSON
    fragments (<512 B), page responses (<4 KB / <32 KB / <128 KB), and large
    blobs cluster together rather than spreading across 1000 distinct sizes.
    """
    for lo, hi in zip(_LENGTH_BUCKET_BOUNDARIES, _LENGTH_BUCKET_BOUNDARIES[1:]):
        if lo <= n < hi:
            return f"len_{lo}_{hi}"
    return f"len_{_LENGTH_BUCKET_BOUNDARIES[-1]}+"


def _extract_status(rec: dict) -> str | None:
    """Normalise the HTTP status code to a string key."""
    for key in ("status", "response_status"):
        val = rec.get(key)
        if val is not None:
            return str(val).strip()
    return None


def _extract_length_bucket(rec: dict) -> str | None:
    """Bucket the response body length."""
    for key in ("content_length", "length", "body_len"):
        val = rec.get(key)
        if val is not None:
            try:
                return _bucket_length(int(val))
            except (TypeError, ValueError):
                pass
    return None


def _extract_content_type_coarse(rec: dict) -> str | None:
    """Return the MIME type without parameters (e.g. ``text/html``)."""
    val = rec.get("content_type") or rec.get("mime_type")
    if not val:
        return None
    # Drop charset/boundary params
    return str(val).split(";", 1)[0].strip().lower() or None


def _extract_header_count(rec: dict) -> str | None:
    """Bucket the number of response headers into coarse groups."""
    headers = rec.get("headers")
    if not isinstance(headers, dict):
        return None
    n = len(headers)
    if n == 0:
        return "hdrs_0"
    if n <= 3:
        return "hdrs_1_3"
    if n <= 7:
        return "hdrs_4_7"
    if n <= 15:
        return "hdrs_8_15"
    return "hdrs_16+"


_NOTABLE_HEADERS = (
    "server",
    "x-powered-by",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "set-cookie",
    "www-authenticate",
    "location",
)


def _extract_notable_headers_present(rec: dict) -> str | None:
    """Produce a frozenset-derived string of which notable headers are present.

    Only emits a non-None value when ``headers`` is a dict. The value is a
    sorted comma-joined string so it is hashable for Counter.
    """
    headers = rec.get("headers")
    if not isinstance(headers, dict):
        return None
    present = sorted(
        h for h in _NOTABLE_HEADERS if h in {k.lower() for k in headers}
    )
    return ",".join(present) if present else "(none)"


def _extract_title(rec: dict) -> str | None:
    val = rec.get("title")
    if val is None:
        return None
    s = str(val).strip()
    return s.lower() if s else None


def _extract_words_bucket(rec: dict) -> str | None:
    """Bucket the word count of the response body."""
    val = rec.get("words")
    if val is None:
        return None
    try:
        n = int(val)
    except (TypeError, ValueError):
        return None
    if n == 0:
        return "words_0"
    if n <= 10:
        return "words_1_10"
    if n <= 100:
        return "words_11_100"
    if n <= 500:
        return "words_101_500"
    if n <= 2000:
        return "words_501_2000"
    return "words_2001+"


def _extract_lines_bucket(rec: dict) -> str | None:
    """Bucket the line count of the response body."""
    val = rec.get("lines")
    if val is None:
        return None
    try:
        n = int(val)
    except (TypeError, ValueError):
        return None
    if n == 0:
        return "lines_0"
    if n <= 5:
        return "lines_1_5"
    if n <= 25:
        return "lines_6_25"
    if n <= 100:
        return "lines_26_100"
    return "lines_101+"


# Attribute name → extractor function
# Order is significant: stable iteration order means deterministic output.
_ATTRIBUTE_EXTRACTORS: tuple[tuple[str, Any], ...] = (
    ("status", _extract_status),
    ("length_bucket", _extract_length_bucket),
    ("content_type", _extract_content_type_coarse),
    ("header_count", _extract_header_count),
    ("notable_headers", _extract_notable_headers_present),
    ("title", _extract_title),
    ("words_bucket", _extract_words_bucket),
    ("lines_bucket", _extract_lines_bucket),
)

# ---------------------------------------------------------------------------
# Weight degradation
# ---------------------------------------------------------------------------

_MAX_WEIGHT = 1.0
_MIN_WEIGHT = 0.05


def _attribute_weight(distinct_count: int, population_size: int) -> float:
    """Compute the per-attribute weight.

    Rules (matching reference-project weights.go philosophy):
    - If distinct_count == 1: the attribute does not vary → weight 0.
    - If distinct_count == 2: binary split → maximum weight.
    - As distinct_count approaches population_size, weight degrades towards
      _MIN_WEIGHT on a log scale so a near-unique attribute does not dominate.

    The degradation formula uses log(2) / log(distinct_count) so a 2-value
    attribute gets weight 1.0 and a 1024-value attribute (in any population)
    gets weight log(2)/log(1024) ≈ 0.1.  We clamp to [_MIN_WEIGHT, _MAX_WEIGHT].
    """
    if distinct_count <= 1:
        return 0.0
    if distinct_count == 2:
        return _MAX_WEIGHT
    raw = math.log(2) / math.log(distinct_count)
    return max(_MIN_WEIGHT, min(_MAX_WEIGHT, raw))


# ---------------------------------------------------------------------------
# Core scoring engine
# ---------------------------------------------------------------------------


def _build_frequency_tables(
    records: list[dict],
) -> dict[str, Counter]:
    """Return {attr_name: Counter({value: count})} for all attributes."""
    tables: dict[str, Counter] = {}
    for attr_name, extractor in _ATTRIBUTE_EXTRACTORS:
        counts: Counter = Counter()
        for rec in records:
            val = extractor(rec)
            if val is not None:
                counts[val] += 1
        tables[attr_name] = counts
    return tables


def _score_record(
    rec: dict,
    tables: dict[str, Counter],
    population_size: int,
) -> tuple[float, list[str]]:
    """Compute the anomaly score for a single record.

    Returns (score, anomalous_attributes) where anomalous_attributes is a list
    of ``"attr=value"`` strings for the attributes that contributed signal.
    """
    total_score = 0.0
    anomalous: list[str] = []

    for attr_name, extractor in _ATTRIBUTE_EXTRACTORS:
        table = tables[attr_name]
        distinct_count = len(table)
        weight = _attribute_weight(distinct_count, population_size)
        if weight == 0.0:
            continue

        val = extractor(rec)
        if val is None:
            continue

        count = table.get(val, 0)
        if count == 0:
            continue

        # Rarity score relative to the records where this attribute is PRESENT,
        # not the whole population: records missing the attribute do not appear
        # in the frequency table, so dividing by population_size would inflate
        # the rarity of values that are in fact ubiquitous among present records.
        present_total = sum(table.values())
        # Rarity: 1.0 when count==1 (appears once), 0.0 when count==present_total.
        rarity = max(0.0, 1.0 - count / present_total)
        contribution = weight * rarity
        if contribution > 0.0:
            total_score += contribution
            anomalous.append(f"{attr_name}={val!r}")

    return total_score, anomalous


def score_population(records: list[dict]) -> list[dict]:
    """Score a population of HTTP response records for anomalousness.

    Returns each record annotated with two extra keys:
    - ``anomaly_score`` (float): higher = more anomalous.  Range [0.0, N] where
      N is the number of active attributes.
    - ``anomalous_attributes`` (list[str]): ``"attr=value"`` strings for the
      attributes that pushed the score up.

    The returned list is sorted descending by ``anomaly_score``, with a
    deterministic stable tie-break on ``url`` (falling back to record position
    in the original list) so the output is reproducible regardless of dict
    insertion order.

    Edge cases:
    - Empty population → returns [].
    - Population of one → the single record scores 0.0 (nothing to compare).
    - Missing fields in a record are silently skipped (tolerant).
    """
    if not records:
        return []

    population_size = len(records)
    tables = _build_frequency_tables(records)

    scored: list[dict] = []
    for idx, rec in enumerate(records):
        score, anomalous = _score_record(rec, tables, population_size)
        annotated = dict(rec)
        annotated["anomaly_score"] = round(score, 6)
        annotated["anomalous_attributes"] = anomalous
        # Store original index for stable tie-break under an un-collidable key so
        # a record that legitimately carries an "_orig_idx" field is not clobbered.
        annotated["__anomaly_sort_idx__"] = idx
        scored.append(annotated)

    # Sort: descending score, then ascending url (or original index for stability)
    scored.sort(
        key=lambda r: (
            -r["anomaly_score"],
            str(r.get("url", "")),
            r["__anomaly_sort_idx__"],
        )
    )

    # Remove internal sort key
    for r in scored:
        del r["__anomaly_sort_idx__"]

    return scored
