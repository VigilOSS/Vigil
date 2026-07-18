"""RED-phase precision tests for `assess.lib.classify_buckets`.

Encodes the subset of the classify-surface 2026-06 TEST-MATRIX that this TDD
slice owns:

  * the `{id}` / `{uuid}` / `{n}` path-object-ref placeholder arm (§4.3),
  * the numeric precision predicates — year exclusion (§4.2), small-int
    exclusion, and the "keep 5+ digit numbers" rule,
  * the collection-noun gate that ALLOWS short prefixes (`/efi/...`, §4.2),
  * the ssrf -> redirect key move (§7),
  * `normalize_path_for_cluster` cluster-key collapsing while the raw
    path-object-ref matcher is unaffected (§5 / override #6).

These describe TARGET behaviour and are expected to FAIL against the current
`classify_buckets.py`. Each test is a single focused assertion of one
behaviour and calls `classify_from_fields` exactly as `test_work_buffer.py`
does (via the `_classify_buckets()` import helper). Both positive matches and
the negative guards are covered.

Source of truth: docs/research/classify-surface-2026-06/IMPLEMENTATION-SPEC.md
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Import the real `assess.lib.classify_buckets` module.

    Mirrors the `_classify_buckets()` helper in `test_work_buffer.py` so the
    import path / sys.path wiring is identical.
    """
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _classify(url_path: str, *, case_type: str = "unknown", query_params=None, body_params=None):
    """Thin wrapper over `classify_from_fields` matching the call convention in
    `test_work_buffer.py` (keyword-only, JSON-encoded param strings).

    Default `case_type` is the floor-less, non-inert `unknown` so these
    precision tests isolate the path-object-ref / bucket logic from the
    producer-`type` floor (the real `api` type floors to gf:api/20; the floor is
    covered by `test_classify_type_floor.py`)."""
    cb = _classify_buckets()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query_params or {}),
        body_params=json.dumps(body_params or {}),
    )


# ---------------------------------------------------------------------------
# Placeholder arm: {id} / {uuid} / {n} (§4.3, matrix I4–I7, I9)
# A pre-normalized template segment is an object-ref candidate that bypasses
# the numeric precision predicates but STILL requires a collection-context
# segment somewhere earlier in the path.
# ---------------------------------------------------------------------------


def test_placeholder_id_with_word_context_is_idor() -> None:
    """`/user/{id}` -> idor: `{id}` placeholder with the context word `user` (I6)."""
    assignment = _classify("/user/{id}")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


def test_placeholder_uuid_token_with_context_is_idor() -> None:
    """`{uuid}` placeholder token (not a literal uuid) still routes to idor
    when preceded by a context segment."""
    assignment = _classify("/files/{uuid}")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


def test_placeholder_n_token_with_context_is_idor() -> None:
    """`{n}` placeholder with context `orders` routes to idor (placeholder arm
    bypasses numeric predicates but the context gate still applies)."""
    assignment = _classify("/orders/{n}")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


def test_placeholder_after_context_in_repeated_template_is_idor() -> None:
    """`/{id}/reports/{id}` -> idor: the trailing `{id}` is preceded by the
    context segment `reports` (I7). Matching fires once."""
    assignment = _classify("/{id}/reports/{id}")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


def test_lone_placeholder_n_is_not_idor() -> None:
    """`/{n}/` (lone, no context segment anywhere) MUST NOT match idor (I9)."""
    assignment = _classify("/{n}/")
    assert assignment["cluster_key"] != "gf:idor"
    assert assignment["priority_score"] == 0
    assert "idor" not in assignment["matched_buckets"]


# ---------------------------------------------------------------------------
# Year exclusion (§4.2, matrix I8 analog)
# A 4-digit year in 1900..2099 is NOT a numeric object-ref.
# ---------------------------------------------------------------------------


def test_year_segment_is_not_idor() -> None:
    """`/news/2024/article` MUST NOT be idor: `2024` is a 4-digit year, excluded
    by the year guard even though `news` is valid context."""
    assignment = _classify("/news/2024/article")
    assert assignment["cluster_key"] != "gf:idor"
    assert "idor" not in assignment["matched_buckets"]
    assert assignment["priority_score"] == 0


def test_lone_year_segment_is_not_idor() -> None:
    """`/2024/` (lone year) MUST NOT match idor — year excluded AND no context."""
    assignment = _classify("/2024/")
    assert assignment["cluster_key"] != "gf:idor"
    assert "idor" not in assignment["matched_buckets"]


# ---------------------------------------------------------------------------
# 5+ digit numbers are KEPT (§4.2 "keep 5+ digit numbers" override #5)
# ---------------------------------------------------------------------------


def test_five_digit_numeric_is_idor() -> None:
    """`/orders/19991` IS idor: 5-digit number is NOT a year and passes the
    small-int gate; `orders` is context. (override #5 "keep 5+ digit numbers")"""
    assignment = _classify("/orders/19991")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


def test_five_digit_year_lookalike_is_kept() -> None:
    """`/efi/19991` — `19991` is 5 digits so the year guard (`^(?:19|20)[0-9]{2}$`,
    exactly 4 digits) does NOT reject it; the short prefix `efi` is valid
    context, so it IS idor."""
    assignment = _classify("/efi/19991")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


# ---------------------------------------------------------------------------
# Small-int handling (§4.2, matrix I10)
# A bare 1-digit integer (1..9) is pagination/ordinal noise, not an object-ref.
# A 2+ digit numeric passes the small-int gate.
# ---------------------------------------------------------------------------


def test_single_digit_pagination_is_not_idor() -> None:
    """`/page/2` MUST NOT be idor: `2` is a bare 1-digit small-int (I10)."""
    assignment = _classify("/page/2")
    assert assignment["cluster_key"] != "gf:idor"
    assert "idor" not in assignment["matched_buckets"]
    assert assignment["priority_score"] == 0


def test_two_digit_numeric_with_context_is_idor() -> None:
    """`/users/42` IS idor: `42` is 2 digits (passes the small-int gate) with
    context `users`. (2-digit and up numerics pass.)"""
    assignment = _classify("/users/42")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


# ---------------------------------------------------------------------------
# Collection-noun gate ALLOWS short prefixes (§4.2 override #5, matrix I4–I5)
# A >=2-char non-id word counts as context, explicitly including short
# prefixes like `efi`, `v2`, `wps`. The gate only rejects a LONE id.
# ---------------------------------------------------------------------------


def test_short_prefix_efi_numeric_is_idor() -> None:
    """`/efi/12345` IS idor: short prefix `efi` (>=2 chars, not an id) counts as
    collection context; `12345` is a 5-digit object id."""
    assignment = _classify("/efi/12345")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


def test_short_prefix_efi_placeholder_is_idor() -> None:
    """`/efi/{id}` IS idor: short prefix `efi` allowed as context for the
    placeholder arm (I4)."""
    assignment = _classify("/efi/{id}")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


def test_short_prefix_wps_placeholder_is_idor() -> None:
    """`/wps/{id}` IS idor: short prefix `wps` allowed as context (I5)."""
    assignment = _classify("/wps/{id}")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35


def test_lone_id_with_no_context_is_not_idor() -> None:
    """`/12345` (lone numeric, no preceding context segment) MUST NOT match —
    the collection-noun gate rejects a lone id with no context."""
    assignment = _classify("/12345")
    assert assignment["cluster_key"] != "gf:idor"
    assert "idor" not in assignment["matched_buckets"]


# ---------------------------------------------------------------------------
# ssrf -> redirect key move (§7, matrix S1–S3)
# The six keys redirect/callback/continue/next/link/dest move OUT of ssrf and
# stay in redirect. ssrf still fires via its /proxy/ /fetch/ path fragments.
# ---------------------------------------------------------------------------


def test_next_param_is_redirect_not_ssrf() -> None:
    """`/account/settings?next=/x` -> redirect only; `next` is no longer an ssrf
    key, so the reason chain MUST NOT contain gf:ssrf (S2, override #7 core)."""
    assignment = _classify("/account/settings", query_params={"next": "/x"})
    assert assignment["cluster_key"] == "gf:redirect"
    assert assignment["priority_score"] == 25
    assert "ssrf" not in assignment["matched_buckets"]
    assert "gf:ssrf" not in (assignment["priority_reason"] or "")


def test_next_param_on_auth_path_is_auth_with_redirect_not_ssrf() -> None:
    """`/login?next=/x` -> auth(40) wins the cluster; redirect(25) is in the
    reason chain; gf:ssrf MUST NOT appear (S1)."""
    assignment = _classify("/login", query_params={"next": "/x"})
    assert assignment["cluster_key"] == "gf:auth"
    assert assignment["priority_score"] == 40
    assert "redirect" in assignment["matched_buckets"]
    assert "ssrf" not in assignment["matched_buckets"]
    assert "gf:ssrf" not in (assignment["priority_reason"] or "")


def test_callback_param_is_not_ssrf_key() -> None:
    """`callback` left the ssrf key set. On a path with no ssrf path fragment,
    a bare `?callback=` must NOT fire ssrf (`callback` is not a redirect key
    either, so this falls through to a path cluster)."""
    assignment = _classify("/widget/load", query_params={"callback": "https://x"})
    assert "ssrf" not in assignment["matched_buckets"]
    assert "gf:ssrf" not in (assignment["priority_reason"] or "")


def test_proxy_fetch_url_param_still_ssrf() -> None:
    """`/proxy/fetch?url=...` -> ssrf still fires: `url` stays an ssrf key AND
    the `/proxy/` `/fetch/` path fragments fire (S3). The key move does NOT
    weaken legitimate ssrf detection."""
    assignment = _classify(
        "/proxy/fetch", query_params={"url": "http://169.254.169.254/"}
    )
    assert assignment["cluster_key"] == "gf:ssrf"
    assert assignment["priority_score"] == 40
    assert "ssrf" in assignment["matched_buckets"]


# ---------------------------------------------------------------------------
# normalize_path_for_cluster: cluster-key collapsing (§5 / override #6,
# matrix N1–N4). The fallback path:* cluster key collapses id-shaped segments
# so distinct ids/years share one cluster — but the RAW path-object-ref
# matcher (§4) is unaffected and still fires on the raw url.
# ---------------------------------------------------------------------------


def test_normalize_collapses_year_into_shared_cluster() -> None:
    """`/explore-mvps/2024/M0004` -> `path:/explore-mvps/{year}` (N1):
    the year segment collapses to `{year}` in the fallback cluster key."""
    assignment = _classify("/explore-mvps/2024/M0004", case_type="unknown")
    assert assignment["cluster_key"] == "path:/explore-mvps/{year}"
    assert assignment["priority_score"] == 0


def test_normalize_two_distinct_years_share_one_cluster() -> None:
    """`/explore-mvps/2024/M0004` and `/explore-mvps/2023/G0058` collapse to the
    SAME cluster key (N1 == N2, override #6)."""
    first = _classify("/explore-mvps/2024/M0004", case_type="unknown")
    second = _classify("/explore-mvps/2023/G0058", case_type="unknown")
    assert first["cluster_key"] == second["cluster_key"]
    assert first["cluster_key"] == "path:/explore-mvps/{year}"


def test_normalize_leaves_idless_path_unchanged() -> None:
    """`/about/company/history` has no id-shaped segments, so the normalized
    fallback is unchanged: `path:/about/company` (N4, regression pin)."""
    assignment = _classify("/about/company/history", case_type="unknown")
    assert assignment["cluster_key"] == "path:/about/company"
    assert assignment["priority_score"] == 0


def test_normalize_does_not_suppress_raw_idor_match() -> None:
    """`/orders/000000000000000000001000/view` -> the long-hex object ref fires
    idor on the RAW url; normalization is NEVER consulted for matching (N3,
    override #6). Proves §4 runs on raw url, not the normalized key."""
    assignment = _classify(
        "/orders/000000000000000000001000/view", case_type="unknown"
    )
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35
