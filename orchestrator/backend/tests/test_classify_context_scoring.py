"""Tests for the boost-only context-scoring layer (Fix 1).

Covers the classify-context-and-surface 2026-06 Part 4 "Fix 1" (Issues 1/E/F/G):
threading the row's URL authority, ingest `source`, and `live_status` into
scoring as a STRICTLY boost-only layer.

Pinned guarantees exercised here:
  (i)   a no-context call is byte-identical to the pre-context output (the
        `/api/users/avatar` + `file` case still yields EXACTLY
        `gf:lfi+gf:upload_fields` / 40 when no `url` kwarg is given);
  (ii)  a `host_root` on a `dev.` host scores 15 with cluster still
        `type:host_root`;
  (iii) the non-default-port / source / live bonuses each add their increment
        and STACK;
  (iv)  the bonus never lowers a score and never perturbs
        `cluster_key` / `priority_reason` / `terminal_reason` / `matched_buckets`.

The import + call convention mirrors `_classify_buckets()` in
`test_classify_precision.py` / `test_work_buffer.py`, so these exercise the real
production `assess.lib.classify_buckets` module.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Import the real `assess.lib.classify_buckets` module (shared convention)."""
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


# ---------------------------------------------------------------------------
# (i) no-context call is byte-identical to before
# ---------------------------------------------------------------------------
def test_no_context_avatar_file_is_byte_identical():
    """The pinned `/api/users/avatar` + `file` case is unchanged with no url."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="unknown",
        url_path="/api/users/avatar",
        query_params=json.dumps({"file": "x"}),
        body_params="{}",
        path_params="{}",
    )
    assert assignment["priority_reason"] == "gf:lfi+gf:upload_fields"
    assert assignment["priority_score"] == 40
    assert assignment["cluster_key"] == "gf:lfi"
    assert assignment["terminal_reason"] is None


def test_no_context_matches_default_kwargs_explicitly_none():
    """Passing url/source/live_status=None is identical to omitting them."""
    cb = _classify_buckets()
    base = cb.classify_from_fields(
        case_type="unknown",
        url_path="/api/users/avatar",
        query_params=json.dumps({"file": "x"}),
    )
    explicit = cb.classify_from_fields(
        case_type="unknown",
        url_path="/api/users/avatar",
        query_params=json.dumps({"file": "x"}),
        url=None,
        source=None,
        live_status=None,
    )
    assert base == explicit


# ---------------------------------------------------------------------------
# (ii) host_root rescue on a nonprod/admin host
# ---------------------------------------------------------------------------
def test_host_root_dev_host_scores_15_cluster_unchanged():
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="host_root",
        url_path="/",
        url="https://dev.example.com/",
    )
    assert assignment["priority_score"] == 15
    assert assignment["cluster_key"] == "type:host_root"
    assert assignment["priority_reason"] is None
    assert assignment["terminal_reason"] is None
    assert assignment["matched_buckets"] == []


def test_host_root_prod_host_stays_zero():
    """A plain prod host_root is NOT rescued (precision-negative)."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="host_root",
        url_path="/",
        url="https://www.example.com/",
    )
    assert assignment["priority_score"] == 0
    assert assignment["cluster_key"] == "type:host_root"


def test_host_label_boundary_precision():
    """`development.example.com` must NOT match the `dev` host label."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="host_root",
        url_path="/",
        url="https://development.example.com/",
    )
    assert assignment["priority_score"] == 0


def test_host_label_internal_hyphen_boundary():
    """`api-qa.example.com` matches `qa` at a `-` boundary."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="host_root",
        url_path="/",
        url="https://api-qa.example.com/",
    )
    assert assignment["priority_score"] == 15


# ---------------------------------------------------------------------------
# (iii) port / source / live bonuses add their increment and STACK
# ---------------------------------------------------------------------------
def test_nondefault_port_bonus():
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="host_root",
        url_path="/",
        url="https://www.example.com:9443/",
    )
    assert assignment["priority_score"] == 5


def test_source_analysis_bonus():
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="host_root",
        url_path="/",
        url="https://www.example.com/",
        source="source-analysis",
    )
    assert assignment["priority_score"] == 5


def test_js_extract_source_bonus():
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="host_root",
        url_path="/",
        url="https://www.example.com/",
        source="katana-js-extract",
    )
    assert assignment["priority_score"] == 5


def test_live_status_bonus():
    cb = _classify_buckets()
    for live in ("live", "200"):
        assignment = cb.classify_from_fields(
            case_type="host_root",
            url_path="/",
            url="https://www.example.com/",
            live_status=live,
        )
        assert assignment["priority_score"] == 5, live


def test_context_bonuses_stack():
    """dev host (+15) + non-default port (+5) + source (+5) + live (+5) = 30."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="host_root",
        url_path="/",
        url="https://dev.example.com:9443/",
        source="source-analysis",
        live_status="live",
    )
    assert assignment["priority_score"] == 30
    assert assignment["cluster_key"] == "type:host_root"


def test_context_bonus_helper_never_negative():
    """`_context_bonus` is always >= 0 (boost-only invariant), incl. junk url."""
    cb = _classify_buckets()
    assert cb._context_bonus(None, None, None) == 0
    assert cb._context_bonus("not a url", "gau-archive", "dead") == 0
    assert cb._context_bonus("http://[bad:port/") >= 0
    assert cb._context_bonus("https://dev.example.com:9443/", "source-analysis", "200") == 30


# ---------------------------------------------------------------------------
# (iv) bonus boosts a matched/floor/fallback score without perturbing routing
# ---------------------------------------------------------------------------
def test_matched_bucket_score_is_boosted_routing_unchanged():
    """A matched bucket on a dev host: score boosted by 15, reason/cluster fixed."""
    cb = _classify_buckets()
    base = cb.classify_from_fields(
        case_type="unknown",
        url_path="/api/users/avatar",
        query_params=json.dumps({"file": "x"}),
    )
    boosted = cb.classify_from_fields(
        case_type="unknown",
        url_path="/api/users/avatar",
        query_params=json.dumps({"file": "x"}),
        url="https://dev.example.com/api/users/avatar",
    )
    assert boosted["priority_score"] == base["priority_score"] + 15
    assert boosted["priority_reason"] == base["priority_reason"]
    assert boosted["cluster_key"] == base["cluster_key"]
    assert boosted["terminal_reason"] == base["terminal_reason"]
    assert boosted["matched_buckets"] == base["matched_buckets"]


def test_floor_score_is_boosted_routing_unchanged():
    """A type-floor row (`api` → gf:api/20) is boosted but keeps its cluster."""
    cb = _classify_buckets()
    base = cb.classify_from_fields(case_type="api", url_path="/foo/bar")
    boosted = cb.classify_from_fields(
        case_type="api",
        url_path="/foo/bar",
        url="https://stage.example.com/foo/bar",
    )
    assert base["cluster_key"] == "gf:api"
    assert boosted["priority_score"] == base["priority_score"] + 15
    assert boosted["priority_reason"] == base["priority_reason"]
    assert boosted["cluster_key"] == base["cluster_key"]


def test_path_fallback_score_is_boosted():
    """An unmatched, unfloored row gets the bonus on the path:* fallback."""
    cb = _classify_buckets()
    base = cb.classify_from_fields(case_type="unknown", url_path="/static/brochure")
    boosted = cb.classify_from_fields(
        case_type="unknown",
        url_path="/static/brochure",
        url="https://internal.example.com/static/brochure",
    )
    assert base["priority_score"] == 0
    assert boosted["priority_score"] == 15
    assert boosted["cluster_key"] == base["cluster_key"]
    assert boosted["priority_reason"] == base["priority_reason"]


def test_dead_archive_context_is_neutral_not_terminal():
    """Archive provenance and a dead verdict never become a hidden skip gate."""
    cb = _classify_buckets()
    base = cb.classify_from_fields(
        case_type="unknown",
        url_path="/static/brochure",
    )
    dead_archive = cb.classify_from_fields(
        case_type="unknown",
        url_path="/static/brochure",
        url="https://www.example.com/static/brochure",
        source="gau-archive",
        live_status="dead",
    )
    assert dead_archive == base
    assert dead_archive["terminal_reason"] is None


def test_inert_and_sourcemap_never_boosted():
    """Inert + sourcemap branches stay fixed even on a nonprod host."""
    cb = _classify_buckets()
    inert = cb.classify_from_fields(
        case_type="image",
        url_path="/logo.png",
        url="https://dev.example.com:9443/logo.png",
        source="source-analysis",
        live_status="live",
    )
    assert inert["priority_score"] == 0
    assert inert["terminal_reason"] == "inert_type"

    smap = cb.classify_from_fields(
        case_type="sourcemap",
        url_path="/app.js.map",
        url="https://dev.example.com:9443/app.js.map",
        source="source-analysis",
        live_status="live",
    )
    # sourcemap is pinned to the interestingext weight, NOT boosted.
    assert smap["priority_score"] == cb._INTERESTINGEXT_WEIGHT
    assert smap["cluster_key"] == "gf:interestingext"
