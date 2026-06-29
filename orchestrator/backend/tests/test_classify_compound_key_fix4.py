"""Fix 4 — compound-key signal recovery, landed as a TIERED mechanism.

The plan's Fix 4 (split `expand_compound_key` on `_`/`-`/camelCase) is non-additive
if applied naively: the inner tokens `id`/`uri`/`url` are HIGH-WEIGHT generic bucket
keys (sqli@40, ssrf@40), so naive splitting flips pinned clusters (idor->sqli,
oauth->ssrf). Landed instead as three layers:

  1. CURATED whole-keys: the common `*_url`/`*_uri` compound families are listed as
     whole keys on `redirect`/`ssrf`, so they match STRONGLY and route precisely
     (`?return_url=` -> redirect, NOT ssrf). Mirrors idor's `*_id` whole-key idiom.
  2. WEAK inner-token rescue: a compound key's `_`/`-`/camelCase inner tokens match
     at a capped weight (`WEAK_TOKEN_CAP`) and are used ONLY when no strong bucket /
     floor fired, rescuing otherwise-score-0 rows (deep coverage / never miss).
  3. SECONDARY cross-routing: on a strongly-matched row, weak buckets become
     `secondary_buckets` (extra coverage routing) WITHOUT changing cluster_key /
     priority_reason / priority_score / matched_buckets — so the strong row is
     byte-identical yet a cross-class param (e.g. `?id=`+`?userCmd=`) still reaches
     the other specialist.

Mirrors the `_classify_buckets()` loader convention in test_classify_precision.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _cb():
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _classify(url_path="/x", *, case_type="unknown", query=None, body=None, url=None):
    cb = _cb()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query or {}),
        body_params=json.dumps(body or {}),
        url=url,
    )


# --- Layer 1: curated whole-keys route precisely (NOT to ssrf) ----------------

def test_return_url_clusters_redirect_not_ssrf():
    a = _classify(query={"return_url": "https://evil.example/"})
    assert a["cluster_key"] == "gf:redirect"
    assert a["priority_score"] == 25


def test_camelcase_returnurl_clusters_redirect():
    # The typer lowercases keys, so `returnUrl` arrives as `returnurl`, caught by
    # the curated concatenated whole-key form.
    a = _classify(query={"returnUrl": "https://evil.example/"})
    assert a["cluster_key"] == "gf:redirect"


def test_redirect_url_and_callback_url_curated():
    assert _classify(query={"redirect_url": "x"})["cluster_key"] == "gf:redirect"
    assert _classify(query={"callback_url": "x"})["cluster_key"] == "gf:redirect"
    assert _classify(query={"next_url": "x"})["cluster_key"] == "gf:redirect"


def test_server_fetch_compounds_cluster_ssrf():
    assert _classify(query={"fetch_url": "x"})["cluster_key"] == "gf:ssrf"
    assert _classify(query={"proxy_url": "x"})["cluster_key"] == "gf:ssrf"
    assert _classify(query={"webhook_url": "x"})["cluster_key"] == "gf:ssrf"


# --- Layer 2: weak inner-token rescue of otherwise-score-0 rows ---------------

def test_novel_compound_with_cmd_token_rescued_capped():
    """`?user_cmd=` has no strong match; the weak `cmd` token rescues it to rce at
    the capped weak weight (20), not the full rce weight (50)."""
    a = _classify(query={"user_cmd": "ls"})
    assert a["cluster_key"] == "gf:rce"
    assert a["priority_score"] == 20  # WEAK_TOKEN_CAP, not 50


def test_novel_camelcase_compound_rescued():
    # camelCase split runs on the ORIGINAL case: `appRedirect` -> {app, redirect};
    # `redirect` is a redirect-only token, so a novel camelCase compound is rescued.
    a = _classify(query={"appRedirect": "https://evil.example/"})
    assert a["cluster_key"] == "gf:redirect"
    assert a["priority_score"] == 20


def test_weak_rescue_does_not_fire_without_a_known_token():
    """A compound key whose inner tokens match no bucket stays a path:* fallback."""
    a = _classify("/blog/post", query={"some_random_widget": "1"})
    assert a["cluster_key"].startswith("path:")
    assert a["priority_score"] == 0


# --- Layer 3: weak NEVER overrides strong (collision safety) ------------------

def test_workspace_id_stays_idor_sqli_only_secondary():
    """`workspace_id` whole-key -> strong idor. The weak `id` token (an sqli key)
    must NOT flip the cluster to sqli; it appears only as a secondary bucket."""
    a = _classify(query={"workspace_id": "42"})
    assert a["cluster_key"] == "gf:idor"
    assert "sqli" not in (a["priority_reason"] or "")
    assert "sqli" not in a["matched_buckets"]
    assert "sqli" in a["secondary_buckets"]


def test_oauth_redirect_uri_stays_oauth_not_ssrf():
    a = _classify(
        "/oauth2/authorize",
        query={"client_id": "abc", "redirect_uri": "https://app/cb"},
    )
    assert a["cluster_key"] == "gf:oauth-oidc"
    assert "ssrf" not in (a["priority_reason"] or "")
    # the inner `uri` token cross-routes to ssrf as a secondary signal only
    assert "ssrf" in a["secondary_buckets"]


# --- Cross-routing: a strong row still reaches the other specialist -----------

def test_cross_class_row_flags_secondary_bucket():
    """A SQLi-clustered row (`?id=`) carrying a `?userCmd=` param must surface rce
    as a secondary bucket so the row reaches the command-injection specialist too."""
    a = _classify(query={"id": "1", "userCmd": "whoami"})
    assert a["cluster_key"] == "gf:sqli"
    assert "rce" in a["secondary_buckets"]
    assert "rce" not in a["matched_buckets"]  # strong list unchanged


def test_sysparm_url_servicenow_strong_with_redirect_ssrf_secondary():
    """ServiceNow `sysparm_url` keeps its strong servicenow cluster, and the inner
    `url` token cross-routes the open-redirect/SSRF angle as secondary coverage."""
    a = _classify(query={"sysparm_url": "https://login.example/"})
    assert a["cluster_key"] == "gf:servicenow"
    assert set(a["secondary_buckets"]) >= {"redirect", "ssrf"}


# --- Regression: strong rows are byte-identical (no secondary leakage) ---------

def test_avatar_file_exact_reason_chain_unchanged():
    a = _classify("/api/users/avatar", query={"file": "x"})
    assert a["priority_reason"] == "gf:lfi+gf:upload_fields"
    assert a["priority_score"] == 40
    # `file` weak-matches lfi/upload_fields, but both are already strong matches,
    # so the secondary list (weak buckets NOT in matched_buckets) is empty.
    assert a["secondary_buckets"] == []


def test_plain_id_param_unaffected():
    """`?id=` weak-matches sqli/idor, but both are already strong matches on `id`,
    so dedup leaves secondary_buckets empty — the strong row is byte-identical."""
    a = _classify("/p", query={"id": "1"})
    assert a["secondary_buckets"] == []
