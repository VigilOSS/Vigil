"""RED-phase tests for the producer-`type` → bucket/floor mechanism.

Encodes the §2 ("Type → (bucket, floor weight) table") and the §2.2 floor
application rule from the authoritative spec
``docs/plans/research/classify-surface-2026-06/IMPLEMENTATION-SPEC.md`` —
specifically the T-group rows of the consolidated test matrix (§12.1).

These tests describe TARGET behaviour for
``agent/scripts/assess/lib/classify_buckets.py`` and are EXPECTED to fail
against the current code (the `_TYPE_FLOOR` mapping and the floor-only
``cluster_key = gf:<floor_bucket>`` branch do not exist yet). They must,
however, COLLECT cleanly: any failure here is a behavioural/assertion failure,
never an import/collection error.

Import + invocation conventions mirror ``test_work_buffer.py``: we put
``agent/scripts`` on ``sys.path`` and import ``assess.lib.classify_buckets``
through a helper, then call ``classify_from_fields`` (keyword-only,
JSON-string params) exactly as that suite does. ``classify_row`` is exercised
through the same dict shape ``classify_from_fields`` builds internally.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Load the classifier module the same way ``test_work_buffer.py`` does."""
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _floor_assignment(case_type: str, url_path: str, **params):
    """Classify a single row via ``classify_from_fields`` (mirrors the suite).

    ``params`` accepts ``query_params`` / ``body_params`` as plain dicts and
    JSON-encodes them — ``classify_from_fields`` expects JSON strings, exactly
    as ``test_work_buffer.py`` passes them.
    """
    cb = _classify_buckets()
    kwargs: dict[str, str] = {}
    if "query_params" in params:
        kwargs["query_params"] = json.dumps(params["query_params"])
    if "body_params" in params:
        kwargs["body_params"] = json.dumps(params["body_params"])
    return cb.classify_from_fields(case_type=case_type, url_path=url_path, **kwargs)


# ---------------------------------------------------------------------------
# Behaviour 1: the type -> (floor_bucket, floor_weight) table (§2.1).
# One assertion-focused test per row, exercised in the floor-only form
# (no bucket fires) so the table's weight + bucket label are isolated.
# ---------------------------------------------------------------------------


def test_floor_table_api_route_floors_to_api_weight_20() -> None:
    """T2: `api_route` with no firing bucket floors to gf:api at weight 20."""
    a = _floor_assignment("api_route", "/api/testplans")
    assert a["priority_score"] == 20
    assert a["cluster_key"] == "gf:api"


def test_floor_table_api_spec_floors_to_api_spec_weight_40() -> None:
    """T3: `api_spec` floors to the label-only gf:api_spec at weight 40."""
    a = _floor_assignment("api_spec", "/api/swagger.json")
    assert a["priority_score"] == 40
    assert a["cluster_key"] == "gf:api_spec"


def test_floor_table_auth_entry_floors_to_auth_weight_40() -> None:
    """T4: `auth_entry` floors to gf:auth at weight 40 (no auth fragment on path)."""
    a = _floor_assignment("auth_entry", "/efi/account")
    assert a["priority_score"] == 40
    assert a["cluster_key"] == "gf:auth"


def test_floor_table_form_floors_to_auth_weight_30() -> None:
    """T5: `form` floors to gf:auth at the lower weight 30."""
    a = _floor_assignment("form", "/contact-us")
    assert a["priority_score"] == 30
    assert a["cluster_key"] == "gf:auth"


def test_floor_table_portal_session_floors_to_auth_weight_35() -> None:
    """T6: `portal_session` floors to gf:auth at weight 35."""
    a = _floor_assignment("portal_session", "/myportal/home")
    assert a["priority_score"] == 35
    assert a["cluster_key"] == "gf:auth"


def test_floor_table_debug_config_floors_to_debug_logic_weight_35() -> None:
    """T11: `debug_config` floors to gf:debug_logic at weight 35."""
    a = _floor_assignment("debug_config", "/some/opaque/path")
    assert a["priority_score"] == 35
    assert a["cluster_key"] == "gf:debug_logic"


def test_floor_table_workflow_floors_to_idor_weight_30() -> None:
    """T12: `workflow` floors to gf:idor at weight 30."""
    a = _floor_assignment("workflow", "/wizard/step/two")
    assert a["priority_score"] == 30
    assert a["cluster_key"] == "gf:idor"


def test_floor_table_event_feed_floors_to_ssrf_weight_25() -> None:
    """§2.1 `event_feed` row: floors to gf:ssrf at weight 25 when no bucket fires."""
    a = _floor_assignment("event_feed", "/some/plain/route")
    assert a["priority_score"] == 25
    assert a["cluster_key"] == "gf:ssrf"


def test_floor_table_graphql_floors_to_graphql_weight_45() -> None:
    """§2.1 `graphql` row: floors to gf:graphql at weight 45 even with no
    graphql path fragment / param (isolates the floor from the bucket)."""
    a = _floor_assignment("graphql", "/data/feed")
    assert a["priority_score"] == 45
    assert a["cluster_key"] == "gf:graphql"


# ---------------------------------------------------------------------------
# Behaviour 2: the cluster_key = gf:<floor_bucket> fix when NO bucket matched.
# The floor-only branch must set cluster_key, priority_reason AND
# matched_buckets from the floor bucket (NOT a path:* fallback). (§2.2)
# ---------------------------------------------------------------------------


def test_floor_only_cluster_key_is_gf_floor_bucket_not_path_fallback() -> None:
    """T2: a floored, bucket-less row clusters as gf:<floor_bucket>, never path:*."""
    a = _floor_assignment("api_route", "/api/testplans")
    assert a["cluster_key"] == "gf:api"
    assert not a["cluster_key"].startswith("path:")


def test_floor_only_priority_reason_is_gf_floor_bucket() -> None:
    """T2: floor-only priority_reason is the single gf:<floor_bucket> token."""
    a = _floor_assignment("api_route", "/api/testplans")
    assert a["priority_reason"] == "gf:api"


def test_floor_only_matched_buckets_is_floor_bucket() -> None:
    """T2: floor-only matched_buckets carries the floor bucket so the 2b bridge
    and fetch-by-priority route it."""
    a = _floor_assignment("api_route", "/api/testplans")
    assert a["matched_buckets"] == ["api"]


def test_floor_only_api_spec_label_routes_as_gf_api_spec() -> None:
    """T3: the `api_spec` floor is a label with no _BUCKETS entry — it still
    produces a fully-populated gf:api_spec floor-only assignment."""
    a = _floor_assignment("api_spec", "/api/swagger.json")
    assert a["cluster_key"] == "gf:api_spec"
    assert a["priority_reason"] == "gf:api_spec"
    assert a["matched_buckets"] == ["api_spec"]
    assert a["terminal_reason"] is None


def test_unfloored_type_with_no_bucket_still_falls_through_to_path() -> None:
    """T13 (negative guard): a type NOT in the floor table and matching no
    bucket must keep the path:* fallback — the floor branch must not hijack
    every bucket-less row."""
    a = _floor_assignment("unknown", "/some/plain/route")
    assert a["priority_score"] == 0
    assert a["cluster_key"].startswith("path:")
    assert a["priority_reason"] is None
    assert a["matched_buckets"] == []


# ---------------------------------------------------------------------------
# Behaviour 3: inert / sourcemap / host_root early-returns still WIN over the
# floor (the floor is applied AFTER these short-circuits — §0.7, §2.2). These
# are the negative guards: adding the floor must not perturb the precedence.
# ---------------------------------------------------------------------------


def test_inert_type_early_return_wins_over_floor() -> None:
    """T8: an inert type short-circuits to type:<t> + inert_type, regardless of
    any later floor logic; floor never resurrects an inert row."""
    a = _floor_assignment("image", "/static/logo.png")
    assert a["priority_score"] == 0
    assert a["cluster_key"] == "type:image"
    assert a["terminal_reason"] == "inert_type"
    assert a["matched_buckets"] == []


def test_sourcemap_early_return_wins_over_floor() -> None:
    """T9: sourcemap short-circuits to gf:interestingext at the interestingext
    weight before the floor stage runs."""
    cb = _classify_buckets()
    a = _floor_assignment("sourcemap", "/static/app.js.map")
    assert a["priority_score"] == cb._INTERESTINGEXT_WEIGHT
    assert a["cluster_key"] == "gf:interestingext"
    assert a["priority_reason"] == "gf:interestingext"
    assert a["terminal_reason"] is None


def test_host_root_early_return_wins_over_floor() -> None:
    """T10: host_root short-circuits to type:host_root at score 0, staying
    pending (no terminal_reason); the floor stage must not touch it."""
    a = _floor_assignment("host_root", "/")
    assert a["priority_score"] == 0
    assert a["cluster_key"] == "type:host_root"
    assert a["terminal_reason"] is None


# ---------------------------------------------------------------------------
# Behaviour 4: score = max(floor, match) — the floor NEVER lowers an existing
# bucket-driven result, and when a real bucket matched the cluster stays the
# bucket winner (the floor's own bucket name is NOT injected into the reason
# chain). (§2.2 invariants, T7.)
# ---------------------------------------------------------------------------


def test_floor_does_not_lower_a_higher_bucket_match() -> None:
    """T7: `event_feed` floors at 25 but a real ssrf bucket (40) fires on
    /proxy/fetch?url=... — score is max(40,25)=40 and the cluster stays gf:ssrf."""
    a = _floor_assignment(
        "event_feed", "/proxy/fetch", query_params={"url": "http://x"}
    )
    assert a["priority_score"] == 40
    assert a["cluster_key"] == "gf:ssrf"
    assert "gf:ssrf" in a["priority_reason"]


def test_floor_bucket_name_not_injected_into_reason_when_bucket_matched() -> None:
    """§2.2 invariant: when a real bucket match exists the floor only raises the
    number — the floor bucket's gf token is NOT appended to the reason chain.

    `form` floors to gf:auth(30); a path firing rce(50) wins. The cluster is
    gf:rce, the score is 50, and gf:auth (the floor token) is absent from the
    reason chain."""
    a = _floor_assignment("form", "/admin/exec/run", query_params={"cmd": "id"})
    assert a["priority_score"] == 50
    assert a["cluster_key"] == "gf:rce"
    assert "gf:rce" in a["priority_reason"]
    assert "gf:auth" not in a["priority_reason"]


def test_floor_raises_score_but_cluster_stays_bucket_winner() -> None:
    """§2.2 invariant: when the floor is HIGHER than the (sole) bucket match, the
    score is raised to the floor but the cluster_key still follows the bucket
    winner — the floor only raises the number, never the routing.

    `auth_entry` floors at 40; a `name=` param fires only xss(20). score becomes
    max(20,40)=40, cluster stays gf:xss, and gf:auth (the floor) is not in the
    reason chain."""
    a = _floor_assignment("auth_entry", "/search", query_params={"name": "x"})
    assert a["priority_score"] == 40
    assert a["cluster_key"] == "gf:xss"
    assert "gf:xss" in a["priority_reason"]
    assert "gf:auth" not in a["priority_reason"]


def test_floor_only_branch_has_no_terminal_reason() -> None:
    """§2.2: floor-only rows stay actionable — terminal_reason is None so
    fetch-by-priority does not exclude them."""
    a = _floor_assignment("workflow", "/wizard/step/two")
    assert a["terminal_reason"] is None


# ---------------------------------------------------------------------------
# Behaviour 5: producer-vocabulary alignment (regression for the floor-key
# mismatch). The floor table MUST key on the types the producer actually emits.
# `assess.lib.classify.classify_type()` (the dominant categorizer) emits `api`
# (the dominant API type) and `api-spec` (HYPHEN); `candidate_type()` relabels
# `api` -> `api_route`. The original floor table only had `api_route` and an
# underscore `api_spec`, so the 1,000+ producer-`api` rows and the real
# hyphenated `api-spec` rows silently got NO floor. These tests pin the fix.
# ---------------------------------------------------------------------------


def test_producer_api_type_floors_to_gf_api_weight_20() -> None:
    """REGRESSION: the producer's dominant `api` type (NOT `api_route`) floors to
    gf:api at weight 20 when no bucket fires. `/api/...` is deliberately not an
    `api` bucket fragment, so a params-less `/api/testplans` row matches no
    bucket and MUST be rescued by the type floor — previously it scored 0."""
    a = _floor_assignment("api", "/api/testplans")
    assert a["priority_score"] == 20
    assert a["cluster_key"] == "gf:api"
    assert a["priority_reason"] == "gf:api"
    assert a["matched_buckets"] == ["api"]
    assert a["terminal_reason"] is None


def test_producer_api_and_api_route_resolve_to_same_floor() -> None:
    """`api` (classify_type) and `api_route` (candidate_type's relabel) are the
    SAME semantic type and MUST produce an identical floor assignment."""
    a_api = _floor_assignment("api", "/api/testplans")
    a_route = _floor_assignment("api_route", "/api/testplans")
    assert a_api == a_route


def test_producer_api_spec_hyphen_floors_like_api_spec_underscore() -> None:
    """REGRESSION: the producer emits `api-spec` (HYPHEN) but the floor key was
    `api_spec` (underscore). The hyphen→underscore normalization must make the
    real `api-spec` type floor to the label-only gf:api_spec at weight 40,
    exactly as the underscore spelling does."""
    a_hyphen = _floor_assignment("api-spec", "/api/swagger.json")
    a_underscore = _floor_assignment("api_spec", "/api/swagger.json")
    assert a_hyphen["priority_score"] == 40
    assert a_hyphen["cluster_key"] == "gf:api_spec"
    assert a_hyphen["priority_reason"] == "gf:api_spec"
    assert a_hyphen["matched_buckets"] == ["api_spec"]
    assert a_hyphen == a_underscore


def test_floor_type_normalization_is_case_and_separator_insensitive() -> None:
    """The floor lookup normalizes case + hyphen/underscore, so any spelling
    variant of a floored type resolves to the same floor. Pins the durable
    mechanism (not just the two specific api spellings)."""
    cb = _classify_buckets()
    # Direct unit check of the normalizer helper.
    assert cb._normalize_floor_type("API-Spec") == "api_spec"
    assert cb._normalize_floor_type("api_route") == "api_route"
    assert cb._normalize_floor_type("GraphQL") == "graphql"
    # End-to-end: an upper/mixed-case + hyphen variant still floors.
    a = _floor_assignment("API-SPEC", "/openapi.json")
    assert a["cluster_key"] == "gf:api_spec"
    assert a["priority_score"] == 40


def test_existing_floor_types_unaffected_by_normalization() -> None:
    """Negative guard: the normalization + new api keys must NOT change any of
    the other floor types. graphql/auth_entry/form/portal_session/debug_config/
    workflow/event_feed all keep their exact (bucket, weight)."""
    cases = {
        "graphql": ("gf:graphql", 45),
        "auth_entry": ("gf:auth", 40),
        "form": ("gf:auth", 30),
        "portal_session": ("gf:auth", 35),
        "debug_config": ("gf:debug_logic", 35),
        "workflow": ("gf:idor", 30),
        "event_feed": ("gf:ssrf", 25),
    }
    for case_type, (expected_cluster, expected_score) in cases.items():
        a = _floor_assignment(case_type, "/some/opaque/route")
        assert a["cluster_key"] == expected_cluster, case_type
        assert a["priority_score"] == expected_score, case_type
        assert a["terminal_reason"] is None, case_type


def test_producer_api_floor_does_not_lower_a_real_bucket_match() -> None:
    """The §2.2 max(floor,match) invariant holds for the new `api` key too: a
    real graphql bucket (45) on an `api`-typed graphql route keeps score 45 and
    cluster gf:graphql — the api floor (20) never lowers it or hijacks routing."""
    a = _floor_assignment("api", "/api/graphql", query_params={"query": "{x}"})
    assert a["priority_score"] == 45
    assert a["cluster_key"] == "gf:graphql"
    assert "gf:graphql" in a["priority_reason"]
