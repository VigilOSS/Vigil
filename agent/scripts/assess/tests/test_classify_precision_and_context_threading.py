"""Three classifier defects found by the 2026-09 vocabulary audit, pinned.

Each was reproduced by execution against the production
``assess.lib.classify_buckets`` before the fix:

  1. ``_UPLOAD_GENERIC_SHADOWS`` omitted ``img_traversal``, so an ``upload``
     row whose only field name is ``image``/``photo``/``thumbnail`` — the
     avatar / profile-picture shape the shadow override exists for — clustered
     ``gf:img_traversal`` at 35 while the byte-identical ``file`` row clustered
     ``gf:upload_fields`` at 40.
  2. A bare ``?query=`` won ``gf:graphql`` at weight 45 on any REST search
     route, indistinguishable from a real ``/graphql`` row. ``classify_buckets``
     already documents why ``/query`` is NOT a graphql PATH fragment ("it would
     mis-bucket REST search routes at weight 45") — the param key then produced
     exactly that misroute.
  3. Three ``classify_row``/``classify_from_fields`` call sites dropped the
     row's ``url``/``source``/``live_status``, silently disabling BOTH the
     ``_context_bonus`` boost (up to +30) and the ``_FULL_URL_REGEX_BUCKETS``
     pass (``cloud_metadata`` / ``object-storage``) for every arjun-discovered
     param, every ``--retype`` row, and the coverage-gate bucket tally.

Fix 2 then regressed GraphQL-over-GET, which this file also pins. Its
corroboration set could only see a POST: ``classify_type()`` derives the
``graphql`` producer type from the path, the content-type, or a braced ``query``
value in the BODY — never from the query string — so
``GET /api/data?query={users{id,email}}``, the documented example in
``agent/references/gf-patterns/graphql.md``, typed ``api`` and lost its graphql
match. The corroboration set now also reads the ``query`` VALUE with the
identical ``{``…``}`` selection-set heuristic ``classify_type`` uses for bodies.

Every routing assertion is swept across ``_PRODUCTION_CASE_TYPES``. The original
file tested only ``case_type="unknown"``: a real producer output
(``classify_type()`` step 19) but the RESIDUAL one. Because the suppression
predicate branches on ``case_type``, a single-type sweep could not fail on a
``case_type`` mutation at all — widening the ``graphql`` escape to
``in ("graphql", "api")``, i.e. fully disabling the suppression for the dominant
row type of an API corpus, broke nothing.

The assertions below are behavioural (scores, cluster keys, reason chains,
tallies), never monkeypatch call-shape checks, so they keep holding if a call
site is refactored as long as the context still reaches the classifier.
"""
from __future__ import annotations

import contextlib
import io
import json

import pytest

from assess.commands import ingest_arjun
from assess.commands.dispatch import work_items as wi
from assess.lib import classify
from assess.lib import classify_buckets as cb
from assess.lib import coverage_checks

from _fake_client import FakeAssessmentClient


# The `case_type` values the PRODUCERS actually emit, taken from every
# `return "..."` in `classify.classify_type()` and
# `candidate_records.candidate_type()`, minus the inert/sourcemap/host_root types
# `classify_row` early-returns on before any bucket runs. `api` leads the tuple:
# `classify_type()` step 4 types every `/api/...` route that way, so it is the
# dominant row type in an API corpus AND the one the graphql suppression's
# `case_type` branch has to get right.
_PRODUCTION_CASE_TYPES: tuple[str, ...] = (
    "api", "page", "form", "api_route", "auth_entry", "unknown",
)


def _classify(case_type: str = "api", url_path: str = "", **params: str) -> dict:
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(params) if params else "{}",
    )


# ---------------------------------------------------------------------------
# 1. The upload shadow override must cover `img_traversal`.
# ---------------------------------------------------------------------------

def _upload(field: str) -> dict:
    return cb.classify_from_fields(
        case_type="upload",
        url_path="/profile/avatar",
        body_params=json.dumps({field: "@a.png"}),
    )


def test_avatar_upload_field_names_cluster_as_upload_not_img_traversal() -> None:
    """`image` and `photo` are the two names shared by `img_traversal` (35) and
    `upload_fields` (30). On an `upload`-typed row the multipart bucket owns the
    cluster — that is the whole point of `select_cluster_bucket`'s shadow
    override, which previously listed only `lfi`/`idor`."""
    for field in ("image", "photo"):
        result = _upload(field)
        assert result["cluster_key"] == "gf:upload_fields", (
            f"upload field {field!r} clustered {result['cluster_key']!r} "
            f"(matched={result['matched_buckets']})"
        )
        assert result["priority_score"] == 35, result
        assert "img_traversal" in result["matched_buckets"], (
            "img_traversal must still be RECORDED — the override moves the "
            "cluster pick only, it never drops a match from the chain"
        )


def test_upload_shadow_override_is_scoped_to_upload_typed_rows() -> None:
    """A non-`upload` row keyed `image` keeps `gf:img_traversal` — the shadow is
    an upload-only disambiguation, not a global demotion of the bucket."""
    result = cb.classify_from_fields(
        case_type="unknown",
        url_path="/render",
        query_params=json.dumps({"image": "../../etc/passwd"}),
    )
    assert result["cluster_key"] == "gf:img_traversal"


# ---------------------------------------------------------------------------
# 2. A bare `?query=` must not win `gf:graphql` — but a BRACED `?query=` must.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize("path", ["/api/v2/products/search", "/blog/search"])
def test_bare_query_param_on_a_rest_search_route_is_not_graphql(
    path: str, case_type: str
) -> None:
    """`/api/v2/products/search?query=shoes` and `/blog/search?query=x` carry no
    GraphQL evidence beyond the single most overloaded key in the table.

    Swept across every producer type: the suppression BRANCHES on `case_type`, so
    the `api` row — which `classify_type()` step 4 produces for every `/api/...`
    route, i.e. most of an API corpus — is the one that has to hold."""
    result = _classify(case_type=case_type, url_path=path, query="shoes")
    assert "graphql" not in result["matched_buckets"], (
        f"{path} still routes to graphql (matched={result['matched_buckets']})"
    )
    assert result["cluster_key"] == "gf:sqli", result
    assert result["priority_score"] == 40, result


def test_bare_query_param_keeps_its_real_sqli_and_xss_signal() -> None:
    """The multi-bucket part of `query`'s overlap is intentional and stays."""
    result = _classify(url_path="/api/v1/products/search", query="widget")
    assert set(result["matched_buckets"]) >= {"sqli", "xss"}


def test_query_on_a_graphql_path_still_wins_graphql_with_the_pinned_chain() -> None:
    """A real GraphQL row is byte-identical to before: the path fragment fires
    graphql in declaration order, so the reason chain keeps `gf:graphql` first."""
    result = _classify(url_path="/graphql", query="{me{id}}")
    assert result["cluster_key"] == "gf:graphql"
    assert result["priority_score"] == 45
    assert result["priority_reason"] == "gf:graphql+gf:sqli+gf:xss"


def test_query_corroborated_by_a_second_graphql_key_still_wins_graphql() -> None:
    """GraphQL mounted at a non-canonical path is recovered by any of its other
    canonical request keys — those remain unambiguous and fire on their own."""
    for partner in ("operationName", "variables", "mutation"):
        result = cb.classify_from_fields(
            case_type="unknown",
            url_path="/custom",
            body_params=json.dumps({"query": "{me}", partner: "x"}),
        )
        assert result["cluster_key"] == "gf:graphql", (partner, result)


def test_query_on_a_producer_typed_graphql_row_still_wins_graphql() -> None:
    """`classify_type()` types a POST body carrying a braced `query` as
    `graphql`, so `POST /custom {"query":"{me}"}` keeps its graphql routing
    through the producer type rather than through the ambiguous key."""
    result = cb.classify_from_fields(
        case_type="graphql",
        url_path="/custom",
        body_params=json.dumps({"query": "{me}"}),
    )
    assert result["cluster_key"] == "gf:graphql"
    assert result["priority_score"] == 45


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize(
    "value",
    [
        "{users{id,email}}",                     # graphql.md's documented example
        "query GetUser($id:ID!){user(id:$id){email}}",
        "{__schema{types{name}}}",               # introspection probe
    ],
)
def test_graphql_over_get_is_corroborated_by_the_braced_query_value(
    value: str, case_type: str
) -> None:
    """The regression Fix 2 introduced. `classify_type()` derives the `graphql`
    producer type from the path, the content-type, or a braced `query` value in
    the BODY — it never reads the query string — so a GET carrying the identical
    evidence typed `api` and had no corroborator at all. GraphQL-over-GET is a
    supported transport (it is how `graphiql` issues its own requests and the
    only form a URL corpus can capture), and
    `https://target.example/api/data?query={users{id,email}}` is the documented
    example in `agent/references/gf-patterns/graphql.md`."""
    result = _classify(case_type=case_type, url_path="/api/data", query=value)
    assert result["cluster_key"] == "gf:graphql", result
    assert result["priority_score"] == 45, result


def test_the_braced_value_corroborator_is_the_typers_own_heuristic() -> None:
    """Deliberately the SAME `"{" in v and "}" in v` test `classify_type()` step 1
    applies to a body, not a stricter one. A stricter regex here would make the
    classifier disagree with the typer on identical evidence: the POST would type
    `graphql` (and keep its match through the producer-type escape) while the GET
    was suppressed. A JSON filter value (`?query={"status":"open"}`) satisfies
    both, which is the accepted cost of that consistency — it is the typer's
    pre-existing false positive, not a new one."""
    braced = cb.classify_from_fields(
        case_type="api", url_path="/api/data",
        query_params=json.dumps({"query": '{"status":"open"}'}),
    )
    typed = cb.classify_from_fields(
        case_type=classify.classify_type(
            "POST", "/api/data", "application/json",
            json.dumps({"query": '{"status":"open"}'}),
        ),
        url_path="/api/data",
        body_params=json.dumps({"query": '{"status":"open"}'}),
    )
    assert braced["cluster_key"] == typed["cluster_key"] == "gf:graphql"


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
def test_an_unbraced_query_value_is_not_corroboration(case_type: str) -> None:
    """The corroborator reads the VALUE SHAPE, not the key's presence: a plain
    search term keeps the row on `sqli`, which is the whole point of Fix 2."""
    for value in ("shoes", "SELECT 1", "", "users"):
        result = _classify(case_type=case_type, url_path="/api/data", query=value)
        assert "graphql" not in result["matched_buckets"], (value, result)


def test_the_braced_value_corroborator_reads_bodies_and_path_params_too() -> None:
    """`collect_keys` unions all three param columns, so the value scan must too —
    otherwise a body-carried braced query on an `api`-typed row (the producer
    types on the PATH before it ever reads the body) would still be suppressed."""
    result = cb.classify_from_fields(
        case_type="api",
        url_path="/api/data",
        body_params=json.dumps({"query": "{me{id}}"}),
    )
    assert result["cluster_key"] == "gf:graphql", result


def test_unambiguous_graphql_keys_fire_without_any_query_param() -> None:
    for key in ("mutation", "subscription", "operationname", "variables"):
        result = _classify(url_path="/custom", **{key: "x"})
        assert "graphql" in result["matched_buckets"], (key, result)


# ---------------------------------------------------------------------------
# 3. Call sites must thread `url` / `source` / `live_status`.
# ---------------------------------------------------------------------------

def test_arjun_enrichment_threads_the_rows_url_source_and_liveness() -> None:
    """`ingest-arjun` enrichment re-classifies an EXISTING row; the row already
    holds the authority, ingest source and liveness the boost layer reads, so
    dropping them under-scored every arjun-discovered parameter by up to 30."""
    row = {
        "id": 1,
        "queue_key": "variant:1:api",
        "type": "api",
        "url": "https://admin.dev.example.com:9443/orders",
        "url_path": "/orders",
        "host": "admin.dev.example.com",
        "source": "source-analysis",
        "live_status": "200",
        "method": "GET",
        "query_params": "{}",
        "body_params": "{}",
        "path_params": "{}",
        "priority_score": 0,
    }
    record = {
        "endpoint": "https://admin.dev.example.com:9443/orders",
        "method": "GET",
        "params": ["id"],
        "header_params": [],
    }

    summary, item = ingest_arjun._enrich_existing(row, record)

    # base 40 (gf:sqli+gf:idor) + 15 nonprod host + 5 port + 5 source + 5 live.
    assert item["priority_score"] == 70, item
    assert summary["priority_score"] == 70
    assert item["cluster_key"] == "gf:sqli"


def test_retype_pass_threads_the_rows_url_source_and_liveness(capsys) -> None:
    """The `--retype` pass re-classifies from a hand-built mirror dict; it
    dropped `url`/`source`/`live_status` while its sibling `_reclassify` branch
    passed all three."""
    fake = FakeAssessmentClient()
    row_id = int(
        fake.add_row(
            queue_key="variant:1:unknown",
            type="unknown",
            status="pending",
            method="POST",
            url="https://admin.dev.example.com:9443/submit",
            url_path="/submit",
            host="admin.dev.example.com",
            source="source-analysis",
            live_status="200",
            content_type="application/x-www-form-urlencoded",
            body="",
            query_params="{}",
            body_params="{}",
            path_params="{}",
            priority_score=0,
            cluster_key=None,
            terminal_reason=None,
        )["id"]
    )

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        wi._reclassify_retype(fake, batch=100, retype_all=False)

    row = fake.row_by_id(row_id)
    assert row["type"] == "form", f"expected unknown -> form, got {row['type']!r}"
    # `form` floors to gf:auth/30, +15 host +5 port +5 source +5 live = 60.
    assert row["priority_score"] == 60, row


def test_coverage_bucket_tally_threads_the_rows_url() -> None:
    """The coverage gate re-classifies rows with no stored `cluster_key`. The
    `object-storage` / `cloud_metadata` markers live in the URL AUTHORITY, so
    without `url=` the `_FULL_URL_REGEX_BUCKETS` pass cannot run at all and the
    row lands in the untyped `""` fallback bucket."""
    fake = FakeAssessmentClient()
    fake.add_row(
        queue_key="seed:1",
        type="unknown",
        status="pending",
        terminal_reason=None,
        host="mybucket.s3.amazonaws.com",
        url="https://mybucket.s3.amazonaws.com/assets/logo",
        url_path="/assets/logo",
        query_params="{}",
        body_params="{}",
        path_params="{}",
        cluster_key=None,
    )

    tally = coverage_checks._pending_buckets_for_host(
        fake, {"host": "mybucket.s3.amazonaws.com", "entry_kind": "host"}
    )
    assert tally == {"object-storage": 1}, tally


# ---------------------------------------------------------------------------
# Versioning: the table edits above must move the stamp, and the new suppression
# branch must move the hand-maintained logic revision.
# ---------------------------------------------------------------------------

def test_upload_shadow_set_and_logic_revision_feed_the_classifier_stamp() -> None:
    assert "img_traversal" in cb._UPLOAD_GENERIC_SHADOWS
    assert cb._CLASSIFIER_VERSION_INPUTS["upload_generic_shadows"] is (
        cb._UPLOAD_GENERIC_SHADOWS
    )
    assert cb._CLASSIFIER_VERSION_INPUTS["logic_revision"] >= 3, (
        "the bare-query graphql suppression is a `classify_row` LOGIC branch, "
        "not a data-table edit — `_CLASSIFIER_LOGIC_REVISION` must be bumped so "
        "`work-buffer reclassify --reclassify-stale` picks the rows up. It moved "
        "1 -> 2 for the suppression itself and 2 -> 3 for the braced-value "
        "corroborator, which reads a NEW input (the param values) that no "
        "digested table can see."
    )
