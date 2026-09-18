"""The `llm_api` bucket — LLM/agent API surfaces in the web/URL track.

`vuln_taxonomy` has declared the `ai-ml` family and its `prompt-injection` /
`ai-ml-security` classes since the taxonomy was written, but NO gf-bucket mapped
to them, so the web track could never route a row there. Measured before this
bucket existed: `/v1/chat/completions` reached only `25 gf:api-versioning` (from
the generic `/v<n>/` regex), and `?system_prompt=` scored 0 and fell back to
`cluster_key = path:/api/assistant`.

The vocabulary sweep in `test_classify_buckets_vocabulary.py` gives every one of
this bucket's keys and fragments its own falsifying row. This file pins the
things a mechanical sweep cannot express: that the bucket WINS the routes it
exists for, that it DISCRIMINATES (the deliberately-excluded generic tokens stay
out), and that it is declared where it cannot reorder an existing weight tie.

Every routing assertion is swept across `_PRODUCTION_CASE_TYPES` rather than the
single `"unknown"` this file originally used. `unknown` IS a real producer output
(`classify_type()` step 19), but it is the RESIDUAL one: an API corpus is
dominated by `api`, and on an `api` row the `_TYPE_FLOOR` entry and the
co-firing `auth`/`oauth-oidc` buckets change exactly the arithmetic a
precision defect hides behind. Testing one type proved nothing about the others.
"""
from __future__ import annotations

import json

import pytest

from assess.lib import classify_buckets as cb
from assess.lib import vuln_taxonomy


# The `case_type` values the PRODUCERS actually emit, taken from every
# `return "..."` in `classify.classify_type()` and
# `candidate_records.candidate_type()`, minus the inert/sourcemap/host_root types
# `classify_row` early-returns on before any bucket runs. `api` leads the tuple
# because it is the dominant type in the API-first corpora this bucket targets.
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
# The routes the bucket exists for.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize(
    "url_path",
    [
        "/v1/chat/completions",          # OpenAI-compatible chat completion
        "/openai/deployments/gpt/chat/completions",  # Azure OpenAI deployment
        "/v1/embeddings",                # vector / RAG ingestion
        "/api/inference",                # self-hosted model inference
    ],
)
def test_llm_api_routes_win_the_cluster(url_path: str, case_type: str) -> None:
    result = _classify(case_type=case_type, url_path=url_path)
    assert result["cluster_key"] == "gf:llm_api", result
    assert result["priority_score"] == 40, result


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize(
    "key",
    [
        "system_prompt", "user_prompt", "prompt_template", "system_message",
        "messages", "max_tokens", "top_p", "tool_choice", "function_call",
        "embeddings",
    ],
)
def test_llm_request_keys_win_the_cluster_on_a_neutral_path(
    key: str, case_type: str
) -> None:
    """`/api/assistant?system_prompt=` scored a hard 0 and fell back to
    `path:/api/assistant` before this bucket existed."""
    result = _classify(case_type=case_type, url_path="/api/assistant", **{key: "x"})
    assert result["cluster_key"] == "gf:llm_api", result
    assert result["priority_score"] == 40, result


def test_versioned_llm_route_outranks_the_generic_api_versioning_signal() -> None:
    """`/v1/chat/completions` fired ONLY `api-versioning` (25) before. Both still
    match; the specific bucket now owns the cluster and `api-versioning` stays in
    the chain as the family-level hint it is."""
    result = _classify(url_path="/v1/chat/completions")
    assert set(result["matched_buckets"]) >= {"llm_api", "api-versioning"}
    assert result["cluster_key"] == "gf:llm_api"


def test_completions_fragment_is_boundary_anchored_not_version_qualified() -> None:
    """The bucket carries `/completions`, never `/v1/chat/completions` — the
    `fragment_in_path` boundary already makes the short form cover every vendor
    mount point. This is the mechanism that let `/v1/messages` and
    `/v1/responses` be REMOVED without losing the chat route (see
    `test_rest_collection_routes_are_not_llm_endpoints`)."""
    fragments = next(frags for name, _w, _k, frags in cb._BUCKETS if name == "llm_api")
    assert "/completions" in fragments
    assert not any(f.startswith("/v1/") for f in fragments), fragments
    for path in (
        "/v1/chat/completions",
        "/openai/deployments/gpt-4o/chat/completions",
        "/api/llm/completions",
    ):
        assert "llm_api" in _classify(url_path=path)["matched_buckets"], path


# ---------------------------------------------------------------------------
# Discrimination — the tokens deliberately kept OUT.
#
# Each row below is a REAL, non-LLM surface that the token names. These are
# negative pins: the keys/fragments they exercise must never re-enter the bucket
# without the row here failing first.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize(
    "url_path,key,value",
    [
        # `model` — every product filter and device catalogue carries one.
        ("/api/products", "model", "x220"),
        # `system` — an ordinary downloads/config route.
        ("/api/downloads", "system", "linux"),
        # `temperature` — IoT / thermostat / weather / lab-equipment APIs.
        ("/api/devices/thermostat/state", "temperature", "21.5"),
        # `tools` / `functions` — generic collection nouns.
        ("/api/widgets", "tools", "x"),
        ("/api/widgets", "functions", "x"),
    ],
)
def test_generic_ai_adjacent_keys_do_not_fire_the_bucket(
    url_path: str, key: str, value: str, case_type: str
) -> None:
    result = _classify(case_type=case_type, url_path=url_path, **{key: value})
    assert "llm_api" not in result["matched_buckets"], result


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize(
    "url_path",
    [
        "/messages",              # a chat/inbox route in any ordinary app
        "/chat",                  # a support-chat widget, not an LLM API
        "/report/generate",       # `/generate` would flood report/export routes
        "/api/responses",         # a survey/form response collection
    ],
)
def test_generic_ai_adjacent_paths_do_not_fire_the_bucket(
    url_path: str, case_type: str
) -> None:
    result = _classify(case_type=case_type, url_path=url_path)
    assert "llm_api" not in result["matched_buckets"], result


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize(
    "url_path",
    [
        "/api/v1/messages/1024",     # the inbox route, version-qualified
        "/api/v1/responses/9182",    # the survey-response route
        "/api/v2/messages/1024",
        "/v1/messages",
        "/v1/responses",
    ],
)
def test_rest_collection_routes_are_not_llm_endpoints(
    url_path: str, case_type: str
) -> None:
    """REST APIs are conventionally versioned, so version-qualifying `/messages`
    and `/responses` buys NO discrimination: `/api/v1/messages` IS the inbox
    route and `/api/v1/responses` IS the survey-response route. Both fragments
    were dropped; the request-key set still catches a real LLM proxy (a
    `messages` / `max_tokens` body), and `/completions` still covers the chat
    route on its own boundary anchor."""
    result = _classify(case_type=case_type, url_path=url_path)
    assert "llm_api" not in result["matched_buckets"], result


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize(
    "url_path",
    ["/api/v1/messages/1024", "/api/v1/responses/9182"],
)
def test_versioned_collection_item_routes_are_an_idor_surface(
    url_path: str, case_type: str
) -> None:
    """With the fragment gone the row lands where its evidence points: a numeric
    object reference under a collection noun is the `path_has_object_ref` IDOR
    shape, not an LLM endpoint."""
    result = _classify(case_type=case_type, url_path=url_path)
    assert result["cluster_key"] == "gf:idor", result
    assert "idor" in result["matched_buckets"], result


# ---------------------------------------------------------------------------
# `prompt` is an RFC-defined OIDC parameter, not an LLM-only key.
#
# OIDC Core §3.1.2.1 defines `prompt` with the values `none`/`login`/`consent`/
# `select_account`; Azure AD, Auth0, Okta, Keycloak and Google all emit it. A
# bare `prompt` key in the `llm_api` set (weight 40) therefore re-clustered the
# highest-value auth surface in a web engagement as an LLM endpoint — accruing an
# unclosable `prompt-injection` coverage item on every SSO entry point and
# turning the gap recommendation into `llm-api-testing` instead of
# `auth-bypass` / `saml-sso-testing`.
#
# The key was DROPPED rather than guarded by a subtractive predicate: any such
# predicate has to enumerate IdP authorize routes and companion vocabulary, and
# every gap in that enumeration silently recreates the defect on the surface that
# can least afford it. The compounds below are unambiguous and carry the recall.
# ---------------------------------------------------------------------------

_OIDC_AUTHORIZE_ROUTES = (
    "/oauth2/authorize",                  # generic / Auth0 / AWS Cognito
    "/oauth2/v2.0/authorize",             # Azure AD v2
    "/connect/authorize",                 # IdentityServer
    "/protocol/openid-connect/auth",      # Keycloak
    "/as/authorization.oauth2",           # PingFederate
)


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
def test_oidc_authorize_url_clusters_as_oauth_not_as_an_llm_endpoint(
    case_type: str,
) -> None:
    result = cb.classify_from_fields(
        case_type=case_type,
        url_path="/oauth2/authorize",
        query_params=json.dumps(
            {
                "client_id": "0oa1b2c3",
                "response_type": "code",
                "prompt": "login",
                "scope": "openid",
            }
        ),
    )
    assert "llm_api" not in result["matched_buckets"], result
    assert result["cluster_key"] == "gf:oauth-oidc", result


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
@pytest.mark.parametrize("url_path", _OIDC_AUTHORIZE_ROUTES)
@pytest.mark.parametrize("value", ["none", "login", "consent", "select_account"])
def test_the_rfc_prompt_values_never_reach_the_llm_bucket(
    url_path: str, value: str, case_type: str
) -> None:
    result = _classify(case_type=case_type, url_path=url_path, prompt=value)
    assert "llm_api" not in result["matched_buckets"], result


@pytest.mark.parametrize("case_type", _PRODUCTION_CASE_TYPES)
def test_login_page_with_an_oidc_prompt_param_stays_an_auth_row(
    case_type: str,
) -> None:
    """`/login?prompt=select_account` used to survive only because `auth` (40) is
    DECLARED ahead of `llm_api` (40) — a tie-break, i.e. luck rather than design.
    It now has no `llm_api` match to tie against at all."""
    result = _classify(case_type=case_type, url_path="/login", prompt="select_account")
    assert "llm_api" not in result["matched_buckets"], result
    assert result["cluster_key"] == "gf:auth", result


def test_bare_prompt_is_not_a_bucket_key_anywhere() -> None:
    """Structural pin on the decision: no bucket may claim the bare token, so a
    future vocabulary add cannot silently re-create the SSO misroute."""
    for name, _weight, key_set, _frags in cb._BUCKETS:
        assert "prompt" not in key_set, name


@pytest.mark.parametrize(
    "key", ["user_prompt", "system_prompt", "prompt_template", "userprompt"]
)
def test_the_unambiguous_prompt_compounds_are_kept(key: str) -> None:
    """Dropping the bare token costs no real LLM recall: the compound spellings
    name the surface unambiguously and no other vocabulary claims them."""
    assert "llm_api" in _classify(url_path="/api/assistant", **{key: "x"})[
        "matched_buckets"
    ]


def test_bucket_is_declared_after_every_existing_weight_40_bucket() -> None:
    """ADR 0008's additive rule: at equal weight the first-declared bucket wins
    `cluster_key`, so a new entry must never be declared ahead of an existing
    tie-mate. `llm_api` is last in the weight-40 run."""
    names = [name for name, _w, _k, _p in cb._BUCKETS]
    weights = {name: w for name, w, _k, _p in cb._BUCKETS}
    forty = [n for n in names if weights[n] == 40]
    assert forty[-1] == "llm_api", forty


# ---------------------------------------------------------------------------
# Routing: the bucket must reach the web LLM skill, not only the mobile one.
# ---------------------------------------------------------------------------

def test_bucket_maps_to_a_canonical_ai_ml_class() -> None:
    cls = vuln_taxonomy.GF_BUCKET_TO_CLASS["llm_api"]
    assert cls == "prompt-injection"
    assert vuln_taxonomy.family_of(cls) == "ai-ml"


def test_bucket_routes_to_the_web_llm_skill() -> None:
    """`derive_bucket_skills()` resolves bucket -> class -> skills declaring it.
    Before `llm-api-testing` existed, both `ai-ml` classes resolved to
    `ai-ml-on-device-security` alone — a mobile/on-device skill — so mapping a
    web LLM-API bucket would have dispatched a web finding to the mobile
    specialist."""
    skills = vuln_taxonomy.derive_bucket_skills().get("llm_api", ())
    assert "llm-api-testing" in skills, skills
