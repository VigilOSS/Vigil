"""RED-phase classifier tests for the classify-surface 2026-06 buckets.

Encodes the IMPLEMENTATION-SPEC (docs/research/classify-surface/
IMPLEMENTATION-SPEC.md) TEST-MATRIX rows for the API/auth-family buckets:
graphql, api, api-versioning, oauth-oidc, auth, jwt, sso, websocket, webhook —
both positive matches and negative guards.

These tests describe TARGET behaviour against the *new* bucket table; they are
expected to FAIL against the current `classify_buckets.py` until the GREEN phase
lands the spec. Import + fixture conventions mirror
`orchestrator/backend/tests/test_work_buffer.py` (the `_classify_buckets()` helper
and the `classify_from_fields` calling convention).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Load the real `assess.lib.classify_buckets` module.

    Mirrors `_classify_buckets()` in test_work_buffer.py so we exercise the same
    import surface (`classify_from_fields` / `classify_row`) the production
    ingest path uses.
    """
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _classify(
    *,
    case_type: str = "unknown",
    url_path: str,
    query_params: dict | None = None,
    body_params: dict | None = None,
):
    """Thin wrapper over `classify_from_fields` matching test_work_buffer.py's
    JSON-string parameter convention. Params are dicts here; we JSON-encode them
    exactly as `_insert_work_item` does before they reach `collect_keys`.

    The default `case_type` is `unknown` — a non-inert type with NO entry in
    `_TYPE_FLOOR` — so these bucket-precision tests isolate bucket matching from
    the producer-`type` floor. (The producer's real `api` type DOES carry a
    floor to gf:api/20; using it as the placeholder here would make every
    bucket-less negative guard floor instead of falling through to path:*. The
    floor itself is covered by `test_classify_type_floor.py`.)
    """
    cb = _classify_buckets()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query_params or {}),
        body_params=json.dumps(body_params or {}),
    )


# ---------------------------------------------------------------------------
# graphql (G) — §6.1 / matrix 12.2
# ---------------------------------------------------------------------------


def test_graphql_api_graphql_path_fragment_matches() -> None:
    """G1: /api/graphql fires the graphql bucket at weight 45."""
    a = _classify(url_path="/api/graphql")
    assert a["cluster_key"] == "gf:graphql"
    assert a["priority_score"] == 45


def test_graphql_graphiql_path_fragment_matches() -> None:
    """G2: /graphiql fires the graphql bucket."""
    a = _classify(url_path="/graphiql")
    assert a["cluster_key"] == "gf:graphql"
    assert a["priority_score"] == 45


def test_graphql_query_variables_param_keys_match() -> None:
    """G3: graphql param keys (query, variables) win over api-versioning regex."""
    a = _classify(url_path="/v1/data", query_params={"query": "...", "variables": "..."})
    assert a["cluster_key"] == "gf:graphql"
    assert a["priority_score"] == 45
    assert "gf:graphql" in a["priority_reason"]
    assert "gf:api-versioning" in a["priority_reason"]


def test_graphql_gql_path_fragment_matches() -> None:
    """A bare /gql endpoint fires graphql (path fragment, §6.1)."""
    a = _classify(url_path="/gql")
    assert a["cluster_key"] == "gf:graphql"
    assert a["priority_score"] == 45


def test_search_query_path_is_not_graphql() -> None:
    """G4 negative guard: /query is NOT a graphql PATH fragment (dropped §6.1);
    a REST /search/query search route must fall through, not mis-bucket at 45."""
    a = _classify(url_path="/search/query")
    assert "graphql" not in a["matched_buckets"]
    assert a["cluster_key"] == "path:/search/query"
    assert a["priority_score"] == 0


# ---------------------------------------------------------------------------
# auth (A) — §6.2 / matrix 12.3
# ---------------------------------------------------------------------------


def test_auth_login_path_fragment_matches() -> None:
    """A1: /login fires auth at weight 40."""
    a = _classify(url_path="/login")
    assert a["cluster_key"] == "gf:auth"
    assert a["priority_score"] == 40


def test_auth_signin_fragment_matches() -> None:
    """A2: /efi/signin fires auth via the /signin fragment."""
    a = _classify(url_path="/efi/signin")
    assert a["cluster_key"] == "gf:auth"
    assert a["priority_score"] == 40


def test_auth_compound_auth_verify_matches() -> None:
    """A3: the compound /auth/verify fragment fires auth (override #8)."""
    a = _classify(url_path="/auth/verify")
    assert a["cluster_key"] == "gf:auth"
    assert a["priority_score"] == 40


def test_auth_compound_email_verify_matches() -> None:
    """A4: the compound /email/verify fragment fires auth (override #8)."""
    a = _classify(url_path="/email/verify")
    assert a["cluster_key"] == "gf:auth"
    assert a["priority_score"] == 40


def test_auth_mfa_fragment_matches() -> None:
    """A6: /mfa fires auth."""
    a = _classify(url_path="/mfa")
    assert a["cluster_key"] == "gf:auth"
    assert a["priority_score"] == 40


def test_auth_username_password_param_keys_match() -> None:
    """An auth-entry param key set (username + password) fires auth (§6.2)."""
    a = _classify(url_path="/sessions", body_params={"username": "x", "password": "y"})
    assert a["cluster_key"] == "gf:auth"
    assert a["priority_score"] == 40


def test_captcha_verify_bare_is_not_auth() -> None:
    """A5 negative guard: bare /verify is EXCLUDED (captcha/verify FP, override #8).
    /captcha/verify must NOT fire auth and must fall through to the path: fallback."""
    a = _classify(url_path="/captcha/verify")
    assert "auth" not in a["matched_buckets"]
    assert a["cluster_key"] == "path:/captcha/verify"
    assert a["priority_score"] == 0


def test_email_query_param_alone_is_not_auth() -> None:
    """Negative guard (§6.2): a bare email= query param is NOT an auth-entry signal
    (email dropped from the auth key set) — must not fire auth."""
    a = _classify(url_path="/contact", query_params={"email": "a@b.com"})
    assert "auth" not in a["matched_buckets"]


def test_auth_saml_acs_cofires_sso_auth_wins() -> None:
    """A7: /saml/acs fires auth(40) and co-fires sso(35 via /saml); best=40 → gf:auth."""
    a = _classify(url_path="/saml/acs")
    assert a["cluster_key"] == "gf:auth"
    assert a["priority_score"] == 40
    assert "gf:auth" in a["priority_reason"]
    assert "gf:sso" in a["priority_reason"]


# ---------------------------------------------------------------------------
# api / api-versioning (V) — §6.3 / §6.4 / matrix 12.4
# ---------------------------------------------------------------------------


def test_api_versioning_v1_regex_matches() -> None:
    """V1: /v1/ fires the api-versioning regex bucket at weight 25."""
    a = _classify(url_path="/v1/")
    assert a["cluster_key"] == "gf:api-versioning"
    assert a["priority_score"] == 25


def test_api_versioning_nested_v3_matches() -> None:
    """V2: nested /dhrp/rns/v3/actions matches the api-versioning regex."""
    a = _classify(url_path="/dhrp/rns/v3/actions")
    assert a["cluster_key"] == "gf:api-versioning"
    assert a["priority_score"] == 25


def test_api_versioning_api_v1_matches() -> None:
    """V3: /person/prefs/api/v1/ matches the api-versioning regex."""
    a = _classify(url_path="/person/prefs/api/v1/")
    assert a["cluster_key"] == "gf:api-versioning"
    assert a["priority_score"] == 25


def test_api_versioning_bare_v3_matches() -> None:
    """A bare trailing /v3 (end-of-string boundary) matches the regex (§3.4)."""
    a = _classify(url_path="/v3")
    assert a["cluster_key"] == "gf:api-versioning"
    assert a["priority_score"] == 25


def test_version_dot_one_is_not_api_versioning() -> None:
    """V4 negative guard: /version/1.0 — segment is `version`, not `v<digits>` →
    no regex, no floor (type api) → falls through. Must NOT be api-versioning."""
    a = _classify(url_path="/version/1.0")
    assert "api-versioning" not in a["matched_buckets"]
    assert a["cluster_key"] == "path:/version/1.0"
    assert a["priority_score"] == 0


def test_validate_endpoint_is_not_api_versioning() -> None:
    """V5 negative guard: /validate/endpoint has no `v<digits>` segment."""
    a = _classify(url_path="/validate/endpoint")
    assert "api-versioning" not in a["matched_buckets"]
    assert a["cluster_key"] == "path:/validate/endpoint"
    assert a["priority_score"] == 0


def test_vue_app_is_not_api_versioning() -> None:
    """Negative guard (§3.4): segment `vue` is not `v`+digits → no regex match."""
    a = _classify(url_path="/vue/app")
    assert "api-versioning" not in a["matched_buckets"]


def test_v1beta_is_not_api_versioning() -> None:
    """Negative guard (§3.4): /v1beta/x — `v1beta` != `v1` at a boundary; the
    (?=[/?#]|$) lookahead rejects `beta` following the digits."""
    a = _classify(url_path="/v1beta/x")
    assert "api-versioning" not in a["matched_buckets"]


def test_v_no_digits_is_not_api_versioning() -> None:
    """Negative guard (§3.4): /v/1 — segment is `v` with no digits → no match."""
    a = _classify(url_path="/v/1")
    assert "api-versioning" not in a["matched_buckets"]


def test_api_apexrest_fragment_fires_api_bucket() -> None:
    """V6: /services/apexrest/Foo fires the (narrowed, path-only) api bucket at 20."""
    a = _classify(url_path="/services/apexrest/Foo")
    assert a["cluster_key"] == "gf:api"
    assert a["priority_score"] == 20


def test_api_rest_versioned_prefers_api_versioning() -> None:
    """V7: /rest/v2/items fires api(20, /rest/) AND api-versioning(25, /v2/);
    best=25 → gf:api-versioning; reason carries both."""
    a = _classify(url_path="/rest/v2/items")
    assert a["cluster_key"] == "gf:api-versioning"
    assert a["priority_score"] == 25
    assert "gf:api" in a["priority_reason"]
    assert "gf:api-versioning" in a["priority_reason"]


def test_bare_api_path_does_not_fire_api_bucket() -> None:
    """Negative guard (§6.3, override #9): bare /api/ is DELIBERATELY OMITTED from
    the api bucket fragments — /api/users/avatar must NOT append gf:api."""
    a = _classify(url_path="/api/users/avatar")
    assert "api" not in a["matched_buckets"]


def test_api_route_floor_rescues_paramless_route() -> None:
    """T2: type=api_route with no bucket match floors to gf:api at weight 20."""
    a = _classify(case_type="api_route", url_path="/api/testplans")
    assert a["cluster_key"] == "gf:api"
    assert a["priority_score"] == 20
    assert a["priority_reason"] == "gf:api"
    assert a["matched_buckets"] == ["api"]


# ---------------------------------------------------------------------------
# oauth-oidc (O) — §6.5 / matrix 12.5
# ---------------------------------------------------------------------------


def test_oauth_oidc_well_known_openid_config_matches() -> None:
    """O1: /.well-known/openid-configuration fires oauth-oidc at weight 35."""
    a = _classify(url_path="/.well-known/openid-configuration")
    assert a["cluster_key"] == "gf:oauth-oidc"
    assert a["priority_score"] == 35


def test_oauth_oidc_connect_token_matches() -> None:
    """O2: /connect/token fires oauth-oidc."""
    a = _classify(url_path="/connect/token")
    assert a["cluster_key"] == "gf:oauth-oidc"
    assert a["priority_score"] == 35


def test_oauth_oidc_oauth2_authorize_with_keys_matches() -> None:
    """O3: /oauth2/authorize + client_id/redirect_uri → oauth-oidc; reason also
    carries gf:redirect (redirect_uri is a redirect key)."""
    a = _classify(
        url_path="/oauth2/authorize",
        query_params={"client_id": "x", "redirect_uri": "y"},
    )
    assert a["cluster_key"] == "gf:oauth-oidc"
    assert a["priority_score"] == 35
    assert "gf:oauth-oidc" in a["priority_reason"]
    assert "gf:redirect" in a["priority_reason"]


def test_oidc_path_fragment_matches() -> None:
    """/oidc/ is an oauth-oidc path fragment (§6.5)."""
    a = _classify(url_path="/oidc/userinfo")
    assert a["cluster_key"] == "gf:oauth-oidc"
    assert a["priority_score"] == 35


def test_oauth_callback_is_not_oauth_oidc() -> None:
    """O4 negative guard (§10.5 regression pin): /oauth/callback contains /oauth
    but NOT /oauth2/ — oauth-oidc must NOT fire. (trust_surface owns it.)"""
    a = _classify(case_type="unknown", url_path="/oauth/callback")
    assert "oauth-oidc" not in a["matched_buckets"]
    assert a["cluster_key"] == "gf:trust_surface"


def test_well_known_extra_is_not_oauth_oidc() -> None:
    """Negative guard: /.well-known-extra is NOT the boundary-anchored
    /.well-known/openid-configuration fragment — oauth-oidc must NOT fire."""
    a = _classify(url_path="/.well-known-extra/config")
    assert "oauth-oidc" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# websocket (W1-W3) — §6.8 / matrix 12.8
# ---------------------------------------------------------------------------


def test_websocket_ws_feed_matches() -> None:
    """W1: /ws/feed fires websocket at weight 30."""
    a = _classify(url_path="/ws/feed")
    assert a["cluster_key"] == "gf:websocket"
    assert a["priority_score"] == 30


def test_websocket_socket_io_matches() -> None:
    """W3: /socket.io/ fires websocket."""
    a = _classify(url_path="/socket.io/")
    assert a["cluster_key"] == "gf:websocket"
    assert a["priority_score"] == 30


def test_websocket_channel_param_key_matches() -> None:
    """A websocket param key (channel) fires the websocket bucket (§6.8)."""
    a = _classify(url_path="/subscribe", query_params={"channel": "alerts"})
    assert a["cluster_key"] == "gf:websocket"
    assert a["priority_score"] == 30


def test_wsdl_is_not_websocket() -> None:
    """W2 negative guard: /ws is boundary-anchored → /wsdl must NOT match
    (the `d` is not a segment boundary)."""
    a = _classify(url_path="/wsdl")
    assert "websocket" not in a["matched_buckets"]
    assert a["cluster_key"] == "path:/wsdl"
    assert a["priority_score"] == 0


# ---------------------------------------------------------------------------
# webhook (W4-W5) — §6.9 / matrix 12.8
# ---------------------------------------------------------------------------


def test_webhook_webhooks_fragment_matches() -> None:
    """W4: /webhooks fires webhook at weight 30."""
    a = _classify(url_path="/webhooks")
    assert a["cluster_key"] == "gf:webhook"
    assert a["priority_score"] == 30


def test_webhook_notify_fragment_matches() -> None:
    """W5: /notify fires webhook."""
    a = _classify(url_path="/notify")
    assert a["cluster_key"] == "gf:webhook"
    assert a["priority_score"] == 30


def test_webhook_endpoint_param_key_matches() -> None:
    """A webhook param key (endpoint) fires the webhook bucket (§6.9)."""
    a = _classify(url_path="/register", body_params={"endpoint": "https://x"})
    assert a["cluster_key"] == "gf:webhook"
    assert a["priority_score"] == 30


def test_webhook_callback_path_is_not_webhook() -> None:
    """Negative guard (§6.9): /callback is OMITTED from webhook (owned by
    trust_surface) — /oauth/callback must NOT fire webhook."""
    a = _classify(case_type="unknown", url_path="/oauth/callback")
    assert "webhook" not in a["matched_buckets"]


def test_events_year_path_is_not_webhook_without_param() -> None:
    """Negative guard (target behaviour): /events/2024/conf is content navigation,
    not a webhook surface — webhook must NOT fire on the bare path when no
    url/endpoint param co-fires."""
    a = _classify(url_path="/events/2024/conf")
    assert "webhook" not in a["matched_buckets"]


def test_events_path_with_endpoint_param_fires_webhook() -> None:
    """Positive counterpart: /events/2024/conf WITH an endpoint param co-firing
    IS a webhook surface — webhook must appear in matched_buckets."""
    a = _classify(
        url_path="/events/2024/conf",
        query_params={"endpoint": "https://hooks.example/x"},
    )
    assert "webhook" in a["matched_buckets"]


# ---------------------------------------------------------------------------
# jwt (W6, W7) — §6.10 / matrix 12.8
# ---------------------------------------------------------------------------


def test_jwt_path_fragment_matches() -> None:
    """W6: /jwt fires the jwt bucket at weight 30."""
    a = _classify(url_path="/jwt")
    assert a["cluster_key"] == "gf:jwt"
    assert a["priority_score"] == 30


def test_jwt_access_token_param_is_secondary_to_trust_surface() -> None:
    """W7 (note ⓐ): /api/auth/token contains /token → trust_surface(35) fires;
    access_token key → jwt(30). best=35 → gf:trust_surface; reason carries gf:jwt
    as the low-incremental secondary reason (override #8)."""
    a = _classify(url_path="/api/auth/token", query_params={"access_token": "x"})
    assert a["cluster_key"] == "gf:trust_surface"
    assert a["priority_score"] == 35
    assert "gf:trust_surface" in a["priority_reason"]
    assert "gf:jwt" in a["priority_reason"]


def test_bare_token_param_is_not_jwt() -> None:
    """Negative guard (§6.10): bare `token` is DROPPED from the jwt key set —
    a ?token= query param alone must NOT fire jwt."""
    a = _classify(url_path="/data", query_params={"token": "abc"})
    assert "jwt" not in a["matched_buckets"]


def test_bare_token_path_is_not_jwt() -> None:
    """Negative guard (§6.10): bare /token is OMITTED from jwt fragments (owned by
    trust_surface) — /token must NOT fire jwt."""
    a = _classify(url_path="/token")
    assert "jwt" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# sso (W8-W10) — §6.11 / matrix 12.8
# ---------------------------------------------------------------------------


def test_sso_login_fragment_matches() -> None:
    """W8: /sso/login fires sso at weight 35."""
    a = _classify(url_path="/sso/login")
    assert a["cluster_key"] == "gf:sso"
    assert a["priority_score"] == 35


def test_sso_saml2_fragment_matches() -> None:
    """W9: /saml2 fires sso (separate fragment from /saml)."""
    a = _classify(url_path="/saml2")
    assert a["cluster_key"] == "gf:sso"
    assert a["priority_score"] == 35


def test_sso_samlresponse_key_with_login_path_auth_wins() -> None:
    """W10: /Login.aspx + SAMLResponse → auth(40 via /login) + sso(35 via key);
    best=40 → gf:auth; reason carries both."""
    a = _classify(url_path="/Login.aspx", query_params={"SAMLResponse": "x"})
    assert a["cluster_key"] == "gf:auth"
    assert a["priority_score"] == 40
    assert "gf:auth" in a["priority_reason"]
    assert "gf:sso" in a["priority_reason"]


def test_sso_bare_sso_fragment_matches() -> None:
    """A bare /sso endpoint fires sso (§6.11 lists both /sso and /sso/)."""
    a = _classify(url_path="/sso")
    assert a["cluster_key"] == "gf:sso"
    assert a["priority_score"] == 35


def test_sso_relaystate_param_key_matches() -> None:
    """An sso param key (relaystate) fires the sso bucket (§6.11)."""
    a = _classify(url_path="/acs", query_params={"RelayState": "x"})
    assert "sso" in a["matched_buckets"]
    assert a["priority_score"] >= 35
