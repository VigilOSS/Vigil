"""Contract tests for the Phase 2a high-value gf buckets.

classify-context-and-surface 2026-06, Part 3 §A — the six high-value buckets
added in Phase 2a:

  * ``servicenow``        (weight 30) -> class ``idor``
  * ``secret_vault``      (weight 45) -> class ``secrets-exposure``
  * ``idp_admin``         (weight 35) -> class ``auth-bypass``
  * ``privileged_action`` (weight 30) -> class ``bfla`` (predicate-gated)
  * ``wordpress``         (weight 35) -> class ``user-enumeration``
  * ``cms_db_admin``      (weight 35) -> class ``auth-bypass``

Each bucket gets a positive match plus a precision negative. The
``privileged_action`` predicate gets the content-slug negatives that motivate
its API/version-or-object-ref precision guard. The module/fixture conventions
mirror ``test_classify_buckets_storage_deser_debug.py`` (the ``_classify_buckets``
loader + the ``classify_from_fields`` call shape).

NOTE on Fix 4 (compound-key widening): Phase 2a's planned ``expand_compound_key``
widening (split on ``_``/``-``/camelCase) is NOT active in this codebase — it is
non-additive here (the ``id`` token is an ``sqli`` key at weight 40, so every
``*_id`` compound key would let ``sqli``/``ssrf`` override the pinned
``idor``/``oauth-oidc`` clusters: it breaks ``test_classify_idor_expanded_param_key_workspace``
and ``test_oauth_oidc_oauth2_authorize_with_keys_matches``). These tests
therefore exercise the buckets via their WHOLE param keys + path fragments,
which is how they fire today. ``test_servicenow_sysparm_url_whole_key_only`` pins
the current (pre-Fix-4) behaviour so the eventual decomposition is a deliberate,
visible change.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Load the real ``assess.lib.classify_buckets`` module (same loader as the
    sibling bucket suites)."""
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _classify(
    url_path: str,
    *,
    case_type: str = "unknown",
    query_params: dict | None = None,
    body_params: dict | None = None,
):
    cb = _classify_buckets()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query_params or {}),
        body_params=json.dumps(body_params or {}),
    )


# ---------------------------------------------------------------------------
# servicenow (weight 30) -> idor (§A.4)
# ---------------------------------------------------------------------------


def test_servicenow_api_now_fragment() -> None:
    a = _classify("/api/now/table/incident")
    assert a["cluster_key"] == "gf:servicenow"
    assert a["priority_score"] == 30
    assert "servicenow" in a["matched_buckets"]


def test_servicenow_nav_to_do_fragment() -> None:
    a = _classify("/nav_to.do")
    assert a["cluster_key"] == "gf:servicenow"
    assert a["priority_score"] == 30


def test_servicenow_auth_redirect_do_fragment() -> None:
    """The classic ``auth_redirect.do`` open-redirect/SSO entry (no leading slash
    in the fragment — `fragment_in_path` searches mid-path)."""
    a = _classify("/auth_redirect.do")
    assert a["cluster_key"] == "gf:servicenow"
    assert a["priority_score"] == 30
    assert "servicenow" in a["matched_buckets"]


def test_servicenow_glide_sso_id_param_key() -> None:
    a = _classify("/portal", query_params={"glide_sso_id": "abc"})
    assert a["cluster_key"] == "gf:servicenow"
    assert a["priority_score"] == 30
    assert "servicenow" in a["matched_buckets"]


def test_servicenow_sysparm_url_whole_key_only() -> None:
    """`sysparm_url` fires servicenow via the WHOLE key. Fix 4 (compound-key
    decomposition) is NOT active here, so the inner `url` token does NOT
    additionally fire ssrf/redirect — this test pins the pre-Fix-4 behaviour."""
    a = _classify("/auth_redirect.do", query_params={"sysparm_url": "https://x"})
    assert "servicenow" in a["matched_buckets"]
    assert "ssrf" not in a["matched_buckets"]
    assert "redirect" not in a["matched_buckets"]


def test_servicenow_negative_ordinary_path() -> None:
    """An ordinary path with no ServiceNow fragment / sysparm key MUST NOT fire."""
    a = _classify("/about/company")
    assert "servicenow" not in a["matched_buckets"]
    assert a["cluster_key"] == "path:/about/company"
    assert a["priority_score"] == 0


# ---------------------------------------------------------------------------
# secret_vault (weight 45) -> secrets-exposure (§A.6)
# ---------------------------------------------------------------------------


def test_secret_vault_v1_secret_fragment() -> None:
    a = _classify("/v1/secret/data/foo")
    assert a["cluster_key"] == "gf:secret_vault"
    assert a["priority_score"] == 45
    assert "secret_vault" in a["matched_buckets"]


def test_secret_vault_vault_fragment() -> None:
    a = _classify("/vault/data")
    assert a["cluster_key"] == "gf:secret_vault"
    assert a["priority_score"] == 45


def test_secret_vault_outranks_trust_surface_on_v1_auth_token() -> None:
    """`/v1/auth/token` co-fires trust_surface(35) via `/token`; secret_vault(45)
    wins the cluster (highest weight) and trust_surface is recorded in the chain.
    This is a higher-value reclassification (score 35 -> 45), not a regression."""
    a = _classify("/v1/auth/token")
    assert a["cluster_key"] == "gf:secret_vault"
    assert a["priority_score"] == 45
    assert "secret_vault" in a["matched_buckets"]
    assert "trust_surface" in a["matched_buckets"]


def test_secret_vault_negative_boundary() -> None:
    """`/v1/secret` is boundary-anchored: `/v1/secretstore` (next char `s`) MUST
    NOT match secret_vault."""
    a = _classify("/v1/secretstore")
    assert "secret_vault" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# idp_admin (weight 35) -> auth-bypass (§A.5)
# ---------------------------------------------------------------------------


def test_idp_admin_auth_realms_fragment() -> None:
    a = _classify("/auth/realms/master")
    assert a["cluster_key"] == "gf:idp_admin"
    assert a["priority_score"] == 35
    assert "idp_admin" in a["matched_buckets"]


def test_idp_admin_realms_fragment_keycloak_v17() -> None:
    """Keycloak v17+ dropped the `/auth` prefix -> bare `/realms/`."""
    a = _classify("/realms/master/protocol/openid-connect")
    assert a["cluster_key"] == "gf:idp_admin"
    assert a["priority_score"] == 35


def test_idp_admin_adfs_ls_keeps_sso_cluster() -> None:
    """`/adfs/ls` co-fires sso(35, `/adfs/`) and idp_admin(35). sso is declared
    BEFORE idp_admin, so the first-at-max-weight tie-break keeps cluster `gf:sso`
    (no existing cluster_key change); idp_admin is additively in the chain."""
    a = _classify("/adfs/ls")
    assert a["cluster_key"] == "gf:sso"
    assert a["priority_score"] == 35
    assert "idp_admin" in a["matched_buckets"]


def test_idp_admin_as_token_keeps_trust_surface_cluster() -> None:
    """`/as/token.oauth2` co-fires trust_surface(35, `/token`) and idp_admin(35).
    trust_surface is declared first -> cluster stays `gf:trust_surface`."""
    a = _classify("/as/token.oauth2")
    assert a["cluster_key"] == "gf:trust_surface"
    assert "idp_admin" in a["matched_buckets"]


def test_idp_admin_negative_ordinary_path() -> None:
    a = _classify("/products/catalog")
    assert "idp_admin" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# wordpress (weight 35) -> user-enumeration (§A.2)
# ---------------------------------------------------------------------------


def test_wordpress_wp_json_fragment() -> None:
    a = _classify("/wp-json/wp/v2/posts")
    assert a["cluster_key"] == "gf:wordpress"
    assert a["priority_score"] == 35
    assert "wordpress" in a["matched_buckets"]


def test_wordpress_xmlrpc_fragment() -> None:
    a = _classify("/xmlrpc.php")
    assert a["cluster_key"] == "gf:wordpress"
    assert a["priority_score"] == 35


def test_wordpress_author_param_key() -> None:
    """`author` (numeric -> user enum) fires wordpress."""
    a = _classify("/blog", query_params={"author": "5"})
    assert a["cluster_key"] == "gf:wordpress"
    assert a["priority_score"] == 35
    assert "wordpress" in a["matched_buckets"]


def test_wordpress_wp_admin_beats_cms_db_admin() -> None:
    """`/wp-admin` is listed by BOTH wordpress and cms_db_admin (both weight 35);
    wordpress is declared first, so the cluster is `gf:wordpress`. Also proves the
    `/admin` boundary matcher does NOT steal it (`-admin`, not `/admin`)."""
    a = _classify("/wp-admin/users.php")
    assert a["cluster_key"] == "gf:wordpress"
    assert "cms_db_admin" in a["matched_buckets"]
    assert "debug_logic" not in a["matched_buckets"]


def test_wordpress_negative_boundary() -> None:
    """`/wp-json` is boundary-anchored: `/wp-jsonx` MUST NOT match."""
    a = _classify("/wp-jsonx/foo")
    assert "wordpress" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# cms_db_admin (weight 35) -> auth-bypass (§A.3)
# ---------------------------------------------------------------------------


def test_cms_db_admin_administrator_fragment() -> None:
    """Joomla `/administrator` — the `/admin` segment matcher misses it (next
    char `i`), so only cms_db_admin catches it."""
    a = _classify("/administrator/index.php")
    assert a["cluster_key"] == "gf:cms_db_admin"
    assert a["priority_score"] == 35
    assert "cms_db_admin" in a["matched_buckets"]
    assert "debug_logic" not in a["matched_buckets"]


def test_cms_db_admin_admin_console_fragment() -> None:
    """`/admin-console` is hyphenated, so debug_logic's `/admin` segment misses
    it; cms_db_admin catches it."""
    a = _classify("/admin-console")
    assert a["cluster_key"] == "gf:cms_db_admin"
    assert a["priority_score"] == 35
    assert "debug_logic" not in a["matched_buckets"]


def test_cms_db_admin_phpmyadmin_fragment() -> None:
    a = _classify("/phpmyadmin/index.php")
    assert a["cluster_key"] == "gf:cms_db_admin"
    assert a["priority_score"] == 35


def test_cms_db_admin_negative_ordinary_admin_segment() -> None:
    """A plain `/admin` segment is owned by debug_logic(30), NOT cms_db_admin —
    cms_db_admin requires one of its specific CMS/DB-admin fragments."""
    a = _classify("/admin/dashboard")
    assert "cms_db_admin" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# privileged_action (weight 30) -> bfla (§A.9, predicate-gated)
# ---------------------------------------------------------------------------


def test_privileged_action_api_sibling() -> None:
    """`/api/users/grant`: verb `grant` + `api` sibling segment fires bfla."""
    a = _classify("/api/users/grant")
    assert a["cluster_key"] == "gf:privileged_action"
    assert a["priority_score"] == 30
    assert "privileged_action" in a["matched_buckets"]


def test_privileged_action_version_sibling() -> None:
    """`/v2/accounts/transfer`: verb `transfer` + `v2` version sibling fires."""
    a = _classify("/v2/accounts/transfer")
    assert "privileged_action" in a["matched_buckets"]
    assert a["cluster_key"] == "gf:privileged_action"
    assert a["priority_score"] == 30


def test_privileged_action_object_ref_guard() -> None:
    """`/users/1024/revoke`: verb `revoke` + embedded object-ref (`1024` with
    `users` context) fires. idor(35, the object ref) outranks privileged_action(30)
    for the cluster; privileged_action is additively in the chain."""
    a = _classify("/users/1024/revoke")
    assert "privileged_action" in a["matched_buckets"]
    assert a["cluster_key"] == "gf:idor"
    assert a["priority_score"] == 35


def test_privileged_action_assume_role_segment() -> None:
    """`assume-role` is the multi-token verb segment form; `/api/assume-role`
    fires via the `api` sibling."""
    a = _classify("/api/assume-role")
    assert "privileged_action" in a["matched_buckets"]
    assert a["cluster_key"] == "gf:privileged_action"


def test_privileged_action_negative_content_slug() -> None:
    """PRECISION: `/transfer-your-number` is a content slug — its single segment
    is `transfer-your-number`, NOT the bare verb `transfer` — so it MUST NOT
    fire privileged_action (the motivating false-positive guard)."""
    a = _classify("/transfer-your-number")
    assert "privileged_action" not in a["matched_buckets"]
    assert a["cluster_key"] == "path:/transfer-your-number"
    assert a["priority_score"] == 0


def test_privileged_action_negative_bare_verb_no_guard() -> None:
    """PRECISION: a bare `/account/transfer` content page (verb present but NO
    API/version sibling and NO object-ref) MUST NOT fire privileged_action."""
    a = _classify("/account/transfer")
    assert "privileged_action" not in a["matched_buckets"]
    assert a["priority_score"] == 0


# ---------------------------------------------------------------------------
# Fix-4 regression pin (Phase 2a item 1): the compound-key widening must not
# perturb the canonical upload reason chain. (Fix 4 is currently reverted as
# non-additive; this pin guards the invariant either way.)
# ---------------------------------------------------------------------------


def test_avatar_file_param_exact_reason_chain_regression_pin() -> None:
    """`/api/users/avatar` with a `file` param still yields EXACTLY
    `gf:lfi+gf:upload_fields` at score 40 — none of the Phase 2a buckets fire on
    this path and the compound-key behaviour is unchanged."""
    a = _classify("/api/users/avatar", case_type="upload", body_params={"file": "x.png"})
    assert a["cluster_key"] == "gf:upload_fields"
    assert a["priority_score"] == 40
    assert a["priority_reason"] == "gf:lfi+gf:upload_fields"
