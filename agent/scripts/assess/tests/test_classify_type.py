"""Typer-layer tests for ``assess.lib.classify.classify_type``.

These pin the high-value recall improvements that stop genuinely-exploitable
surfaces from landing as ``type='unknown'`` when the only signal is the URL
shape (every ingest caller currently passes ``content_type=""``). Each new
behaviour is paired with the strict false-positive (FP) negatives that the
segment-boundary guards must reject, so a future loosening of a regex trips a
red test instead of silently flooding the work buffer.

The assess ``tests/conftest.py`` puts ``agent/scripts`` on ``sys.path``, so the
source module imports directly (no ``importlib`` dance, unlike the orchestrator
suite which loads it by file path).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import ingest_endpoints
from assess.lib.classify import classify_type
from assess.lib.db import db_init


# --------------------------------------------------------------------------- #
# Item 1 — extension gaps
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/reports/q1.pdf",
        "/files/form.doc",
        "/files/form.docx",
        "/sheets/data.xls",
        "/sheets/data.xlsx",
        "/decks/pitch.ppt",
        "/decks/pitch.pptx",
        "/legal/contract.rtf",
        "/legal/contract.odt",
    ],
)
def test_office_and_pdf_extensions_type_data(path: str) -> None:
    assert classify_type("GET", path, "", "") == "data"


def test_existing_data_extensions_unchanged() -> None:
    # Regression pin: the pre-existing data extensions must keep typing `data`.
    for path in (
        "/x.json",
        "/x.xml",
        "/x.csv",
        "/x.yaml",
        "/x.yml",
        "/x.txt",
    ):
        assert classify_type("GET", path, "", "") == "data", path


def test_svg_extension_types_page_not_image() -> None:
    # Deliberate SVG-as-XSS-surface decision: .svg is a page, never inert image.
    assert classify_type("GET", "/assets/logo.svg", "", "") == "page"


def test_svg_content_type_still_page() -> None:
    # Pre-existing _PAGE_CT routing of image/svg+xml must be preserved.
    assert classify_type("GET", "/whatever", "image/svg+xml", "") == "page"


def test_other_image_extensions_still_image() -> None:
    # SVG carve-out must not leak into the rest of the image family.
    assert classify_type("GET", "/assets/logo.png", "", "") == "image"
    assert classify_type("GET", "/assets/photo.jpg", "", "") == "image"


@pytest.mark.parametrize(
    "path",
    [
        "/cgi-bin/login.php/extra",
        "/portal/default.aspx?id=1",
        "/legacy/index.jsp/menu",
        "/forms/submit.do/step2",
        "/struts/foo.action?x=1",
        "/sites/page.cfm/sub",
        "/domino/db.nsf/view",
    ],
)
def test_mid_path_app_extension_types_page(path: str) -> None:
    # A known app extension followed by /, ?, ~, or end-of-path is an app route.
    assert classify_type("GET", path, "", "") == "page"


def test_terminal_app_extension_still_page() -> None:
    # Pre-existing terminal .php/.aspx/.jsp behaviour unchanged.
    assert classify_type("GET", "/index.php", "", "") == "page"
    assert classify_type("GET", "/default.aspx", "", "") == "page"
    assert classify_type("GET", "/page.jsp", "", "") == "page"


def test_mid_path_extension_segment_boundary_fp_guard() -> None:
    # FP guard: `.do` inside the literal segment `medicaid.documents` must NOT
    # match — the char after `.do` is `c`, not a segment boundary.
    result = classify_type("GET", "/medicaid.documents/list", "", "")
    assert result != "page", result
    assert result == "unknown", result


# --------------------------------------------------------------------------- #
# Item 2 — API path de-anchor (full segments anywhere in the path)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/api/users",
        "/rest/things",
        "/internal/api/users",
        "/svc/rest/orders",
        "/v1/users",
        "/v2",
        "/foo/v3/bar",
        "/app/v10/items",
    ],
)
def test_api_path_de_anchored_types_api(path: str) -> None:
    assert classify_type("GET", path, "", "") == "api"


def test_api_path_start_anchored_still_api() -> None:
    # Regression pin from test_work_buffer.
    assert classify_type("GET", "/api/users", "", "") == "api"


@pytest.mark.parametrize(
    "path",
    [
        "/api-guide",
        "/rest-easy",
        "/preview1/foo",
        "/version/1.0",
        "/restful-design",
        "/vue/app",
    ],
)
def test_api_path_fp_guards(path: str) -> None:
    assert classify_type("GET", path, "", "") != "api", path


# --------------------------------------------------------------------------- #
# Item 3 — lexical app-route typing (floor-carrying types)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/login",
        "/signin",
        "/sign-in",
        "/sso",
        "/saml",
        "/auth",
        "/oauth",
        "/mfa",
        "/2fa",
        "/otp",
        "/logout",
        "/account/login",
        "/idp/sso/redirect",
    ],
)
def test_auth_routes_type_auth_entry(path: str) -> None:
    assert classify_type("GET", path, "", "") == "auth_entry"


@pytest.mark.parametrize(
    "path",
    [
        "/admin",
        "/debug",
        "/config",
        "/.env",
        "/actuator",
        "/console",
        "/internal/admin",
        "/app/.env",
    ],
)
def test_debug_routes_type_debug_config(path: str) -> None:
    assert classify_type("GET", path, "", "") == "debug_config"


@pytest.mark.parametrize(
    "path",
    [
        "/aura",
        "/sfsites",
        "/s/foo",
        "/s",
        "/lightning/aura/bar",
    ],
)
def test_portal_routes_type_portal_session(path: str) -> None:
    assert classify_type("GET", path, "", "") == "portal_session"


@pytest.mark.parametrize(
    "path",
    [
        "/login-help-article",
        "/about/admin-team",
        "/configuration-guide",
        "/authentication-overview",
        "/single-sign-on-faq",
        "/css/site.css",  # static asset, not the `/s` portal segment
        "/consoles-for-sale",
    ],
)
def test_lexical_route_segment_boundary_fp_guards(path: str) -> None:
    # None of these substrings sit on a segment boundary, so they must NOT be
    # rescued into a floor-carrying type. They land on their real type
    # (mostly `unknown`, but `/css/site.css` is a real stylesheet).
    result = classify_type("GET", path, "", "")
    assert result not in ("auth_entry", "debug_config", "portal_session"), (
        path,
        result,
    )


def test_static_asset_wins_over_lexical_route() -> None:
    # An auth route is normally extensionless; when a real static-asset
    # extension is present the file-extension rule must still win.
    assert classify_type("GET", "/login/app.js", "", "") == "javascript"
    assert classify_type("GET", "/admin/theme.css", "", "") == "stylesheet"
    assert classify_type("GET", "/auth/logo.png", "", "") == "image"


def test_api_route_wins_over_lexical_auth() -> None:
    # Cascade priority: `/api/login` is an api surface (step 4) before the
    # late lexical rescue runs.
    assert classify_type("GET", "/api/login", "", "") == "api"


# --------------------------------------------------------------------------- #
# Item 3b — auth-MANAGEMENT lexical coverage (account-takeover surfaces)
# --------------------------------------------------------------------------- #
#
# Cross-corpus pocket of high-value AUTH-MANAGEMENT routes (password reset,
# account activation/unlock, signup/registration, email verification) that the
# original auth set (`login|signin|sso|...`) did not cover, so they landed
# `type='unknown'`. Confirmed real examples: acme-agency-example's camelCase
# `/efi/security/forgotPassword`, `/efi/security/activateUserAccount`,
# `/efi/security/unlockUserAccount`, `/efi/signup`; acme's hyphenated
# `/forgot-password`. These are prime ATO surfaces and must be rescued to
# `auth_entry` (floor 40), while strict segment boundaries keep content slugs
# (`/forgot-password-help`, `/registration-information`, `/security-policy`)
# OUT.


@pytest.mark.parametrize(
    "path",
    [
        # password reset / forgot — hyphenated and camelCase-lowercased
        "/forgot-password",
        "/forgotpassword",
        "/efi/security/forgotPassword",  # acme-agency-example camelCase + /security/ prefix
        "/reset-password",
        "/resetpassword",
        "/efi/security/resetPassword",
        "/change-password",
        "/changepassword",
        # account activation / unlock
        "/activate",
        "/activate-account",
        "/efi/security/activateUserAccount",  # acme-agency-example camelCase
        "/unlock",
        "/unlock-account",
        "/efi/security/unlockUserAccount",  # acme-agency-example camelCase
        # account recovery
        "/recover",
        "/recovery",
        "/account/recover",
        # signup / registration
        "/signup",
        "/sign-up",
        "/efi/signup",  # acme-agency-example
        "/register",
        "/registration",
        # email verification
        "/verify-email",
        "/verifyemail",
        "/email-verify",
        "/emailverify",
        # /security/ route-segment hint followed by an auth-management verb
        "/efi/security/forgotpassword",
        "/security/resetPassword",
    ],
)
def test_auth_management_routes_type_auth_entry(path: str) -> None:
    # Account-takeover surfaces (password reset / activate / unlock / recover /
    # signup / register / email-verify, plus a `/security/<auth-verb>` hint) are
    # rescued to the floor-carrying `auth_entry` type.
    assert classify_type("GET", path, "", "") == "auth_entry", path


@pytest.mark.parametrize(
    "path",
    [
        # content slugs that merely CONTAIN an auth-management keyword but do
        # not sit on a clean trailing segment boundary
        "/forgot-password-help",
        "/forgot-password-help-article",
        "/password-reset-instructions-article",
        "/password-tips",
        "/registration-information",
        "/registration-fee-schedule",
        "/signup-bonus-terms",
        "/activate-your-warranty-online",
        "/unlockable-content",
        "/recovery-stories",
        "/verify-email-deliverability-guide",
        # `/security/` content pages (NOT followed by an auth-management verb)
        "/security-policy",
        "/security/policy",
        "/security/advisories",
        "/efi/security/dashboard",
    ],
)
def test_auth_management_segment_boundary_fp_guards(path: str) -> None:
    # None of these sit on a clean segment boundary after a real auth-management
    # keyword (or the `/security/` hint is followed by a non-auth segment), so
    # they must NOT be rescued to a floor-carrying type.
    result = classify_type("GET", path, "", "")
    assert result not in ("auth_entry", "debug_config", "portal_session"), (
        path,
        result,
    )


def test_auth_management_camelcase_still_matches_with_query_and_fragment() -> None:
    # The boundary lookahead `(?=[/?#]|$)` must fire on `?` and `#` too, not just
    # end-of-path, so a camelCase reset route with a token query still types
    # auth_entry (classify_type strips the query, but the trailing boundary on
    # the bare path is end-of-string here).
    assert classify_type("GET", "/efi/security/forgotPassword?token=abc", "", "") == "auth_entry"
    assert classify_type("GET", "/signup#step2", "", "") == "auth_entry"


def test_static_asset_wins_over_lexical_auth_management() -> None:
    # A real static-asset extension still wins over the late auth-management
    # rescue (the same cascade-priority guarantee as the base auth set).
    assert classify_type("GET", "/forgot-password/app.js", "", "") == "javascript"
    assert classify_type("GET", "/signup/hero.png", "", "") == "image"


def test_api_route_wins_over_lexical_auth_management() -> None:
    # `/api/forgot-password` is an api surface (step 4) before the late rescue.
    assert classify_type("GET", "/api/forgot-password", "", "") == "api"


# --------------------------------------------------------------------------- #
# Item 3c — account/profile surfaces are LEFT to idor (decision pin)
# --------------------------------------------------------------------------- #
#
# A bare `/account`, `/profile`, `/settings`, `/me` is NOT an auth-CREDENTIAL
# entry point; it is an object-reference (IDOR/BOLA) surface. The real
# exploitable shape `/account/<id>` is already covered by the idor
# path-object-ref rule in classify_buckets, and adding `/account` to the idor
# bucket's path fragments would break the pinned `/account/settings?next=/x ->
# gf:redirect` precision test. So `classify_type` deliberately does NOT rescue a
# bare account/profile route into `auth_entry` (that would be a wrong-cluster
# false signal). They stay `unknown` at the typer layer and are handled by idor
# downstream when an object reference is present.


@pytest.mark.parametrize(
    "path",
    ["/account", "/profile", "/settings", "/me"],
)
def test_bare_account_profile_not_typed_auth_entry(path: str) -> None:
    result = classify_type("GET", path, "", "")
    assert result != "auth_entry", (path, result)
    assert result == "unknown", (path, result)


@pytest.mark.parametrize(
    "path",
    ["/account-benefits", "/profile-photo-tips", "/settings-overview"],
)
def test_account_profile_content_slugs_not_typed_auth_entry(path: str) -> None:
    # Segment-boundary guard: a content slug starting with `account`/`profile`
    # must not be rescued either.
    assert classify_type("GET", path, "", "") != "auth_entry", path


# --------------------------------------------------------------------------- #
# Item 4 — content-type signal threading (typer must accept and use it)
# --------------------------------------------------------------------------- #


def test_content_type_json_types_api_on_write() -> None:
    # A POST carrying application/json is an api surface even with a bare path.
    assert classify_type("POST", "/submit", "application/json", "") == "api"


def test_content_type_html_types_page() -> None:
    assert classify_type("GET", "/anything", "text/html", "") == "page"


def test_bare_url_list_path_still_works() -> None:
    # No content_type at all (the dominant ingest path) must still classify.
    assert classify_type("GET", "/v1/users") == "api"
    assert classify_type("GET", "/reports/q1.pdf") == "data"
    assert classify_type("GET", "/login") == "auth_entry"


# --------------------------------------------------------------------------- #
# Item 4 — ingest-endpoints threads a JSON `content_type` into the typer
# --------------------------------------------------------------------------- #


def _run_ingest(monkeypatch, tmp_path: Path, lines: list[str]) -> dict[str, str]:
    """Run ingest-endpoints over `lines` with a fake backend; return the
    persisted {url_path: type} map from the work_items table.

    Mirrors the FakeClient harness used by ``test_work_buffer`` so the host-side
    ingest CLI runs without a live FastAPI backend.
    """
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")
    db_path = engagement_dir / "cases.db"
    db_path.touch()
    db_init(str(db_path))

    monkeypatch.setattr(
        ingest_endpoints,
        "load_config",
        lambda engagement_dir=None: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(ingest_endpoints, "auth_active_context", lambda _eng: "anonymous")

    class FakeClient:
        def __init__(self, *a, **k) -> None:
            pass

        def post(self, endpoint, payload):
            if endpoint == "request-observations/bulk":
                return {
                    "count": len(payload.get("items", [])),
                    "records": [
                        {"request_variant": {"id": idx}, "service": {"id": idx}}
                        for idx, _item in enumerate(payload.get("items", []), start=1)
                    ],
                }
            return {"request_variant": {"id": 1}, "service": {"id": 1}}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(ingest_endpoints, "AssessmentClient", FakeClient)

    input_file = tmp_path / "endpoints.txt"
    input_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ingest_endpoints.run(
        SimpleNamespace(
            db_path=str(db_path),
            source="recon",
            input_file=str(input_file),
            engagement_dir=str(engagement_dir),
            egress_blocked_hosts=None,
        )
    )

    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute("SELECT url_path, type FROM work_items").fetchall()
    finally:
        conn.close()
    return {url_path: case_type for url_path, case_type in rows}


def test_ingest_threads_json_content_type_into_typer(monkeypatch, tmp_path: Path) -> None:
    # A JSON row with an explicit content_type (and no `type` override) must
    # reach the typer: a POST with application/json on a bare `/submit` path
    # types `api`, where the bare-URL path would leave it `unknown`.
    types = _run_ingest(
        monkeypatch,
        tmp_path,
        [
            json.dumps(
                {
                    "url": "https://app.example.com/submit",
                    "method": "POST",
                    "content_type": "application/json",
                }
            )
        ],
    )
    assert types.get("/submit") == "api"


def test_ingest_bare_url_list_unaffected(monkeypatch, tmp_path: Path) -> None:
    # The dominant bare-URL-list path carries no content_type; classification
    # must be unchanged (path-shape-only) — no regression.
    types = _run_ingest(
        monkeypatch,
        tmp_path,
        ["https://app.example.com/v1/users"],
    )
    assert types.get("/v1/users") == "api"


# --------------------------------------------------------------------------- #
# Cross-cutting regression pins (existing behaviour must not change)
# --------------------------------------------------------------------------- #


def test_existing_typing_regressions() -> None:
    assert classify_type("GET", "/backup.zip", "", "") == "archive"
    assert classify_type("GET", "/exports/site.tar.gz", "", "") == "archive"
    assert classify_type("GET", "/static/app.js.map", "application/json", "") == "sourcemap"
    assert classify_type("GET", "/", "", "") == "host_root"
    assert classify_type("GET", "", "", "") == "host_root"
    assert classify_type("GET", "/openapi.json", "", "") == "api-spec"
    assert classify_type("GET", "/graphql", "", "") == "graphql"
    assert classify_type("GET", "/app.js", "", "") == "javascript"
    assert classify_type("GET", "/app.css", "", "") == "stylesheet"


# --------------------------------------------------------------------------- #
# Phase 0 — ASP.NET / WCF handler extensions stop dropping to `unknown` (Issue A)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/trace.axd",
        "/handler.ashx",
        "/service.asmx",
        "/data.svc",
        "/elmah.axd",
    ],
)
def test_dotnet_handler_terminal_extension_types_page(path: str) -> None:
    # `.axd/.ashx/.asmx/.svc` are routed application surfaces, not `unknown`.
    result = classify_type("GET", path, "", "")
    assert result == "page", (path, result)
    assert result != "unknown", (path, result)


@pytest.mark.parametrize(
    "path",
    [
        "/foo.svc?wsdl",
        "/legacy/service.asmx?wsdl",
        "/handlers/upload.ashx/op",
    ],
)
def test_dotnet_handler_extension_with_boundary_types_page(path: str) -> None:
    # `?`/`/` after the handler extension is a valid app-route boundary.
    assert classify_type("GET", path, "", "") == "page", path


def test_dotnet_handler_extension_segment_boundary_fp_guard() -> None:
    # FP guard: `.axd` inside the literal segment `report.axdx` must NOT type as
    # an app route (next char `x` is not a segment boundary).
    result = classify_type("GET", "/report.axdx", "", "")
    assert result != "page", result
    assert result == "unknown", result


# --------------------------------------------------------------------------- #
# Phase 0 — extensioned auth-entry pages reach `auth_entry` (Issue C)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/wp-login.php",
        "/WP-Login.php",
        "/portal/user-signin.aspx",
        "/auth/account-login.jsp",
        "/foo-sign-in.aspx",
        "/tenant-login.do",
    ],
)
def test_extensioned_auth_pages_type_auth_entry(path: str) -> None:
    # WordPress wp-login.php and the generic `*-login`/`*-signin` extensioned
    # forms reach the floor-carrying `auth_entry` type instead of `page`.
    assert classify_type("GET", path, "", "") == "auth_entry", path


@pytest.mark.parametrize(
    "path",
    [
        "/index.php",
        "/default.aspx",
        "/page.jsp",
        "/cgi-bin/login.php/extra",
        "/login-help.php",
        "/blog-post.php",
    ],
)
def test_extensioned_auth_fp_guards_stay_page(path: str) -> None:
    # Ordinary pages (no `<prefix>-login`/`<prefix>-signin` keyword at a clean
    # segment boundary before the extension) still type `page`.
    assert classify_type("GET", path, "", "") == "page", path


# --------------------------------------------------------------------------- #
# Phase 0 — api-spec recall strengthened (Issue I backstop)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/swagger-resources",
        "/redoc",
        "/api-docs.json",
        "/v3/api-docs",
        "/swagger-ui",
        "/swagger-ui.html",
        "/api/v3/api-docs",
    ],
)
def test_api_spec_paths_strengthened(path: str) -> None:
    assert classify_type("GET", path, "", "") == "api-spec", path


def test_api_spec_existing_forms_unchanged() -> None:
    # Regression pin: the pre-existing api-spec forms must keep typing `api-spec`.
    for path in (
        "/api-docs",
        "/openapi",
        "/openapi.yaml",
        "/swagger",
        "/swagger.json",
        "/v1/api-docs",
    ):
        assert classify_type("GET", path, "", "") == "api-spec", path


@pytest.mark.parametrize(
    "path",
    [
        "/redocument",
        "/swagger-resources-guide",
        "/redoc-tutorial",
    ],
)
def test_api_spec_fp_guards(path: str) -> None:
    # Segment-boundary guards: a longer slug that merely starts with an api-spec
    # keyword must NOT be typed `api-spec`.
    assert classify_type("GET", path, "", "") != "api-spec", path
