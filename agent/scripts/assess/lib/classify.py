"""URL type classification — replaces lib/classify.sh.

Pure Python regex replaces 30+ grep subprocess pairs per call.
Same classification priority order as the bash version.

Per-host URL budgeting was removed in the mid-engagement refactor — the
previous 1000-URL cap silently deferred 4,300+ URLs in a single Katana crawl.
Volume control now lives in the inline classification at insert time
(low-signal types are stamped `status='skipped'`); deferral is reserved for
genuine network failure modes (egress-blocked hosts).
"""
from __future__ import annotations

import json
import re

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Pre-compiled patterns (one-time cost)
_GRAPHQL_PATH = re.compile(r"/graphql", re.IGNORECASE)
_GRAPHQL_CT = re.compile(r"^application/graphql$", re.IGNORECASE)
_WS_SCHEME = re.compile(r"^wss?://", re.IGNORECASE)
_WS_PATH = re.compile(r"/ws(/|$)|^/socket\.io(/|$)", re.IGNORECASE)
# Strengthened (Issue I backstop): added `api-docs.json`, `swagger-resources`,
# `swagger-ui`, `redoc`, and `/v3/api-docs` recall on top of the original
# alternatives. Every alternative stays segment-bounded by `(^|/)...(/|$)` so the
# FP set stays out: `/redocument` (next char `u`), `/swagger-resources-guide`
# (next char `-`) all reject. (`/v[0-9]+/api-docs` is also covered by the bare
# `api-docs` alternative since `api-docs` follows a `/` there.)
_API_SPEC_PATH = re.compile(
    r"(^|/)("
    r"api-docs(\.json)?"
    r"|openapi(\.json|\.yaml|\.yml)?"
    r"|swagger(\.json|\.yaml|\.yml|-ui(\.html)?|-resources)?"
    r"|redoc"
    r"|v[0-9]+/api-docs"
    r")(/|$)",
    re.IGNORECASE,
)
# De-anchored (was `^/(api|rest)...`): an `api` / `rest` / `v<n>` SEGMENT
# anywhere in the path is an API surface, not just at the path root — Katana
# crawls routinely surface `/internal/api/...` and `/svc/v2/...`. Every
# alternative is segment-bounded by `(^|/)...(/|$)` so the FP set stays out:
# `/api-guide` (next char `-`), `/rest-easy`, `/preview1/` (no `/v` boundary),
# `/version/1.0` (`v` not followed by a digit), `/vue/app` all reject.
_API_PATH = re.compile(
    r"(^|/)(api|rest)(/|$)|(^|/)v[0-9]+(/|$)", re.IGNORECASE
)
_API_CT = re.compile(r"application/json", re.IGNORECASE)
_UPLOAD_CT = re.compile(r"multipart/form-data", re.IGNORECASE)
_FORM_CT = re.compile(r"application/x-www-form-urlencoded", re.IGNORECASE)
_JS_EXT = re.compile(r"\.js$", re.IGNORECASE)
_JS_CT = re.compile(r"text/javascript|application/javascript", re.IGNORECASE)
_CSS_EXT = re.compile(r"\.css$", re.IGNORECASE)
_CSS_CT = re.compile(r"text/css", re.IGNORECASE)
# `.svg` is typed `page`, NOT image/inert — preserving the deliberate
# SVG-as-XSS-surface decision that `_PAGE_CT` already encodes for the
# `image/svg+xml` content-type. It stays out of `_IMAGE_EXT`.
_PAGE_EXT = re.compile(r"\.(html?|xhtml|php|aspx?|jsp|svg)$", re.IGNORECASE)
_PAGE_CT = re.compile(r"text/html|application/xhtml|image/svg\+xml", re.IGNORECASE)
# Mid-path (de-anchored) app-route extensions: a server-side app extension
# followed by `/`, `?`, `~`, or end-of-path is a routed application surface
# (e.g. `/login.php/extra`, `/db.nsf/view`, `/submit.do/step2`), not a static
# file. Matched against the FULL url_path so the `?` lookahead fires before the
# query is stripped. The leading `\.` plus the boundary lookahead keep it on a
# segment boundary, so the literal segment `/medicaid.documents/` does NOT match
# (`.do` is followed by `c`). A real static-asset rule (js/css/image) sits
# EARLIER in the cascade, so `/app.php/style.css` still types `stylesheet`.
# ASP.NET HTTP handlers (`.axd`,`.ashx`,`.asmx`) and WCF services (`.svc`) are
# routed application surfaces too (Issue A: WebResource.axd padding oracle,
# ViewState/Telerik deserialization, ELMAH `.axd`, `.asmx`/`.svc?wsdl` SOAP/WCF),
# so they type `page` instead of dropping to `unknown`. The `dotnet_handler`
# bucket then scores them regardless of type.
_APP_ROUTE_EXT = re.compile(
    r"\.(php|aspx?|jsp|do|action|cfm|nsf|axd|ashx|asmx|svc)(?=[/?~]|$)",
    re.IGNORECASE,
)
_DATA_EXT = re.compile(
    r"\.(json|xml|csv|ya?ml|txt|pdf|docx?|xlsx?|pptx?|rtf|odt)$", re.IGNORECASE
)
_DATA_CT = re.compile(
    r"application/json|application/xml|text/csv|text/xml|application/pdf|text/plain|application/ld\+json|text/markdown",
    re.IGNORECASE,
)
_IMAGE_CT = re.compile(r"^image/", re.IGNORECASE)
_SVG_CT = re.compile(r"svg", re.IGNORECASE)
_IMAGE_EXT = re.compile(r"\.(png|jpg|jpeg|gif|webp|ico|bmp|tiff|avif|apng)$", re.IGNORECASE)
_VIDEO_CT = re.compile(r"^(video|audio)/", re.IGNORECASE)
_VIDEO_EXT = re.compile(r"\.(mp4|webm|avi|mp3|wav|ogg)$", re.IGNORECASE)
_FONT_CT = re.compile(r"^font/|application/vnd\.ms-fontobject", re.IGNORECASE)
_FONT_EXT = re.compile(r"\.(woff|woff2|ttf|otf|eot)$", re.IGNORECASE)
_ARCHIVE_CT = re.compile(r"zip|gzip|tar|rar|7z|bzip", re.IGNORECASE)
_ARCHIVE_EXT = re.compile(r"\.(zip|tar|tgz|gz|rar|7z|bz2|xz)$", re.IGNORECASE)

# Sourcemaps and PWA/web manifests: low-signal for vulnerability work but
# captured by Katana / mitmproxy in volume. Distinct case_types so
# `db._SKIP_TYPES` can stamp them `status='skipped'` at insert time.
_SOURCEMAP_EXT = re.compile(r"\.(map|js\.map|css\.map)$", re.IGNORECASE)
_MANIFEST_EXT = re.compile(r"\.(webmanifest|manifest)$", re.IGNORECASE)
_MANIFEST_CT = re.compile(r"application/manifest\+json", re.IGNORECASE)

# Lexical app-route rescue (highest-value `unknown`-recall fix). Auth/admin/
# portal routes are normally extensionless, so they fall through every
# extension/static-asset rule above and used to land `type='unknown'`,
# stripping them of the `_TYPE_FLOOR` floors keyed on these exact spellings
# (`auth_entry`,`debug_config`,`portal_session` in classify_buckets.py). Each
# rule matches a segment ONLY: `(^|/)<seg>(?=[/?#]|$)`. The boundary suffix
# rejects substrings — `/login-help-article`, `/about/admin-team`,
# `/configuration-guide` do NOT match. These run LATE in the cascade (after
# every file-extension/static-asset rule, after api/data) so a real static
# asset or an api segment still wins; this is purely a last-chance rescue
# before `unknown`. `.env` is regex-escaped; `oauth` is listed alongside `auth`
# so `/oauth` matches via the `oauth` alternative (the `auth` alternative needs
# a `/` before it and so will not fire inside `oauth`). Order within the list
# below is the resolution order on the (rare) co-occurring single segment.
#
# AUTH-MANAGEMENT extension (account-takeover surfaces). A recurring,
# set of high-value auth-management routes — password
# reset, account activation/unlock, signup/registration, account recovery,
# email verification — fell through the original auth set
# (`login|signin|sso|...`) and landed `type='unknown'`. Regression examples include camelCase `/efi/security/forgotPassword`,
# `/efi/security/activateUserAccount`, `/efi/security/unlockUserAccount`,
# `/efi/signup` and the hyphenated `/forgot-password`. These rescue to
# `auth_entry` (floor 40) alongside the base auth keywords.
#
# classify_type matches on the (case-insensitive) path, so each keyword tolerates
# BOTH the hyphenated form (`forgot-password`) and the camelCase-lowercased form
# (`forgotPassword` → `forgotpassword`) via optional `-?` separators. Every rule
# stays segment-anchored `(^|/)<kw>(?=[/?#]|$)`: the trailing boundary lookahead
# is what keeps content slugs OUT — `/forgot-password-help` (next char `-`),
# `/registration-information`, `/activate-your-warranty-online`,
# `/unlockable-content`, `/recovery-stories`, `/account-benefits` all fail
# because the keyword is not followed by a `/`, `?`, `#`, or end-of-path.
#
# The `/security/` route-segment hint is covered by these verb-anchored rules:
# `/efi/security/forgotPassword` matches the `forgot-?password` keyword on its
# own segment, while `/efi/security/dashboard` does NOT match any auth verb and
# so is correctly left alone — no separate `/security/`-prefixed rule is needed
# (and adding one would only re-match what the verb rules already catch).
#
# account/profile DECISION: bare `/account`,`/profile`,`/settings`,`/me` are NOT
# rescued here. They are object-reference (IDOR/BOLA) surfaces, not auth-CREDENTIAL
# entry points; the exploitable shape `/account/<id>` is already handled by the
# idor path-object-ref rule in classify_buckets, and folding `/account` into the
# idor bucket's path fragments would break the pinned
# `/account/settings?next=/x -> gf:redirect` precision test. Typing a bare
# `/account` as `auth_entry` would be a wrong-cluster false signal, so it stays
# `unknown` at the typer layer.
_LEXICAL_ROUTE_RULES: tuple[tuple["re.Pattern[str]", str], ...] = (
    (
        re.compile(
            r"(^|/)(login|signin|sign-in|sso|saml|auth|oauth|mfa|2fa|otp|logout)"
            r"(?=[/?#]|$)",
            re.IGNORECASE,
        ),
        "auth_entry",
    ),
    (
        # Auth-MANAGEMENT verbs (account-takeover surfaces). Segment-anchored;
        # `-?` makes the separator optional so the camelCase-lowercased form
        # (`forgotpassword`, `activateuseraccount`) and the hyphenated form
        # (`forgot-password`, `activate-account`) both match. The
        # `activate`/`unlock` variants accept an optional trailing
        # `(-?user)?-?account` so `/activate`, `/activate-account`, and
        # `/activateUserAccount` all fire, while
        # `/activate-your-warranty-online` (no boundary after `activate`) does
        # not.
        re.compile(
            r"(^|/)("
            r"forgot-?password"
            r"|reset-?password"
            r"|change-?password"
            r"|activate(-?user)?-?account|activate"
            r"|unlock(-?user)?-?account|unlock"
            r"|recovery|recover"
            r"|sign-?up"
            r"|registration|register"
            r"|verify-?email|email-?verify"
            r")(?=[/?#]|$)",
            re.IGNORECASE,
        ),
        "auth_entry",
    ),
    (
        re.compile(
            r"(^|/)(admin|debug|config|\.env|actuator|console)(?=[/?#]|$)",
            re.IGNORECASE,
        ),
        "debug_config",
    ),
    (
        re.compile(
            r"(^|/)(aura|sfsites|s)(?=[/?#]|$)",
            re.IGNORECASE,
        ),
        "portal_session",
    ),
    (
        # Extensioned auth-entry pages (Issue C). WordPress `wp-login.php` and the
        # generic `<prefix>-login` / `<prefix>-signin` portal forms carry a
        # server-side page/app extension, so the page rule (step 9) would type
        # them `page` and strip their `auth_entry` floor. The step-9 page rule
        # consults these rescue rules BEFORE defaulting to `page`, so an
        # extensioned auth page reaches `auth_entry`. Segment-anchored: a
        # `<prefix>-` must precede the `login`/`signin` keyword, which must
        # immediately precede a known app/page extension and then a segment
        # boundary — `/wp-login.php`, `/user-signin.aspx`, `/account-login.jsp`
        # match; `/login-help.php` (keyword not at segment end) and a plain
        # content page `/blog-post.php` (no auth keyword) do NOT. The other
        # (extensionless) rescue rules above cannot match an extensioned segment
        # at all — their trailing `(?=[/?#]|$)` boundary rejects the `.<ext>` — so
        # this is the only rule the step-9 reclaim can fire.
        re.compile(
            r"(^|/)[a-z0-9_]+-(?:login|signin|sign-in)"
            r"\.(?:php|aspx?|jsp|do|action|cfm)(?=[/?#]|$)",
            re.IGNORECASE,
        ),
        "auth_entry",
    ),
)


def classify_type(method: str, url_path: str, content_type: str = "", body_snippet: str = "") -> str:
    """Classify a request into a case type. Same priority order as classify.sh."""
    method_upper = method.upper()
    ct_lower = content_type.lower() if content_type else ""
    path_no_query = url_path.split("?", 1)[0]
    is_write = method_upper in _WRITE_METHODS

    # 1. graphql
    if _GRAPHQL_PATH.search(url_path):
        return "graphql"
    if ct_lower and _GRAPHQL_CT.search(ct_lower):
        return "graphql"
    if body_snippet:
        try:
            obj = json.loads(body_snippet)
            qval = obj.get("query", "")
            if qval and "{" in qval and "}" in qval:
                return "graphql"
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

    # 2. websocket
    if _WS_SCHEME.search(url_path):
        return "websocket"
    if _WS_PATH.search(url_path):
        return "websocket"

    # 3. api-spec
    if _API_SPEC_PATH.search(url_path):
        return "api-spec"

    # 4. api
    if _API_PATH.search(url_path):
        return "api"
    if is_write and _API_CT.search(ct_lower):
        return "api"

    # 5. upload
    if _UPLOAD_CT.search(ct_lower):
        return "upload"

    # 6. form
    if method_upper in ("POST", "PUT") and _FORM_CT.search(ct_lower):
        return "form"

    # 7. javascript
    if _JS_EXT.search(path_no_query):
        return "javascript"
    if _JS_CT.search(ct_lower):
        return "javascript"

    # 8. stylesheet
    if _CSS_EXT.search(path_no_query):
        return "stylesheet"
    if _CSS_CT.search(ct_lower):
        return "stylesheet"

    # 9. page
    # Issue C — extensioned auth-entry reclaim. The lexical auth rescue (step 17)
    # runs AFTER this page rule, so an auth route carrying a page/app extension
    # (`wp-login.php`, `portal-signin.aspx`, `account-login.jsp`) would otherwise
    # be swallowed as `page` and stripped of its `auth_entry` floor. When the path
    # IS page/app-extensioned, consult the lexical auth-route rules first and
    # return the matched (auth) type. Only the dedicated extensioned-auth rule can
    # match here — the other (extensionless) rescue rules' trailing
    # `(?=[/?#]|$)` boundary rejects the `.<ext>` — so ordinary pages
    # (`/index.php`, `/cgi-bin/login.php/extra`) still fall through to `page`.
    if _PAGE_EXT.search(path_no_query) or _APP_ROUTE_EXT.search(url_path):
        for route_rx, route_type in _LEXICAL_ROUTE_RULES:
            if route_rx.search(path_no_query):
                return route_type
    if _PAGE_EXT.search(path_no_query):
        return "page"
    # Mid-path app-route extension (`/login.php/extra`, `/db.nsf/view`). Run on
    # the FULL url_path so the `?` lookahead sees the query separator.
    if _APP_ROUTE_EXT.search(url_path):
        return "page"
    if _PAGE_CT.search(ct_lower):
        return "page"

    # 10. sourcemap (.map / .js.map / .css.map). Source maps are useful as
    # source intel for `source-analyzer` (they reveal original file paths and
    # symbols), but the URL itself never deserves a vulnerability-analyst
    # probe. Check before generic data content-types so `.js.map` responses
    # served as application/json or text/plain still get skipped at insert.
    if _SOURCEMAP_EXT.search(path_no_query):
        return "sourcemap"

    # 11. data
    if _DATA_EXT.search(path_no_query):
        return "data"
    if _DATA_CT.search(ct_lower):
        return "data"

    # 12. image (excluding svg, already handled as page)
    if _IMAGE_CT.search(ct_lower) and not _SVG_CT.search(ct_lower):
        return "image"
    if _IMAGE_EXT.search(path_no_query):
        return "image"

    # 13. video/audio
    if _VIDEO_CT.search(ct_lower):
        return "video"
    if _VIDEO_EXT.search(path_no_query):
        return "video"

    # 14. font
    if _FONT_CT.search(ct_lower):
        return "font"
    if _FONT_EXT.search(path_no_query):
        return "font"

    # 15. archive
    if _ARCHIVE_CT.search(ct_lower):
        return "archive"
    if _ARCHIVE_EXT.search(path_no_query):
        return "archive"

    # 16. PWA / web manifest. Pure metadata.
    if _MANIFEST_EXT.search(path_no_query):
        return "manifest"
    if _MANIFEST_CT.search(ct_lower):
        return "manifest"

    # 17. lexical app-route rescue. Extensionless auth/admin/portal routes that
    # matched no extension/static-asset/api/data rule above are rescued into the
    # floor-carrying types (`auth_entry`,`debug_config`,`portal_session`) keyed
    # in classify_buckets `_TYPE_FLOOR`, instead of dropping to `unknown`. Run on
    # path_no_query (the query is a separate signal); the segment-boundary
    # lookahead in each pattern guards against substring FPs. Placed LATE so a
    # real static asset (`/login/app.js` → javascript at step 7) or an api
    # segment (`/api/login` → api at step 4) still wins.
    for route_rx, route_type in _LEXICAL_ROUTE_RULES:
        if route_rx.search(path_no_query):
            return route_type

    # 18. host_root — a bare scheme://host[/] with no path, query, or content-type
    # signal. These are live host landing URLs from host-level ingestion (e.g.
    # `ingest-endpoints` of resolved live hosts) that carry no exploitable surface
    # on their own; they are Phase-2 crawl seeds, not vuln-analyst work. Typing
    # them distinctly (instead of "unknown") lets the dispatcher route/track them
    # as "needs a crawl" rather than leaving them as unrouted unknowns forever.
    if path_no_query in ("", "/") and "?" not in url_path and not ct_lower:
        return "host_root"

    # 19. unknown
    return "unknown"
