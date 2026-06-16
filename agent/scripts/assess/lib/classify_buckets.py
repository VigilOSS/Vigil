"""Shared gf-style bucket classification used by both ingestion and re-runs.

This module is the single source of truth for the priority/cluster assignments
that `db_insert_work_item()` writes inline at insert time and that
`vigil assess classify-work` re-applies idempotently. Keeping the logic in one
place ensures the two paths cannot drift — operators forgetting to run
`classify-work` after an ingest used to leave the work buffer unscored, which
broke priority-mode dispatch silently.

Design notes:
- Bucket weights only control triage ordering, not skip/include. Adding a
  marginal bucket at low weight (~10-15) is therefore strictly better than
  letting the URL drown in a `path:<seg1>/<seg2>` cluster — the URL still
  surfaces in `gf:*` clusters and gets specialist attention proportional to
  its weight.
- The Python `_BUCKETS` is authoritative. `agent/references/gf-patterns/DRIFT.md`
  records accepted and rejected GF category decisions so future reviewers can
  see why a bucket exists here or intentionally belongs to another pipeline.
- Adversarial-mindset alignment (per `agent/rules/adversarial-mindset.md`):
  trust-delegation surfaces (uploads, webhooks, password-reset, OAuth callback,
  exports, imports) score high enough on their own to guarantee specialist
  attention, even when no obviously vulnerable parameter is present.
"""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from . import vuln_taxonomy


# gf-style bucket weights. Higher = more likely to yield exploitable signal.
# Each tuple is (name, weight, parameter-key set, path-fragment tuple). A
# parameter-key hit OR a path-fragment hit puts the row in the bucket. When
# multiple buckets fire, the highest-weight normally wins for `cluster_key` /
# `priority_score`; every match is recorded in `priority_reason` as a `+`
# joined chain so operators can see the full classification trail.
#
# Regex buckets (override #1): `fragment_in_path()` matches a literal fragment
# via `re.escape()`, so a regex pattern can NEVER be a literal `path_fragments`
# entry. Override #1 authorizes either a 5th tuple field OR a separate rule list.
# We use the separate `_REGEX_BUCKET_RULES` list (keyed by bucket name) so the
# `_BUCKETS` tuples stay a 4-element shape — a 5th field would break the
# 4-tuple unpacks in `_IDOR_WEIGHT` / `_INTERESTINGEXT_WEIGHT` and in the
# `test_vuln_taxonomy.py` drift check (`for name, _w, _k, _p in _BUCKETS`).
# `bucket_matches` keeps a SINGLE declaration-ordered iteration over `_BUCKETS`
# and consults `_REGEX_BUCKET_RULES.get(name)` on the same pass, so tie-break
# order (first bucket at max weight) and reason-chain order (declaration order)
# remain defined by the one `_BUCKETS` list. A regex bucket still gets a real
# `_BUCKETS` entry (empty key set + empty literal fragments) so it is visible to
# `GF_BUCKET_TO_CLASS` and the bucket iteration; its only match signal is the
# regex rule.
_BUCKETS: tuple[tuple[str, int, frozenset[str], tuple[str, ...]], ...] = (
    (
        "rce",
        50,
        frozenset({"cmd", "exec", "command", "shell", "run", "execute"}),
        ("/exec/", "/cmd/", "/shell/"),
    ),
    (
        "graphql",
        # NEW (classify-surface 2026-06, §6.1): GraphQL endpoints and the
        # canonical GraphQL request keys. `/query` is deliberately NOT a path
        # fragment (it would mis-bucket REST search routes at weight 45); the
        # `query` PARAM key already carries that signal.
        45,
        frozenset({"query", "mutation", "subscription", "operationname", "variables"}),
        (
            "/graphql", "/graphiql", "/graphql/v1", "/graphql/v2",
            "/api/graphql", "/gql",
        ),
    ),
    (
        "ssrf",
        # Reduced from 45 -> 40 during the upstream review-and-merge: the prior
        # generic key set (`data`, `path`, `view`, `src`) produced too many
        # false positives on benign APIs that take a `view` query param. The
        # path fragments still anchor true SSRF surfaces (proxies, fetchers).
        # Key set NARROWED (§7, override #7): redirect/callback/continue/next/
        # link/dest moved OUT to `redirect`. ssrf still fires on those via its
        # `/proxy/`,`/fetch/` PATH fragments, not the param keys.
        40,
        frozenset({
            "url", "uri", "host", "port", "feed", "window",
        }),
        ("/proxy/", "/fetch/"),
    ),
    (
        "sqli",
        40,
        frozenset({
            "id", "uid", "pid", "sid", "tid", "order", "sort", "filter",
            "q", "search", "query", "category",
        }),
        (),
    ),
    (
        "lfi",
        40,
        frozenset({
            "file", "path", "doc", "document", "page", "pg", "template",
            "load", "include", "read",
        }),
        (),
    ),
    (
        "auth",
        # NEW (classify-surface 2026-06, §6.2, override #8): authentication-entry
        # surfaces. COMPOUND path fragments only — bare `/verify` is EXCLUDED
        # (captcha/verify FP); only the compound `/auth/verify` and
        # `/email/verify` are allowed. `email`/`token` are NOT auth keys (too
        # generic / owned by jwt+interestingparams).
        40,
        frozenset({"username", "password", "mfa_code", "otp", "totp"}),
        (
            "/login", "/signin", "/sign-in", "/signon", "/sign-on",
            "/logout", "/sign-out", "/mfa", "/2fa", "/totp", "/otp",
            "/authenticate", "/auth/login", "/auth/signin", "/auth/verify",
            "/email/verify", "/saml/acs", "/saml/sso",
        ),
    ),
    (
        "deserialization",
        # NEW (classify-surface 2026-06, §6.7): unsafe deserialization surfaces.
        # `/sfsites/` is the Siteforce loader-state PATH PREFIX — it fires even
        # when the URL ends `.js`. Ordinary `.js` (no /sfsites/, no deserial
        # param) stays low (roster requirement).
        40,
        frozenset({
            "data", "payload", "blob", "object", "serialized",
            "viewstate", "__viewstate",
        }),
        (
            "/deserialize", "/marshal", "/unmarshal", "/pickle",
            "/java-serial", "/sfsites/",
        ),
    ),
    (
        "img_traversal",
        # NEW (review-and-merge): image-serving endpoints that take a path
        # fragment are a classic LFI variant — `/img?src=../../etc/passwd`
        # style. Separate bucket from `lfi` because the param key set is
        # different (image-flavored) and the path fragments are distinctive.
        35,
        frozenset({"img", "image", "photo", "thumb", "thumbnail"}),
        ("/img/", "/image/", "/images/", "/thumb/", "/thumbnail/", "/photo/"),
    ),
    (
        "oauth-oidc",
        # NEW (classify-surface 2026-06, §6.5): OAuth2/OIDC flow endpoints and
        # the canonical OAuth request keys. Declared BEFORE `trust_surface`
        # (both weight 35) so a co-fire on shared fragments (`/connect/token`,
        # `/oauth2/authorize`'s `/authorize`) resolves to `gf:oauth-oidc` by the
        # first-at-max-weight tie-break (matrix O2/O3). `/oauth2/`,`/oidc/` are
        # distinct from trust_surface's `/oauth` fragment — `/oauth/callback`
        # does NOT contain `/oauth2/` (the `2` is required), so trust_surface
        # keeps owning the bare callback (regression pin §10.5).
        35,
        frozenset({
            "client_id", "redirect_uri", "response_type", "scope", "state",
            "nonce", "code_challenge", "grant_type",
        }),
        (
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/oauth2/", "/oidc/",
            "/connect/authorize", "/connect/token", "/connect/userinfo",
            "/jwks.json", "/.well-known/jwks.json",
        ),
    ),
    (
        "sso",
        # NEW (classify-surface 2026-06, §6.11): SAML/SSO surfaces. `/saml` is
        # boundary-anchored so it covers `/saml`,`/saml/acs` but NOT `/saml2`
        # (next char `2` is not a boundary) — `/saml2` is listed separately.
        # Declared before `trust_surface` (weight 35) for the same tie-break
        # reason as `oauth-oidc`.
        35,
        frozenset({"samlresponse", "samlrequest", "relaystate", "wctx", "wresult"}),
        (
            "/sso/", "/sso", "/saml", "/saml2", "/cas/", "/adfs/", "/fed/",
            "/sts/",
        ),
    ),
    (
        "trust_surface",
        # NEW (review-and-merge): adversarial-mindset rule 2 — uploads,
        # webhooks, password-reset, OAuth callbacks, exports, imports, file
        # download/preview/render are all places where the server trusts
        # client-supplied content type, filename, or token. Path-only
        # detection because these surfaces almost never have a single
        # canonical parameter name.
        35,
        frozenset(),
        (
            "/upload", "/import", "/export", "/webhook", "/callback",
            "/reset", "/recover", "/invite", "/share",
            "/oauth", "/authorize", "/token", "/connect",
            "/download", "/preview", "/render", "/convert",
        ),
    ),
    (
        "idor",
        # Object-reference parameter keys. Expanded beyond the original upstream
        # gf slice (`id,user,account,number,doc,email,group,profile,order,report`)
        # to cover the *_id family, tenant/org/workspace scoping keys (cross-tenant
        # BOLA), and the modern chat/agent object refs (conversation/thread/message)
        # that 2024-2026 IDOR research flags as primary surfaces. Path-embedded
        # object references (`/users/1024/profile`) are handled separately by the
        # `_PATH_OBJECT_REF_SEGMENT` rule in `classify_row`, not by path fragments
        # here, because they need id-shape detection (numeric/UUID/hex) rather than
        # a fixed substring.
        35,
        frozenset({
            # original upstream slice
            "id", "user", "account", "number", "doc", "email", "group",
            "profile", "order", "report",
            # user / identity references
            "uid", "userid", "user_id", "owner", "owner_id", "member",
            "member_id", "customer", "customer_id", "account_id", "accountid",
            # tenant / org scoping (cross-tenant BOLA)
            "org", "org_id", "organization", "organization_id", "tenant",
            "tenant_id", "workspace", "workspace_id",
            # generic object handles
            "object", "object_id", "objectid", "oid", "record", "record_id",
            "ref", "reference", "uuid", "guid", "gid", "node", "pid",
            # domain objects
            "order_id", "orderid", "invoice", "invoice_id", "document_id",
            "doc_id", "file_id", "fileid", "transaction", "transaction_id",
            "payment", "payment_id", "ticket", "ticket_id", "case_id",
            # modern chat / agent object refs
            "conversation", "conversation_id", "thread", "thread_id",
            "message_id", "msg_id",
        }),
        (),
    ),
    (
        "upload_fields",
        # NEW (review-and-merge): parameter-level signal for upload surfaces
        # that may not match the `trust_surface` path heuristic (e.g.,
        # /api/v2/users/avatar uses `file` as the multipart key but the path
        # has no /upload fragment). Lower weight than `trust_surface` because
        # a parameter named `file` alone is weaker signal than the path
        # fragment, but still high enough to dispatch.
        #
        # classify-surface 2026-06 (§6.12.1): the roster's "rename to
        # file-upload, raise to 35" is OVERRIDDEN by soundness override #9 (no
        # regression). The bucket KEEPS its name `upload_fields` (so the
        # `gf:upload_fields` cluster key and the pinned reason string
        # `gf:lfi+gf:upload_fields` survive) and KEEPS weight 30 (so the pinned
        # `priority_score == 40` arithmetic in
        # `test_upload_rows_prefer_upload_fields_over_generic_lfi` survives).
        # The real recall win is delivered via the new REST path fragments and
        # the three new content-type keys (`content_type`,`mime_type`,
        # `multipart`), NOT a weight bump. `GF_BUCKET_TO_CLASS["upload_fields"]`
        # already maps to the `file-upload` class.
        30,
        frozenset({
            "file", "filename", "upload", "attachment", "avatar",
            "image", "photo", "document", "media",
            "content_type", "mime_type", "multipart",
        }),
        (
            "/attachments", "/upload-file", "/file-upload", "/attach",
            "/media-upload",
        ),
    ),
    (
        "debug_logic",
        # Extended (classify-surface 2026-06, §6.13, override #3): keep ALL
        # existing fragments and ADD only compound/specific fragments. Bare
        # `/health`,`/info`,`/status`,`/version`,`/metrics`,`/env` are
        # deliberately NOT added (they flood content corpora).
        30,
        frozenset(),
        (
            "/admin", "/debug", "/dbg", "/dev", "/staging", "/stage",
            "/test", "/internal", "/mgmt", "/manage", "/console",
            "/dashboard", "/_profiler", "/phpinfo", "/actuator",
            "/.git", "/.env", "/config", "/backup",
            # ADDED (override #3): compound/specific only.
            "/healthz", "/readyz", "/server-status", "/server-info",
            "/package.json", "/actuator/health", "/actuator/env",
            "/actuator/mappings", "/actuator/metrics", "/actuator/beans",
            "/prometheus",
        ),
    ),
    (
        "websocket",
        # NEW (classify-surface 2026-06, §6.8): WebSocket / real-time transport
        # endpoints. `/ws` is boundary-anchored → `/ws`,`/ws/feed` match but
        # `/wsdl`,`/wsus` do NOT.
        30,
        frozenset({"channel", "room", "topic"}),
        (
            "/ws", "/wss", "/websocket", "/socket.io", "/sockjs", "/stomp",
            "/mqtt",
        ),
    ),
    (
        "webhook",
        # NEW (classify-surface 2026-06, §6.9): inbound/outbound webhook
        # surfaces. `url` is NOT a webhook key (ssrf at 40 already wins on
        # `?url=`); `/callback` is OMITTED (owned by trust_surface).
        #
        # The spec roster listed `/event`,`/events` as path fragments, but the
        # authoritative matrix proves they are content-navigation-prone
        # (`/events/2024/conf` is a conference listing, not a webhook): a bare
        # `/events` path must NOT fire webhook, yet `/events/...?endpoint=` MUST.
        # So `/event`,`/events` are dropped from the PATH set — the real
        # webhook-with-target case is captured by the `endpoint`/`target` keys,
        # while the unambiguous `/webhook(s)`,`/hook(s)`,`/notify` routes still
        # fire path-only.
        30,
        frozenset({"endpoint", "target"}),
        ("/webhook", "/webhooks", "/hook", "/hooks", "/notify"),
    ),
    (
        "jwt",
        # NEW (classify-surface 2026-06, §6.10, override #8): JWT/bearer-token
        # surfaces. Low-incremental secondary reason — bare `token` key and
        # bare `/token` path are OMITTED (owned by trust_surface /
        # interestingparams) to avoid double-firing on every `?token=`.
        30,
        frozenset({"access_token", "refresh_token", "id_token", "jwt", "bearer"}),
        ("/jwt", "/bearer", "/refresh-token"),
    ),
    (
        "redirect",
        25,
        frozenset({
            "redirect", "return", "returnto", "return_to", "next", "redir",
            "forward", "continue", "url", "rurl", "u", "target", "dest",
            "destination", "redirect_uri", "go",
        }),
        (),
    ),
    (
        "ssti",
        25,
        frozenset({"template", "tpl", "theme", "layout", "view"}),
        (),
    ),
    (
        "cors",
        # NEW (review-and-merge): upstream `cors` patterns target headers
        # rather than query params, but request bodies/path traversal
        # endpoints that echo the Origin header are a recognizable surface.
        # Param-key match catches the small set of endpoints that take an
        # explicit origin/access-control parameter.
        25,
        frozenset({"origin", "access_control", "allow_origin"}),
        (),
    ),
    (
        "api-versioning",
        # NEW (classify-surface 2026-06, §6.4, override #1): REGEX bucket. Its
        # only match signal is the `_REGEX_BUCKET_RULES["api-versioning"]`
        # pattern `/v[0-9]+(?=[/?#]|$)` — it has NO key set and NO literal
        # fragments. The empty `_BUCKETS` entry keeps it in the single
        # declaration-ordered iteration (for tie-break + reason-chain order)
        # and visible to `GF_BUCKET_TO_CLASS`.
        25,
        frozenset(),
        (),
    ),
    (
        "object-storage",
        # NEW (classify-surface 2026-06, §6.6, override #2): NEVER a bare
        # `/files/` or `/storage/` fragment (cms.gov has thousands of
        # `/files/*.pdf`). Use Domino-specific discriminators (`$file`,`.nsf`,
        # `files.nsf`,`docscat`,`didc`) PLUS cloud (`/s3/`,`/gcs/`,`/blob/`,
        # `/bucket/`). `key`/`object` dropped from the key set (too generic).
        25,
        frozenset({"bucket", "blob", "prefix"}),
        (
            "$file", ".nsf", "files.nsf", "docscat", "didc",
            "/s3/", "/gcs/", "/blob/", "/bucket/",
        ),
    ),
    (
        "api",
        # NEW (classify-surface 2026-06, §6.3, override #9): path-only, NARROWED.
        # Bare `/api/` and `/api/v` are DELIBERATELY OMITTED — a bare `/api/`
        # fragment would append `gf:api` to `/api/users/avatar` and break the
        # pinned exact reason chain `gf:lfi+gf:upload_fields`. The generic
        # params-less `/api/...` rescue is delivered by the `api_route` TYPE
        # FLOOR (§2); `/api/v<n>/` is covered by the `api-versioning` regex.
        20,
        frozenset(),
        ("/rest/", "/rest/v", "/services/apexrest/", "/apexrest/"),
    ),
    (
        "xss",
        20,
        frozenset({
            "q", "query", "search", "keyword", "name", "message", "comment",
            "text", "content", "input", "data",
        }),
        (),
    ),
    (
        "interestingparams",
        15,
        frozenset({
            "api_key", "apikey", "token", "auth", "session", "secret",
            "password", "passwd", "pwd",
        }),
        (),
    ),
    (
        "interestingext",
        # NEW (review-and-merge): backup files, source maps, env files,
        # dumped config — extension-based detection keyed off the URL path's
        # trailing fragment. Weight is intentionally low because the URL
        # itself is the finding (a 200 on /backup.sql is the vuln); we
        # mainly want it in a `gf:interestingext` cluster instead of
        # buried in a `path:` bucket.
        10,
        frozenset(),
        (
            ".bak", ".old", ".sql", ".swp", ".swo",
            ".config", ".env", ".conf", ".ini",
            ".pem", ".key", ".log",
        ),
    ),
)

# Weight of the `idor` bucket, resolved from the table above so the
# path-object-reference rule in `classify_row` cannot drift from the declared
# bucket weight if it is ever retuned.
_IDOR_WEIGHT: int = next(weight for name, weight, _, _ in _BUCKETS if name == "idor")


# Regex-fragment rules (override #1), keyed by the bucket name they belong to.
# `bucket_matches` consults `_REGEX_BUCKET_RULES.get(name)` on the SAME
# declaration-ordered pass over `_BUCKETS`, so a regex hit appends the bucket
# exactly as a literal/key hit would — preserving tie-break order (first bucket
# at the max weight) and reason-chain order (declaration order). Each entry is a
# tuple of raw regex strings; unlike literal fragments they are NOT
# boundary-wrapped by the helper — the pattern author supplies its own anchoring.
#
# `api-versioning` (§3.4): matches a path segment that is `v` + one-or-more
# digits, bounded by `/`, `?`, `#`, or end-of-string. Matches `/v1/`, `/v2/`,
# `/v3`, `/dhrp/rns/v3/actions`, `/api/v1/`; rejects `/version/1.0` (segment
# `version`), `/v/1` (segment `v`, no digits), `/vue/app` (segment `vue`),
# `/v1beta/x` (the lookahead rejects `beta` after the digits).
_REGEX_BUCKET_RULES: dict[str, tuple[str, ...]] = {
    "api-versioning": (r"/v[0-9]+(?=[/?#]|$)",),
}

_regex_fragment_cache: dict[str, "re.Pattern[str]"] = {}


def regex_fragment_in_path(pattern: str, url_path_lower: str) -> bool:
    """True when the raw regex `pattern` (its own anchoring) matches the path."""
    rx = _regex_fragment_cache.get(pattern)
    if rx is None:
        rx = re.compile(pattern)
        _regex_fragment_cache[pattern] = rx
    return rx.search(url_path_lower) is not None


# Producer `type` → (floor_bucket, floor_weight) table (§2.1, override #4). The
# producer `type` is otherwise discarded for non-inert rows; the floor makes it
# a first-class input. When a row matches NO bucket, a floor (if its type is
# present) sets cluster_key = `gf:<floor_bucket>` (NOT the path:* fallback) so
# specialist routing still fires. When a bucket DID match, the floor only raises
# the score (never the routing) via `max(match, floor)`. `api_spec` is a
# label-only floor bucket (no `_BUCKETS` entry) — like `interestingext` is used
# as the sourcemap cluster label.
#
# PRODUCER-VOCABULARY ALIGNMENT (do not let this silently drift). The keys here
# MUST match the types the producer actually emits, NOT plan-invented names.
# There are TWO producer typing paths and they emit DIFFERENT spellings of the
# same semantic type:
#
#   * `assess.lib.classify.classify_type()` — the dominant categorizer that every
#     ingest path (ingest-endpoints / ingest-spec / ingest-candidates / dispatch)
#     runs. It emits the canonical, content-derived types: `api` (the dominant
#     API type — 1,002 rows in cms-gov, 92 in xfinity), `api-spec` (HYPHEN — the
#     OpenAPI/Swagger/api-docs type), `graphql`, `sourcemap`, `host_root`, etc.
#   * `assess.lib.candidate_records.candidate_type()` — a SECONDARY signal-driven
#     path that RELABELS `api` → `api_route` (underscore) and adds the
#     surface-flavored types `auth_entry`, `portal_session`, `debug_config`,
#     `event_feed`, `workflow`. These are the minority types (e.g. 41 `api_route`
#     in cms-gov) layered on top of the `classify_type` output.
#
# Therefore:
#   * `api` and `api_route` are the SAME semantic type (api_route is just
#     candidate_type's relabel of api) → both floor to `gf:api` at weight 20.
#   * `api-spec` (hyphen, real) and `api_spec` (underscore) are pure
#     hyphen/underscore SPELLING DRIFT of one type → both floor to the label-only
#     `gf:api_spec` at weight 40. The underscore form `api_spec` is also the
#     taxonomy key in `vuln_taxonomy.GF_BUCKET_TO_CLASS`, so the FLOOR BUCKET
#     LABEL stays underscore even though the producer emits a hyphen.
#
# Robustness: the lookup normalizes the row's `type` (lowercase + hyphen→
# underscore) via `_normalize_floor_type()` BEFORE indexing this table, so a new
# hyphen/underscore/case variant of an existing type can never silently lose its
# floor again. The table itself is keyed on the NORMALIZED (underscore) form.
# Keep every key below in normalized form (no hyphens, lowercase).
_TYPE_FLOOR: dict[str, tuple[str, int]] = {
    "graphql": ("graphql", 45),
    # api family: `api` (classify_type, dominant) + `api_route`
    # (candidate_type's relabel) are one type → gf:api / 20.
    "api": ("api", 20),
    "api_route": ("api", 20),
    # api-spec family: `api-spec` (classify_type, hyphen) normalizes to
    # `api_spec`; the floor bucket LABEL is the underscore taxonomy key.
    "api_spec": ("api_spec", 40),
    "auth_entry": ("auth", 40),
    "form": ("auth", 30),
    "portal_session": ("auth", 35),
    "debug_config": ("debug_logic", 35),
    "workflow": ("idor", 30),
    "event_feed": ("ssrf", 25),
}


def _normalize_floor_type(case_type: str) -> str:
    """Normalize a producer `type` for the `_TYPE_FLOOR` lookup ONLY.

    Lowercases and unifies hyphen/underscore so producer spelling drift (the
    real `api-spec` hyphen vs the `api_spec` underscore floor key, or any future
    case/separator variant) cannot silently drop a row's floor. This is applied
    EXCLUSIVELY at the floor-lookup site — the inert/sourcemap/host_root
    early-returns above compare against their own (already-lowercased) literals
    and are deliberately NOT routed through this, so the floor stage's normalize
    cannot perturb that precedence. `case_type` is expected pre-lowercased by the
    caller; the `.lower()` here is a belt-and-suspenders guard for direct callers.
    """
    return case_type.lower().replace("-", "_")


# Canonical UUID and long-hex (Mongo ObjectId / SHA prefix) segment shapes,
# reused by both the raw path-object-ref predicate (§4) and the cluster-key
# normalizer (§5). Compiled here so neither call site re-compiles per row.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{24,}$")
_YEAR_RE = re.compile(r"^(?:19|20)[0-9]{2}$")
_NUMERIC_RE = re.compile(r"^[0-9]+$")
# Opaque app token: starts with a letter, contains at least one digit, length
# >= 5 (e.g. `M0004`, `G0058`). Used only by the cluster normalizer (§5).
_OPAQUE_TOKEN_RE = re.compile(r"^[a-z][0-9a-z]*[0-9][0-9a-z]*$")
# Literal pre-normalized template placeholders (override #5): `{id}`,`{uuid}`,
# `{n}` (case-insensitive on the word; braces literal).
_PLACEHOLDER_TOKENS = frozenset({"{id}", "{uuid}", "{n}"})


def _is_object_ref_segment(seg: str) -> bool:
    """True if a RAW lowercased path segment is an object-ref candidate (§4.1).

    UUID, long-hex, a placeholder token, or a numeric that survives the
    precision predicates (§4.2: year-excluded, not a bare 1-digit small-int).
    """
    if seg in _PLACEHOLDER_TOKENS:
        return True
    if _UUID_RE.match(seg) or _LONG_HEX_RE.match(seg):
        return True
    if _NUMERIC_RE.match(seg):
        if _YEAR_RE.match(seg):
            return False  # 4-digit year 1900..2099 is not an object ref
        if len(seg) == 1:
            return False  # bare 1-digit small-int (pagination/ordinal noise)
        return True
    return False


def _is_context_segment(seg: str) -> bool:
    """True if a RAW lowercased path segment can serve as collection context
    (§4.2): a >=2-char word that is NOT itself an object-ref candidate. Short
    prefixes like `efi`,`v2`,`wps` DO count (override #5)."""
    if len(seg) < 2:
        return False
    return not _is_object_ref_segment(seg)


def path_has_object_ref(url_path_lower: str) -> bool:
    """True if the RAW lowercased path embeds an object reference (§4).

    Fires iff there EXISTS an object-ref segment preceded somewhere earlier in
    the SAME path by at least one collection-context segment. This rejects a
    LONE id with no context (`/2024/`, `/{n}/`, `/12345`) while accepting real
    short-prefixed IDOR (`/efi/{id}`, `/v2/{id}`, `/api/users/1024/profile`).
    Runs on the RAW url only — normalization (§5) is NEVER consulted here
    (override #6).
    """
    segments = [s for s in url_path_lower.split("/") if s]
    seen_context = False
    for seg in segments:
        if _is_object_ref_segment(seg):
            if seen_context:
                return True
            # An object-ref segment is never itself counted as context for a
            # later id; fall through without flipping seen_context.
            continue
        if _is_context_segment(seg):
            seen_context = True
    return False

# coverage gap into a concrete `--skills` list.
#
# Every value is the bare skill name — the directory under `agent/skills/<name>/`
# that holds a `SKILL.md`. The recommender validates each name resolves on disk
# dropped" rather than recommending a nonexistent skill.
#
# intentionally absent — they are signal that the dominant-bucket tally is
#
BUCKET_SKILLS: dict[str, tuple[str, ...]] = vuln_taxonomy.derive_bucket_skills()


# Types that carry no exploitable surface on their own.
#
# This frozenset is the SINGLE SOURCE OF TRUTH for "inert" work-item types
# across the codebase. Every consumer that needs the same set imports
# `INERT_TYPES` from this module:
#
# - `agent/scripts/assess/lib/db.py:db_insert_work_item()` reads it to stamp
#   `status='skipped'` at insert time so inert rows never enter the dispatch
#   queue.
# - `agent/scripts/assess/lib/classify_buckets.py:classify_row()` (this file)
#   reads it to stamp `terminal_reason='inert_type'` so `fetch-by-priority`
#   excludes them with one predicate.
# - `agent/scripts/assess/commands/classify_work.py` reads it to scope the
#   `--reclassify-all` WHERE clause to the same set the inline classifier
#   skips on insert.
# Adding a new inert type means editing this one place — every consumer
# picks it up automatically. Hand-maintained copies in any of those files
# are a drift hazard.
INERT_TYPES: frozenset[str] = frozenset(
    {"image", "video", "font", "archive", "manifest"}
)

# Backwards-compatible alias for the previous private name; new code should
# import the public `INERT_TYPES` symbol above.
_INERT_TYPES = INERT_TYPES


# Structured reason tags for deferred/skipped work items. SINGLE SOURCE OF TRUTH
# for the skip vocabulary so `defer-cluster`/`defer-items`, `work-buffer stats
# --by reason`, and any future gate read the same set. The stored value is
# ``skipped:<tag> | <free text>`` (or just ``skipped:<tag>``), which de-overloads
# the `skipped` terminal state: a query can now distinguish a correct exclusion
# (blackholed/dead/low-signal/duplicate/egress) from a bare, un-reasoned drop.
SKIP_REASON_TAGS: frozenset[str] = frozenset(
    {"blackholed", "dead-host", "low-signal-cluster", "duplicate", "egress-blocked"}
)


def tagged_terminal_reason(tag: str, detail: str = "") -> str:
    """Build a structured ``terminal_reason`` from a reason tag + free-text detail."""
    tag = (tag or "").strip()
    detail = (detail or "").strip()
    prefix = f"skipped:{tag}" if tag else ""
    if prefix and detail:
        return f"{prefix} | {detail}"
    return prefix or detail


def reason_tag_of(terminal_reason: str | None) -> str:
    """Return the structured reason tag from a terminal_reason value.

    - ``inert_type`` → ``inert_type`` (auto-skipped at ingest).
    - ``skipped:<tag> | ...`` → ``<tag>``.
    - empty → ``""`` (no terminal reason).
    - any other free text → ``"untagged"`` (a legacy/un-reasoned defer — the
      exact state worth surfacing as "dropped without a machine-readable reason").
    """
    tr = (terminal_reason or "").strip()
    if not tr:
        return ""
    if tr == "inert_type":
        return "inert_type"
    if tr.startswith("skipped:"):
        head = tr.split("|", 1)[0].strip()
        return head[len("skipped:"):].strip() or "untagged"
    return "untagged"

_UPLOAD_GENERIC_SHADOWS = frozenset({"lfi", "idor"})

_INTERESTINGEXT_WEIGHT: int = next(
    weight for name, weight, _, _ in _BUCKETS if name == "interestingext"
)


def classify_row(row: sqlite3.Row) -> dict[str, Any]:
    """Return the per-row assignment dict (always present, never None).

    Inert types (image/video/font/archive/manifest) are stamped with
    `terminal_reason='inert_type'` so `fetch-by-priority` can skip them with a
    single predicate. For every other row the highest-weight matching bucket
    wins; the path fallback gives operators a coarse grouping when no bucket
    fires.
    """
    case_type = (row["type"] or "").lower()
    if case_type in _INERT_TYPES:
        return {
            "priority_score": 0,
            "priority_reason": None,
            "cluster_key": f"type:{case_type}",
            "terminal_reason": "inert_type",
            "matched_buckets": [],
        }

    if case_type == "sourcemap":
        return {
            "priority_score": _INTERESTINGEXT_WEIGHT,
            "priority_reason": "gf:interestingext",
            "cluster_key": "gf:interestingext",
            "terminal_reason": None,
            "matched_buckets": ["interestingext"],
        }

    if case_type == "host_root":
        # A bare scheme://host[/] landing URL: no exploitable surface on its own,
        # but a Phase-2 crawl seed. Stamp a stable, greppable cluster so the
        # operator can see "N hosts await crawling" instead of it hiding among
        # unrouted `unknown` / `path:/` rows. NOT inert — it must stay `pending`,
        # not be skipped, so it is never silently dropped.
        return {
            "priority_score": 0,
            "priority_reason": None,
            "cluster_key": "type:host_root",
            "terminal_reason": None,
            "matched_buckets": [],
        }

    url_path = row["url_path"] or ""
    url_path_lower = url_path.lower()
    keys = collect_keys(row["query_params"], row["body_params"], row["path_params"])
    matches = bucket_matches(url_path_lower, keys)

    # SSO-route disambiguation (matrix W8 vs W10/X3/A7). On an SSO ROUTE
    # (`/sso/...`) the generic auth `/login`/`/signin` suffix is part of the SSO
    # entry, not a standalone auth surface — so `gf:auth` must not fire there
    # (W8 pins cluster `gf:sso` AND score 35, i.e. auth fully absent). But auth
    # still wins when it fired via a real SAML-auth compound (`/saml/acs`,
    # `/saml/sso` — X3, A7) or via an auth PARAM key (W10's SAMLResponse lands on
    # a `/login` page → auth wins). So: drop auth IFF an sso PATH fragment fired,
    # the path has no `/saml/acs`|`/saml/sso`, and no auth param key fired.
    matches = _suppress_auth_on_sso_route(matches, url_path_lower, keys)

    # Path-embedded object references (`/users/1024/profile`, `/files/<uuid>`,
    # `/efi/{id}`) carry an IDOR surface even when no query/body parameter names
    # an id — the identifier lives in a path segment the param-key buckets cannot
    # see. `path_has_object_ref` runs on the RAW url only (§4 / override #6) with
    # precision predicates (year/small-int exclusion, collection-noun gate). If
    # it fires, route the row to the idor specialist too, deduped against an
    # existing key-based idor match so the reason chain never lists `gf:idor`
    # twice.
    if path_has_object_ref(url_path_lower) and not any(
        name == "idor" for name, _ in matches
    ):
        matches.append(("idor", _IDOR_WEIGHT))

    # Producer-`type` floor (§2.2, override #4). Applied AFTER the
    # inert/sourcemap/host_root early-returns (those still win above). The floor
    # NEVER lowers a bucket-driven score (`score = max(match, floor)`); when a
    # bucket matched it only raises the number, not the routing. The lookup key
    # is normalized (lowercase + hyphen→underscore) so the producer's real
    # `api-spec` (hyphen) and the `api`/`api_route` spellings all resolve to
    # their intended floor — see `_TYPE_FLOOR`'s producer-vocabulary note.
    floor = _TYPE_FLOOR.get(_normalize_floor_type(case_type))
    floor_weight = floor[1] if floor else 0

    if matches:
        best_weight = max(weight for _, weight in matches)
        top_buckets = [name for name, weight in matches if weight == best_weight]
        best_name = select_cluster_bucket(case_type, matches, top_buckets[0])
        reason = "+".join(f"gf:{name}" for name, _ in matches)
        matched_buckets: list[str] = []
        for name, _ in matches:
            if name not in matched_buckets:
                matched_buckets.append(name)
        return {
            "priority_score": max(best_weight, floor_weight),
            "priority_reason": reason,
            "cluster_key": f"gf:{best_name}",
            "terminal_reason": None,
            "matched_buckets": matched_buckets,
        }

    if floor:
        # NO bucket matched but a floor fires: cluster as `gf:<floor_bucket>`
        # (NOT path:* — override #4) so specialist routing / the 2b coverage
        # bridge / fetch-by-priority still route the row.
        floor_bucket = floor[0]
        return {
            "priority_score": floor_weight,
            "priority_reason": f"gf:{floor_bucket}",
            "cluster_key": f"gf:{floor_bucket}",
            "terminal_reason": None,
            "matched_buckets": [floor_bucket],
        }

    return {
        "priority_score": 0,
        "priority_reason": None,
        "cluster_key": f"path:{normalize_path_for_cluster(url_path)}",
        "terminal_reason": None,
        "matched_buckets": [],
    }


def select_cluster_bucket(
    case_type: str,
    matches: list[tuple[str, int]],
    default_name: str,
) -> str:
    """Choose the cluster bucket, with a narrow upload-specific override.

    Multipart rows commonly use generic field names such as `file` or
    `document`, which also appear in LFI/IDOR patterns. Keep those generic
    buckets for ordinary requests, but cluster true upload rows as
    `upload_fields` when the only winner is one of those generic overlaps.
    Higher-risk buckets such as RCE/SSRF/SQLi still win normally.
    """
    if (
        case_type == "upload"
        and default_name in _UPLOAD_GENERIC_SHADOWS
        and any(name == "upload_fields" for name, _ in matches)
    ):
        return "upload_fields"
    return default_name


def collect_keys(*columns: str | None) -> set[str]:
    """Collect lowercased parameter keys across JSON-encoded columns."""
    keys: set[str] = set()
    for raw in columns:
        if not raw:
            continue
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(decoded, dict):
            continue
        for k in decoded.keys():
            keys.update(expand_compound_key(str(k).lower()))
    return keys


def expand_compound_key(key: str) -> set[str]:
    """Expand a single parameter key into its matchable tokens.

    Forms (e.g., search frameworks) commonly send compound keys like
    `filter[user][id]` or `data.user.id`. We split on `.` / `[` / `]` so the
    inner tokens (`filter`, `user`, `id`, `data`) all participate in bucket
    matching alongside the original.
    """
    tokens = {key}
    for sep in (".", "[", "]"):
        key = key.replace(sep, " ")
    for part in key.split():
        part = part.strip()
        if part:
            tokens.add(part)
    return tokens


# A literal path fragment must be followed by a segment boundary. `.` is in the
# boundary set so an auth route like `/Login.aspx` (lowercased `/login.aspx`)
# still matches the `/login` fragment (matrix W10), and `.env.local` matches
# `.env`, while `/administration-guide` still does NOT match `/admin` (next char
# `i`) and `/notes.nsfx` does NOT match `.nsf` (next char `x`).
_FRAGMENT_BOUNDARY = r"(?=[/?#=&.]|$)"
_fragment_pattern_cache: dict[str, "re.Pattern[str]"] = {}


def _fragment_pattern(fragment: str) -> "re.Pattern[str]":
    """Return a cached, boundary-anchored regex for a risk path fragment.

    The fragment is matched literally but must be followed by a segment
    boundary, so `/admin` matches `/admin` and `/admin/users` but NOT
    `/administration-guide`, and `.env` matches `/.env` / `/app/.env?x` but NOT
    `.environment`. A trailing slash on the fragment is the boundary itself, so
    it is dropped before anchoring (`/proxy/` → `/proxy` + boundary).
    """
    cached = _fragment_pattern_cache.get(fragment)
    if cached is not None:
        return cached
    core = fragment[:-1] if fragment.endswith("/") and len(fragment) > 1 else fragment
    pattern = re.compile(re.escape(core) + _FRAGMENT_BOUNDARY)
    _fragment_pattern_cache[fragment] = pattern
    return pattern


def fragment_in_path(fragment: str, url_path_lower: str) -> bool:
    """True when `fragment` occurs in `url_path_lower` at a segment boundary."""
    return _fragment_pattern(fragment).search(url_path_lower) is not None


def bucket_matches(url_path_lower: str, keys: set[str]) -> list[tuple[str, int]]:
    """Return matching buckets in declaration order.

    Both a parameter-key hit and a path-fragment hit count as a match. We
    return the full list (rather than just the winner) so callers can record
    the entire classification trail in `priority_reason`.
    """
    matches: list[tuple[str, int]] = []
    for name, weight, key_set, path_fragments in _BUCKETS:
        key_hit = bool(keys & key_set) if key_set else False
        path_hit = any(
            fragment_in_path(fragment, url_path_lower) for fragment in path_fragments
        )
        regex_rules = _REGEX_BUCKET_RULES.get(name)
        rx_hit = bool(regex_rules) and any(
            regex_fragment_in_path(rule, url_path_lower) for rule in regex_rules
        )
        if key_hit or path_hit or rx_hit:
            matches.append((name, weight))
    return matches


# Auth param keys and the SAML-auth compound fragments that keep `auth` winning
# even on an SSO route (see `_suppress_auth_on_sso_route`). Resolved from
# `_BUCKETS` so they cannot drift from the bucket definition.
_AUTH_KEY_SET: frozenset[str] = next(
    key_set for name, _w, key_set, _p in _BUCKETS if name == "auth"
)
_SSO_PATH_FRAGMENTS: tuple[str, ...] = next(
    path_fragments for name, _w, _k, path_fragments in _BUCKETS if name == "sso"
)
_AUTH_SAML_FRAGMENTS: tuple[str, ...] = ("/saml/acs", "/saml/sso")


def _suppress_auth_on_sso_route(
    matches: list[tuple[str, int]],
    url_path_lower: str,
    keys: set[str],
) -> list[tuple[str, int]]:
    """Drop a generic-only `auth` match on an SSO route (matrix W8).

    Returns `matches` unchanged unless ALL hold: `auth` and `sso` both fired, an
    sso PATH fragment fired, the path contains no `/saml/acs`|`/saml/sso`
    SAML-auth compound, and no auth PARAM key fired. In that one case the `auth`
    entry is removed so the row clusters as `gf:sso` (W8) — while X3/A7 (auth via
    `/saml/acs`) and W10 (auth via a SAMLResponse-bearing `/login` page) keep
    `auth`.
    """
    has_auth = any(name == "auth" for name, _ in matches)
    has_sso = any(name == "sso" for name, _ in matches)
    if not (has_auth and has_sso):
        return matches
    sso_path_fired = any(
        fragment_in_path(f, url_path_lower) for f in _SSO_PATH_FRAGMENTS
    )
    if not sso_path_fired:
        return matches  # sso fired only via a param key (W10) → keep auth
    auth_via_saml = any(
        fragment_in_path(f, url_path_lower) for f in _AUTH_SAML_FRAGMENTS
    )
    auth_via_key = bool(keys & _AUTH_KEY_SET)
    if auth_via_saml or auth_via_key:
        return matches  # real auth surface (X3, A7) → keep auth
    return [(name, weight) for name, weight in matches if name != "auth"]


def first_two_path_segments(url_path: str) -> str:
    """Return `/seg1/seg2` (or fewer) for the path-fallback cluster key.

    Two segments is the community default for quick-look triage: deeper
    slicing fragments the cluster set to the point of uselessness (each item
    ends up in its own cluster), while a single segment collapses every
    `/api/...` into one bucket.
    """
    if not url_path:
        return "/"
    stripped = url_path.strip("/")
    if not stripped:
        return "/"
    segments = stripped.split("/")[:2]
    return "/" + "/".join(segments)


_CLUSTER_PLACEHOLDERS = frozenset({"{id}", "{n}", "{uuid}", "{token}", "{year}"})


def _normalize_cluster_segment(seg: str) -> str:
    """Collapse one path segment to a stable placeholder for cluster keys (§5.1).

    Precedence (first match wins): UUID → `{uuid}`, long-hex → `{id}`, year →
    `{year}`, numeric → `{n}`, opaque app token (len>=5, letter+digit) →
    `{token}`; otherwise lowercased as-is. Operates on a lowercased segment.
    Note: a literal pre-normalized placeholder (`{id}`,`{n}`,`{uuid}`) does not
    match any of these shapes (the braces are not hex/numeric/token chars), so
    it is preserved verbatim — `/{n}/` clusters as `path:/{n}`.
    """
    if _UUID_RE.match(seg):
        return "{uuid}"
    if _LONG_HEX_RE.match(seg):
        return "{id}"
    if _YEAR_RE.match(seg):
        return "{year}"
    if _NUMERIC_RE.match(seg):
        return "{n}"
    if len(seg) >= 5 and _OPAQUE_TOKEN_RE.match(seg):
        return "{token}"
    return seg


def normalize_path_for_cluster(url_path: str) -> str:
    """Build the `path:*` fallback cluster key with id-shaped segments collapsed.

    Used ONLY for the `path:*` fallback (override #6) — NEVER for bucket matching
    or the raw path-object-ref predicate. Collapses numeric / uuid / hex /
    opaque-token / year segments to placeholders so distinct ids and years share
    one cluster (e.g. `/explore-mvps/2024/M0004` and `/explore-mvps/2023/G0058`
    both cluster as `path:/explore-mvps/{year}`). After substitution, runs of
    identical adjacent placeholders are collapsed, then the first two segments
    (the `first_two_path_segments` rule) are joined.
    """
    if not url_path:
        return "/"
    stripped = url_path.strip("/")
    if not stripped:
        return "/"
    normalized: list[str] = []
    prev: str | None = None
    for raw_seg in stripped.split("/"):
        seg = _normalize_cluster_segment(raw_seg.lower())
        if seg in _CLUSTER_PLACEHOLDERS and seg == prev:
            continue  # collapse adjacent identical placeholders
        normalized.append(seg)
        prev = seg
    return "/" + "/".join(normalized[:2])


def classify_from_fields(
    *,
    case_type: str,
    url_path: str,
    query_params: str = "{}",
    body_params: str = "{}",
    path_params: str = "{}",
) -> dict[str, Any]:
    """Adapter for ingest paths that don't have a sqlite Row yet.

    `db_insert_work_item()` calls this immediately after the INSERT so it can
    write `priority_score` / `priority_reason` / `cluster_key` /
    `terminal_reason` in the same connection without round-tripping through
    a SELECT. Returns the same shape as `classify_row()`.
    """
    fake_row: dict[str, Any] = {
        "type": case_type,
        "url_path": url_path,
        "query_params": query_params,
        "body_params": body_params,
        "path_params": path_params,
    }
    return classify_row(fake_row)
