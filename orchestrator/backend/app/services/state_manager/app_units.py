"""App-unit prefix discovery and depth scoring.

An **app unit** is an APPLICATION boundary keyed ``(host, port-class,
path-prefix)`` — a finer, orthogonal grain to a network service
(``assessment_services`` = host:port). The scorer answers the depth-gate's
central question: *is this URL a whole application worth a dedicated, deep
campaign?* It produces a gated ``structure × risk − suppressors`` score, a
``depth_tier`` (thin / endpoint-cluster / app-unit / application), a
``deep_required`` boolean, a sample-size ``confidence``, and per-signal
``evidence_json`` source counts.

INVARIANTS:
  * **WARN-FIRST.** This is a stored, transparent, advisory signal. It does NOT
    hard-block anything. Terminal enforcement is owned by the separate depth
    backstop; nothing here raises to refuse a transition.
  * **WEB-ONLY.** ``score_application_units`` no-ops for code/blue engagements
    (they carry no request_variants anyway, but we guard explicitly so an
    app unit is never persisted for a non-web track).
  * **Read OUTCOMES, not tool runs.** The scorer reads request_variants /
    observations / surfaces / intel / class-typed coverage_items. It NEVER
    joins ``assessment_command_runs`` (the per_host_coverage contract).
  * **Under-observed ≠ thin (R-H5).** A host with command/probe activity but
    ZERO request_variants scores as UNDER-OBSERVED (low confidence, WARN),
    never a ``thin`` auto-pass.

The weights and thresholds below are a transparent heuristic rubric. Re-evaluate
them against finished-engagement data before changing them; treat every numeric
constant as calibrated, not sacred.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

from ..events import _engagement_or_404
from . import _common
from ._common import _fetch_all



_APP_FRAMEWORK_TOKENS: tuple[str, ...] = (
    "django", "flask", "fastapi", "rails", "ruby on rails", "laravel",
    "symfony", "spring", "spring boot", "express", "nest", "nestjs", "koa",
    "asp.net", "asp net", ".net", "dotnet", "node.js", "nodejs", "php",
    "tomcat", "jetty", "wildfly", "jboss", "struts", "play framework",
    "gin", "echo", "fiber", "actix", "rocket", "phoenix", "elixir",
    "wordpress", "drupal", "joomla", "magento", "shopify", "sharepoint",
    "rock rms", "rockrms", "rock.", "sitecore", "umbraco", "typo3",
    "adobe experience manager", "aem", "liferay", "confluence", "jira",
    "gitlab", "jenkins", "grafana", "kibana", "actuator", "spring actuator",
    "react", "angular", "vue", "vue.js", "svelte", "next.js", "nextjs",
    "nuxt", "ember", "backbone",
    "graphql", "apollo", "hasura", "swagger", "openapi", "kong", "apigee",
    "wso2",
)

_STATIC_ASSET_CONTENT_FAMILIES: frozenset[str] = frozenset(
    {"image", "font", "style", "css", "script", "media",
     "video", "audio", "binary", "asset"}
)

_STATIC_ASSET_EXTENSIONS: frozenset[str] = frozenset(
    {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tiff",
     "css", "scss", "less", "woff", "woff2", "ttf", "otf", "eot",
     "mp4", "webm", "mp3", "wav", "ogg", "avif",
     "map", "pdf", "zip", "gz", "tar", "js", "mjs"}
)

_DYNAMIC_CONTENT_FAMILIES: frozenset[str] = frozenset(
    {"json", "form", "form-data", "multipart", "xml", "html"}
)

_DECISIVE_SURFACE_TYPES: frozenset[str] = frozenset(
    {"auth_entry", "object_reference", "privileged_write", "api_documentation"}
)

_AUTH_SURFACE_TYPES: frozenset[str] = frozenset({"auth_entry", "account_recovery"})

TIER_THIN = "thin"
TIER_ENDPOINT_CLUSTER = "endpoint-cluster"
TIER_APP_UNIT = "app-unit"
TIER_APPLICATION = "application"

CONF_LOW = "low"
CONF_MEDIUM = "medium"
CONF_HIGH = "high"


def _port_class(scheme: str, port: int) -> str:
    scheme = (scheme or "").lower()
    if port in (80, 443):
        return "web"
    if scheme == "https" and port == 443:
        return "web"
    if scheme == "http" and port == 80:
        return "web"
    return f"port-{port}"


def _path_segments(path: str) -> list[str]:
    return [seg for seg in (path or "/").split("/") if seg]


def _depth1_prefix(path: str) -> str:
    """First path segment (or apex ``/``)."""
    segs = _path_segments(path)
    return "/" + segs[0] if segs else "/"


def _depth2_prefix(path: str) -> str | None:
    """First two path segments, or None when the path has fewer than two."""
    segs = _path_segments(path)
    if len(segs) < 2:
        return None
    return "/" + segs[0] + "/" + segs[1]


def _path_under_prefix(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    p = "/" + "/".join(_path_segments(path))
    pre = "/" + "/".join(_path_segments(prefix))
    return p == pre or p.startswith(pre + "/")


def _path_extension(path: str) -> str:
    last = _path_segments(path)
    if not last:
        return ""
    seg = last[-1]
    if "." not in seg:
        return ""
    return seg.rsplit(".", 1)[1].lower()


def _is_static_asset(variant: dict[str, Any]) -> bool:
    """True when a variant is a param-less GET serving a static asset.

    Derived from content_type_family OR the path extension (depth-gate §5.0 /
    db.py note). The extension fallback is what makes this fire on real ingest
    data, where most assets land with content_type_family='unknown'.
    """
    if str(variant.get("method") or "").upper() != "GET":
        return False
    if (
        _schema_nonempty(variant.get("query_schema_json"))
        or _schema_nonempty(variant.get("body_schema_json"))
        or _schema_nonempty(variant.get("path_schema_json"))
    ):
        return False
    fam = str(variant.get("content_type_family") or "").lower()
    if fam in _STATIC_ASSET_CONTENT_FAMILIES:
        return True
    return _path_extension(variant.get("normalized_path") or "") in _STATIC_ASSET_EXTENSIONS


_SPLIT_MIN_DISTINCT_PATHS = 6


def _subtree_independently_promotes(variants: list[dict[str, Any]]) -> bool:
    """True when a depth-2 sub-tree is rich enough to be its own app unit.

    The split rule from §5.2.1: split when the sub-segment independently clears
    the app-unit promotion gate. We approximate "clears the gate" with a cheap
    structural pre-check (enough distinct paths AND param/method richness) so we
    don't have to fully score before clustering — the full §5.2 score still
    runs afterwards on whichever boundary we pick.
    """
    distinct = {v["normalized_path"] for v in variants}
    if len(distinct) < _SPLIT_MIN_DISTINCT_PATHS:
        return False
    methods = {str(v.get("method") or "").upper() for v in variants}
    has_params = any(
        _schema_nonempty(v.get("query_schema_json"))
        or _schema_nonempty(v.get("body_schema_json"))
        or _schema_nonempty(v.get("path_schema_json"))
        for v in variants
    )
    write = bool(methods & {"PUT", "PATCH", "DELETE", "POST"})
    return has_params or write


def _discover_prefixes(variants: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Cluster one authority's variants into FINAL app-unit prefixes.

    depth-gate §5.2.1: group by the first 1–2 segments, MERGE a child into its
    parent when the child has few paths / shares signals, and SPLIT a depth-2
    sub-segment into its own unit when it independently clears app-unit
    promotion. The apex ``/`` is always a candidate (degenerate prefix); a host
    with no path data is a single ``/`` unit.
    """
    by_d1: dict[str, list[dict[str, Any]]] = {}
    for v in variants:
        by_d1.setdefault(_depth1_prefix(v["normalized_path"]), []).append(v)

    final: dict[str, list[dict[str, Any]]] = {}
    for d1, d1_variants in by_d1.items():
        if d1 == "/":
            final["/"] = list(d1_variants)
            continue
        by_d2: dict[str, list[dict[str, Any]]] = {}
        for v in d1_variants:
            d2 = _depth2_prefix(v["normalized_path"]) or d1
            by_d2.setdefault(d2, []).append(v)

        promoted: dict[str, list[dict[str, Any]]] = {
            d2: vs for d2, vs in by_d2.items()
            if d2 != d1 and _subtree_independently_promotes(vs)
        }
        if not promoted:
            final[d1] = list(d1_variants)
            continue
        remainder: list[dict[str, Any]] = []
        for d2, vs in by_d2.items():
            if d2 in promoted:
                final[d2] = list(vs)
            else:
                remainder.extend(vs)
        if remainder:
            final[d1] = remainder

    return final


def _schema_nonempty(raw: Any) -> bool:
    if not raw:
        return False
    try:
        obj = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        return False
    return bool(obj)


def _id_like_keys(raw: Any) -> bool:
    """True when a param schema carries object/tenant-reference-shaped keys."""
    try:
        obj = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        return False
    if not isinstance(obj, dict):
        return False
    for key in obj.keys():
        k = str(key).lower()
        if k in ("id", "uuid", "guid", "uid", "user_id", "account_id",
                 "object_id", "tenant_id", "order_id", "doc_id", "file_id"):
            return True
        if k.endswith("_id") or (str(key).endswith("Id") and len(key) > 2):
            return True
    return False


def _path_has_segment_token(path: str, tokens: tuple[str, ...]) -> bool:
    segs = _path_segments(path.lower())
    for seg in segs:
        for tok in tokens:
            if seg == tok or seg.startswith(tok + "-") or seg.startswith(tok + "."):
                return True
    return False


_PRIV_TOKENS = ("admin", "administrator", "internal", "manage", "management",
                "console", "dashboard", "actuator", "superuser", "root")
_API_DOC_TOKENS = ("swagger", "openapi", "api-docs", "apidocs", "graphql",
                   "graphiql", "redoc")
_WORKFLOW_TOKENS = ("cart", "checkout", "payment", "pay", "billing", "invoice",
                   "order", "export", "transfer", "withdraw", "subscribe")
_AUTH_PATH_TOKENS = ("login", "signin", "sign-in", "signup", "sign-up",
                    "register", "auth", "oauth", "sso", "saml", "session",
                    "logout", "password", "reset", "recover", "mfa", "2fa",
                    "token", "callback")
_SSRF_PARAM_TOKENS = ("url", "uri", "redirect", "next", "return", "callback",
                     "fetch", "dest", "target", "webhook", "proxy", "image_url",
                     "feed", "rss", "import")
_FILE_TOKENS = ("upload", "download", "file", "attachment", "import", "export",
               "document", "media")


def _params_match_tokens(variant: dict[str, Any], tokens: tuple[str, ...]) -> bool:
    for col in ("query_schema_json", "body_schema_json", "path_schema_json"):
        try:
            obj = json.loads(variant.get(col) or "{}")
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            for key in obj.keys():
                k = str(key).lower()
                if k in tokens:
                    return True
    return False


_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _is_valid_hostname(host: str) -> bool:
    """Backend hostname-validation predicate — DNS-label / IP-literal shape.

    Mirrors the agent-side ``scope.looks_like_host`` contract WITHOUT importing
    agent code (the backend must not depend on the agent tree): admits an
    IPv4/IPv6 literal, ``localhost``, or a multi-label DNS hostname (every label
    a valid RFC-1123 DNS label AND at least one dot). REJECTS a bare single label
    (``us-east-1`` / a region / service / placeholder token), a path fragment, or
    any string carrying a character no hostname may hold.

    :func:`_split_host_path` is maximally lenient (it treats the first whitespace
    token as the host even with no scheme), so without this gate descriptors like
    ``us-east-1`` become bogus host keys that materialize ``deep_required`` app
    units and hard-block the terminal report edge on garbage (I-08).
    """
    h = (host or "").strip().strip(".").lower()
    if not h or len(h) > 253:
        return False
    if h == "localhost":
        return True
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        pass
    labels = h.split(".")
    if len(labels) < 2:
        return False
    return all(_HOSTNAME_LABEL_RE.match(label) for label in labels)


def _split_host_path(descriptor: str) -> tuple[str, str]:
    """RAW ``(host, path)`` split of a surface descriptor — maximally lenient, NO
    hostname validation.

    Comparison helpers that match a parsed host against an ALREADY-TRUSTED
    app-unit host (the depth ledger's finding / deferral / credential mappers)
    use THIS directly, so a trusted single-label or IP unit host still matches;
    ingest paths that MINT unit keys go through :func:`_surface_host_path`, which
    adds the hostname gate.
    """
    raw = (descriptor or "").strip()
    if not raw:
        return "", "/"
    first = raw.split()[0]
    if "://" in first:
        parsed = urlparse(first)
        host = (parsed.hostname or "").strip("[]").lower()
        path = parsed.path or "/"
        rest = raw.split(None, 1)
        if path == "/" and len(rest) == 2 and rest[1].startswith("/"):
            path = rest[1].split()[0]
        return host, path or "/"
    parts = raw.split(None, 1)
    hostport = parts[0].strip("'\"<>()").rstrip(",;").rstrip(".")
    host = hostport
    if hostport.count(":") == 1:
        h, _, p = hostport.rpartition(":")
        if p.isdigit():
            host = h
    path = "/"
    if len(parts) == 2 and parts[1].startswith("/"):
        path = parts[1].split()[0]
    return host.lower(), path or "/"


def _surface_host_path(descriptor: str) -> tuple[str, str]:
    """``(host, path)`` for a surface descriptor with the host HOSTNAME-VALIDATED.

    A descriptor whose host is not a syntactic hostname/IP (``us-east-1``, a bare
    path, a service label, a placeholder) yields an EMPTY host, so every ingest
    site that guards on a truthy host skips it — the gate that stops garbage
    descriptors from minting bogus ``deep_required`` app units (I-08).
    """
    host, path = _split_host_path(descriptor)
    if host and not _is_valid_hostname(host):
        return "", path
    return host, path


def _prefix_from_path(path: str) -> str:
    """First-segment app-unit prefix for a path (``/login/session`` -> ``/login``;
    root/empty -> ``/``). Used to place a surface-only decisive unit at a prefix
    that contains the surface (so the ledger attributes it by containment)."""
    segments = [s for s in (path or "").split("/") if s]
    return "/" + segments[0] if segments else "/"


def _score_structure(
    variants: list[dict[str, Any]],
    statuses: list[int],
    framework_hits: int,
) -> tuple[int, dict[str, Any]]:
    ev: dict[str, Any] = {}
    distinct_paths = {v["normalized_path"] for v in variants}
    methods = {str(v["method"]).upper() for v in variants}

    n_paths = len(distinct_paths)
    if n_paths >= 20:
        path_pts = 3
    elif n_paths >= 6:
        path_pts = 2
    elif n_paths >= 2:
        path_pts = 1
    else:
        path_pts = 0
    ev["path_richness"] = {"points": path_pts, "distinct_paths": n_paths}

    write_methods = methods & {"PUT", "PATCH", "DELETE"}
    if write_methods:
        method_pts = 2
    elif len(methods) >= 2:
        method_pts = 1
    else:
        method_pts = 0
    ev["method_diversity"] = {"points": method_pts, "methods": sorted(methods)}

    param_rows = sum(
        1
        for v in variants
        if _schema_nonempty(v.get("query_schema_json"))
        or _schema_nonempty(v.get("body_schema_json"))
        or _schema_nonempty(v.get("path_schema_json"))
    )
    if param_rows >= 5:
        param_pts = 2
    elif param_rows >= 1:
        param_pts = 1
    else:
        param_pts = 0
    ev["param_richness"] = {"points": param_pts, "param_bearing_variants": param_rows}

    dynamic_rows = sum(
        1 for v in variants
        if str(v.get("content_type_family") or "").lower() in _DYNAMIC_CONTENT_FAMILIES
    )
    cookie_rows = sum(1 for v in variants if _schema_nonempty(v.get("cookie_schema_json")))
    routing = len({s for s in statuses if s}) >= 2
    dyn_pts = 0
    if dynamic_rows:
        dyn_pts += 1
    if cookie_rows or routing:
        dyn_pts += 1
    ev["dynamic_stateful"] = {
        "points": dyn_pts,
        "dynamic_content_variants": dynamic_rows,
        "session_cookie_variants": cookie_rows,
        "status_routing": routing,
    }

    if framework_hits >= 2:
        fw_pts = 2
    elif framework_hits >= 1:
        fw_pts = 1
    else:
        fw_pts = 0
    ev["framework_fingerprint"] = {"points": fw_pts, "framework_components": framework_hits}

    total = path_pts + method_pts + param_pts + dyn_pts + fw_pts
    return total, ev


def _score_risk(
    variants: list[dict[str, Any]],
    statuses: list[int],
    unit_surface_types: set[str],
    coverage_classes: set[str],
    version_skew: bool,
) -> tuple[int, dict[str, Any]]:
    ev: dict[str, Any] = {}
    paths = [v["normalized_path"] for v in variants]
    auth_contexts = {str(v.get("auth_context") or "anonymous") for v in variants}

    auth_surface = bool(unit_surface_types & _AUTH_SURFACE_TYPES)
    auth_path = any(_path_has_segment_token(p, _AUTH_PATH_TOKENS) for p in paths)
    auth_pts = 0
    if auth_surface:
        auth_pts += 2
    if auth_path:
        auth_pts += 1
    auth_pts = min(auth_pts, 3)
    ev["auth_surface"] = {"points": auth_pts, "auth_surface": auth_surface, "auth_path": auth_path}

    gated = any(s in (401, 403) for s in statuses)
    gated_pts = 2 if gated else 0
    ev["auth_gated_routing"] = {"points": gated_pts, "saw_401_403": gated}

    id_refs = any(
        _id_like_keys(v.get("query_schema_json")) or _id_like_keys(v.get("path_schema_json"))
        or _id_like_keys(v.get("body_schema_json"))
        for v in variants
    )
    obj_surface = "object_reference" in unit_surface_types
    idor_class = bool(coverage_classes & {"idor", "bola", "bfla"})
    obj_pts = 0
    if obj_surface:
        obj_pts += 2
    if id_refs or idor_class:
        obj_pts += 1
    obj_pts = min(obj_pts, 3)
    ev["object_references"] = {
        "points": obj_pts, "object_surface": obj_surface,
        "id_like_params": id_refs, "idor_class": idor_class,
    }

    priv_surface = "privileged_write" in unit_surface_types
    priv_path = any(_path_has_segment_token(p, _PRIV_TOKENS) for p in paths)
    priv_pts = 0
    if priv_surface:
        priv_pts += 2
    if priv_path:
        priv_pts += 1
    priv_pts = min(priv_pts, 3)
    ev["privileged_write"] = {"points": priv_pts, "priv_surface": priv_surface, "priv_path": priv_path}

    api_surface = "api_documentation" in unit_surface_types
    api_path = any(_path_has_segment_token(p, _API_DOC_TOKENS) for p in paths)
    api_pts = 0
    if api_surface:
        api_pts += 2
    if api_path:
        api_pts += 1
    api_pts = min(api_pts, 3)
    ev["api_inventory"] = {"points": api_pts, "api_surface": api_surface, "api_path": api_path}

    wf_surface = "workflow_token" in unit_surface_types
    wf_path = any(_path_has_segment_token(p, _WORKFLOW_TOKENS) for p in paths)
    wf_pts = 0
    if wf_surface:
        wf_pts += 2
    if wf_path:
        wf_pts += 1
    wf_pts = min(wf_pts, 3)
    ev["business_workflow"] = {"points": wf_pts, "workflow_surface": wf_surface, "workflow_path": wf_path}

    skew_pts = 2 if version_skew else 0
    ev["version_skew"] = {"points": skew_pts, "version_skew": version_skew}

    diversity_pts = 2 if len(auth_contexts) >= 2 else 0
    ev["auth_context_diversity"] = {
        "points": diversity_pts, "auth_contexts": sorted(auth_contexts),
    }

    n_classes = len(coverage_classes)
    if n_classes >= 3:
        density_pts = 2
    elif n_classes >= 1:
        density_pts = 1
    else:
        density_pts = 0
    ev["gf_density"] = {"points": density_pts, "distinct_classes": sorted(coverage_classes)}

    total = (auth_pts + gated_pts + obj_pts + priv_pts + api_pts + wf_pts
             + skew_pts + diversity_pts + density_pts)
    return total, ev


def _score_suppressors(
    variants: list[dict[str, Any]],
    statuses: list[int],
    risk_signals_present: bool,
    confidence: str,
) -> tuple[int, dict[str, Any]]:
    """Return (suppressor_magnitude, evidence). Magnitude is POSITIVE; the
    caller subtracts it (depth-gate §5.2 ``total = structure + risk − suppressors``)."""
    ev: dict[str, Any] = {}
    total = 0
    distinct_paths = {v["normalized_path"] for v in variants}

    if len(distinct_paths) <= 1:
        total += 2
        ev["single_path"] = {"points": -2}

    if variants and all(_is_static_asset(v) for v in variants):
        total += 4
        ev["static_only"] = {"points": -4, "all_static_assets": True}

    if statuses and all(s == 404 for s in statuses):
        total += 4
        ev["parked_404"] = {"points": -4}

    any_params = any(
        _schema_nonempty(v.get("query_schema_json"))
        or _schema_nonempty(v.get("body_schema_json"))
        for v in variants
    )
    if not any_params and not risk_signals_present:
        total += 2
        ev["marketing_only"] = {"points": -2}

    if confidence == CONF_LOW:
        total += 1
        ev["weak_sample"] = {"points": -1}

    return total, ev


def _confidence_for(n_variants: int, n_observations: int) -> str:
    sample = max(n_variants, n_observations)
    if sample >= 12:
        return CONF_HIGH
    if sample >= 4:
        return CONF_MEDIUM
    return CONF_LOW


def _classify_tier(
    structure: int, risk: int, total: int,
    decisive_surface: bool,
) -> tuple[str, bool]:
    """Gated tier + deep_required (depth-gate §5.2). Totals alone never promote.

    Manual override is applied by the caller; this is the pure scorer verdict.
    """
    if decisive_surface:
        if total >= 13 and structure >= 6 and risk >= 6:
            return TIER_APPLICATION, True
        return TIER_APP_UNIT, True

    if total >= 13 and structure >= 6 and risk >= 6:
        return TIER_APPLICATION, True
    if risk >= 6 and structure >= 2:
        return TIER_APP_UNIT, True
    if total >= 8 and structure >= 3 and risk >= 3:
        return TIER_APP_UNIT, True
    if total >= 4:
        return TIER_ENDPOINT_CLUSTER, False
    return TIER_THIN, False


def _is_web_engagement(engagement) -> bool:
    """WEB-ONLY guard. Code/blue tracks never get app units persisted.

    engagement_type is free text from scope.json (``web`` / ``red`` / None for
    legacy red engagements, vs ``code`` / ``blue``). We treat anything that is
    NOT explicitly a code/blue track as web-eligible, so legacy red web
    engagements (type None or 'red') still score.
    """
    etype = str(getattr(engagement, "engagement_type", "") or "").lower()
    return etype not in ("code", "blue")


def score_application_units(engagement_id: int) -> dict[str, Any]:
    """Discover prefixes, score each app unit, persist, and recompute the
    ``application_unit_id`` containment cache. Idempotent.

    Returns a summary dict (units + a warn list). WARN-FIRST: never raises to
    block; the worst it does for an under-observed host is emit a WARN entry.
    WEB-ONLY: for code/blue engagements it persists nothing and returns an
    empty, skipped result.
    """
    engagement = _engagement_or_404(engagement_id)
    if not _is_web_engagement(engagement):
        return {
            "skipped": True,
            "reason": f"non-web engagement_type={engagement.engagement_type!r}; "
                      "app-unit scoring is web-only",
            "units": [],
            "warnings": [],
        }

    eng_id = engagement.id

    # I-07 scope admission: exclude out-of-scope hosts (SSO/CDN/vendor and
    # wildcard co-tenants) from EVERY host source that mints a unit key, through
    # the SAME primitive ``web_uncovered_high_route_hosts`` uses. Lazy import
    # avoids the app_units<->coverage module cycle (coverage imports this module).
    # ``scope_admission`` is None when scope cannot be determined / has no
    # allowlist — then ``_in_scope`` fails OPEN (keeps every host), never silently
    # dropping all units.
    from .coverage import _engagement_scope_admission, _host_admitted_by_scope

    scope_admission = _engagement_scope_admission(engagement)

    def _in_scope(host: str) -> bool:
        if scope_admission is None:
            return True
        return _host_admitted_by_scope(host, scope_admission[0], scope_admission[1])

    with _common.get_connection() as connection:
        variants = _fetch_all(
            connection,
            "SELECT id, scheme, host, port, method, normalized_path, auth_context, "
            "content_type_family, query_schema_json, body_schema_json, path_schema_json, "
            "cookie_schema_json FROM assessment_request_variants WHERE engagement_id = ?",
            (eng_id,),
        )
        observations = _fetch_all(
            connection,
            "SELECT request_variant_id, response_status FROM assessment_request_observations "
            "WHERE engagement_id = ?",
            (eng_id,),
        )
        surfaces = _fetch_all(
            connection,
            "SELECT surface_type, target_descriptor FROM assessment_surfaces WHERE engagement_id = ?",
            (eng_id,),
        )
        tech = _fetch_all(
            connection,
            "SELECT component FROM intel_tech_components WHERE engagement_id = ? "
            "AND superseded_by_id IS NULL",
            (eng_id,),
        )
        coverage = _fetch_all(
            connection,
            "SELECT request_variant_id, attack_family FROM assessment_coverage_items "
            "WHERE engagement_id = ?",
            (eng_id,),
        )
        probe_hosts = _fetch_all(
            connection,
            "SELECT DISTINCT target_host FROM assessment_probe_runs "
            "WHERE engagement_id = ? AND target_host != ''",
            (eng_id,),
        )

    status_by_variant: dict[int, list[int]] = {}
    for obs in observations:
        vid = obs.get("request_variant_id")
        st = obs.get("response_status")
        if vid is not None and st is not None:
            status_by_variant.setdefault(int(vid), []).append(int(st))

    _GENERIC_FAMILIES = {
        "endpoint-review", "parameter-review", "session-review",
        "header-review", "service-validation",
    }
    classes_by_variant: dict[int, set[str]] = {}
    for ci in coverage:
        vid = ci.get("request_variant_id")
        fam = str(ci.get("attack_family") or "").strip().lower()
        if vid is None or not fam or fam in _GENERIC_FAMILIES:
            continue
        classes_by_variant.setdefault(int(vid), set()).add(fam)

    framework_components = {
        str(t["component"]).lower()
        for t in tech
        if any(tok in str(t["component"]).lower() for tok in _APP_FRAMEWORK_TOKENS)
    }
    framework_hits = len(framework_components)

    parsed_surfaces: list[tuple[str, str, str]] = []
    for s in surfaces:
        # _surface_host_path validates the hostname (I-08); _in_scope drops
        # out-of-scope hosts (I-07).
        host, path = _surface_host_path(str(s.get("target_descriptor") or ""))
        if host and _in_scope(host):
            parsed_surfaces.append((host, path, str(s.get("surface_type") or "")))

    authorities: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for v in variants:
        host = str(v.get("host") or "").lower()
        if not host or not _in_scope(host):
            continue
        pc = _port_class(str(v.get("scheme") or ""), int(v.get("port") or 0))
        authorities.setdefault((host, pc), []).append(v)

    variant_hosts = {h for (h, _pc) in authorities}

    result_units: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    unit_id_by_key: dict[tuple[str, str, str], int] = {}
    prefix_for_variant: dict[int, tuple[str, str, str]] = {}

    with _common.get_connection() as connection:
        for (host, port_class), hv in authorities.items():
            versions = set()
            for v in hv:
                for seg in _path_segments(v["normalized_path"]):
                    sl = seg.lower()
                    if len(sl) >= 2 and sl[0] == "v" and sl[1:].isdigit():
                        versions.add(sl)
            host_version_skew = len(versions) >= 2

            prefixes = _discover_prefixes(hv)
            for prefix, pv in prefixes.items():
                if not pv:
                    continue
                for v in pv:
                    prefix_for_variant[int(v["id"])] = (host, port_class, prefix)

                unit_statuses: list[int] = []
                unit_classes: set[str] = set()
                for v in pv:
                    unit_statuses.extend(status_by_variant.get(int(v["id"]), []))
                    unit_classes |= classes_by_variant.get(int(v["id"]), set())

                unit_surface_types: set[str] = set()
                for s_host, s_path, s_type in parsed_surfaces:
                    if s_host == host and _path_under_prefix(s_path, prefix):
                        unit_surface_types.add(s_type)
                decisive_surface = bool(unit_surface_types & _DECISIVE_SURFACE_TYPES)

                n_obs = len(unit_statuses)
                confidence = _confidence_for(len(pv), n_obs)

                structure, struct_ev = _score_structure(pv, unit_statuses, framework_hits)
                risk, risk_ev = _score_risk(
                    pv, unit_statuses, unit_surface_types, unit_classes, host_version_skew,
                )
                risk_signals_present = risk > 0 or decisive_surface
                suppressor, supp_ev = _score_suppressors(
                    pv, unit_statuses, risk_signals_present, confidence,
                )
                total = structure + risk - suppressor

                depth_tier, deep_required = _classify_tier(
                    structure, risk, total, decisive_surface,
                )

                evidence = {
                    "structure": struct_ev,
                    "risk": risk_ev,
                    "suppressors": supp_ev,
                    "sample": {
                        "variant_count": len(pv),
                        "observation_count": n_obs,
                        "confidence": confidence,
                    },
                    "port_classes": sorted({
                        _port_class(str(v.get("scheme") or ""), int(v.get("port") or 0))
                        for v in pv
                    }),
                    "decisive_surface": decisive_surface,
                    "surface_types": sorted(unit_surface_types),
                    "version_skew_host_level": host_version_skew,
                }

                unit_id, override, override_reason, eff_tier, eff_deep = _upsert_unit(
                    connection, eng_id, host, port_class, prefix,
                    deep_required=deep_required, depth_tier=depth_tier,
                    structure=structure, risk=risk, suppressor=suppressor,
                    total=total, confidence=confidence, evidence=evidence,
                )
                unit_id_by_key[(host, port_class, prefix)] = unit_id

                unit_summary = {
                    "id": unit_id,
                    "host": host,
                    "port_class": port_class,
                    "path_prefix": prefix,
                    "structure_score": structure,
                    "risk_score": risk,
                    "suppressor_score": suppressor,
                    "total_score": total,
                    "depth_tier": eff_tier,
                    "deep_required": eff_deep,
                    "confidence": confidence,
                    "override": override,
                    "override_reason": override_reason,
                    "decisive_surface": decisive_surface,
                }
                result_units.append(unit_summary)

                if confidence == CONF_LOW and eff_tier == TIER_THIN and not override:
                    warnings.append({
                        "host": host, "port_class": port_class, "path_prefix": prefix,
                        "reason": "under-observed: low confidence; re-score after more "
                                  "collection before trusting 'thin'.",
                    })

        # Probe target_host is a lenient free-text column: hostname-validate it
        # (I-08 — drop `us-east-1` / label / placeholder targets) and scope-admit
        # it (I-07) before it can mint an under-observed unit.
        touched_hosts: set[str] = set()
        for r in probe_hosts:
            host = str(r.get("target_host") or "").strip().lower()
            if host and _is_valid_hostname(host) and _in_scope(host):
                touched_hosts.add(host)
        for host in sorted(touched_hosts - variant_hosts):
            if not host:
                continue
            evidence = {
                "structure": {}, "risk": {}, "suppressors": {},
                "sample": {"variant_count": 0, "observation_count": 0, "confidence": CONF_LOW},
                "under_observed": True,
                "note": "host has probe activity but no request_variants (R-H5).",
            }
            unit_id, override, override_reason, eff_tier, eff_deep = _upsert_unit(
                connection, eng_id, host, "web", "/",
                deep_required=False, depth_tier=TIER_THIN,
                structure=0, risk=0, suppressor=0, total=0,
                confidence=CONF_LOW, evidence=evidence,
            )
            unit_id_by_key[(host, "web", "/")] = unit_id
            result_units.append({
                "id": unit_id, "host": host, "port_class": "web", "path_prefix": "/",
                "structure_score": 0, "risk_score": 0, "suppressor_score": 0,
                "total_score": 0, "depth_tier": eff_tier, "deep_required": eff_deep,
                "confidence": CONF_LOW, "override": override,
                "override_reason": override_reason, "decisive_surface": False,
            })
            warnings.append({
                "host": host, "port_class": "web", "path_prefix": "/",
                "reason": "under-observed: probe activity but zero request_variants; "
                          "discover this host's paths before scoring depth (R-H5).",
            })

        def _surface_already_covered(shost: str, spath: str) -> bool:
            return any(
                h == shost and _path_under_prefix(spath, p)
                for (h, _, p) in unit_id_by_key
            )

        decisive_only: dict[tuple[str, str], set[str]] = {}
        for shost, spath, stype in parsed_surfaces:
            if stype not in _DECISIVE_SURFACE_TYPES:
                continue
            if _surface_already_covered(shost, spath):
                continue
            prefix = _prefix_from_path(spath)
            decisive_only.setdefault((shost, prefix), set()).add(stype)
        for (host, prefix), stypes in sorted(decisive_only.items()):
            key = (host, "web", prefix)
            if key in unit_id_by_key:
                continue
            evidence = {
                "structure": {}, "risk": {"decisive_surface": sorted(stypes)},
                "suppressors": {},
                "sample": {"variant_count": 0, "observation_count": 0, "confidence": CONF_LOW},
                "decisive_surface": True,
                "decisive_surface_only": True,
                "surface_types": sorted(stypes),
                "note": "decisive surface(s) with no request_variants yet; materialized "
                        "so the S17 confidence-independent terminal block can fire.",
            }
            unit_id, override, override_reason, eff_tier, eff_deep = _upsert_unit(
                connection, eng_id, host, "web", prefix,
                deep_required=True, depth_tier=TIER_APP_UNIT,
                structure=0, risk=0, suppressor=0, total=0,
                confidence=CONF_LOW, evidence=evidence,
            )
            unit_id_by_key[key] = unit_id
            result_units.append({
                "id": unit_id, "host": host, "port_class": "web", "path_prefix": prefix,
                "structure_score": 0, "risk_score": 0, "suppressor_score": 0,
                "total_score": 0, "depth_tier": eff_tier, "deep_required": eff_deep,
                "confidence": CONF_LOW, "override": override,
                "override_reason": override_reason, "decisive_surface": True,
            })
            warnings.append({
                "host": host, "port_class": "web", "path_prefix": prefix,
                "reason": f"decisive surface(s) {sorted(stypes)} with no request_variants — "
                          "materialized as deep_required; crawl this host to score depth.",
            })

        warnings.extend(_prune_stale_units(connection, eng_id, set(unit_id_by_key)))

        _recompute_unit_links(connection, eng_id, prefix_for_variant, unit_id_by_key)

    return {"skipped": False, "units": result_units, "warnings": warnings}


def _prune_stale_units(
    connection, engagement_id: int, current_keys: set[tuple[str, str, str]]
) -> list[dict[str, Any]]:
    """Delete app-unit rows whose (host, port_class, path_prefix) is no longer in
    the current discovered set. Returns a warning per pruned unit that
    carried a MANUAL override, so dropping an operator decision is surfaced, never
    silent (the override is stale once its prefix is no longer observed)."""
    rows = connection.execute(
        "SELECT id, host, port_class, path_prefix, override "
        "FROM assessment_application_units WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    stale_ids: list[int] = []
    warnings: list[dict[str, Any]] = []
    for row in rows:
        if (row["host"], row["port_class"], row["path_prefix"]) in current_keys:
            continue
        stale_ids.append(int(row["id"]))
        if row["override"]:
            warnings.append({
                "host": row["host"], "port_class": row["port_class"],
                "path_prefix": row["path_prefix"],
                "reason": f"pruned a stale unit carrying a manual '{row['override']}' "
                          "override — its path-prefix is no longer observed "
                          "(boundaries changed); re-mark a current unit if intended.",
            })
    if stale_ids:
        connection.executemany(
            "DELETE FROM assessment_application_units WHERE id = ?",
            [(uid,) for uid in stale_ids],
        )
    return warnings


def _upsert_unit(
    connection, engagement_id: int, host: str, port_class: str, prefix: str,
    *, deep_required: bool, depth_tier: str, structure: int, risk: int,
    suppressor: int, total: int, confidence: str, evidence: dict[str, Any],
) -> tuple[int, str | None, str | None, str, bool]:
    """Insert/update an app unit. Preserve any manual override; a manual
    mark-deep/clear-deep ALWAYS wins over the scorer verdict (depth-gate §5.2).

    Returns (unit_id, override, override_reason, effective_tier, effective_deep).
    """
    existing = connection.execute(
        "SELECT id, override, override_reason FROM assessment_application_units "
        "WHERE engagement_id = ? AND host = ? AND port_class = ? AND path_prefix = ?",
        (engagement_id, host, port_class, prefix),
    ).fetchone()
    override = existing["override"] if existing else None
    override_reason = existing["override_reason"] if existing else None

    eff_deep = deep_required
    eff_tier = depth_tier
    if override == "mark-deep":
        eff_deep = True
        if eff_tier in (TIER_THIN, TIER_ENDPOINT_CLUSTER):
            eff_tier = TIER_APP_UNIT
    elif override == "clear-deep":
        eff_deep = False

    evidence_json = json.dumps(evidence, ensure_ascii=False)
    if existing is None:
        cursor = connection.execute(
            """
            INSERT INTO assessment_application_units (
                engagement_id, host, port_class, path_prefix, deep_required,
                depth_tier, structure_score, risk_score, suppressor_score,
                total_score, confidence, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, host, port_class, prefix, 1 if eff_deep else 0,
             eff_tier, structure, risk, suppressor, total, confidence, evidence_json),
        )
        return int(cursor.lastrowid), override, override_reason, eff_tier, eff_deep

    connection.execute(
        """
        UPDATE assessment_application_units
        SET deep_required = ?, depth_tier = ?, structure_score = ?, risk_score = ?,
            suppressor_score = ?, total_score = ?, confidence = ?, evidence_json = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (1 if eff_deep else 0, eff_tier, structure, risk, suppressor, total,
         confidence, evidence_json, existing["id"]),
    )
    return int(existing["id"]), override, override_reason, eff_tier, eff_deep


def _resolve_target_unit(
    host: str, path: str, port_class: str,
    unit_id_by_key: dict[tuple[str, str, str], int],
) -> int | None:
    """Resolve a (host, path, port-class) to the smallest containing unit.

    Used for null-FK probes whose only anchor is target_host/target_path. We
    pick the most specific (longest path_prefix) persisted unit that contains
    the path within the same host+port-class — exactly the §5.0 containment
    rule, against the boundaries the scorer just persisted.
    """
    best: tuple[int, int] | None = None
    for (u_host, u_pc, u_prefix), uid in unit_id_by_key.items():
        if u_host != host or u_pc != port_class:
            continue
        if _path_under_prefix(path, u_prefix):
            plen = len(_path_segments(u_prefix))
            if best is None or plen > best[0]:
                best = (plen, uid)
    return best[1] if best else None


def _recompute_unit_links(
    connection, engagement_id: int,
    prefix_for_variant: dict[int, tuple[str, str, str]],
    unit_id_by_key: dict[tuple[str, str, str], int],
) -> None:
    """Repopulate the denormalized application_unit_id cache on coverage_items
    and probe_runs by containment. Source of truth is host+port-class+path:
      * coverage_items / probe_runs with a request_variant_id resolve through
        the variant's FINAL clustered prefix (``prefix_for_variant`` — the exact
        boundary the scorer chose, so attribution can't drift from scoring).
      * probe_runs with a null request_variant_id resolve through the probe's
        target_host/target_path/target_port containment.
    Idempotent: clears then re-sets every row for the engagement.
    """
    connection.execute(
        "UPDATE assessment_coverage_items SET application_unit_id = NULL WHERE engagement_id = ?",
        (engagement_id,),
    )
    connection.execute(
        "UPDATE assessment_probe_runs SET application_unit_id = NULL WHERE engagement_id = ?",
        (engagement_id,),
    )
    connection.execute(
        "UPDATE assessment_work_items SET application_unit_id = NULL WHERE engagement_id = ?",
        (engagement_id,),
    )

    cov = _fetch_all(
        connection,
        "SELECT id, request_variant_id FROM assessment_coverage_items WHERE engagement_id = ?",
        (engagement_id,),
    )
    for row in cov:
        vid = row.get("request_variant_id")
        if vid is None:
            continue
        key = prefix_for_variant.get(int(vid))
        if key and key in unit_id_by_key:
            connection.execute(
                "UPDATE assessment_coverage_items SET application_unit_id = ? WHERE id = ?",
                (unit_id_by_key[key], row["id"]),
            )

    work_items = _fetch_all(
        connection,
        "SELECT id, request_variant_id, coverage_item_id FROM assessment_work_items "
        "WHERE engagement_id = ?",
        (engagement_id,),
    )
    coverage_unit_by_id = {
        int(row["id"]): row.get("application_unit_id")
        for row in _fetch_all(
            connection,
            "SELECT id, application_unit_id FROM assessment_coverage_items WHERE engagement_id = ?",
            (engagement_id,),
        )
    }
    for row in work_items:
        unit_id = coverage_unit_by_id.get(int(row["coverage_item_id"])) if row.get("coverage_item_id") else None
        if unit_id is None and row.get("request_variant_id") is not None:
            key = prefix_for_variant.get(int(row["request_variant_id"]))
            if key:
                unit_id = unit_id_by_key.get(key)
        if unit_id is not None:
            connection.execute(
                "UPDATE assessment_work_items SET application_unit_id = ? WHERE id = ?",
                (unit_id, row["id"]),
            )

    probes = _fetch_all(
        connection,
        "SELECT id, request_variant_id, target_host, target_path, target_port "
        "FROM assessment_probe_runs WHERE engagement_id = ?",
        (engagement_id,),
    )
    for row in probes:
        unit_id: int | None = None
        vid = row.get("request_variant_id")
        if vid is not None:
            key = prefix_for_variant.get(int(vid))
            if key and key in unit_id_by_key:
                unit_id = unit_id_by_key[key]
        if unit_id is None:
            t_host = str(row.get("target_host") or "").lower()
            t_path = str(row.get("target_path") or "/") or "/"
            t_port = row.get("target_port")
            if t_host:
                pc = _port_class("", int(t_port)) if t_port else "web"
                unit_id = _resolve_target_unit(t_host, t_path, pc, unit_id_by_key)
        if unit_id is not None:
            connection.execute(
                "UPDATE assessment_probe_runs SET application_unit_id = ? WHERE id = ?",
                (unit_id, row["id"]),
            )


def set_app_unit_override(
    engagement_id: int, unit_id: int, *, override: str | None, reason: str | None = None,
) -> dict[str, Any]:
    """Set/clear the manual override on an app unit.

    ``override`` is one of 'mark-deep' / 'clear-deep' / None (None clears it and
    reverts to the pure scorer verdict on the next pass).
    """
    engagement = _engagement_or_404(engagement_id)
    if override not in (None, "mark-deep", "clear-deep"):
        raise ValueError("override must be 'mark-deep', 'clear-deep', or None")
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_application_units WHERE id = ? AND engagement_id = ?",
            (unit_id, engagement.id),
        ).fetchone()
        if row is None:
            raise ValueError(f"app unit id={unit_id} not found for this engagement")
        if override == "mark-deep":
            deep = True
            tier = row["depth_tier"]
            if tier in (TIER_THIN, TIER_ENDPOINT_CLUSTER):
                tier = TIER_APP_UNIT
        elif override == "clear-deep":
            deep = False
            tier = row["depth_tier"]
        else:
            ev = json.loads(row["evidence_json"] or "{}")
            decisive = bool(ev.get("decisive_surface") or ev.get("decisive_surface_only"))
            tier, deep = _classify_tier(
                row["structure_score"], row["risk_score"], row["total_score"],
                decisive,
            )
        connection.execute(
            """
            UPDATE assessment_application_units
            SET override = ?, override_reason = ?, deep_required = ?, depth_tier = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (override, (reason or "").strip() or None, 1 if deep else 0, tier, unit_id),
        )
        updated = connection.execute(
            "SELECT * FROM assessment_application_units WHERE id = ?", (unit_id,),
        ).fetchone()
    return dict(updated)


def list_application_units(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        rows = _fetch_all(
            connection,
            "SELECT * FROM assessment_application_units WHERE engagement_id = ? "
            "ORDER BY host, port_class, path_prefix",
            (engagement.id,),
        )
    for row in rows:
        raw = row.get("evidence_json")
        if isinstance(raw, str) and raw:
            try:
                row["evidence"] = json.loads(raw)
            except (ValueError, TypeError):
                row["evidence"] = {}
        else:
            row["evidence"] = {}
        row["deep_required"] = bool(row.get("deep_required"))
    return rows
