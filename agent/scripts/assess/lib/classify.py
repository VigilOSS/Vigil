"""URL type classification — replaces lib/classify.sh.

Pure Python regex replaces 30+ grep subprocess pairs per call.
Same classification priority order as the bash version.
"""
from __future__ import annotations

import json
import re
import sqlite3
from urllib.parse import urlparse

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Per-host URL budgets (1D.2). The default content-rich tier is 1000 URLs;
# API-tier hosts (api.* / *.api.example.test) cap at 200 because their
# surface is method × parameter, not URL × URL; sitemap-bearing hosts allow
# 2000 because the sitemap declares the canonical surface and we should not
# truncate below it.
PER_HOST_BUDGET_CONTENT_RICH = 1000
PER_HOST_BUDGET_API_TIER = 200
PER_HOST_BUDGET_SITEMAP_BEARING = 2000

_API_TIER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^api\.", re.IGNORECASE),
    re.compile(r"\.api\.", re.IGNORECASE),
    re.compile(r"^api-[\w-]+\.", re.IGNORECASE),
)

# Pre-compiled patterns (one-time cost)
_GRAPHQL_PATH = re.compile(r"/graphql", re.IGNORECASE)
_GRAPHQL_CT = re.compile(r"^application/graphql$", re.IGNORECASE)
_WS_SCHEME = re.compile(r"^wss?://", re.IGNORECASE)
_WS_PATH = re.compile(r"/ws(/|$)|^/socket\.io(/|$)", re.IGNORECASE)
_API_SPEC_PATH = re.compile(
    r"^/(api-docs|openapi(\.json)?|swagger(\.json|-ui(\.html)?)?|v[0-9]+/api-docs)(/|$)",
    re.IGNORECASE,
)
_API_PATH = re.compile(r"^/(api|rest)(/|$)|/v[0-9]+(/|$)", re.IGNORECASE)
_API_CT = re.compile(r"application/json", re.IGNORECASE)
_UPLOAD_CT = re.compile(r"multipart/form-data", re.IGNORECASE)
_FORM_CT = re.compile(r"application/x-www-form-urlencoded", re.IGNORECASE)
_JS_EXT = re.compile(r"\.js$", re.IGNORECASE)
_JS_CT = re.compile(r"text/javascript|application/javascript", re.IGNORECASE)
_CSS_EXT = re.compile(r"\.css$", re.IGNORECASE)
_CSS_CT = re.compile(r"text/css", re.IGNORECASE)
_PAGE_EXT = re.compile(r"\.(html?|xhtml|php|aspx?|jsp)$", re.IGNORECASE)
_PAGE_CT = re.compile(r"text/html|application/xhtml|image/svg\+xml", re.IGNORECASE)
_DATA_EXT = re.compile(r"\.(json|xml|csv|ya?ml|txt)$", re.IGNORECASE)
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
    if _PAGE_EXT.search(path_no_query):
        return "page"
    if _PAGE_CT.search(ct_lower):
        return "page"

    # 10. data
    if _DATA_EXT.search(path_no_query):
        return "data"
    if _DATA_CT.search(ct_lower):
        return "data"

    # 11. image (excluding svg, already handled as page)
    if _IMAGE_CT.search(ct_lower) and not _SVG_CT.search(ct_lower):
        return "image"
    if _IMAGE_EXT.search(path_no_query):
        return "image"

    # 12. video/audio
    if _VIDEO_CT.search(ct_lower):
        return "video"
    if _VIDEO_EXT.search(path_no_query):
        return "video"

    # 13. font
    if _FONT_CT.search(ct_lower):
        return "font"
    if _FONT_EXT.search(path_no_query):
        return "font"

    # 14. archive
    if _ARCHIVE_CT.search(ct_lower):
        return "archive"

    # 15. unknown
    return "unknown"


def per_host_budget(
    host: str,
    *,
    sitemap_hosts: set[str] | None = None,
    overrides: dict[str, int] | None = None,
) -> int:
    """Return the per-host URL budget for a given host (1D.2).

    Match order is operator-override > sitemap-bearing > API-tier > default.
    The override is checked first because the operator may legitimately want
    to cap a known-large content host BELOW 200 (e.g. CDN dump) or RAISE a
    sitemap-bearing host above 2000; both intents must beat the heuristic
    rules. Sitemap-bearing matches before API-tier because a sitemap-bearing
    `api.example.test` host is a strict superset of the API-tier's
    expectation and the sitemap declares the canonical surface.

    Hostname matching is case-insensitive and tolerates a trailing dot.
    """
    if not host:
        return PER_HOST_BUDGET_CONTENT_RICH
    normalized = host.rstrip(".").lower()

    if overrides and normalized in overrides:
        return int(overrides[normalized])

    if sitemap_hosts and normalized in sitemap_hosts:
        return PER_HOST_BUDGET_SITEMAP_BEARING

    for pattern in _API_TIER_PATTERNS:
        if pattern.search(normalized):
            return PER_HOST_BUDGET_API_TIER

    return PER_HOST_BUDGET_CONTENT_RICH


def host_active_count(db_path_or_conn, host: str) -> int:
    """Return the active (pending+processing+done) row count for a host.

    Reads from the ``work_items_per_host`` view, falling back to a direct
    aggregate query when the view is missing (legacy DBs that bypass the
    db_init migration). Accepts either a sqlite3.Connection (so the
    ingestion path can share its existing connection without paying the
    open/close cost per URL) or a path string.

    Hostname is normalized to lower-case + trailing-dot stripped to match
    the view's host expression.
    """
    normalized = (host or "").rstrip(".").lower()
    if not normalized:
        return 0

    owns_conn = False
    if isinstance(db_path_or_conn, sqlite3.Connection):
        conn = db_path_or_conn
    else:
        conn = sqlite3.connect(str(db_path_or_conn), timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        owns_conn = True

    try:
        view_exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view' AND name='work_items_per_host'"
        ).fetchone()
        if view_exists:
            row = conn.execute(
                "SELECT active_count FROM work_items_per_host WHERE host = ?",
                (normalized,),
            ).fetchone()
            return int(row[0]) if row and row[0] is not None else 0

        # Fallback aggregate when the view migration has not run yet.
        row = conn.execute(
            """
            SELECT COUNT(*) FROM work_items
            WHERE status IN ('pending', 'processing', 'done')
              AND lower(
                CASE
                    WHEN instr(substr(url, instr(url, '://') + 3), '/') > 0
                        THEN substr(
                            substr(url, instr(url, '://') + 3),
                            1,
                            instr(substr(url, instr(url, '://') + 3), '/') - 1
                        )
                    ELSE substr(url, instr(url, '://') + 3)
                END
              ) = ?
            """,
            (normalized,),
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    finally:
        if owns_conn:
            conn.close()


def parse_budget_overrides(override_args: list[str] | tuple[str, ...] | None) -> dict[str, int]:
    """Parse ``--budget-override host:N`` operator overrides into a host->int map.

    Accepts the raw flag values argparse hands us (a list of strings, one per
    --budget-override occurrence, each in ``host:N`` form). Invalid entries
    raise ValueError so the CLI fails fast rather than silently dropping a
    misformatted override. Hostnames are normalized to lower-case +
    trailing-dot stripped to match the view's host expression.
    """
    if not override_args:
        return {}
    overrides: dict[str, int] = {}
    for raw in override_args:
        if ":" not in raw:
            raise ValueError(f"--budget-override expects host:N form, got {raw!r}")
        host_part, _, count_part = raw.partition(":")
        host_normalized = host_part.strip().rstrip(".").lower()
        if not host_normalized:
            raise ValueError(f"--budget-override missing host in {raw!r}")
        try:
            count = int(count_part.strip())
        except ValueError as exc:
            raise ValueError(
                f"--budget-override count must be an integer in {raw!r}"
            ) from exc
        if count < 0:
            raise ValueError(f"--budget-override count must be non-negative in {raw!r}")
        overrides[host_normalized] = count
    return overrides


def host_from_url(url: str) -> str:
    """Extract a normalized hostname from a URL for budget bookkeeping."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    return (parsed.hostname or "").rstrip(".").lower()
