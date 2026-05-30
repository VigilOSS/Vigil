"""Shared gf-style bucket classification used by both ingestion and re-runs.

This module is the single source of truth for the priority/cluster assignments
that `db_insert_work_item()` writes inline at insert time and that
`aith assess classify-work` re-applies idempotently. Keeping the logic in one
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
import sqlite3
from typing import Any


# gf-style bucket weights. Higher = more likely to yield exploitable signal.
# Each tuple is (name, weight, parameter-key set, path-fragment tuple). A
# parameter-key hit OR a path-fragment hit puts the row in the bucket. When
# multiple buckets fire, the highest-weight normally wins for `cluster_key` /
# `priority_score`; every match is recorded in `priority_reason` as a `+`
# joined chain so operators can see the full classification trail.
_BUCKETS: tuple[tuple[str, int, frozenset[str], tuple[str, ...]], ...] = (
    (
        "rce",
        50,
        frozenset({"cmd", "exec", "command", "shell", "run", "execute"}),
        ("/exec/", "/cmd/", "/shell/"),
    ),
    (
        "ssrf",
        # Reduced from 45 -> 40 during the upstream review-and-merge: the prior
        # generic key set (`data`, `path`, `view`, `src`) produced too many
        # false positives on benign APIs that take a `view` query param. The
        # path fragments still anchor true SSRF surfaces (proxies, fetchers).
        40,
        frozenset({
            "url", "uri", "host", "port", "redirect", "feed",
            "callback", "continue", "next", "window",
            "link", "dest",
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
        35,
        frozenset({
            "id", "user", "account", "number", "doc", "email", "group",
            "profile", "order", "report",
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
        30,
        frozenset({
            "file", "filename", "upload", "attachment", "avatar",
            "image", "photo", "document", "media",
        }),
        (),
    ),
    (
        "debug_logic",
        30,
        frozenset(),
        (
            "/admin", "/debug", "/dbg", "/dev", "/staging", "/stage",
            "/test", "/internal", "/mgmt", "/manage", "/console",
            "/dashboard", "/_profiler", "/phpinfo", "/actuator",
            "/.git", "/.env", "/config", "/backup",
        ),
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
#
# Adding a new inert type means editing this one place — every consumer
# picks it up automatically. Hand-maintained copies in any of those files
# are a drift hazard.
INERT_TYPES: frozenset[str] = frozenset(
    {"image", "video", "font", "archive", "sourcemap", "manifest"}
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


def classify_row(row: sqlite3.Row) -> dict[str, Any]:
    """Return the per-row assignment dict (always present, never None).

    Inert types (image/video/font/archive/sourcemap/manifest) are stamped
    with `terminal_reason='inert_type'` so `fetch-by-priority` can skip them
    with a single predicate. For every other row the highest-weight matching
    bucket wins; the path fallback gives operators a coarse grouping when
    no bucket fires.
    """
    case_type = (row["type"] or "").lower()
    if case_type in _INERT_TYPES:
        return {
            "priority_score": 0,
            "priority_reason": None,
            "cluster_key": f"type:{case_type}",
            "terminal_reason": "inert_type",
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
        }

    url_path = row["url_path"] or ""
    keys = collect_keys(row["query_params"], row["body_params"], row["path_params"])
    matches = bucket_matches(url_path.lower(), keys)

    if matches:
        best_weight = max(weight for _, weight in matches)
        top_buckets = [name for name, weight in matches if weight == best_weight]
        best_name = select_cluster_bucket(case_type, matches, top_buckets[0])
        reason = "+".join(f"gf:{name}" for name, _ in matches)
        return {
            "priority_score": best_weight,
            "priority_reason": reason,
            "cluster_key": f"gf:{best_name}",
            "terminal_reason": None,
        }

    return {
        "priority_score": 0,
        "priority_reason": None,
        "cluster_key": f"path:{first_two_path_segments(url_path)}",
        "terminal_reason": None,
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


def bucket_matches(url_path_lower: str, keys: set[str]) -> list[tuple[str, int]]:
    """Return matching buckets in declaration order.

    Both a parameter-key hit and a path-fragment hit count as a match. We
    return the full list (rather than just the winner) so callers can record
    the entire classification trail in `priority_reason`.
    """
    matches: list[tuple[str, int]] = []
    for name, weight, key_set, path_fragments in _BUCKETS:
        key_hit = bool(keys & key_set) if key_set else False
        path_hit = any(fragment in url_path_lower for fragment in path_fragments)
        if key_hit or path_hit:
            matches.append((name, weight))
    return matches


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
