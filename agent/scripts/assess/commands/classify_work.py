"""assess.py classify-work — deterministic gf-style classification for work_items.

Operators run this after ingest to populate `priority_score`, `priority_reason`,
`cluster_key`, and `terminal_reason` on pending rows. The resulting signals feed
`dispatch fetch-by-priority` and `list-clusters` so specialists attack the
highest-signal surfaces first on 50k+ URL corpora. Classification is purely
string-matching on URL paths and parameter KEYS (not values) so the output is
stable across runs, easy to audit, and cheap to rerun after a new ingest batch.

Design notes:
- We match gf-style buckets (rce, ssrf, sqli, lfi, idor, redirect, xss, ssti,
  debug_logic, interestingparams) using the same conservative keyword set the
  community gf-patterns repo uses. Keys are matched as whole tokens against
  query/body/path maps; path fragments are matched as substrings so
  `/admin/users` both lands in `debug_logic` and exposes `id` for `idor`.
- We layer narrowly-scoped platform overlays after gf matching. These overlays
  add deterministic coverage for high-volume platform surfaces whose controller
  names do not map cleanly to generic vuln buckets; they do not outrank concrete
  vuln buckets when a stronger gf signal is present.
- We intentionally record every matching bucket in `priority_reason` (as
  `gf:a+overlay:b+...`) even though `cluster_key` and `priority_score` track
  the single highest-weight bucket. That lets operators triage sub-clusters
  later without re-running classification.
- Inert types (image/video/font/archive) are already `status='skipped'` at
  insert time; we clean them up by stamping `terminal_reason='inert_type'` so
  that `fetch-by-priority` can exclude them with a single predicate.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from typing import Any, Iterable

from assess.lib.db import db_init


# gf-style bucket weights. Higher = more likely to yield exploitable signal.
# The weight ordering mirrors the community consensus (rce/ssrf/sqli highest,
# interestingparams lowest because those keys rarely appear in query strings
# for real auth-sensitive endpoints).
_BUCKETS: tuple[tuple[str, int, frozenset[str], tuple[str, ...]], ...] = (
    (
        "rce",
        50,
        frozenset({"cmd", "exec", "command", "shell", "run", "execute"}),
        ("/exec/", "/cmd/", "/shell/"),
    ),
    (
        "ssrf",
        45,
        frozenset({
            "url", "uri", "host", "port", "path", "redirect", "feed",
            "callback", "data", "continue", "next", "window", "view",
            "link", "src", "dest",
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
        "idor",
        35,
        frozenset({
            "id", "user", "account", "number", "doc", "email", "group",
            "profile", "order", "report",
        }),
        (),
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
        "xss",
        20,
        frozenset({
            "q", "query", "search", "keyword", "name", "message", "comment",
            "text", "content", "input", "data",
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
        "interestingparams",
        15,
        frozenset({
            "api_key", "apikey", "token", "auth", "session", "secret",
            "password", "passwd", "pwd",
        }),
        (),
    ),
)

_INERT_TYPES = frozenset({"image", "video", "font", "archive"})
_SALESFORCE_AURA_PATH_FRAGMENTS: tuple[str, ...] = (
    "/aura",
    "/s/sfsites/aura",
)
_SALESFORCE_CONTROLLER_SUFFIXES: tuple[str, ...] = (
    "executeactions",
    "getobjectinfo",
    "getrecordactions",
    "getlistviewdata",
)
_SALESFORCE_OVERLAY_WEIGHT = 18


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "classify-work",
        help="Classify pending work_items with gf-style priority and cluster keys",
    )
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument(
        "--batch",
        type=int,
        default=500,
        help="Rows to read per batch (default: 500). Commits once per batch so a "
        "crash leaves at most one batch of work re-classifiable.",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    db_path = args.db_path
    batch = max(1, int(args.batch))
    db_init(db_path)

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        classified = 0
        updated = 0
        cluster_counts: Counter[str] = Counter()

        while True:
            rows = conn.execute(
                """
                SELECT id, type, url_path, query_params, body_params, path_params
                FROM work_items
                WHERE priority_score = 0
                  AND cluster_key IS NULL
                  AND terminal_reason IS NULL
                LIMIT ?
                """,
                (batch,),
            ).fetchall()
            if not rows:
                break

            for row in rows:
                classified += 1
                assignment = _classify_row(row)
                if assignment is None:
                    continue
                cluster_counts[assignment["cluster_key"]] += 1
                result = conn.execute(
                    """
                    UPDATE work_items
                    SET priority_score = ?,
                        priority_reason = ?,
                        cluster_key = ?,
                        terminal_reason = COALESCE(?, terminal_reason),
                        status = CASE WHEN ? IS NOT NULL THEN 'skipped' ELSE status END
                    WHERE id = ?
                    """,
                    (
                        assignment["priority_score"],
                        assignment["priority_reason"],
                        assignment["cluster_key"],
                        assignment["terminal_reason"],
                        assignment["terminal_reason"],
                        row["id"],
                    ),
                )
                updated += result.rowcount
            conn.commit()

            if len(rows) < batch:
                break

        summary = {
            "classified": classified,
            "updated": updated,
            "by_cluster": dict(sorted(cluster_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    finally:
        conn.close()


def _classify_row(row: sqlite3.Row) -> dict[str, Any] | None:
    """Return the per-row assignment dict or None if nothing changed.

    We treat inert types (image/video/font/archive) as terminal without running
    the gf buckets — the insert path already sets `status='skipped'`, so we
    only need to stamp `terminal_reason` so that `fetch-by-priority` can skip
    them with a single predicate. For every other row we pick the single
    highest-weight bucket as the cluster; the path fallback gives operators a
    coarse grouping when no bucket fires.
    """
    case_type = (row["type"] or "").lower()
    if case_type in _INERT_TYPES:
        return {
            "priority_score": 0,
            "priority_reason": None,
            "cluster_key": f"type:{case_type}",
            "terminal_reason": "inert_type",
        }

    url_path = row["url_path"] or ""
    keys = _collect_keys(row["query_params"], row["body_params"], row["path_params"])
    matches = _bucket_matches(url_path.lower(), keys)

    if matches:
        # Prefer the largest weight; break ties by bucket declaration order so
        # the output is fully deterministic across runs and platforms.
        best_weight = max(weight for _, weight, _ in matches)
        top_buckets = [
            (name, prefix)
            for name, weight, prefix in matches
            if weight == best_weight
        ]
        best_name, best_prefix = top_buckets[0]
        reason = "+".join(f"{prefix}:{name}" for name, _, prefix in matches)
        return {
            "priority_score": best_weight,
            "priority_reason": reason,
            "cluster_key": f"{best_prefix}:{best_name}",
            "terminal_reason": None,
        }

    return {
        "priority_score": 0,
        "priority_reason": None,
        "cluster_key": f"path:{_first_two_path_segments(url_path)}",
        "terminal_reason": None,
    }


def _collect_keys(*columns: str | None) -> set[str]:
    """Collect lowercased parameter keys across JSON-encoded columns.

    Ingest stores query/body/path params as JSON objects; we only care about
    the key names because values frequently contain secrets/PII we shouldn't
    be inspecting client-side. Columns that are null, empty, or malformed are
    quietly skipped so classification never fails on a partial row.

    Compound keys (e.g. Salesforce's `aura.token`, Rails-style `user[id]`, or
    ASP.NET `user.email`) are expanded so each recognizable leaf token is
    exposed to bucket matching. Without this, exact set-membership against
    `{"token", "id", ...}` misses the bulk of real-world Salesforce, Rails,
    and .NET payloads where interesting keys are nested under a namespace.
    """
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
            keys.update(_expand_compound_key(str(k).lower()))
    return keys


def _expand_compound_key(key: str) -> set[str]:
    """Expand a single parameter key into its matchable tokens.

    `aura.token` → {`aura.token`, `aura`, `token`}
    `user[id]` → {`user[id]`, `user`, `id`}
    `order.sort` → {`order.sort`, `order`, `sort`}
    `plain` → {`plain`}

    Returns a set including the original key plus every leaf token extracted
    by splitting on `.` and bracket boundaries (`[`, `]`). Empty tokens are
    dropped.
    """
    tokens = {key}
    # Split on both dot-notation and bracket-notation boundaries.
    for sep in (".", "[", "]"):
        key = key.replace(sep, " ")
    for part in key.split():
        part = part.strip()
        if part:
            tokens.add(part)
    return tokens


def _bucket_matches(url_path_lower: str, keys: set[str]) -> list[tuple[str, int, str]]:
    """Return matching buckets in declaration order.

    A bucket matches when either a parameter key is in its key set OR the URL
    path contains one of its declared fragments. Platform overlays append after
    the gf buckets. We preserve declaration order so ties resolve
    deterministically downstream.
    """
    matches: list[tuple[str, int, str]] = []
    for name, weight, key_set, path_fragments in _BUCKETS:
        key_hit = bool(keys & key_set) if key_set else False
        path_hit = any(fragment in url_path_lower for fragment in path_fragments)
        if key_hit or path_hit:
            matches.append((name, weight, "gf"))
    if _salesforce_overlay_matches(url_path_lower, keys):
        matches.append(("salesforce", _SALESFORCE_OVERLAY_WEIGHT, "overlay"))
    return matches


def _salesforce_overlay_matches(url_path_lower: str, keys: set[str]) -> bool:
    if any(fragment in url_path_lower for fragment in _SALESFORCE_AURA_PATH_FRAGMENTS):
        return True
    return any(
        suffix in key
        for key in keys
        for suffix in _SALESFORCE_CONTROLLER_SUFFIXES
    )


def _first_two_path_segments(url_path: str) -> str:
    """Return `/seg1/seg2` (or fewer) for the path-fallback cluster key.

    We clip to two segments because deeper slicing fragments the cluster set
    to the point of uselessness (each item ends up in its own cluster) while a
    single segment collapses every `/api/...` into one bucket. Two is the
    community default for quick-look triage.
    """
    if not url_path:
        return "/"
    stripped = url_path.strip("/")
    if not stripped:
        return "/"
    segments = stripped.split("/")[:2]
    return "/" + "/".join(segments)
