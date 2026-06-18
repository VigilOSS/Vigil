"""vigil assess list-clusters — cluster manifest for operator triage.

Groups pending work_items by `cluster_key` and emits per-cluster summaries so
the operator can decide which clusters deserve specialist dispatch and which
should be deferred (via `vigil assess work-buffer <db> defer-cluster …`). The ordering — by max
priority_score DESC then count DESC — mirrors the priority-first dispatch
heuristic: the cluster with the single highest-signal row wins, and for ties
the noisier cluster surfaces first because deferring it buys the most
throughput when it turns out to be low-signal.

We surface up to 5 representative URLs per cluster so the operator can sanity-check
the cluster label at a glance without running a separate query. Earliest/latest
timestamps let operators spot stale clusters that outlived an earlier ingest.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import sqlite3
from typing import Any

from assess.lib.db import db_init


_DEFAULT_LIMIT = 100
_DEFAULT_STATUS = "pending"
_SAMPLE_URLS = 5


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "list-clusters",
        help="Summarize pending work_items grouped by cluster_key",
    )
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument(
        "--limit",
        type=int,
        default=_DEFAULT_LIMIT,
        help=f"Max cluster rows to return (default: {_DEFAULT_LIMIT}). Increase when the "
        "corpus is large and you want the long tail; the ordering ensures the most useful "
        "clusters always come first.",
    )
    p.add_argument(
        "--status",
        default=_DEFAULT_STATUS,
        help=f"Work-item status filter (default: {_DEFAULT_STATUS}). Switch to 'skipped' to "
        "audit deferred clusters.",
    )
    p.add_argument(
        "--host",
        default="",
        help=(
            "Filter clusters to those that contain at least one work_item whose URL "
            "matches the given host. Exact match by default with optional :port stripped "
            "(e.g. --host example.com matches https://example.com/x and https://example.com:8443/y "
            "but NOT api.example.com). Wildcard syntax with leading '*' uses fnmatch "
            "(e.g. --host '*.example.com' matches api.example.com and admin.example.com). "
            "The filter runs in SQL across ALL items in each cluster, not just the 5 representative "
            "samples, so a host present anywhere in the cluster surfaces it."
        ),
    )
    p.set_defaults(func=run)


def _url_host(url: str) -> str:
    """Extract the host portion of a URL string for ``--host`` filtering.

    work_items rows store the full URL in ``url``; we parse just enough to
    isolate the hostname so the filter matches on a real component rather
    than a substring of the path.
    """
    if not url:
        return ""
    candidate = url.strip()
    scheme_marker = "://"
    if scheme_marker in candidate:
        candidate = candidate.split(scheme_marker, 1)[1]
    # Drop credentials prefix if any.
    if "@" in candidate:
        candidate = candidate.split("@", 1)[1]
    slash_idx = candidate.find("/")
    host_with_port = candidate if slash_idx == -1 else candidate[:slash_idx]
    if ":" in host_with_port:
        host_with_port = host_with_port.split(":", 1)[0]
    return host_with_port.lower()


def _host_matches(item_host: str, host_filter: str) -> bool:
    """Match a normalized work-item host against the user-supplied filter.

    Exact comparison by default. Filters that contain shell wildcards (``*`` or
    ``?``) fall through to fnmatch so ``*.example.com`` lights up subdomains
    while ``example.com`` stays anchored to the bare host.
    """
    if not item_host:
        return False
    if any(ch in host_filter for ch in "*?["):
        return fnmatch.fnmatchcase(item_host, host_filter)
    return item_host == host_filter


def run(args: argparse.Namespace) -> None:
    db_path = args.db_path
    limit = max(1, int(args.limit))
    status = args.status
    host_filter = (args.host or "").strip().lower()

    db_init(db_path)

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")

        matching_clusters: set | None = None
        if host_filter:
            # Walk every work_item under the chosen status and collect the
            # cluster_keys whose URLs map to the requested host. Doing the host
            # match in Python keeps the wildcard semantics consistent with the
            # documented contract (exact-or-fnmatch) while still considering
            # ALL items, not just the 5 sample rows the legacy filter looked at.
            url_rows = conn.execute(
                "SELECT cluster_key, url FROM work_items WHERE status = ? "
                "AND url IS NOT NULL AND url != ''",
                (status,),
            ).fetchall()
            matching_clusters = set()
            for row in url_rows:
                if _host_matches(_url_host(row["url"]), host_filter):
                    matching_clusters.add(row["cluster_key"])
            if not matching_clusters:
                print(json.dumps({
                    "status": status,
                    "host_filter": host_filter,
                    "cluster_count": 0,
                    "clusters": [],
                }, ensure_ascii=False, indent=2))
                return

        if matching_clusters is None:
            cluster_rows = conn.execute(
                """
                SELECT cluster_key,
                       COUNT(*) AS count,
                       MAX(priority_score) AS max_priority,
                       AVG(priority_score) AS avg_priority,
                       MIN(created_at) AS earliest_created_at,
                       MAX(created_at) AS latest_created_at
                FROM work_items
                WHERE status = ?
                GROUP BY cluster_key
                ORDER BY max_priority DESC, count DESC, cluster_key
                LIMIT ?
                """,
                (status, limit),
            ).fetchall()
        else:
            null_in_set = None in matching_clusters
            non_null = [k for k in matching_clusters if k is not None]
            params: list[Any] = [status]
            null_clause = ""
            if non_null and null_in_set:
                placeholders_nn = ",".join("?" * len(non_null))
                null_clause = f"(cluster_key IS NULL OR cluster_key IN ({placeholders_nn}))"
                params.extend(non_null)
            elif non_null:
                placeholders_nn = ",".join("?" * len(non_null))
                null_clause = f"cluster_key IN ({placeholders_nn})"
                params.extend(non_null)
            else:
                null_clause = "cluster_key IS NULL"
            params.append(limit)
            cluster_rows = conn.execute(
                f"""
                SELECT cluster_key,
                       COUNT(*) AS count,
                       MAX(priority_score) AS max_priority,
                       AVG(priority_score) AS avg_priority,
                       MIN(created_at) AS earliest_created_at,
                       MAX(created_at) AS latest_created_at
                FROM work_items
                WHERE status = ? AND {null_clause}
                GROUP BY cluster_key
                ORDER BY max_priority DESC, count DESC, cluster_key
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()

        clusters: list[dict[str, Any]] = []
        for row in cluster_rows:
            sample_rows = conn.execute(
                """
                SELECT method, url
                FROM work_items
                WHERE status = ?
                  AND ((? IS NULL AND cluster_key IS NULL) OR cluster_key = ?)
                ORDER BY priority_score DESC, id ASC
                LIMIT ?
                """,
                (status, row["cluster_key"], row["cluster_key"], _SAMPLE_URLS),
            ).fetchall()

            sample_urls = [
                f"{sample['method']} {sample['url']}"
                for sample in sample_rows
            ]

            clusters.append({
                "cluster_key": row["cluster_key"],
                "count": row["count"],
                "max_priority_score": row["max_priority"],
                "avg_priority_score": round(row["avg_priority"] or 0.0, 2),
                "earliest_created_at": row["earliest_created_at"],
                "latest_created_at": row["latest_created_at"],
                "sample_urls": sample_urls,
            })

        print(json.dumps({
            "status": status,
            "host_filter": host_filter or None,
            "cluster_count": len(clusters),
            "clusters": clusters,
        }, ensure_ascii=False, indent=2))
    finally:
        conn.close()
