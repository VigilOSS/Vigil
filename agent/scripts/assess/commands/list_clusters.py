"""assess.py list-clusters — cluster manifest for operator triage.

Groups pending work_items by `cluster_key` and emits per-cluster summaries so
the operator can decide which clusters deserve specialist dispatch and which
should be deferred (via `dispatch defer-cluster`). The ordering — by max
priority_score DESC then count DESC — mirrors the priority-first dispatch
heuristic: the cluster with the single highest-signal row wins, and for ties
the noisier cluster surfaces first because deferring it buys the most
throughput when it turns out to be low-signal.

We surface 3-5 representative URLs per cluster so the operator can sanity-check
the cluster label at a glance without running a separate query. Earliest/latest
timestamps let operators spot stale clusters that outlived an earlier ingest.
"""
from __future__ import annotations

import argparse
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
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    db_path = args.db_path
    limit = max(1, int(args.limit))
    status = args.status

    db_init(db_path)

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
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
            clusters.append({
                "cluster_key": row["cluster_key"],
                "count": row["count"],
                "max_priority_score": row["max_priority"],
                "avg_priority_score": round(row["avg_priority"] or 0.0, 2),
                "earliest_created_at": row["earliest_created_at"],
                "latest_created_at": row["latest_created_at"],
                "sample_urls": [
                    f"{sample['method']} {sample['url']}"
                    for sample in sample_rows
                ],
            })

        print(json.dumps({
            "status": status,
            "cluster_count": len(clusters),
            "clusters": clusters,
        }, ensure_ascii=False, indent=2))
    finally:
        conn.close()
