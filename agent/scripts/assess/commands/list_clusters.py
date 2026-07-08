"""vigil assess list-clusters — cluster manifest for operator triage.

Groups pending work_items by `cluster_key` and emits per-cluster summaries so
the operator can decide which clusters deserve specialist dispatch and which
should be deferred (via `vigil assess work-buffer defer-cluster …`). The ordering — by max
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
from collections import defaultdict
from typing import Any

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


_DEFAULT_LIMIT = 100
_DEFAULT_STATUS = "pending"
_SAMPLE_URLS = 5


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "list-clusters",
        help="Summarize pending work_items grouped by cluster_key",
    )
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
            "The filter runs across ALL items in each cluster, not just the 5 representative "
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
    limit = max(1, int(args.limit))
    status = args.status
    host_filter = (args.host or "").strip().lower()

    # Read every work_item of the chosen status from the backend and do the
    # cluster rollup / host-filter / sampling in Python. The former in-SQL
    # GROUP BY / ORDER BY / LIMIT is reproduced verbatim below so the printed
    # manifest is byte-for-byte identical to the local-SQLite version.
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        rows = client.get_all_pages(f"work-items?status={status}")

    matching_clusters: set | None = None
    if host_filter:
        # Walk every work_item under the chosen status and collect the
        # cluster_keys whose URLs map to the requested host. Doing the host
        # match in Python keeps the wildcard semantics consistent with the
        # documented contract (exact-or-fnmatch) while still considering
        # ALL items, not just the 5 sample rows the legacy filter looked at.
        matching_clusters = set()
        for row in rows:
            url = row.get("url")
            if not url:
                continue
            if _host_matches(_url_host(url), host_filter):
                matching_clusters.add(row.get("cluster_key"))
        if not matching_clusters:
            print(json.dumps({
                "status": status,
                "host_filter": host_filter,
                "cluster_count": 0,
                "clusters": [],
            }, ensure_ascii=False, indent=2))
            return

    # Group by cluster_key (NULL/None is a single group, mirroring GROUP BY).
    grouped: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row.get("cluster_key")].append(row)

    rollups: list[dict[str, Any]] = []
    for cluster_key, items in grouped.items():
        if matching_clusters is not None and cluster_key not in matching_clusters:
            continue
        priorities = [int(item.get("priority_score") or 0) for item in items]
        max_priority = max(priorities) if priorities else 0
        avg_priority = (sum(priorities) / len(priorities)) if priorities else 0.0
        created = [item.get("created_at") for item in items if item.get("created_at")]
        rollups.append({
            "cluster_key": cluster_key,
            "count": len(items),
            "max_priority": max_priority,
            "avg_priority": avg_priority,
            "earliest_created_at": min(created) if created else None,
            "latest_created_at": max(created) if created else None,
            "items": items,
        })

    # ORDER BY max_priority DESC, count DESC, cluster_key — with the SQLite
    # tie-break semantics: NULL cluster_key sorts FIRST in the ascending
    # cluster_key leg (the `is not None` flag makes None precede any string).
    rollups.sort(
        key=lambda c: (
            -c["max_priority"],
            -c["count"],
            (c["cluster_key"] is not None, c["cluster_key"] or ""),
        )
    )
    rollups = rollups[:limit]

    clusters: list[dict[str, Any]] = []
    for rollup in rollups:
        # Up to 5 representative rows per cluster, ORDER BY priority_score DESC,
        # id ASC — the same tie-break the SQL sample query used.
        sample_rows = sorted(
            rollup["items"],
            key=lambda item: (-(int(item.get("priority_score") or 0)), int(item.get("id") or 0)),
        )[:_SAMPLE_URLS]
        sample_urls = [
            f"{sample.get('method')} {sample.get('url')}"
            for sample in sample_rows
        ]

        clusters.append({
            "cluster_key": rollup["cluster_key"],
            "count": rollup["count"],
            "max_priority_score": rollup["max_priority"],
            "avg_priority_score": round(rollup["avg_priority"] or 0.0, 2),
            "earliest_created_at": rollup["earliest_created_at"],
            "latest_created_at": rollup["latest_created_at"],
            "sample_urls": sample_urls,
        })

    print(json.dumps({
        "status": status,
        "host_filter": host_filter or None,
        "cluster_count": len(clusters),
        "clusters": clusters,
    }, ensure_ascii=False, indent=2))
