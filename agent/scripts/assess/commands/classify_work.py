"""aith assess classify-work — idempotent re-application of gf-style classification.

Classification now runs *inline* during `db_insert_work_item()` so the work
buffer is always scored at insert time. This command is retained for two
reasons:

1. Re-applying classification after a bucket-table change in
   `assess.lib.classify_buckets._BUCKETS` (e.g., adding a new bucket) so the
   already-ingested rows pick up the new weights without re-ingesting.
2. Repairing pre-refactor engagement DBs whose work_items were inserted before
   inline classification existed.

The bucket logic itself lives in `assess.lib.classify_buckets`. This command
is a thin batch-loop around it.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter

from assess.lib.classify_buckets import INERT_TYPES, classify_row as _classify_row
from assess.lib.db import db_init


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "classify-work",
        help="Re-apply gf-style priority/cluster classification to work_items",
    )
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument(
        "--batch",
        type=int,
        default=500,
        help="Rows to read per batch (default: 500). Commits once per batch so a "
        "crash leaves at most one batch of work re-classifiable.",
    )
    p.add_argument(
        "--reclassify-all",
        dest="reclassify_all",
        action="store_true",
        help=(
            "Also rewrite priority/cluster on rows that are already scored. "
            "Use this when you intentionally changed `_BUCKETS` in "
            "`assess.lib.classify_buckets` and want the new weights applied "
            "to the existing buffer. WARNING: this overwrites manual "
            "operator triage (e.g. priority_score raised by hand, custom "
            "cluster_key) — narrow your scope or accept the loss before "
            "running."
        ),
    )
    # Deprecated alias retained because the previous release shipped with
    # `--only-unscored` as an opt-in to the safe predicate. The safe predicate
    # is now the default, so the flag is a no-op; we accept it without error
    # so older runbooks and tests do not break mid-cutover.
    p.add_argument(
        "--only-unscored",
        dest="only_unscored",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    db_path = args.db_path
    batch = max(1, int(args.batch))
    reclassify_all = bool(getattr(args, "reclassify_all", False))
    db_init(db_path)

    # Default predicate is narrow: only touch rows that have not already been
    # scored. This protects manual operator triage (priority bumps, custom
    # cluster keys, deferred:* markers) from being silently overwritten by an
    # operator who runs `classify-work` thinking it is a benign refresh —
    # since classification is inline at ingest, the only legitimate reason to
    # touch already-scored rows is a deliberate `_BUCKETS` change, which the
    # operator opts in to with `--reclassify-all`.
    #
    # The inert-type list is sourced from `classify_buckets.INERT_TYPES` so
    # this command, the inline insert path in db.py, and the bucket
    # classifier all read the same set. Adding a new inert type elsewhere
    # only requires editing classify_buckets.INERT_TYPES.
    inert_placeholders = ",".join("?" * len(INERT_TYPES))
    inert_params = tuple(sorted(INERT_TYPES))
    base_predicate = (
        f"(status = 'pending' OR (status = 'skipped' AND type IN ({inert_placeholders})))"
    )
    if reclassify_all:
        where_clause = base_predicate
        where_params: tuple = inert_params
    else:
        where_clause = (
            f"{base_predicate} "
            "AND priority_score = 0 AND cluster_key IS NULL "
            "AND terminal_reason IS NULL"
        )
        where_params = inert_params

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        classified = 0
        updated = 0
        cluster_counts: Counter[str] = Counter()

        # Track an offset so we don't loop forever in the wide WHERE case
        # (where rows already match it after the UPDATE).
        last_id = 0
        while True:
            rows = conn.execute(
                f"""
                SELECT id, type, url_path, query_params, body_params, path_params
                FROM work_items
                WHERE {where_clause}
                  AND id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (*where_params, last_id, batch),
            ).fetchall()
            if not rows:
                break

            for row in rows:
                last_id = max(last_id, int(row["id"]))
                classified += 1
                assignment = _classify_row(row)
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
