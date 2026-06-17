"""vigil assess classify-work — idempotent re-application of gf-style classification.

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

from assess.lib.classify import classify_type
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
    p.add_argument(
        "--reclaim-skipped",
        dest="reclaim_skipped",
        action="store_true",
        help=(
            "Re-evaluate EVERY status='skipped' row against the CURRENT inert "
            "policy and un-strand any whose type is no longer inert, flipping it "
            "back to 'pending' and clearing its stale terminal_reason (L4-7). "
            "Use after an inert-policy change (e.g. a type was removed from "
            "classify_buckets.INERT_TYPES, like sourcemap) so previously-skipped "
            "rows that are now testable re-enter the work queue. WARNING: this "
            "also reverses MANUAL skips of non-inert items — it is opt-in for "
            "exactly that reason; the default predicate never touches a skipped "
            "row that carries a terminal_reason."
        ),
    )
    p.add_argument(
        "--retype",
        dest="retype",
        action="store_true",
        help=(
            "Re-derive `work_items.type` for in-scope rows by re-running the "
            "typer (`assess.lib.classify.classify_type`) against each row's "
            "STORED method/url_path/content_type/body, then re-apply the "
            "downstream priority/cluster/terminal_reason for any row whose type "
            "changed. Default scope is the SAFE narrow set `type='unknown'` "
            "only — already-typed rows are never re-typed unless `--retype-all` "
            "is also given. Use this to propagate a typer improvement onto an "
            "already-ingested corpus without re-ingesting. Many proxy-captured "
            "rows carry a stored content_type that was never fed to the typer "
            "at ingest, so this also repairs that historical gap. Idempotent: "
            "re-running changes nothing once every row is at its derived type."
        ),
    )
    p.add_argument(
        "--retype-all",
        dest="retype_all",
        action="store_true",
        help=(
            "Broaden `--retype` scope to EVERY row, not just `type='unknown'`. "
            "WARNING: this can overwrite a `type` an operator set by hand (or an "
            "override_type from a curated ingest path). Implies `--retype`."
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
    reclaim_skipped = bool(getattr(args, "reclaim_skipped", False))
    retype = bool(getattr(args, "retype", False))
    retype_all = bool(getattr(args, "retype_all", False))
    db_init(db_path)

    # `--retype` is a distinct, opt-in pass: it re-derives `type` from each
    # row's stored fields and re-applies the downstream bucket classification
    # only for rows whose type actually changed. It never runs implicitly with
    # the bucket-only re-classification paths above — typing and bucketing are
    # separate concerns and an operator opts into re-typing explicitly. We
    # dispatch to it here and return its own summary so the two passes cannot
    # be conflated. `--retype-all` implies `--retype`.
    if retype or retype_all:
        _retype_pass(db_path, batch=batch, retype_all=retype_all)
        return

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
    if reclaim_skipped:
        where_clause: str = "status = 'skipped'"
        where_params: tuple = ()
    elif reclassify_all:
        where_clause = base_predicate
        where_params = inert_params
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
        reclaimed = 0
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
                if reclaim_skipped:
                    if assignment["terminal_reason"] is None:
                        reclaimed += 1
                    result = conn.execute(
                        """
                        UPDATE work_items
                        SET priority_score = ?,
                            priority_reason = ?,
                            cluster_key = ?,
                            terminal_reason = ?,
                            status = CASE WHEN ? IS NOT NULL THEN 'skipped' ELSE 'pending' END
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
                else:
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
            "reclaimed_to_pending": reclaimed,
            "by_cluster": dict(sorted(cluster_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    finally:
        conn.close()


def _retype_pass(db_path: str, *, batch: int, retype_all: bool) -> None:
    """Re-derive `work_items.type` from each in-scope row's stored fields.

    Why this exists: typing (`classify.classify_type`) and bucketing
    (`classify_buckets.classify_row`) are separate stages. The bucket-only
    re-runs above consume the stored `type` verbatim, so a typer improvement is
    inert on an already-ingested corpus until the rows are re-typed. This pass
    closes that gap WITHOUT re-ingesting, and — crucially — feeds the typer the
    row's STORED `content_type` and request `body`, which the ingest paths
    historically passed as `""` (so a proxy-captured row whose content_type was
    only known post-hoc never benefited from content-type typing).

    Scope safety mirrors `--reclassify-all`: the default is the NARROW
    `type='unknown'` set so already-typed rows (including operator/override
    types) are never silently re-typed; `--retype-all` opts into the broad set.

    For every row whose type actually CHANGES we (a) rewrite `type` and (b)
    re-apply the downstream bucket classification for the NEW type — including
    the insert-path inert-skip (`status='skipped'` + `terminal_reason=
    'inert_type'` for a row newly typed into `INERT_TYPES`). A row whose type is
    unchanged is left entirely alone, which makes the pass idempotent: a second
    run finds no changes.

    Safety: rows are never deleted; work commits once per batch (a crash leaves
    at most one batch re-runnable, and the pass is idempotent so re-running is
    safe); a JSON summary reports rows scanned, retyped, and the old→new type
    transition tally.
    """
    # Default scope is narrow (type='unknown' only); --retype-all widens it to
    # every row. Either way we page by `id > last_id` so a row that re-types to
    # a still-in-scope value (only possible under --retype-all, e.g. unknown
    # stays unknown) cannot loop forever.
    if retype_all:
        where_clause = "1 = 1"
    else:
        where_clause = "type = 'unknown'"

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        scanned = 0
        retyped = 0
        transitions: Counter[str] = Counter()

        last_id = 0
        while True:
            rows = conn.execute(
                f"""
                SELECT id, method, type, url_path, content_type, body, queue_key,
                       query_params, body_params, path_params
                FROM work_items
                WHERE {where_clause}
                  AND id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (last_id, batch),
            ).fetchall()
            if not rows:
                break

            for row in rows:
                last_id = max(last_id, int(row["id"]))
                scanned += 1
                old_type = row["type"] or "unknown"
                # Read the STORED content_type / body and pass them to the
                # typer. Coalesce NULL → "" so the typer always gets a string
                # (path/extension typing still applies on an empty content
                # type), never None.
                method = row["method"] or "GET"
                content_type = row["content_type"] or ""
                body_snippet = row["body"] or ""
                new_type = classify_type(
                    method, row["url_path"] or "", content_type, body_snippet
                )

                if new_type == old_type:
                    # No change → leave the row entirely alone (idempotency).
                    continue

                retyped += 1
                transitions[f"{old_type}->{new_type}"] += 1

                # Re-apply downstream classification for the NEW type. Build a
                # lightweight row mirror that carries the new type so the bucket
                # classifier sees it (it reads `type`, `url_path`, and the param
                # columns). The skip/restore below mirrors the --reclaim-skipped
                # pass: a row whose new classification is terminal (e.g. newly
                # typed into INERT_TYPES → terminal_reason='inert_type') is
                # stamped status='skipped'; a row that re-types to an actionable
                # (non-terminal) type is restored to status='pending' so an
                # inert→actionable retype becomes dispatchable again.
                mirror = {
                    "type": new_type,
                    "url_path": row["url_path"],
                    "query_params": row["query_params"],
                    "body_params": row["body_params"],
                    "path_params": row["path_params"],
                }
                assignment = _classify_row(mirror)
                # queue_key embeds the type only for variant:/service:/coverage:
                # keys, where it is the trailing ':'-segment. Detect that precisely
                # by the trailing segment matching the OLD type; arjun:/deferred:/
                # seed: keys carry a params_sig or URL there, not a type, and must
                # NOT be rewritten (doing so corrupts the key). When it IS the type,
                # re-ingest dedups on queue_key (UNIQUE + INSERT OR IGNORE), so the
                # stored key must track the new type or a later re-ingest inserts a
                # duplicate row; preserve the `<scheme>:<id>:` prefix and swap only
                # the trailing type. UPDATE OR IGNORE: in the rare case a
                # `<scheme>:<id>:<new_type>` row already exists, skip this row rather
                # than tripping the UNIQUE(queue_key) constraint mid-pass.
                old_qk = row["queue_key"] or ""
                if ":" in old_qk and old_qk.rsplit(":", 1)[1] == old_type:
                    new_qk = old_qk.rsplit(":", 1)[0] + ":" + new_type
                else:
                    new_qk = old_qk
                conn.execute(
                    """
                    UPDATE OR IGNORE work_items
                    SET type = ?,
                        queue_key = ?,
                        priority_score = ?,
                        priority_reason = ?,
                        cluster_key = ?,
                        terminal_reason = ?,
                        status = CASE
                            WHEN ? IS NOT NULL THEN 'skipped'
                            WHEN status = 'skipped' THEN 'pending'
                            ELSE status
                        END
                    WHERE id = ?
                    """,
                    (
                        new_type,
                        new_qk,
                        assignment["priority_score"],
                        assignment["priority_reason"],
                        assignment["cluster_key"],
                        assignment["terminal_reason"],
                        assignment["terminal_reason"],
                        row["id"],
                    ),
                )
            conn.commit()

            if len(rows) < batch:
                break

        summary = {
            "scanned": scanned,
            "retyped": retyped,
            "scope": "all" if retype_all else "unknown",
            "by_transition": dict(
                sorted(transitions.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    finally:
        conn.close()
