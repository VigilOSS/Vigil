"""vigil assess classify-work — idempotent re-application of gf-style classification.

Classification runs *inline* during ingest (client-side, in the work_item block
the backend derives), so the work buffer is always scored at insert time. This
command is retained for two reasons:

1. Re-applying classification after a bucket-table change in
   `assess.lib.classify_buckets._BUCKETS` (e.g., adding a new bucket) so the
   already-ingested rows pick up the new weights without re-ingesting.
2. Re-typing an already-ingested corpus after a typer improvement.

The bucket logic itself lives in `assess.lib.classify_buckets`. This command is a
thin batch-loop around it: it reads the backend work buffer, re-scores/re-types
in Python, and force-writes the changed fields back via the backend
`work-items/update` endpoint (ADR 0013).
"""
from __future__ import annotations

import argparse
import json
from collections import Counter

from assess.lib.classify import classify_type
from assess.lib.classify_buckets import (
    CLASSIFIER_VERSION,
    INERT_TYPES,
    MANUAL_CLASSIFIER_VERSION,
    classify_row as _classify_row,
)
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config

# Chunk size for the backend update POST.
_UPDATE_CHUNK = 500


def _row_get(row, key, default=None):
    """Tolerant column getter for a work-item row dict.

    Returns `default` when the column is absent or stored NULL, so threading the
    context kwargs never breaks on a row that lacks an optional column.
    """
    try:
        value = row[key]
    except (IndexError, KeyError, TypeError):
        return default
    return value if value is not None else default


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "classify-work",
        help="Re-apply gf-style priority/cluster classification to the work buffer",
    )
    p.add_argument(
        "--batch",
        type=int,
        default=500,
        help="Rows to POST per update batch (default: 500).",
    )
    p.add_argument(
        "--reclassify-all",
        dest="reclassify_all",
        action="store_true",
        help=(
            "Also rewrite priority/cluster on rows that are already scored. "
            "Use this when you intentionally changed `_BUCKETS` in "
            "`assess.lib.classify_buckets` and want the new weights applied "
            "to the existing buffer. NOTE (backend narrowing): rows stamped "
            "`manual` are re-scored here too, but the older local path could "
            "additionally overwrite them — behavior is otherwise identical."
        ),
    )
    p.add_argument(
        "--reclassify-stale",
        dest="reclassify_stale",
        action="store_true",
        help=(
            "Re-score only rows whose `classifier_version` is stale — NULL "
            "(legacy) or different from the CURRENT `classify_buckets."
            "CLASSIFIER_VERSION` — while LEAVING rows stamped `manual` "
            "untouched. Idempotent: a second run reports 0 updates."
        ),
    )
    p.add_argument(
        "--reclaim-skipped",
        dest="reclaim_skipped",
        action="store_true",
        help=(
            "Re-evaluate EVERY status='skipped' row against the CURRENT inert "
            "policy and un-strand any whose type is no longer inert, flipping it "
            "back to 'pending' and clearing its stale terminal_reason. Use after "
            "an inert-policy change. WARNING: this also reverses MANUAL skips of "
            "non-inert items — opt-in for exactly that reason."
        ),
    )
    p.add_argument(
        "--retype",
        dest="retype",
        action="store_true",
        help=(
            "Re-derive `type` for in-scope rows by re-running the typer against "
            "each row's STORED method/url_path/content_type/body, then re-apply "
            "the downstream priority/cluster/terminal_reason for any row whose "
            "type changed. Default scope is the SAFE narrow set `type='unknown'` "
            "only. Idempotent."
        ),
    )
    p.add_argument(
        "--retype-all",
        dest="retype_all",
        action="store_true",
        help=(
            "Broaden `--retype` scope to EVERY row, not just `type='unknown'`. "
            "WARNING: can overwrite a hand-set `type`. Implies `--retype`."
        ),
    )
    # Deprecated no-op alias retained so older runbooks/tests do not break.
    p.add_argument(
        "--only-unscored",
        dest="only_unscored",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    p.set_defaults(func=run)


def _matches_predicate(row, *, reclaim_skipped, reclassify_stale, reclassify_all) -> bool:
    """Replicate the former SQL WHERE predicates in Python."""
    status = row.get("status")
    row_type = row.get("type")
    cv = _row_get(row, "classifier_version")
    base = status == "pending" or (status == "skipped" and row_type in INERT_TYPES)

    if reclaim_skipped:
        return status == "skipped"
    if reclassify_stale:
        # stale AND not-manual; NULL cv counts as stale+not-manual (kept).
        return base and cv != CLASSIFIER_VERSION and cv != MANUAL_CLASSIFIER_VERSION
    if reclassify_all:
        return base
    # default: unscored only.
    return (
        base
        and int(row.get("priority_score") or 0) == 0
        and _row_get(row, "cluster_key") is None
        and _row_get(row, "terminal_reason") is None
    )


def run(args: argparse.Namespace) -> None:
    batch = max(1, int(args.batch))
    reclassify_all = bool(getattr(args, "reclassify_all", False))
    reclassify_stale = bool(getattr(args, "reclassify_stale", False))
    reclaim_skipped = bool(getattr(args, "reclaim_skipped", False))
    retype = bool(getattr(args, "retype", False))
    retype_all = bool(getattr(args, "retype_all", False))

    cfg = load_config(args.engagement_dir)

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        # `--retype` is a distinct, opt-in pass (re-derive `type` then re-bucket
        # only rows whose type changed); it never runs implicitly with the
        # bucket-only re-classification paths. `--retype-all` implies `--retype`.
        if retype or retype_all:
            _retype_pass(client, batch=batch, retype_all=retype_all)
            return

        rows = client.get_all_pages("work-items")
        classified = 0
        reclaimed = 0
        cluster_counts: Counter[str] = Counter()
        from_version_counts: Counter[str] = Counter()
        updates: list[dict] = []

        for row in rows:
            if not _matches_predicate(
                row,
                reclaim_skipped=reclaim_skipped,
                reclassify_stale=reclassify_stale,
                reclassify_all=reclassify_all,
            ):
                continue
            classified += 1
            from_version_counts[_row_get(row, "classifier_version") or "none"] += 1
            assignment = _classify_row(
                row,
                url=_row_get(row, "url"),
                source=_row_get(row, "source"),
                live_status=_row_get(row, "live_status"),
            )
            cluster_counts[assignment["cluster_key"]] += 1

            update = {
                "id": row["id"],
                "priority_score": assignment["priority_score"],
                "priority_reason": assignment["priority_reason"],
                "cluster_key": assignment["cluster_key"],
                "classifier_version": CLASSIFIER_VERSION,
            }
            if reclaim_skipped:
                # terminal_reason set directly (may clear); status derived from it.
                update["terminal_reason"] = assignment["terminal_reason"]
                update["status"] = "skipped" if assignment["terminal_reason"] is not None else "pending"
                if assignment["terminal_reason"] is None:
                    reclaimed += 1
            else:
                # COALESCE-keep the existing terminal_reason; only flip to skipped
                # when a NEW terminal_reason appears (else keep the current status).
                if assignment["terminal_reason"] is not None:
                    update["terminal_reason"] = assignment["terminal_reason"]
                    update["status"] = "skipped"
                # else: leave terminal_reason/status untouched (omit the keys).
            updates.append(update)

        updated = 0
        for start in range(0, len(updates), batch):
            chunk = updates[start:start + batch]
            if chunk:
                resp = client.post("work-items/update", {"updates": chunk})
                updated += int(resp.get("affected", 0))

        summary = {
            "classified": classified,
            "updated": updated,
            "reclaimed_to_pending": reclaimed,
            "classifier_version": CLASSIFIER_VERSION,
            "by_cluster": dict(sorted(cluster_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "from_version": dict(
                sorted(from_version_counts.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))


def _retype_pass(client, *, batch: int, retype_all: bool) -> None:
    """Re-derive `type` from each in-scope row's stored fields (backend-backed).

    Feeds the typer the row's STORED `content_type` and request `body`. For every
    row whose type CHANGES, rewrites `type` (+ the type-suffixed queue_key) and
    re-applies the downstream bucket classification for the NEW type. Rows whose
    type is unchanged are left alone (idempotent). Never deletes; a queue_key
    collision on the rewrite is skipped by the backend's UPDATE OR IGNORE.
    """
    rows = client.get_all_pages("work-items")
    scanned = 0
    retyped = 0
    transitions: Counter[str] = Counter()
    updates: list[dict] = []

    for row in rows:
        row_type = row.get("type") or "unknown"
        if not retype_all and row_type != "unknown":
            continue
        scanned += 1
        old_type = row_type
        method = row.get("method") or "GET"
        content_type = _row_get(row, "content_type", "") or ""
        body_snippet = _row_get(row, "body", "") or ""
        new_type = classify_type(method, row.get("url_path") or "", content_type, body_snippet)

        if new_type == old_type:
            continue

        retyped += 1
        transitions[f"{old_type}->{new_type}"] += 1

        mirror = {
            "type": new_type,
            "url_path": row.get("url_path"),
            "query_params": row.get("query_params"),
            "body_params": row.get("body_params"),
            "path_params": row.get("path_params"),
        }
        assignment = _classify_row(mirror)

        # queue_key embeds the type only for variant:/service:/coverage: keys,
        # where it is the trailing ':'-segment. Only rewrite when the trailing
        # segment matches the OLD type; arjun:/deferred:/seed: keys carry a
        # params_sig/URL there and must NOT be rewritten.
        old_qk = row.get("queue_key") or ""
        if old_qk.startswith(("variant:", "service:", "coverage:")) and old_qk.rsplit(":", 1)[1] == old_type:
            new_qk = old_qk.rsplit(":", 1)[0] + ":" + new_type
        else:
            new_qk = old_qk

        update = {
            "id": row["id"],
            "type": new_type,
            "queue_key": new_qk,
            "priority_score": assignment["priority_score"],
            "priority_reason": assignment["priority_reason"],
            "cluster_key": assignment["cluster_key"],
            "terminal_reason": assignment["terminal_reason"],
            "classifier_version": CLASSIFIER_VERSION,
            # Terminal → skipped; a previously-skipped row that re-types to an
            # actionable (non-terminal) type is restored to pending; else keep.
            "status": (
                "skipped" if assignment["terminal_reason"] is not None
                else ("pending" if row.get("status") == "skipped" else row.get("status"))
            ),
        }
        updates.append(update)

    applied = 0
    for start in range(0, len(updates), batch):
        chunk = updates[start:start + batch]
        if chunk:
            resp = client.post("work-items/update", {"updates": chunk})
            applied += int(resp.get("affected", 0))

    summary = {
        "scanned": scanned,
        "retyped": retyped,
        "applied": applied,
        "scope": "all" if retype_all else "unknown",
        "by_transition": dict(
            sorted(transitions.items(), key=lambda kv: (-kv[1], kv[0]))
        ),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
