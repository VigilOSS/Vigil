"""vigil assess work-buffer — backend work-buffer (assessment_work_items) ops."""
from __future__ import annotations

import sys

from assess.commands import dispatch
from assess.lib.classify_buckets import SKIP_REASON_TAGS


_ACTION_HELP: dict[str, str] = {
    "stats": (
        "Usage: vigil assess work-buffer stats "
        "[--by status|source|cluster|host|reason|classifier_version] "
        "[--status STATUS]\n\n"
        "Print work-buffer counts grouped by status or another supported axis.\n"
        "--status narrows host-grouped stats; other groupings ignore it.\n"
        "'classifier_version' sizes taxonomy drift (current vs stale vs (none) vs manual).\n"
    ),
    "peek": (
        "Usage: vigil assess work-buffer peek <type> [limit]\n\n"
        "Preview pending work items of the given type without claiming them.\n"
    ),
    "fetch": (
        "Usage: vigil assess work-buffer fetch <type> <limit> <agent>\n\n"
        "Claim pending work items of the given type for an agent.\n"
    ),
    "fetch-by-priority": (
        "Usage: vigil assess work-buffer fetch-by-priority <limit> [auto|agent]\n\n"
        "Claim the highest-priority pending work items across types.\n"
    ),
    "fetch-by-unit": (
        "Usage: vigil assess work-buffer fetch-by-unit [--unit-id ID] [--path PREFIX] "
        "[--class TYPE] [--limit N] [--agent auto|NAME]\n\n"
        "Atomically claim one coherent app unit. With no unit id, select the "
        "highest-EV unsatisfied unit; an omitted limit is depth/saturation sized.\n"
    ),
    "defer-cluster": (
        "Usage: vigil assess work-buffer defer-cluster <cluster_key> --reason TEXT "
        "[--reason-tag TAG] [--dry-run]\n\n"
        "Mark a whole cluster skipped/deferred with an auditable reason.\n"
    ),
    "defer-items": (
        "Usage: vigil assess work-buffer defer-items <id> [<id> ...] --reason TEXT "
        "[--reason-tag TAG] [--dry-run]\n\n"
        "Mark specific work-item ids skipped/deferred with an auditable reason.\n"
    ),
    "set-rationale": (
        "Usage: vigil assess work-buffer set-rationale <id> [<id> ...] "
        "--rationale TEXT\n\n"
        "Persist the triage conclusion on selected work items without changing "
        "their lifecycle status.\n"
    ),
    "done": (
        "Usage: vigil assess work-buffer done <id> [<id> ...]\n\n"
        "Mark claimed work items done.\n"
    ),
    "error": (
        "Usage: vigil assess work-buffer error <id> [<id> ...]\n\n"
        "Mark claimed work items errored.\n"
    ),
    "reset-stale": (
        "Usage: vigil assess work-buffer reset-stale <minutes>\n\n"
        "Return stale processing rows to pending.\n"
    ),
    "mark-manual": (
        "Usage: vigil assess work-buffer mark-manual <id> [<id> ...]\n\n"
        "Stamp classifier_version='manual' on hand-tuned rows so "
        "work-buffer reclassify --reclassify-stale leaves them untouched.\n"
    ),
    "reclassify": (
        "Usage: vigil assess work-buffer reclassify "
        "[--reclassify-all | --reclassify-stale | --reclaim-skipped | --retype | --retype-all] "
        "[--batch N]\n\n"
        "Re-apply gf-style priority/cluster classification to the work buffer "
        "(default: unscored rows only). --retype re-derives `type` from stored "
        "fields; --retype-all widens that to every row.\n"
    ),
    "link-surface": (
        "Usage: vigil assess work-buffer link-surface "
        "--surface-id <id>[,<id>] [--cluster <key>] [--queue-key <key>] "
        "[--relation <label>] [--link-evidence-ref <ref>]\n\n"
        "Link backend surfaces to the request variants behind selected "
        "work_items (by --cluster and/or --queue-key).\n"
    ),
    "clusters": (
        "Usage: vigil assess work-buffer clusters "
        "[--limit N] [--status STATUS] [--host HOST]\n\n"
        "Summarize work_items grouped by cluster_key (folded-in list-clusters), "
        "ordered by max priority then count, with up to 5 representative URLs "
        "per cluster.\n"
    ),
}


def maybe_print_action_help(tokens: list[str]) -> None:
    # tokens are the argv after `work-buffer`; the action is now the first token.
    if len(tokens) >= 2 and any(token in {"-h", "--help"} for token in tokens[1:]):
        text = _ACTION_HELP.get(tokens[0])
        if text:
            print(text)
            sys.exit(0)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "work-buffer",
        help="Operate on the backend work buffer (assessment_work_items).",
        usage="vigil assess work-buffer <action> [args...]",
    )
    p.add_argument("action", choices=dispatch._DB_ACTIONS)  # noqa: SLF001 - wrapper over the dispatch surface.
    p.add_argument("extra", nargs="*", help="Action-specific arguments")
    p.add_argument("--reason", default="", help="Reason for defer-cluster / defer-items.")
    p.add_argument(
        "--rationale",
        dest="triage_rationale",
        default="",
        help="Triage conclusion for set-rationale.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview defer-items/defer-cluster matches without mutating them.",
    )
    p.add_argument(
        "--reason-tag",
        dest="reason_tag",
        default="",
        choices=("", *sorted(SKIP_REASON_TAGS)),
        help="Structured reason tag for defer-cluster / defer-items. Stamps terminal_reason "
        "as `skipped:<tag> | <--reason text>` so a query can tell a correct exclusion from a bare drop.",
    )
    p.add_argument(
        "--by",
        default="status",
        choices=("status", "source", "cluster", "host", "reason", "classifier_version"),
        help="Group axis for stats. 'reason' groups deferred/skipped rows by reason tag "
        "(surfaces 'untagged' drops). 'classifier_version' sizes reclassification drift "
        "(current vs stale vs (none)/legacy vs manual).",
    )
    p.add_argument("--unit-id", type=int, default=None, help="Explicit app-unit id for fetch-by-unit.")
    p.add_argument("--path", default="", help="Optional app-unit path-prefix narrowing.")
    p.add_argument("--class", dest="work_class", default="", help="Optional work-item type narrowing.")
    p.add_argument("--limit", dest="unit_limit", type=int, default=None, help="Explicit fetch-by-unit batch size.")
    p.add_argument("--agent", dest="unit_agent", default="auto", help="fetch-by-unit routed agent (default auto).")
    # reclassify (folded-in classify-work) flags.
    p.add_argument("--batch", type=int, default=500, help="(reclassify) Rows to POST per update batch (default: 500).")
    p.add_argument("--reclassify-all", dest="reclassify_all", action="store_true",
                   help="(reclassify) Also rewrite priority/cluster on already-scored rows (after a `_BUCKETS` change).")
    p.add_argument("--reclassify-stale", dest="reclassify_stale", action="store_true",
                   help="(reclassify) Re-score only rows whose classifier_version is stale, leaving `manual` rows untouched.")
    p.add_argument("--reclaim-skipped", dest="reclaim_skipped", action="store_true",
                   help="(reclassify) Re-evaluate every skipped row against the current inert policy; un-strand non-inert ones.")
    p.add_argument("--retype", dest="retype", action="store_true",
                   help="(reclassify) Re-derive `type` for type='unknown' rows from stored fields, then re-bucket changed rows.")
    p.add_argument("--retype-all", dest="retype_all", action="store_true",
                   help="(reclassify) Broaden --retype to EVERY row (can overwrite a hand-set type). Implies --retype.")
    # link-surface (folded-in link-surface-work-items) flags.
    p.add_argument("--cluster", action="append", default=[], metavar="CLUSTER_KEY",
                   help="(link-surface) Select work_items by cluster_key (repeatable).")
    p.add_argument("--queue-key", dest="queue_key", action="append", default=[], metavar="QUEUE_KEY",
                   help="(link-surface) Select work_items by exact queue_key (repeatable).")
    p.add_argument("--surface-id", dest="surface_id", action="append", default=[], metavar="SURFACE_ID",
                   help="(link-surface) Backend surface id to link (repeatable or comma-separated).")
    p.add_argument("--relation", default="", help="(link-surface) Free-text relation label, e.g. primary-endpoint.")
    p.add_argument("--link-evidence-ref", dest="link_evidence_ref", default="",
                   help="(link-surface) Evidence reference for the surface link.")
    # clusters (folded-in list-clusters) flags.
    p.add_argument(
        "--status",
        dest="cluster_status",
        default="",
        help=(
            "(clusters/stats --by host) Work-item status filter. "
            "Clusters default to pending; host stats default to all statuses."
        ),
    )
    p.add_argument("--host", dest="cluster_host", default="",
                   help="(clusters) Only clusters containing a work_item whose URL matches this host "
                        "(exact, or leading-'*' fnmatch wildcard).")
    p.set_defaults(func=run)


def run(args) -> None:
    if args.action == "clusters":
        # Folded-in list-clusters: delegate to the standalone renderer with a
        # clusters-scoped namespace (its own --limit/--status/--host semantics).
        from types import SimpleNamespace

        from assess.commands import list_clusters

        limit = getattr(args, "unit_limit", None)
        list_clusters.run(
            SimpleNamespace(
                engagement_dir=getattr(args, "engagement_dir", None),
                limit=limit if limit is not None else 100,
                status=getattr(args, "cluster_status", "pending") or "pending",
                host=getattr(args, "cluster_host", "") or "",
            )
        )
        return
    dispatch.run(args)
