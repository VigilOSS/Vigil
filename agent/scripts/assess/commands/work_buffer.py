"""vigil assess work-buffer — backend work-buffer (assessment_work_items) ops."""
from __future__ import annotations

import sys

from assess.commands import dispatch
from assess.lib.classify_buckets import SKIP_REASON_TAGS


_ACTION_HELP: dict[str, str] = {
    "stats": (
        "Usage: vigil assess work-buffer stats "
        "[--by status|source|cluster|host|reason|classifier_version]\n\n"
        "Print work-buffer counts grouped by status or another supported axis.\n"
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
    "defer-cluster": (
        "Usage: vigil assess work-buffer defer-cluster <cluster_key> --reason TEXT "
        "[--reason-tag TAG]\n\n"
        "Mark a whole cluster skipped/deferred with an auditable reason.\n"
    ),
    "defer-items": (
        "Usage: vigil assess work-buffer defer-items <id> [<id> ...] --reason TEXT "
        "[--reason-tag TAG]\n\n"
        "Mark specific work-item ids skipped/deferred with an auditable reason.\n"
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
        "classify-work --reclassify-stale leaves them untouched.\n"
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
    p.set_defaults(func=run)


def run(args) -> None:
    dispatch.run(args)
