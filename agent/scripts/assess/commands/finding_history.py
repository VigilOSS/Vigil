"""vigil assess finding history — read one finding's transition ledger."""
from __future__ import annotations

import json
import shlex
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.list_output import ListPage, lookahead_limit, page_from_backend, report_page


_MAX_HISTORY_LIMIT = 1000


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "history",
        help="Read the append-only transition history for one finding",
    )
    parser.add_argument("finding_slug", help="Canonical finding slug")
    parser.add_argument("--limit", type=int, default=100, help="Maximum transitions to print")
    parser.add_argument("--offset", type=int, default=0, help="Transition offset")
    parser.add_argument(
        "--paginate",
        action="store_true",
        help="Fetch every transition page from --offset through the oldest record",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="No-op: finding history always emits JSON.",
    )
    parser.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    requested_slug = str(args.finding_slug)
    slug = quote(requested_slug, safe="")
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        limit = int(args.limit)
        offset = int(args.offset)
        if args.paginate:
            transitions = []
            next_offset = offset
            while True:
                page_rows = client.get(
                    f"findings/{slug}/transitions?"
                    + urlencode({"limit": limit, "offset": next_offset})
                )
                _require_transitions(page_rows, requested_slug=requested_slug)
                transitions.extend(page_rows)
                if len(page_rows) < limit:
                    break
                next_offset += len(page_rows)
        else:
            request_limit, used_lookahead = lookahead_limit(
                limit, maximum=_MAX_HISTORY_LIMIT
            )
            transitions = client.get(
                f"findings/{slug}/transitions?"
                + urlencode({"limit": request_limit, "offset": offset})
            )
    _require_transitions(transitions, requested_slug=requested_slug)
    if args.paginate:
        exact_total = offset + len(transitions) if transitions or offset == 0 else None
        page = ListPage(
            rows=transitions,
            offset=offset,
            total=exact_total,
            total_at_least=exact_total,
            has_more=False,
        )
    else:
        page = page_from_backend(
            transitions,
            limit=limit,
            offset=offset,
            used_lookahead=used_lookahead,
        )
    transitions = page.rows
    continuation = (
        "vigil assess finding history "
        f"{shlex.quote(requested_slug)} --limit {limit} "
        f"--offset {page.offset + len(page.rows)}"
    )
    report_page(
        page,
        noun="finding transitions",
        continuation_command=continuation,
    )
    if transitions:
        warn_untrusted_data()
    print(json.dumps(transitions, indent=2, ensure_ascii=False))


def _require_transitions(transitions, *, requested_slug: str) -> None:
    if not isinstance(transitions, list) or any(
        not isinstance(transition, dict)
        or not isinstance(transition.get("id"), int)
        or isinstance(transition.get("id"), bool)
        or transition["id"] < 1
        or not isinstance(transition.get("action"), str)
        or not transition["action"].strip()
        for transition in transitions
    ):
        raise AssessError(
            f"finding history: backend returned malformed transition history "
            f"for {requested_slug}"
        )
