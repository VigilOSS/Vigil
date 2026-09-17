"""vigil assess code-lead — bind a tracked intel lead to a place in the code.

Research turns up prior art ("this project's SAML parser had a signature
bypass in 2023"). `vigil assess intel record note` with `lead_status` set in
the payload already tracks that as a lead; this verb is the half that says
*where* to look, turns the bound file into claimable analysis work, and is what
the code completeness gate reads when it refuses to seal a scan with an
unanswered lead.

There is no second lead store here. Every disposition is still
``intel_notes.lead_status`` — `vigil assess intel update note <id>`.
"""
from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlencode

# Both halves of the one audited queue write: `_normalize_queue_items` applies
# the item cap, the priority range and the dedupe the backend expects, and
# `submit_queue_items` owns the snapshot pair, the batching and the conflict
# exit. A caller that reaches the second without the first is correct only by
# accident — the rules live in one place and this command uses them.
from assess.commands.code_dispatch import _normalize_queue_items, submit_queue_items
from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.config import load_config
from assess.lib.contracts import MAX_LEAD_BINDING_PAGE

_LEAD_QUEUE_BATCH_THEME = "prior-art-lead"


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "code-lead",
        help="Bind prior-art leads to code locations and turn them into queue work",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vigil assess code-lead bind 7 --repo-id 3 --file-path src/saml/parser.py \\\n"
            "      --line-start 120 --line-end 190 --prior-art CVE-2023-9999\n"
            "  vigil assess code-lead list --lead-status open\n"
            "  vigil assess code-lead queue --dry-run\n"
            "  vigil assess code-lead unbind 4 --reason 'wrong parser'\n\n"
            "A lead is closed on the note, never here:\n"
            "  vigil assess intel update note 7 --inline '{\"lead_status\": \"ruled_out\"}'\n"
        ),
    )
    action = p.add_subparsers(dest="lead_action")
    action.required = False

    bind = action.add_parser(
        "bind",
        help="Point one tracked lead at one file (optionally one line range).",
    )
    bind.add_argument("note_id", type=int, help="Intel note id of the tracked lead")
    bind.add_argument(
        "--repo-id", dest="repo_id", type=int, required=True,
        help="Repository the file belongs to",
    )
    bind.add_argument(
        "--file-path", dest="file_path", required=True,
        help="Repo-relative path as it exists in the current sealed generation",
    )
    bind.add_argument(
        "--line-start", dest="line_start", type=int,
        help="First line of the prior-art region; omit both line flags to bind the whole file",
    )
    bind.add_argument(
        "--line-end", dest="line_end", type=int,
        help="Last line of the prior-art region (defaults to --line-start)",
    )
    bind.add_argument(
        "--prior-art", dest="prior_art_ref", default="",
        help="What the lead came from: a CVE id, advisory URL, or past-audit reference",
    )
    bind.add_argument(
        "--rationale", default="",
        help="Why this location: the reasoning a specialist should start from",
    )
    bind.add_argument(
        "--bound-by", dest="bound_by", default="",
        help="Agent or operator making the binding (audit attribution)",
    )
    bind.set_defaults(func=_run_bind)

    listing = action.add_parser(
        "list",
        help="Page lead bindings with their obligation, queue and staleness state.",
    )
    listing.add_argument("--note-id", dest="note_id", type=int, help="One lead only")
    listing.add_argument("--repo-id", dest="repo_id", type=int, help="One repository only")
    listing.add_argument(
        "--lead-status", dest="lead_status",
        choices=("open", "in_progress", "resolved", "ruled_out"),
        help="Filter on the lead's own disposition",
    )
    listing.add_argument(
        "--include-superseded", dest="include_superseded", action="store_true",
        help="Also show stale (generation-superseded) and retracted bindings",
    )
    listing.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON.")
    listing.set_defaults(func=_run_list)

    queue = action.add_parser(
        "queue",
        help="Create analysis queue rows for bound files that have none yet.",
    )
    queue.add_argument("--note-id", dest="note_id", type=int, help="One lead only")
    queue.add_argument("--repo-id", dest="repo_id", type=int, help="One repository only")
    queue.add_argument(
        "--dry-run", dest="dry_run", action="store_true",
        help="Print the queue items that would be submitted without writing them",
    )
    queue.set_defaults(func=_run_queue)

    unbind = action.add_parser(
        "unbind", help="Retract one binding, leaving the lead and its status alone."
    )
    unbind.add_argument("binding_id", type=int, help="Binding id from `code-lead list`")
    unbind.add_argument(
        "--reason", required=True,
        help="Why the lead does not live here after all",
    )
    unbind.set_defaults(func=_run_unbind)

    def _print_help_when_missing(_args) -> None:
        p.print_help()
        raise SystemExit(1)

    p.set_defaults(func=_print_help_when_missing)


def _location(binding: dict) -> str:
    path = str(binding.get("file_path") or "")
    start = binding.get("line_start")
    end = binding.get("line_end")
    if start is None:
        return path
    if end is None or int(end) == int(start):
        return f"{path}:{start}"
    return f"{path}:{start}-{end}"


def _run_bind(args) -> None:
    cfg = load_config(args.engagement_dir)
    payload = {
        "note_id": args.note_id,
        "repo_id": args.repo_id,
        "file_path": args.file_path,
        "line_start": args.line_start,
        "line_end": args.line_end,
        "prior_art_ref": args.prior_art_ref,
        "rationale": args.rationale,
        "bound_by": args.bound_by,
    }
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        binding = client.post("code/lead-bindings", payload)

    require_write_result(
        binding if isinstance(binding, dict) else {},
        operation="code-lead bind",
        positive_ids=("id", "note_id", "file_id", "repo_generation"),
    )
    print(
        f"Bound lead {binding['note_id']} to {_location(binding)} "
        f"(binding {binding['id']}, repo {binding['repo_id']} generation "
        f"{binding['repo_generation']}, {binding.get('repo_role', '')})"
    )
    if binding.get("carries_obligation"):
        if binding.get("queued"):
            print(
                f"Already claimable as queue item {binding['queue_item_id']} "
                f"({binding.get('queue_status', '')})."
            )
        else:
            print(
                "No analysis queue row covers this file yet — create one with "
                "`vigil assess code-lead queue`."
            )
    else:
        # B8: reference source is citable and owes nothing. Say so, or the
        # operator waits for work that will never be created.
        print(
            "This repository carries no review obligation, so the binding is a "
            "citation: no queue row and no completion gate."
        )


def _fetch_bindings(cfg, *, note_id, repo_id, lead_status=None, include_superseded=False):
    filters: list[tuple[str, str]] = []
    if note_id is not None:
        filters.append(("note_id", str(note_id)))
    if repo_id is not None:
        filters.append(("repo_id", str(repo_id)))
    if lead_status:
        filters.append(("lead_status", str(lead_status)))
    if include_superseded:
        filters.append(("include_superseded", "true"))
    filters.append(("limit", str(MAX_LEAD_BINDING_PAGE)))
    query = urlencode(filters)
    endpoint = "code/lead-bindings" + (f"?{query}" if query else "")
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(endpoint)
    if not isinstance(result, dict):
        print("Backend returned a non-object lead-binding listing", file=sys.stderr)
        raise SystemExit(1)
    items = [item for item in (result.get("items") or []) if isinstance(item, dict)]
    total = int(result.get("total", len(items)) or 0)
    if total > len(items):
        print(
            f"code-lead: this page carries {len(items)} of {total} matching "
            "bindings; narrow with --note-id/--repo-id before treating it as "
            "the whole worklist.",
            file=sys.stderr,
        )
    return items, total


def _run_list(args) -> None:
    cfg = load_config(args.engagement_dir)
    items, total = _fetch_bindings(
        cfg,
        note_id=args.note_id,
        repo_id=args.repo_id,
        lead_status=args.lead_status,
        include_superseded=args.include_superseded,
    )
    if args.as_json:
        print(json.dumps({"total": total, "items": items}, indent=2, ensure_ascii=False))
        return

    print(f"=== Prior-Art Lead Bindings ({len(items)} of {total}) ===")
    if not items:
        print("No lead bindings matched these filters.")
        # An empty page is not an empty worklist. The default filter hides every
        # binding whose generation moved on, which after a re-ingest is all of
        # them — while the completion gate goes on counting those leads.
        hidden = 0 if args.include_superseded else _hidden_binding_count(cfg, args)
        if hidden:
            print(
                f"{hidden} binding(s) are hidden by the default filter (stale or "
                "retracted). See them with `vigil assess code-lead list "
                "--include-superseded`."
            )
        print(
            "Bind one with `vigil assess code-lead bind <note-id> --repo-id <id> "
            "--file-path <path>`."
        )
        return
    print(
        f"{'ID':>5}  {'LEAD':>5}  {'STATUS':<12}{'BINDING':<9}{'ROLE':<10}"
        f"{'QUEUE':<14}{'PRIOR ART':<22}LOCATION"
    )
    for item in items:
        queue_item_id = item.get("queue_item_id")
        queue_cell = (
            f"{queue_item_id}/{item.get('queue_status', '')}"
            if queue_item_id is not None
            else "-"
        )
        print(
            f"{item.get('id', '?')!s:>5}  {item.get('note_id', '?')!s:>5}  "
            f"{item.get('lead_status', ''):<12}{item.get('binding_status', ''):<9}"
            f"{item.get('repo_role', ''):<10}{queue_cell:<14}"
            f"{str(item.get('prior_art_ref') or '-'):<22}{_location(item)}"
        )
        # The title is what an operator recognises the lead by; it is too long
        # for the table, so it rides underneath its own row.
        print(f"{'':>12}  {item.get('lead_title', '')}")
    print(
        "Close a lead on the note itself: `vigil assess intel update note <lead-id> "
        "--inline '{\"lead_status\": \"resolved\"}'` (or ruled_out)."
    )


def _hidden_binding_count(cfg, args) -> int:
    """How many bindings the default filter left out of an empty page."""

    _items, total = _fetch_bindings(
        cfg,
        note_id=args.note_id,
        repo_id=args.repo_id,
        lead_status=args.lead_status,
        include_superseded=True,
    )
    return total


def _guidance_line(binding: dict) -> str:
    prior_art = str(binding.get("prior_art_ref") or "")
    attribution = f" ({prior_art})" if prior_art else ""
    line = (
        f"prior-art lead {binding.get('note_id')}{attribution}: "
        f"{binding.get('lead_title', '')} @ {_location(binding)}"
    )
    rationale = str(binding.get("rationale") or "")
    return f"{line} — {rationale}" if rationale else line


def _run_queue(args) -> None:
    cfg = load_config(args.engagement_dir)
    # Superseded rows are asked for on purpose: `stale` is the exact complement
    # of the listing default, so the bindings this command has to report on are
    # precisely the ones an unfiltered read can never return.
    items, _total = _fetch_bindings(
        cfg, note_id=args.note_id, repo_id=args.repo_id, include_superseded=True
    )

    # Everything the backend already decided is read, never recomputed:
    # `carries_obligation` is the reference-repo and open-lead verdict, and
    # `queued` is the file's current canonical queue attempt.
    stale = [
        item
        for item in items
        if item.get("carries_obligation") and item.get("binding_status") == "stale"
    ]
    queueable = [
        item
        for item in items
        if item.get("carries_obligation")
        and item.get("binding_status") == "current"
        and not item.get("queued")
    ]
    if stale:
        print(
            f"{len(stale)} binding(s) are stale — their line ranges were read "
            "from source that has since been replaced. Re-read and re-bind them "
            "with `vigil assess code-lead bind` before they can become work: "
            + ", ".join(
                f"binding {item.get('id')} (lead {item.get('note_id')})"
                for item in stale
            )
        )
    if not queueable:
        if stale:
            # The obligation is real and unanswered; the re-bind above is what
            # stands between it and a queue row. Saying "nothing to queue" here
            # would explain the gate away instead of explaining it.
            print(
                "Nothing more to queue until those bindings are re-bound at the "
                "current generation."
            )
        else:
            print(
                "Nothing to queue: no bound file carries an unanswered obligation "
                "without a current analysis queue row."
            )
        return

    # One queue row per file, carrying every lead that points into it.
    by_file: dict[int, dict] = {}
    for item in queueable:
        file_id = item.get("file_id")
        if not isinstance(file_id, int):
            print(
                f"Binding {item.get('id')} carries no file_id; refusing to queue "
                "an unidentified file",
                file=sys.stderr,
            )
            raise SystemExit(1)
        # The queue rejects any priority that is not the file's current band, so
        # the file's own value is the only correct one — and an absent one is a
        # backend projection bug, not something to guess a default for.
        priority = item.get("analysis_priority")
        if not isinstance(priority, int) or isinstance(priority, bool):
            print(
                f"Binding {item.get('id')} carries no analysis_priority for file "
                f"{file_id}; refusing to queue a row the backend would reject",
                file=sys.stderr,
            )
            raise SystemExit(1)
        entry = by_file.setdefault(
            file_id,
            {
                "file_id": file_id,
                "priority": priority,
                "batch_theme": _LEAD_QUEUE_BATCH_THEME,
                "guidance_hypotheses": [],
            },
        )
        entry["guidance_hypotheses"].append(_guidance_line(item))

    raw_items = list(by_file.values())
    queue_items = _normalize_queue_items(cfg, raw_items)
    if args.dry_run:
        # The normalised items, because those are what a real run submits.
        print(json.dumps(queue_items, indent=2, ensure_ascii=False))
        print(
            f"[dry-run] would queue {len(queue_items)} file(s) from "
            f"{len(queueable)} binding(s)"
        )
        return

    submit_queue_items(
        cfg,
        raw_items=raw_items,
        normalized_items=queue_items,
        mode="initial",
        reason="",
        label="prior-art-leads",
        command_name="code-lead queue",
    )


def _run_unbind(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        binding = client.post(
            f"code/lead-bindings/{args.binding_id}/unbind", {"reason": args.reason}
        )
    require_write_result(
        binding if isinstance(binding, dict) else {},
        operation="code-lead unbind",
        expected={"binding_status": "unbound"},
        positive_ids=("id", "note_id"),
    )
    print(
        f"Unbound binding {binding['id']} from lead {binding['note_id']}; the "
        f"lead itself is unchanged and still {binding.get('lead_status', '')}."
    )
