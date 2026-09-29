"""vigil assess operator-checkpoint — the operator's own durable checkpoint.

Every dispatched specialist writes a handoff row; the operator wrote nothing for
itself, so its state died with the session. This verb writes that missing row.

The record is references-plus-one-note by construction: finding slugs, dispatch
agent ids, command-run ids and artifact ids all have to resolve to rows the
backend already holds (the write is refused, naming the unknown ids, when one
does not), the phase is server-derived, and ``--intent`` is the single free-text
block — UNVERIFIED operator intent, never a finding and never evidence. The
renderers label it that way so a later reader cannot mistake it for a fact.
"""
from __future__ import annotations

import json

from assess.lib.client import AssessmentClient, AssessError, require_write_result
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.render_containment import contain_separators


INTENT_LABEL = "intent (UNVERIFIED operator intent — not a finding, not evidence)"
_SHOW_ALL_PAGE_SIZE = 50


def render_intent_lines(intent_note: object, *, indent: str = "  ") -> list[str]:
    """Render the intent note losslessly without letting it forge structure.

    The note is the operator's own words, bounded at 8000 characters, so it
    routinely spans several lines. Emitted raw inside a ``- `` bullet, a second
    line beginning ``## `` or ``- `` would break out of the list and impersonate
    one of the brief's own section boundaries — a resuming agent reads that
    brief as its operating picture, so a forged heading is a correctness bug.

    The note is contained by the SHARED rule, not a note-specific one. It is the
    longest free-text field in a document whose other 29 rows already render
    through ``contain_separators``; a second pattern here meant this field
    admitted separators the reference rows beside it contained. The note is
    operator-authored, so the path is ADR 0018's at one remove — target output
    pasted into a note — which is narrower than a reference value but not
    different in kind.

    Containment is applied to the RENDERING only: every line of a multi-line
    note carries a fixed continuation indent so none of it starts at column
    zero. Nothing is trimmed, collapsed, escaped, or dropped — masking the
    operator's own text would be exactly the control ADR 0019 forbids.
    """
    label = f"{indent}- {INTENT_LABEL}:"
    body = str(intent_note or "")
    continuation = f"{indent}    "
    contained = contain_separators(body, indent=continuation)
    # Equality is the separator test: a note the shared rule did not touch is a
    # note with no separator in it, so it keeps the inline single-line shape
    # without this function restating which characters those are.
    if contained == body:
        return [f"{label} {body}"]
    return [label, f"{continuation}{contained}"]


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "operator-checkpoint",
        help=(
            "Record or read the operator's own durable checkpoint "
            "(backend references + one unverified intent note)."
        ),
    )
    action_sub = p.add_subparsers(dest="action")
    action_sub.required = True

    sp_record = action_sub.add_parser(
        "record",
        help="Append a checkpoint; a correction is a new version, never an edit.",
        description=(
            "Append checkpoint N+1 and supersede the previous current one. Every "
            "--finding / --agent-id / --command-run / --artifact must already "
            "exist in this engagement or the write is refused."
        ),
    )
    sp_record.add_argument(
        "--intent",
        required=True,
        help=(
            "What you were about to do and why. Recorded and rendered as "
            "UNVERIFIED operator intent — never as a finding or evidence."
        ),
    )
    sp_record.add_argument(
        "--finding",
        dest="findings",
        action="append",
        default=[],
        metavar="SLUG",
        help="Finding slug this checkpoint points at (repeatable).",
    )
    sp_record.add_argument(
        "--agent-id",
        dest="agent_ids",
        action="append",
        default=[],
        metavar="ID",
        help="Dispatch agent_id this checkpoint points at (repeatable).",
    )
    sp_record.add_argument(
        "--command-run",
        dest="command_runs",
        action="append",
        default=[],
        type=int,
        metavar="N",
        help="Command-run id this checkpoint points at (repeatable).",
    )
    sp_record.add_argument(
        "--artifact",
        dest="artifacts",
        action="append",
        default=[],
        type=int,
        metavar="N",
        help="Indexed artifact id this checkpoint points at (repeatable).",
    )
    sp_record.add_argument("--json", dest="as_json", action="store_true")
    sp_record.set_defaults(func=_run_record)

    sp_show = action_sub.add_parser(
        "show",
        help="Print the current checkpoint, or the whole supersession chain.",
    )
    sp_show.add_argument(
        "--all",
        dest="show_all",
        action="store_true",
        help="Walk the full supersession chain instead of the current row only.",
    )
    sp_show.add_argument("--json", dest="as_json", action="store_true")
    sp_show.set_defaults(func=_run_show)


def _client(args) -> AssessmentClient:
    cfg = load_config(args.engagement_dir)
    return AssessmentClient(cfg.base_url, cfg.engagement_key)


def _run_record(args) -> None:
    payload = {
        "intent_note": args.intent,
        "finding_slugs": list(args.findings),
        "dispatch_agent_ids": list(args.agent_ids),
        "command_run_ids": list(args.command_runs),
        "artifact_ids": list(args.artifacts),
    }
    client = _client(args)
    try:
        row = require_write_result(
            client.post("operator-checkpoints", payload),
            operation="record operator checkpoint",
            positive_ids=("id", "checkpoint_version"),
        )
    finally:
        client.close()
    if args.as_json:
        print(json.dumps(row, indent=2, ensure_ascii=False))
    else:
        print(_render_checkpoint(row))


def _run_show(args) -> None:
    client = _client(args)
    try:
        if getattr(args, "show_all", False):
            rows: list[dict] = []
            total: int | None = None
            while total is None or len(rows) < total:
                endpoint = (
                    "operator-checkpoints?include_superseded=true"
                    f"&limit={_SHOW_ALL_PAGE_SIZE}&offset={len(rows)}"
                )
                page = _require_checkpoint_page(client.get(endpoint))
                page_rows = page["checkpoints"]
                page_total = page.get("total_count")
                if not isinstance(page_total, int) or page_total < 0:
                    raise AssessError(
                        "operator-checkpoint show: backend returned a malformed "
                        "checkpoint page"
                    )
                if total is None:
                    total = page_total
                elif page_total != total:
                    raise AssessError(
                        "operator-checkpoint show: checkpoint total changed while "
                        "reading the chain; run the command again"
                    )
                if not page_rows and len(rows) < total:
                    raise AssessError(
                        "operator-checkpoint show: backend ended the checkpoint "
                        "chain before its reported total"
                    )
                rows.extend(page_rows)
            body = {
                "checkpoints": rows,
                "returned_count": len(rows),
                "total_count": total,
            }
        else:
            body = _require_checkpoint_page(client.get("operator-checkpoints"))
    finally:
        client.close()
    if args.as_json:
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return
    rows = body["checkpoints"]
    if not rows:
        print(
            "# Operator Checkpoint\n\n"
            "- none recorded for this engagement "
            "(`vigil assess operator-checkpoint record --intent \"...\"`)"
        )
        return
    warn_untrusted_data()
    total = body.get("total_count")
    lines = ["# Operator Checkpoint", ""]
    for row in rows:
        lines.extend(render_checkpoint_lines(row))
        lines.append("")
    lines.pop()
    if isinstance(total, int) and total > len(rows):
        lines.extend((
            "",
            f"- … showing {len(rows)} of {total} checkpoints "
            "(`vigil assess operator-checkpoint show --all`)",
        ))
    print("\n".join(lines))


def _require_checkpoint_page(body: object) -> dict:
    if not isinstance(body, dict) or not isinstance(body.get("checkpoints"), list):
        raise AssessError(
            "operator-checkpoint show: backend returned a malformed checkpoint page"
        )
    return body


def render_phase_field(row: dict) -> str:
    """Render the checkpoint's position on every track the engagement runs.

    A dual-track engagement advances the web track (``current_phase``) and the
    code track (``code_phase``) independently, so one unlabelled ``phase=``
    would let a reader take a code-track position for a web one. When both are
    present each is named by its track; a single-track engagement has nothing
    to confuse it with, so it keeps the bare ``phase=`` and gains no empty
    code field.
    """
    current = row.get("current_phase") or "unknown"
    code_phase = row.get("code_phase")
    if not code_phase:
        return f"phase={current}"
    return f"web_phase={current} code_phase={code_phase}"


def render_checkpoint_reference_lines(row: dict) -> list[str]:
    """Render the four reference lists — shared with the resume brief.

    A reference is not a safe identifier just because the backend made it
    resolve: `DispatchCreate.agent_id` is bounded by `max_length` and nothing
    else, so a dispatch can exist under an id carrying a line separator and
    `dispatch_agent_ids` then passes the must-resolve check precisely because
    that row really is there. Rendered raw, whatever follows the separator
    starts at column zero of a document a resuming agent reads as its operating
    picture, where a `## ...` line reads as one of that document's own section
    boundaries.

    Containment covers the whole assembled row, label included, and only
    inserts the rendering indent after a separator: a reference carrying none
    renders exactly as it always did, and no character is ever dropped
    (ADR 0019).
    """
    lines: list[str] = []
    for label, key in (
        ("findings", "finding_slugs"),
        ("dispatch agent_ids", "dispatch_agent_ids"),
        ("command runs", "command_run_ids"),
        ("artifacts", "artifact_ids"),
    ):
        values = row.get(key) or []
        rendered = ", ".join(str(value) for value in values) if values else "-"
        lines.append(contain_separators(f"  - {label}: {rendered}"))
    return lines


def render_checkpoint_lines(row: dict) -> list[str]:
    """Shared human render — the intent is always labelled UNVERIFIED."""

    version = row.get("checkpoint_version")
    superseded_by = row.get("superseded_by_checkpoint_version")
    header = f"- checkpoint #{version} {render_phase_field(row)}"
    header += f" source={row.get('source') or 'unknown'}"
    header += f" client={row.get('client_name') or 'unknown'}"
    header += f" at={row.get('created_at') or 'unknown'}"
    if superseded_by is not None:
        header += f" (superseded by checkpoint #{superseded_by})"
    else:
        header += " (current)"
    lines = [header]
    lines.extend(render_checkpoint_reference_lines(row))
    lines.extend(render_intent_lines(row.get("intent_note")))
    return lines


def _render_checkpoint(row: dict) -> str:
    return "\n".join(render_checkpoint_lines(row))
