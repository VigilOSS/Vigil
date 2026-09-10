"""vigil assess log — append an activity entry to the backend.

Replaces the old ``log.md`` append path. POSTs to
``/engagements/{key}/activity-entries`` and emits an ``activity.recorded``
event. CLI shape is preserved for back-compat with existing agents:

    vigil assess log <agent> <title> <action> <result>

An optional positional ``eng_dir`` is still accepted in the first slot —
older callers used that calling convention before ``--engagement-dir``
resolution was centralized. When five positional args are given, the first
is treated as the engagement dir; with four, it's the agent name.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.config import load_config
from assess.lib.json_inputs import parse_json_argument, parse_optional_inline_json


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "log",
        help="POST an activity log entry to the backend (replaces log.md append)",
    )
    # The eng_dir positional is optional for back-compat with the old 5-arg
    # calling convention `vigil assess log <eng_dir> <agent> <title> <action> <result>`.
    p.add_argument("eng_dir", nargs="?", default=None, help="Engagement dir (optional if resolvable)")
    p.add_argument("agent")
    p.add_argument("title")
    p.add_argument("action")
    p.add_argument("result")
    p.add_argument(
        "--actor-kind",
        default=argparse.SUPPRESS,
        choices=["operator", "agent", "hook", "system"],
        help=(
            "Actor kind — defaults to 'agent' since vigil assess log is "
            "specialist-driven. Also accepted before the subcommand as "
            "`vigil assess --actor-kind operator log ...`."
        ),
    )
    p.add_argument("--metadata-inline", help="Inline JSON object stored on activity_entries.metadata")
    p.add_argument("--metadata-file", help="Path to a JSON object stored on activity_entries.metadata")
    p.set_defaults(func=run)


def _trim(text: str) -> str:
    text = text.replace("\r", " ").replace("\n", " ")
    return re.sub(r"\s+", " ", text).strip()


def _truncate(text: str, max_len: int) -> str:
    text = _trim(text)
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def run(args) -> None:
    eng_dir = args.eng_dir
    agent = args.agent
    title = args.title
    action = args.action
    result = args.result

    metadata_inline = getattr(args, "metadata_inline", None)
    metadata_file = getattr(args, "metadata_file", None)
    if metadata_inline and metadata_file:
        print("pass only one of --metadata-inline or --metadata-file", file=sys.stderr)
        sys.exit(1)
    try:
        if metadata_file:
            metadata, _ = parse_json_argument(
                metadata_file,
                inline=False,
                description="activity metadata JSON",
            )
        else:
            metadata = parse_optional_inline_json(
                metadata_inline,
                default=None,
                description="activity metadata JSON",
            )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if metadata is not None and not isinstance(metadata, dict):
        print("activity metadata JSON must be an object", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(eng_dir)

    # Normalise length to match the backend pydantic caps (see
    # ActivityEntryRecordRequest: title ≤ 512, action/result ≤ 4096). We trim
    # to slightly under the caps so callers don't trip the 422 path for
    # prose-style input that's a few chars over.
    payload = {
        "actor_kind": getattr(args, "actor_kind", None) or "agent",
        "actor_name": agent,
        "title": _truncate(title, 480),
        "action": _truncate(action, 3800),
        "result": _truncate(result, 3800),
    }
    if metadata is not None:
        payload["metadata"] = metadata

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        try:
            require_write_result(
                client.post_engagement("activity-entries", payload),
                operation="record activity entry",
                expected={
                    "actor_kind": payload["actor_kind"],
                    "actor_name": payload["actor_name"],
                    "title": payload["title"],
                },
                positive_ids=("id",),
            )
        except Exception as exc:
            # activity.py is async-friendly but the CLI must never lose the
            # operator's log entry. Print the error and exit non-zero; an
            # unreadable acknowledgement may already be durable, so its
            # diagnostic directs callers to inspect instead of retrying.
            print(f"vigil assess log: failed to record activity entry: {exc}", file=sys.stderr)
            sys.exit(1)

    # Emit event (fire-and-forget).
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as event_client:
        event_client.post_event(
            {
                "event_type": "activity.recorded",
                "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
                "task_name": "activity-entry",
                "agent_name": agent,
                "summary": payload["title"],
            }
        )
