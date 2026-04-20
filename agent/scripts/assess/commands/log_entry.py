"""assess.py log — append an activity entry to the backend.

Replaces the old ``log.md`` append path. POSTs to
``/engagements/{key}/activity-entries`` and emits an ``activity.recorded``
event. CLI shape is preserved for back-compat with existing agents:

    assess.py log <agent> <title> <action> <result>

An optional positional ``eng_dir`` is still accepted in the first slot —
older callers used that calling convention before ``--engagement-dir``
resolution was centralized. When five positional args are given, the first
is treated as the engagement dir; with four, it's the agent name.
"""
from __future__ import annotations

import os
import re
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "log",
        help="POST an activity log entry to the backend (replaces log.md append)",
    )
    # The eng_dir positional is optional for back-compat with the old 5-arg
    # calling convention `assess.py log <eng_dir> <agent> <title> <action> <result>`.
    p.add_argument("eng_dir", nargs="?", default=None, help="Engagement dir (optional if resolvable)")
    p.add_argument("agent")
    p.add_argument("title")
    p.add_argument("action")
    p.add_argument("result")
    p.add_argument(
        "--actor-kind",
        default="agent",
        choices=["operator", "agent", "hook", "system"],
        help="Actor kind — defaults to 'agent' since assess.py log is specialist-driven",
    )
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

    cfg = load_config(eng_dir)

    # Normalise length to match the backend pydantic caps (see
    # ActivityEntryRecordRequest: title ≤ 512, action/result ≤ 4096). We trim
    # to slightly under the caps so callers don't trip the 422 path for
    # prose-style input that's a few chars over.
    payload = {
        "actor_kind": args.actor_kind,
        "actor_name": agent,
        "title": _truncate(title, 480),
        "action": _truncate(action, 3800),
        "result": _truncate(result, 3800),
    }

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        try:
            client.post_engagement("activity-entries", payload)
        except Exception as exc:
            # activity.py is async-friendly but the CLI must never lose the
            # operator's log entry. Print the error and exit non-zero so
            # callers can retry; do NOT silently drop.
            print(f"assess.py log: failed to record activity entry: {exc}", file=sys.stderr)
            sys.exit(1)
    finally:
        client.close()

    # Emit event (fire-and-forget).
    event_client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        event_client.post_event(
            {
                "event_type": "activity.recorded",
                "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
                "task_name": "activity-entry",
                "agent_name": agent,
                "summary": payload["title"],
            }
        )
    finally:
        event_client.close()
