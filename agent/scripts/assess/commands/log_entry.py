"""assess.py log — lock + append markdown to log.md + emit event."""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.locking import file_lock


def register(subparsers) -> None:
    p = subparsers.add_parser("log", help="Append an entry to log.md")
    p.add_argument("eng_dir", nargs="?", default=None, help="Engagement dir (optional if resolvable)")
    p.add_argument("agent")
    p.add_argument("title")
    p.add_argument("action")
    p.add_argument("result")
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
    # Handle the 4-arg vs 5-arg calling convention
    eng_dir = args.eng_dir
    agent = args.agent
    title = args.title
    action = args.action
    result = args.result

    cfg = load_config(eng_dir)
    eng_dir = cfg.engagement_dir

    log_file = Path(eng_dir) / "log.md"
    if not log_file.is_file():
        print(f"log.md not found in {eng_dir}", file=sys.stderr)
        sys.exit(1)

    timestamp = time.strftime("%H:%M")
    short_title = _truncate(title, 80)
    short_action = _truncate(action, 240)
    short_result = _truncate(result, 360)

    lock_path = str(Path(eng_dir) / ".log.lock.d")
    with file_lock(lock_path, max_attempts=50, interval=0.1):
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"\n## [{timestamp}] {short_title} — {agent}\n")
            f.write(f"\n**Action**: {short_action}\n")
            f.write(f"**Result**: {short_result}\n")

    # Emit event (fire-and-forget)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        client.post_event({
            "event_type": "artifact.updated",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": "log.md",
            "agent_name": agent,
            "summary": short_title,
        })
    finally:
        client.close()
