"""assess.py code-dispatch — analysis queue dispatch engine for the code analysis pipeline."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("code-dispatch", help="Code analysis queue dispatch engine")
    p.add_argument("action", help="stats|fetch|done|error|needs-context|reset-stale|queue")
    p.add_argument("extra", nargs="*", help="Action-specific arguments")
    p.set_defaults(func=run)


def run(args) -> None:
    action = args.action
    extra = args.extra or []

    cfg = load_config(args.engagement_dir)

    if action == "stats":
        _stats(cfg)
    elif action == "fetch":
        if len(extra) < 2:
            print("Usage: code-dispatch fetch <limit> <agent-name>", file=sys.stderr)
            sys.exit(1)
        _fetch(cfg, int(extra[0]), extra[1])
    elif action == "done":
        if len(extra) < 2:
            print("Usage: code-dispatch done <id1,id2,...> <disposition> [notes]", file=sys.stderr)
            sys.exit(1)
        notes = extra[2] if len(extra) > 2 else ""
        _done(cfg, extra[0], extra[1], notes)
    elif action == "error":
        if not extra:
            print("Usage: code-dispatch error <id1,id2,...> [notes]", file=sys.stderr)
            sys.exit(1)
        notes = extra[1] if len(extra) > 1 else ""
        _error(cfg, extra[0], notes)
    elif action == "needs-context":
        if not extra:
            print("Usage: code-dispatch needs-context <id1,id2,...> [expansion-json-file]", file=sys.stderr)
            sys.exit(1)
        expansion_file = extra[1] if len(extra) > 1 else None
        _needs_context(cfg, extra[0], expansion_file)
    elif action == "reset-stale":
        if not extra:
            print("Usage: code-dispatch reset-stale <minutes>", file=sys.stderr)
            sys.exit(1)
        _reset_stale(cfg, int(extra[0]))
    elif action == "queue":
        if not extra:
            print("Usage: code-dispatch queue <queue-items-json-file>", file=sys.stderr)
            sys.exit(1)
        _queue(cfg, extra[0])
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        print("Actions: stats, fetch, done, error, needs-context, reset-stale, queue", file=sys.stderr)
        sys.exit(1)


def _validate_id_list(id_list: str) -> list[int]:
    """Validate and parse comma-separated ID list."""
    import re
    if not re.match(r"^[0-9,]+$", id_list):
        print("ERROR: id_list must contain only numeric IDs separated by commas", file=sys.stderr)
        sys.exit(1)
    return [int(x) for x in id_list.split(",") if x]


def _stats(cfg) -> None:
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.get('code/analysis-queue/stats')
    finally:
        client.close()

    if isinstance(result, dict):
        print("=== Code Analysis Queue Stats ===")
        for key in ('pending', 'processing', 'done', 'error', 'needs_context'):
            val = result.get(key, 0)
            print(f"  {key}: {val}")
        total = sum(result.get(k, 0) for k in ('pending', 'processing', 'done', 'error', 'needs_context'))
        print(f"  total: {total}")
        # Print any extra fields
        for key, val in result.items():
            if key not in ('pending', 'processing', 'done', 'error', 'needs_context'):
                print(f"  {key}: {val}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _fetch(cfg, limit: int, agent_name: str) -> None:
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue/fetch', {
            'limit': limit,
            'agent_name': agent_name,
        })
    finally:
        client.close()

    print(json.dumps(result, indent=2, ensure_ascii=False))


def _done(cfg, id_list: str, disposition: str, notes: str = "") -> None:
    ids = _validate_id_list(id_list)
    payload: dict = {'item_ids': ids, 'disposition': disposition}
    if notes:
        payload['notes'] = notes
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue/done', payload)
    finally:
        client.close()

    updated = result.get('updated', 0) if isinstance(result, dict) else result
    print(f"Marked done ({disposition}): {updated} item(s)")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _error(cfg, id_list: str, notes: str = "") -> None:
    ids = _validate_id_list(id_list)
    payload: dict = {'item_ids': ids}
    if notes:
        payload['notes'] = notes
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue/error', payload)
    finally:
        client.close()

    updated = result.get('updated', 0) if isinstance(result, dict) else result
    print(f"Marked error: {updated} item(s)")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _needs_context(cfg, id_list: str, expansion_file: str | None) -> None:
    ids = _validate_id_list(id_list)

    payload: dict = {'item_ids': ids}
    if expansion_file:
        ep = Path(expansion_file)
        if not ep.is_file():
            print(f"Expansion JSON file not found: {expansion_file}", file=sys.stderr)
            sys.exit(1)
        expansion = json.loads(ep.read_text(encoding="utf-8"))
        payload['expansion_request'] = expansion

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue/needs-context', payload)
    finally:
        client.close()

    print(f"Marked needs-context: {id_list}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _reset_stale(cfg, minutes: int) -> None:
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue/reset-stale', {'minutes': minutes})
    finally:
        client.close()

    reset_count = result.get('reset', 0) if isinstance(result, dict) else 0
    print(f"Reset {reset_count} stale item(s) (stuck > {minutes} min)")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _queue(cfg, queue_items_file: str) -> None:
    fp = Path(queue_items_file)
    if not fp.is_file():
        print(f"Queue items JSON file not found: {queue_items_file}", file=sys.stderr)
        sys.exit(1)

    items = json.loads(fp.read_text(encoding="utf-8"))
    if isinstance(items, dict):
        # Single item wrapped
        items = [items]
    if not isinstance(items, list):
        print("Queue items file must contain a JSON array or object", file=sys.stderr)
        sys.exit(1)

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue', {'items': items})
    finally:
        client.close()

    queued_count = result.get('queued', len(items)) if isinstance(result, dict) else len(items)
    print(f"Queued {queued_count} analysis item(s)")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))
