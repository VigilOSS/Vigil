"""assess.py code-dispatch — analysis queue dispatch engine for the code analysis pipeline."""
from __future__ import annotations

from fnmatch import fnmatch
import json
import sys
from pathlib import Path

from assess.lib.code_audit import write_json_snapshot
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config

_CODE_FILE_LOOKUP_PAGE_SIZE = 10000
_DONE_DISPOSITIONS = ("clean", "finding", "suspicious")


def register(subparsers) -> None:
    p = subparsers.add_parser("code-dispatch", help="Code analysis queue dispatch engine")
    p.add_argument(
        "action",
        help="stats|fetch|done|error|needs-context|reset-stale|queue|requeue-triggers",
    )
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
        if len(extra) < 3:
            print(
                "Usage: code-dispatch done <item-id> <disposition> <cwe-coverage-json-file> [notes] [--dry-run]\n"
                f"Valid dispositions: {', '.join(_DONE_DISPOSITIONS)}\n"
                "CWE coverage must be a JSON array like "
                "[{\"family\":\"ssrf\",\"effort\":80}]",
                file=sys.stderr,
            )
            sys.exit(1)
        notes_parts: list[str] = []
        dry_run = False
        for token in extra[3:]:
            if token == "--dry-run":
                dry_run = True
            else:
                notes_parts.append(token)
        notes = " ".join(notes_parts)
        _done(cfg, extra[0], extra[1], extra[2], notes, dry_run=dry_run)
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
    elif action == "requeue-triggers":
        if not extra:
            print("Usage: code-dispatch requeue-triggers <triggers-json-file>", file=sys.stderr)
            sys.exit(1)
        _requeue_triggers(cfg, extra[0])
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        print(
            "Actions: stats, fetch, done, error, needs-context, reset-stale, queue, requeue-triggers",
            file=sys.stderr,
        )
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

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-fetch",
        label=agent_name,
        payload=result,
        metadata={"command": "code-dispatch fetch", "agent_name": agent_name, "limit": limit},
    )
    print(f"Saved audit snapshot: {snapshot.name}", file=sys.stderr)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _done(
    cfg,
    id_list: str,
    disposition: str,
    cwe_file: str,
    notes: str = "",
    *,
    dry_run: bool = False,
) -> None:
    ids = _validate_id_list(id_list)
    if len(ids) != 1:
        print("ERROR: code-dispatch done accepts exactly one queue item id", file=sys.stderr)
        sys.exit(1)
    normalized_disposition = disposition.strip().lower()
    if normalized_disposition not in _DONE_DISPOSITIONS:
        print(
            f"ERROR: invalid disposition {disposition!r}; expected one of: {', '.join(_DONE_DISPOSITIONS)}",
            file=sys.stderr,
        )
        sys.exit(1)

    cwe_path = Path(cwe_file)
    if not cwe_path.is_file():
        print(f"CWE coverage JSON file not found: {cwe_file}", file=sys.stderr)
        sys.exit(1)
    cwe_data = json.loads(cwe_path.read_text(encoding="utf-8"))
    if not isinstance(cwe_data, list):
        print("CWE coverage payload must be a JSON array", file=sys.stderr)
        sys.exit(1)
    for idx, entry in enumerate(cwe_data):
        if not isinstance(entry, dict):
            print(f"CWE coverage entry {idx} must be a JSON object", file=sys.stderr)
            sys.exit(1)
        family = str(entry.get("family", "")).strip()
        if not family:
            print(
                f"CWE coverage entry {idx} is missing family; expected entries like "
                "{\"family\":\"ssrf\",\"effort\":80}",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            float(entry.get("effort", 0))
        except (TypeError, ValueError):
            print(f"CWE coverage entry {idx} has a non-numeric effort", file=sys.stderr)
            sys.exit(1)

    payload: dict = {'item_ids': ids, 'disposition': normalized_disposition}
    if notes:
        payload['notes'] = notes
    payload['cwe_coverage'] = cwe_data
    if dry_run:
        print("Dry run only; no queue state was changed.")
        print(json.dumps({"endpoint": "code/analysis-queue/done", "payload": payload}, indent=2, ensure_ascii=False))
        return
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue/done', payload)
    finally:
        client.close()

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-done",
        label=normalized_disposition,
        payload=result,
        metadata={"command": "code-dispatch done", "item_ids": ids, "disposition": normalized_disposition},
    )
    updated = result.get('updated', 0) if isinstance(result, dict) else result
    print(f"Marked done ({normalized_disposition}): {updated} item(s)")
    print(f"Saved audit snapshot: {snapshot.name}")
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

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-error",
        label="items",
        payload=result,
        metadata={"command": "code-dispatch error", "item_ids": ids},
    )
    updated = result.get('updated', 0) if isinstance(result, dict) else result
    print(f"Marked error: {updated} item(s)")
    print(f"Saved audit snapshot: {snapshot.name}")
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

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-needs-context",
        label="items",
        payload={"request": payload, "response": result},
        source_path=expansion_file,
        metadata={"command": "code-dispatch needs-context", "item_ids": ids},
    )
    print(f"Marked needs-context: {id_list}")
    print(f"Saved audit snapshot: {snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _reset_stale(cfg, minutes: int) -> None:
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue/reset-stale', {'minutes': minutes})
    finally:
        client.close()

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-reset-stale",
        label=f"{minutes}m",
        payload=result,
        metadata={"command": "code-dispatch reset-stale", "minutes": minutes},
    )
    reset_count = result.get('reset', 0) if isinstance(result, dict) else 0
    print(f"Reset {reset_count} stale item(s) (stuck > {minutes} min)")
    print(f"Saved audit snapshot: {snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _fetch_code_files(cfg) -> list[dict]:
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        rows: list[dict] = []
        offset = 0
        while True:
            page = client.get(f'code/files?limit={_CODE_FILE_LOOKUP_PAGE_SIZE}&offset={offset}')
            if not isinstance(page, list):
                result = page
                break
            rows.extend(page)
            if len(page) < _CODE_FILE_LOOKUP_PAGE_SIZE:
                result = rows
                break
            offset += _CODE_FILE_LOOKUP_PAGE_SIZE
    finally:
        client.close()
    if not isinstance(result, list):
        print("Could not fetch code files for queue normalization", file=sys.stderr)
        sys.exit(1)
    return result


def _normalize_string_list(value) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if item in (None, ""):
                continue
            if isinstance(item, str):
                result.append(item)
            else:
                result.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
        return result
    if isinstance(value, str):
        return [value]
    return [json.dumps(value, ensure_ascii=False, sort_keys=True)]


def _flatten_queue_specs(item, inherited: dict | None = None) -> list[dict]:
    if not isinstance(item, dict):
        print("Queue items must be JSON objects", file=sys.stderr)
        sys.exit(1)

    inherited_fields = dict(inherited or {})
    for key in ('priority', 'batch_theme', 'slot_types', 'guidance_hypotheses', 'repo_id'):
        if key in item and item[key] not in (None, ""):
            inherited_fields[key] = item[key]

    for collection_key in ('items', 'batches'):
        if collection_key in item:
            collection = item.get(collection_key)
            if not isinstance(collection, list):
                print(f"Queue field '{collection_key}' must be a JSON array", file=sys.stderr)
                sys.exit(1)
            flattened: list[dict] = []
            for child in collection:
                flattened.extend(_flatten_queue_specs(child, inherited_fields))
            return flattened

    if 'files' in item:
        collection = item.get('files')
        if not isinstance(collection, list):
            print("Queue field 'files' must be a JSON array", file=sys.stderr)
            sys.exit(1)
        flattened = []
        for child in collection:
            if isinstance(child, str):
                child_item = {'file_path': child}
            elif isinstance(child, dict):
                child_item = child
            else:
                print("Queue 'files' entries must be strings or JSON objects", file=sys.stderr)
                sys.exit(1)
            flattened.extend(_flatten_queue_specs(child_item, inherited_fields))
        return flattened

    if 'file_paths' in item:
        collection = item.get('file_paths')
        if not isinstance(collection, list):
            print("Queue field 'file_paths' must be a JSON array", file=sys.stderr)
            sys.exit(1)
        flattened = []
        for file_path in collection:
            flattened.extend(_flatten_queue_specs({'file_path': file_path}, inherited_fields))
        return flattened

    if 'path' in item and 'file_path' not in item:
        item = dict(item)
        item['file_path'] = item.pop('path')
    if 'glob' in item and 'file_path' not in item:
        item = dict(item)
        item['file_path'] = item.pop('glob')

    if 'file_id' in item or 'file_path' in item:
        leaf = dict(inherited_fields)
        leaf.update(item)
        return [leaf]

    print("Queue item is missing file_id/file_path or a supported batch wrapper", file=sys.stderr)
    sys.exit(1)


def _resolve_queue_file_ids(item: dict, code_files: list[dict]) -> list[int]:
    file_id = item.get('file_id')
    if file_id not in (None, ""):
        try:
            return [int(file_id)]
        except (TypeError, ValueError):
            print(f"Invalid queue file_id: {file_id!r}", file=sys.stderr)
            sys.exit(1)

    file_path = str(item.get('file_path', '')).strip()
    if not file_path:
        print("Queue item must include file_id or file_path", file=sys.stderr)
        sys.exit(1)

    repo_id = item.get('repo_id')
    if repo_id not in (None, ""):
        try:
            repo_id = int(repo_id)
        except (TypeError, ValueError):
            print(f"Invalid queue repo_id: {repo_id!r}", file=sys.stderr)
            sys.exit(1)
    else:
        repo_id = None

    has_glob = any(ch in file_path for ch in "*?[")
    matches: list[dict] = []
    for row in code_files:
        candidate = str(row.get('file_path', ''))
        if has_glob:
            if fnmatch(candidate, file_path):
                matches.append(row)
        elif candidate == file_path:
            matches.append(row)

    if repo_id is not None:
        matches = [row for row in matches if int(row.get('repo_id', -1)) == repo_id]

    if not matches:
        print(f"No code file found for queue path: {file_path}", file=sys.stderr)
        sys.exit(1)

    if not has_glob and len(matches) > 1:
        print(
            f"Ambiguous queue path {file_path!r}; include file_id or repo_id to disambiguate",
            file=sys.stderr,
        )
        sys.exit(1)

    return [int(row['id']) for row in matches]


def _normalize_queue_items(cfg, raw_items: list[dict]) -> list[dict]:
    flattened: list[dict] = []
    for item in raw_items:
        flattened.extend(_flatten_queue_specs(item))

    needs_lookup = any(entry.get('file_id') in (None, "") for entry in flattened)
    code_files = _fetch_code_files(cfg) if needs_lookup else []

    normalized: list[dict] = []
    seen: set[str] = set()
    for entry in flattened:
        if entry.get('context_id') not in (None, ""):
            print(
                "Queue item includes obsolete field `context_id`. "
                "The hunt queue is file-level only and carries file_id plus metadata such as "
                "batch_theme, slot_types, guidance_hypotheses, and structural-index context.",
                file=sys.stderr,
            )
            sys.exit(1)

        file_ids = _resolve_queue_file_ids(entry, code_files)
        for file_id in file_ids:
            normalized_item: dict = {
                'file_id': file_id,
                'priority': max(0, min(100, int(entry.get('priority', 50)))),
                'batch_theme': str(entry.get('batch_theme', '')),
                'slot_types': _normalize_string_list(entry.get('slot_types')),
                'guidance_hypotheses': _normalize_string_list(entry.get('guidance_hypotheses')),
            }

            dedupe_key = json.dumps(normalized_item, sort_keys=True, ensure_ascii=False)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            normalized.append(normalized_item)

    return normalized


def _queue(cfg, queue_items_file: str) -> None:
    """Queue analysis items. Items can include batch_theme, slot_types, and
    guidance_hypotheses fields alongside the existing format — those are
    passed through as-is to the backend."""
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

    normalized_items = _normalize_queue_items(cfg, items)

    submit_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-submit",
        label=fp.stem,
        payload={"input": items, "normalized": normalized_items},
        source_path=str(fp),
        metadata={"command": "code-dispatch queue", "count": len(normalized_items)},
    )
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue', {'items': normalized_items})
    finally:
        client.close()

    response_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-response",
        label=fp.stem,
        payload=result,
        source_path=str(submit_snapshot),
        metadata={"command": "code-dispatch queue", "count": len(normalized_items)},
    )
    inserted_count = result.get('inserted', len(normalized_items)) if isinstance(result, dict) else len(normalized_items)
    print(f"Queued {inserted_count} analysis item(s)")
    print(f"Audit snapshots: {submit_snapshot.name}, {response_snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _requeue_triggers(cfg, triggers_file: str) -> None:
    """Requeue cross-file triggers as new analysis queue items.

    Reads a JSON file containing a cross_file_triggers array (as produced in
    analysis results) and reformats each trigger as a queue item with the
    triggering finding context, then posts to code/analysis-queue.
    """
    fp = Path(triggers_file)
    if not fp.is_file():
        print(f"Triggers JSON file not found: {triggers_file}", file=sys.stderr)
        sys.exit(1)

    raw = json.loads(fp.read_text(encoding="utf-8"))

    # Accept either a bare array or an object with a cross_file_triggers key
    if isinstance(raw, dict):
        triggers = raw.get('cross_file_triggers', [])
    elif isinstance(raw, list):
        triggers = raw
    else:
        print("Triggers file must contain a JSON array or object", file=sys.stderr)
        sys.exit(1)

    if not triggers:
        print("No triggers to requeue.")
        return

    # Convert triggers to queue items
    items = []
    for trigger in triggers:
        item: dict = {
            'file_path': trigger.get('file_path', ''),
            'reason': trigger.get('reason', ''),
            'trigger_context': {
                'vuln_class': trigger.get('vuln_class', ''),
                'source': 'cross_file_trigger',
            },
        }
        passthrough_fields = {
            'file_id',
            'repo_id',
            'priority',
            'batch_theme',
            'slot_types',
            'guidance_hypotheses',
        }
        # Pass through any extra fields from the trigger
        for key in trigger:
            if key in passthrough_fields:
                item[key] = trigger[key]
            elif key not in ('file_path', 'reason', 'vuln_class'):
                item['trigger_context'][key] = trigger[key]
        items.append(item)

    submit_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-requeue-triggers",
        label=fp.stem,
        payload=items,
        source_path=str(fp),
        metadata={"command": "code-dispatch requeue-triggers", "count": len(items)},
    )
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/analysis-queue/requeue', {'items': items})
    finally:
        client.close()

    response_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-requeue-response",
        label=fp.stem,
        payload=result,
        source_path=str(submit_snapshot),
        metadata={"command": "code-dispatch requeue-triggers", "count": len(items)},
    )
    inserted_count = result.get('inserted', len(items)) if isinstance(result, dict) else len(items)
    print(f"Requeued {inserted_count} trigger item(s)")
    if isinstance(result, dict):
        not_found = result.get("not_found") or []
        ambiguous = result.get("ambiguous") or []
        if not_found:
            print(f"Not found: {', '.join(str(item) for item in not_found)}")
        if ambiguous:
            print(f"Ambiguous without repo_id: {', '.join(str(item) for item in ambiguous)}")
    print(f"Audit snapshots: {submit_snapshot.name}, {response_snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))
