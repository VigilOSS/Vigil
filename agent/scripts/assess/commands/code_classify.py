"""assess.py code-classify — bulk-classify code files by tier and role."""
from __future__ import annotations

from fnmatch import fnmatch
import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("code-classify", help="Bulk-classify code files for analysis prioritization")
    p.add_argument("classifications_json", help="Path to JSON file with array of classification objects")
    p.set_defaults(func=run)


def _fetch_code_files(cfg) -> list[dict]:
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.get('code/files?limit=5000')
    finally:
        client.close()
    if not isinstance(result, list):
        print("Could not fetch code files for path resolution", file=sys.stderr)
        sys.exit(1)
    return result


def _resolve_matching_file_ids(item: dict, code_files: list[dict]) -> list[int]:
    file_id = item.get('file_id')
    if file_id not in (None, ""):
        try:
            return [int(file_id)]
        except (TypeError, ValueError):
            print(f"Invalid file_id in classification item: {file_id!r}", file=sys.stderr)
            sys.exit(1)

    file_path = str(item.get('file_path', '')).strip()
    if not file_path:
        print("Classification item must include either 'file_id' or 'file_path'", file=sys.stderr)
        sys.exit(1)

    repo_id = item.get('repo_id')
    if repo_id not in (None, ""):
        try:
            repo_id = int(repo_id)
        except (TypeError, ValueError):
            print(f"Invalid repo_id in classification item: {repo_id!r}", file=sys.stderr)
            sys.exit(1)
    else:
        repo_id = None

    has_glob = any(ch in file_path for ch in "*?[")
    matches = []
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
        print(f"No code file found for classification path: {file_path}", file=sys.stderr)
        sys.exit(1)

    if not has_glob and len(matches) > 1:
        print(
            f"Ambiguous classification path {file_path!r}; include file_id or repo_id to disambiguate",
            file=sys.stderr,
        )
        sys.exit(1)

    return [int(row['id']) for row in matches]


def _normalize_classifications(payload: list[dict], code_files: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for item in payload:
        file_ids = _resolve_matching_file_ids(item, code_files)
        for file_id in file_ids:
            normalized_item = dict(item)
            normalized_item.pop('file_path', None)
            normalized_item.pop('repo_id', None)
            normalized_item['file_id'] = file_id
            normalized.append(normalized_item)
    return normalized


def run(args) -> None:
    json_path = Path(args.classifications_json)
    if not json_path.is_file():
        print(f"Classifications JSON file not found: {args.classifications_json}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        print("Classifications file must contain a JSON array", file=sys.stderr)
        sys.exit(1)

    if not payload:
        print("No classifications to submit.", file=sys.stderr)
        sys.exit(0)

    # Validate required fields
    for i, item in enumerate(payload):
        if not isinstance(item, dict):
            print(f"Item {i} is not a JSON object", file=sys.stderr)
            sys.exit(1)
        if 'file_id' not in item and 'file_path' not in item:
            print(f"Item {i} missing required field 'file_id' or 'file_path'", file=sys.stderr)
            sys.exit(1)
        if 'classification' not in item:
            print(f"Item {i} missing required field 'classification'", file=sys.stderr)
            sys.exit(1)

    cfg = load_config(args.engagement_dir)
    normalized_payload = payload
    if any(item.get('file_id') in (None, "") for item in payload):
        normalized_payload = _normalize_classifications(payload, _fetch_code_files(cfg))

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/files/bulk-classify', {'classifications': normalized_payload})
    finally:
        client.close()

    classified_count = result.get('updated', len(normalized_payload))

    # Compute tier breakdown
    tier_counts: dict[str, int] = {}
    for item in normalized_payload:
        tier = item.get('classification', 'unknown')
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    print(f"=== Code Classification Summary ===")
    print(f"Total classified: {classified_count}")
    print(f"\nBreakdown by tier:")
    for tier in sorted(tier_counts.keys()):
        print(f"  {tier}: {tier_counts[tier]}")
