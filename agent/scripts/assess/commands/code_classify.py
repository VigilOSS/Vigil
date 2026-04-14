"""assess.py code-classify — bulk-classify code files by tier and role."""
from __future__ import annotations

from fnmatch import fnmatch
import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.schema_validation import load_schema

_CODE_FILE_LOOKUP_PAGE_SIZE = 10000
_ALLOWED_CLASSIFICATION_KEYS = frozenset(
    {
        "file_id",
        "file_path",
        "repo_id",
        "classification",
        "role",
        "slot_types",
        "language",
        "analysis_priority",
    }
)
_CLASSIFICATION_SCHEMA = load_schema("code-file-classification.schema.json")
_VALID_CLASSIFICATIONS = frozenset(
    _CLASSIFICATION_SCHEMA["properties"]["classification"]["enum"]
)
_VALID_SLOT_TYPES = frozenset(
    _CLASSIFICATION_SCHEMA["properties"]["slot_types"]["items"]["enum"]
)


def register(subparsers) -> None:
    p = subparsers.add_parser("code-classify", help="Bulk-classify code files for analysis prioritization")
    p.add_argument("classifications_json", help="Path to JSON file with array of classification objects")
    p.set_defaults(func=run)


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


_LOCAL_ONLY_FIELDS = frozenset({"file_path", "repo_id"})


def _strip_local_fields(payload: list[dict]) -> list[dict]:
    """Remove client-side lookup fields before sending to the backend."""
    result: list[dict] = []
    for item in payload:
        cleaned = {k: v for k, v in item.items() if k not in _LOCAL_ONLY_FIELDS}
        result.append(cleaned)
    return result


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


def _validate_classification_payload(payload: list[dict]) -> list[str]:
    errors: list[str] = []

    for i, item in enumerate(payload):
        if not isinstance(item, dict):
            errors.append(f"Item {i} is not a JSON object")
            continue

        unknown_keys = sorted(set(item) - _ALLOWED_CLASSIFICATION_KEYS)
        if unknown_keys:
            if "slot_types_json" in unknown_keys:
                errors.append(
                    f"Item {i} uses unsupported field 'slot_types_json'; use 'slot_types' instead"
                )
            else:
                errors.append(f"Item {i} has unsupported fields: {', '.join(unknown_keys)}")

        if 'file_id' not in item and 'file_path' not in item:
            errors.append(f"Item {i} missing required field 'file_id' or 'file_path'")

        classification = item.get("classification")
        if classification is None:
            errors.append(f"Item {i} missing required field 'classification'")
            continue
        if not isinstance(classification, str) or classification not in _VALID_CLASSIFICATIONS:
            errors.append(
                f"Item {i} classification must be one of: {', '.join(sorted(_VALID_CLASSIFICATIONS))}"
            )
            continue

        slot_types = item.get("slot_types", [])
        if slot_types is None:
            slot_types = []
        if not isinstance(slot_types, list):
            errors.append(f"Item {i} slot_types must be a JSON array")
            continue
        invalid_slots = [
            slot
            for slot in slot_types
            if not isinstance(slot, str) or slot not in _VALID_SLOT_TYPES
        ]
        if invalid_slots:
            invalid_display = ", ".join(repr(slot) for slot in invalid_slots)
            errors.append(
                f"Item {i} slot_types contains invalid values: {invalid_display}. "
                f"Allowed values: {', '.join(sorted(_VALID_SLOT_TYPES))}"
            )

        if classification in {"critical", "high"} and not slot_types:
            errors.append(f"Item {i} slot_types is required for {classification} classifications")

    return errors


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

    errors = _validate_classification_payload(payload)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    if any(item.get('file_id') in (None, "") for item in payload):
        normalized_payload = _normalize_classifications(payload, _fetch_code_files(cfg))
    else:
        normalized_payload = _strip_local_fields(payload)

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
