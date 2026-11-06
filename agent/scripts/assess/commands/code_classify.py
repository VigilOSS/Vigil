"""vigil assess code-record classify — bulk-classify code files by tier and role."""
from __future__ import annotations

from fnmatch import fnmatch
import json
import sys
from pathlib import Path

from assess.lib.bulk_ingest import DEFAULT_BULK_WRITE_SIZE
from assess.lib.client import (
    DEFAULT_READ_TIMEOUT_SECONDS,
    AssessmentClient,
    AssessError,
    require_write_result,
)
from assess.lib.code_languages import CANONICAL_CODE_LANGUAGES, CODE_LANGUAGE_ALIASES
from assess.lib.code_structural_identity import parse_code_file_page
from assess.lib.config import load_config
from assess.lib.contracts import CODE_SKIP_REASONS
from assess.lib.schema_validation import load_schema

_CODE_FILE_LOOKUP_PAGE_SIZE = 10000
# One classification row re-derives the file's required vuln families, resyncs
# its queue priority and can invalidate the repo's structural binding, so a
# full chunk cannot be held to the 10s default response budget.
_BULK_CLASSIFY_SECONDS_PER_FILE = 0.1
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
        "skip_reason",
    }
)
_CLASSIFICATION_SCHEMA = load_schema("code-file-classification.schema.json")
_VALID_CLASSIFICATIONS = frozenset(
    _CLASSIFICATION_SCHEMA["properties"]["classification"]["enum"]
)
_VALID_SLOT_TYPES = frozenset(
    _CLASSIFICATION_SCHEMA["properties"]["slot_types"]["items"]["enum"]
)
# The skip vocabulary is the backend's. Prefer the generated schema when it
# declares the enum, and otherwise the one agent-side mirror both skip doors
# already share — never a third copy of the list in this file.
_VALID_SKIP_REASONS = frozenset(
    _CLASSIFICATION_SCHEMA["properties"].get("skip_reason", {}).get("enum")
    or CODE_SKIP_REASONS
)
_CLASSIFICATION_PRIORITY_BANDS = {
    tier: (int(bounds[0]), int(bounds[1]))
    for tier, bounds in _CLASSIFICATION_SCHEMA[
        "x-classification-priority-bands"
    ].items()
}


def register(subparsers) -> None:
    p = subparsers.add_parser("classify", help="Bulk-classify code files for analysis prioritization")
    p.add_argument("classifications_json", help="Path to JSON file with array of classification objects")
    p.set_defaults(func=run)


def _fetch_code_files(cfg) -> list[dict]:
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        rows: list[dict] = []
        offset = 0
        expected_total: int | None = None
        while True:
            page = client.get(f'code/files?limit={_CODE_FILE_LOOKUP_PAGE_SIZE}&offset={offset}')
            try:
                items, total, has_more = parse_code_file_page(
                    page,
                    expected_offset=offset,
                    context="code file lookup response",
                )
            except ValueError:
                result = None
                break
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                result = None
                break
            rows.extend(items)
            if not has_more:
                result = rows
                break
            offset += len(items)
    if result is None:
        print("Could not fetch code files for path resolution", file=sys.stderr)
        sys.exit(1)
    return result


def _resolve_matching_file_ids(item: dict, code_files: list[dict]) -> list[int]:
    file_id = item.get('file_id')
    if file_id not in (None, ""):
        if type(file_id) is not int or file_id <= 0:
            print(f"Invalid file_id in classification item: {file_id!r}", file=sys.stderr)
            sys.exit(1)
        return [file_id]

    file_path = str(item.get('file_path', '')).strip()
    if not file_path:
        print("Classification item must include either 'file_id' or 'file_path'", file=sys.stderr)
        sys.exit(1)

    repo_id = item.get('repo_id')
    if repo_id not in (None, ""):
        if type(repo_id) is not int or repo_id <= 0:
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


def _canonical_language(value: object) -> object:
    """Fold documented aliases and casing to the parser-canonical language.

    The backend treats a `language` that differs from the stored one as proof
    that the repo's parser-derived facts are invalid. Restating the SAME
    language as `c++` or `TypeScript` must therefore not read as a change.
    An unrecognized label is passed through untouched: the backend, not this
    command, is authoritative over what a classification may name.
    """
    if not isinstance(value, str):
        return value
    trimmed = value.strip()
    if not trimmed:
        return trimmed
    lowered = trimmed.lower()
    candidate = CODE_LANGUAGE_ALIASES.get(lowered, lowered)
    return candidate if candidate in CANONICAL_CODE_LANGUAGES else trimmed


def _strip_local_fields(payload: list[dict]) -> list[dict]:
    """Remove client-side lookup fields before sending to the backend."""
    result: list[dict] = []
    for item in payload:
        cleaned = {k: v for k, v in item.items() if k not in _LOCAL_ONLY_FIELDS}
        if 'language' in cleaned:
            cleaned['language'] = _canonical_language(cleaned['language'])
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
            if 'language' in normalized_item:
                normalized_item['language'] = _canonical_language(
                    normalized_item['language']
                )
            normalized.append(normalized_item)
    return normalized


def _allowed_skip_reasons_text() -> str:
    return (
        f", one of: {', '.join(sorted(_VALID_SKIP_REASONS))}"
        if _VALID_SKIP_REASONS
        else ""
    )


def _skip_reason_errors(index: int, item: dict, classification: str) -> list[str]:
    """Hold a classify-time skip to the same standard the close path holds.

    `code-dispatch done skipped` has always demanded a standard reason, and
    coverage only counts a skip that carries one. Classifying a file as `skip`
    is the same decision made earlier, so an unexplained one is the same
    unaccounted file — recorded, uncounted, and with nothing to say why.
    """
    raw = item.get("skip_reason")
    if classification != "skip":
        if raw not in (None, ""):
            return [
                f"Item {index} sets skip_reason on a {classification} "
                "classification; skip_reason only describes classification='skip'"
            ]
        return []
    reason = raw.strip() if isinstance(raw, str) else ""
    if not reason:
        return [
            f"Item {index} classification 'skip' requires skip_reason"
            f"{_allowed_skip_reasons_text()}"
        ]
    if _VALID_SKIP_REASONS and reason not in _VALID_SKIP_REASONS:
        return [
            f"Item {index} skip_reason {reason!r} is not a standard skip reason"
            f"{_allowed_skip_reasons_text()}"
        ]
    return []


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

        errors.extend(_skip_reason_errors(i, item, classification))

        if "analysis_priority" not in item:
            errors.append(f"Item {i} missing required field 'analysis_priority'")
            continue
        priority = item["analysis_priority"]
        if type(priority) is not int:
            errors.append(f"Item {i} analysis_priority must be an integer")
            continue
        minimum, maximum = _CLASSIFICATION_PRIORITY_BANDS[classification]
        if not minimum <= priority <= maximum:
            expected = str(minimum) if minimum == maximum else f"between {minimum} and {maximum}"
            errors.append(
                f"Item {i} analysis_priority must be {expected} for {classification} classification"
            )

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

    seen_file_ids: set[int] = set()
    for index, item in enumerate(normalized_payload):
        file_id = _resolve_matching_file_ids(item, [])[0]
        if file_id in seen_file_ids:
            print(
                f"Item {index} repeats file_id {file_id}: classification request "
                "contains duplicate file IDs; submit one classification per file",
                file=sys.stderr,
            )
            sys.exit(1)
        seen_file_ids.add(file_id)

    # A whole classification pass is one array in the operator's file but it is
    # not one write: every sibling bulk assessment write caps and chunks, and an
    # unchunked 28k-file POST is one BEGIN IMMEDIATE transaction answered inside
    # the 10s default — on timeout the operator cannot tell whether it committed.
    classified_count = 0
    committed_chunks = 0
    invalidated_repo_ids: list[int] = []
    language_changes: list[dict] = []
    chunk_starts = range(0, len(normalized_payload), DEFAULT_BULK_WRITE_SIZE)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for start in chunk_starts:
            chunk = normalized_payload[start : start + DEFAULT_BULK_WRITE_SIZE]
            chunk_timeout = _BULK_CLASSIFY_SECONDS_PER_FILE * len(chunk)
            try:
                result = client.post(
                    'code/files/bulk-classify',
                    {'classifications': chunk},
                    **(
                        {"read_timeout": chunk_timeout}
                        if chunk_timeout > DEFAULT_READ_TIMEOUT_SECONDS
                        else {}
                    ),
                )
                result = require_write_result(
                    result,
                    operation="classify code files",
                    expected={"total": len(chunk)},
                    nonnegative_counts=("updated",),
                )
                if result['updated'] > len(chunk):
                    raise AssessError(
                        "classify code files: backend response reported more updated rows "
                        "than were submitted; the write may have committed, so inspect "
                        "durable state and do not retry automatically"
                    )
            except AssessError:
                # Every chunk before this one is its own committed transaction,
                # and the accumulated count used to die with the exception —
                # leaving the operator to re-submit the whole file, which
                # re-applies the durable prefix. The invalidation those chunks
                # reported is just as durable, so its repair command has to be
                # printed here too and not only after a completed pass.
                _report_partial_commit(
                    committed_chunks=committed_chunks,
                    total_chunks=len(chunk_starts),
                    classified_count=classified_count,
                    failed_start=start,
                    failed_length=len(chunk),
                    submitted_total=len(normalized_payload),
                    authored_total=len(payload),
                )
                _warn_on_structural_invalidation(
                    {
                        "structural_index_invalidated_repo_ids": invalidated_repo_ids,
                        "language_changes": language_changes,
                    }
                )
                raise
            classified_count += result['updated']
            committed_chunks += 1
            repo_ids, changes = _structural_invalidation(result)
            for repo_id in repo_ids:
                if repo_id not in invalidated_repo_ids:
                    invalidated_repo_ids.append(repo_id)
            language_changes.extend(changes)

    tier_counts: dict[str, int] = {}
    for item in normalized_payload:
        tier = item.get('classification', 'unknown')
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    print("=== Code Classification Summary ===")
    print(f"Total classified: {classified_count}")
    print("\nBreakdown by tier:")
    for tier in sorted(tier_counts.keys()):
        print(f"  {tier}: {tier_counts[tier]}")

    _warn_on_structural_invalidation(
        {
            "structural_index_invalidated_repo_ids": invalidated_repo_ids,
            "language_changes": language_changes,
        }
    )


def _report_partial_commit(
    *,
    committed_chunks: int,
    total_chunks: int,
    classified_count: int,
    failed_start: int,
    failed_length: int,
    submitted_total: int,
    authored_total: int,
) -> None:
    """Say how far a pass got when one of its chunks failed.

    A pass is one array in the operator's file and one committed transaction
    per chunk, so a failure partway leaves a durable prefix with nothing in the
    output to say where it ends. The failing chunk's own fate is NOT decided
    here: the refusal that follows this report owns that claim.
    """
    failed_end = failed_start + failed_length - 1
    print(
        f"\nWARNING: this classification pass stopped partway: {committed_chunks} of "
        f"{total_chunks} chunk(s) committed ({classified_count} row(s) classified).",
        file=sys.stderr,
    )
    print(
        f"  failing chunk: items {failed_start}-{failed_end}; the error below says "
        "whether its own rows may have landed.",
        file=sys.stderr,
    )
    if failed_end + 1 < submitted_total:
        print(
            f"  not sent: items {failed_end + 1}-{submitted_total - 1}.",
            file=sys.stderr,
        )
    if failed_start:
        print(
            f"  items 0-{failed_start - 1} are committed, so re-submitting this whole "
            f"file would re-apply them; re-submit from item {failed_start} once the "
            "cause is fixed.",
            file=sys.stderr,
        )
    if authored_total != submitted_total:
        print(
            f"  these indexes are into the {submitted_total} classification(s) sent "
            f"after file_path resolution, not the {authored_total} item(s) in the file.",
            file=sys.stderr,
        )


def _structural_invalidation(result: object) -> tuple[list[int], list[dict]]:
    """Pull one chunk's invalidation report out of its write response."""
    if not isinstance(result, dict):
        return [], []
    raw_repo_ids = result.get('structural_index_invalidated_repo_ids')
    repo_ids = (
        [repo_id for repo_id in raw_repo_ids if type(repo_id) is int]
        if isinstance(raw_repo_ids, list)
        else []
    )
    raw_changes = result.get('language_changes')
    changes = (
        [change for change in raw_changes if isinstance(change, dict)]
        if isinstance(raw_changes, list)
        else []
    )
    return repo_ids, changes


def _warn_on_structural_invalidation(result: object) -> None:
    """Say so when a classification changed a repo's structural-index binding.

    A `language` that names a different parser genuinely invalidates
    tree-sitter-derived facts, and the backend acts on that. Until now this
    failed silently: one restated language on one file out of hundreds could
    leave a repo undispatchable with nothing in the classify output to say so.
    """
    if not isinstance(result, dict):
        return
    repo_ids = result.get('structural_index_invalidated_repo_ids')
    if not isinstance(repo_ids, list) or not repo_ids:
        return
    print(
        "\nWARNING: a language change in this batch invalidated the structural-index "
        f"binding for repo(s): {', '.join(str(repo_id) for repo_id in repo_ids)}.",
        file=sys.stderr,
    )
    changes = result.get('language_changes')
    if isinstance(changes, list):
        for change in changes[:20]:
            if isinstance(change, dict):
                print(
                    f"  {change.get('file_path', change.get('file_id', '?'))}: "
                    f"{change.get('previous_language', '?')} -> {change.get('language', '?')}",
                    file=sys.stderr,
                )
    for repo_id in repo_ids:
        print(
            f"  repair repo {repo_id}: vigil assess code-index build <snapshot-dir>/source "
            f"--repo-id {repo_id} then vigil assess code-index sync --repo-id {repo_id} "
            "(neither advances the generation)",
            file=sys.stderr,
        )
