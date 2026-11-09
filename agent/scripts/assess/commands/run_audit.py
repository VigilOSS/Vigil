"""vigil assess run-audit — inspect and update generic run accounting."""
from __future__ import annotations

import codecs
import hashlib
import json
import os
import sys
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable
from urllib.parse import urlencode

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.code_snapshot import RootedSourceTree, SourceSnapshotRaceError
from assess.lib.config import Config, load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.list_output import ListPage, report_page


_MAX_LIST_LIMIT = 1000
_SOURCE_LOOKUP_LIMIT = 1000
_SOURCE_IMPORT_BATCH_SIZE = 1000
_STREAM_CHUNK_BYTES = 1024 * 1024
_INVENTORY_STATUSES = frozenset({"included", "excluded", "missing"})
_PARSER_STATUSES = frozenset({"parsed", "failed", "not_applicable"})
_OBLIGATION_STATUSES = frozenset(
    {"open", "resolved", "blocked", "deferred", "accepted_gap", "released"}
)
_CANDIDATE_STATES = frozenset(
    {"open", "promoted", "rejected", "duplicate", "deferred"}
)
_INVENTORY_COMMITMENT_VERSION = "v1"
_SOURCE_IDENTITY_FIELDS = (
    "target_key",
    "declared_root",
    "path",
    "content_sha256",
    "byte_size",
    "line_count",
    "encoding",
    "inventory_status",
    "exclusion_reason",
    "parser_status",
    "parser_error",
)


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "run-audit",
        help="Record and inspect generic run sources, reads, obligations, and candidates.",
    )
    families = parser.add_subparsers(dest="run_audit_family", required=True)

    sources = families.add_parser("sources", help="Import or list source inventory.")
    source_actions = sources.add_subparsers(dest="run_audit_action", required=True)
    source_import = source_actions.add_parser(
        "import", help="Import a source-inventory JSON document."
    )
    source_import.add_argument("run_id", type=int)
    source_import.add_argument("payload_file")
    source_import.set_defaults(func=_run_sources_import)
    source_commitment = source_actions.add_parser(
        "commitment",
        help="Compute exact per-target inventory commitments before starting a scan.",
    )
    source_commitment.add_argument("payload_file")
    source_commitment.set_defaults(func=_run_sources_commitment)
    _register_list(source_actions, _run_list)

    reads = families.add_parser(
        "source-read", help="Deliver and durably record verified source bytes."
    )
    read_actions = reads.add_subparsers(dest="run_audit_action", required=True)
    record_read = read_actions.add_parser(
        "record", help="Read verified local bytes, deliver them, then record the range."
    )
    record_read.add_argument("run_id", type=int)
    record_read.add_argument("source_id", type=int)
    record_read.add_argument("source_path")
    record_read.add_argument("--agent-id", required=True)
    record_read.add_argument("--attempt", required=True, type=int)
    record_read.add_argument("--byte-start", type=int, default=0)
    record_read.add_argument("--byte-end", type=int)
    record_read.add_argument("--proof-receipt-id", type=int)
    record_read.add_argument(
        "--output",
        help="Create this file with the exact source bytes; default emits decoded text to stdout.",
    )
    record_read.set_defaults(func=_run_source_read_record)
    _register_list(read_actions, _run_list)

    obligations = families.add_parser(
        "obligation", help="Record, update, release, or list run obligations."
    )
    obligation_actions = obligations.add_subparsers(
        dest="run_audit_action", required=True
    )
    obligation_record = obligation_actions.add_parser(
        "record", help="Record an obligation from a JSON document."
    )
    obligation_record.add_argument("run_id", type=int)
    obligation_record.add_argument("payload_file")
    obligation_record.set_defaults(func=_run_obligation_record)
    obligation_update = obligation_actions.add_parser(
        "update", help="Update an obligation from a JSON document."
    )
    obligation_update.add_argument("run_id", type=int)
    obligation_update.add_argument("obligation_id", type=int)
    obligation_update.add_argument("payload_file")
    obligation_update.set_defaults(func=_run_obligation_update)
    obligation_release = obligation_actions.add_parser(
        "release",
        help="Release an unread or accepted-gap proof-run source the producer will not read.",
    )
    obligation_release.add_argument("run_id", type=int)
    obligation_release.add_argument("obligation_id", type=int)
    obligation_release.add_argument(
        "--agent-id", required=True, help="The run's producer dispatch agent id."
    )
    obligation_release.add_argument(
        "--reason", required=True, help="Why this source will not be read."
    )
    obligation_release.set_defaults(func=_run_obligation_release)
    _register_list(obligation_actions, _run_list)

    candidates = families.add_parser(
        "candidate", help="Record, update, list, or inspect run candidates."
    )
    candidate_actions = candidates.add_subparsers(
        dest="run_audit_action", required=True
    )
    candidate_record = candidate_actions.add_parser(
        "record", help="Record a candidate from a JSON document."
    )
    candidate_record.add_argument("run_id", type=int)
    candidate_record.add_argument("payload_file")
    candidate_record.set_defaults(func=_run_candidate_record)
    candidate_update = candidate_actions.add_parser(
        "update", help="Update a candidate from a JSON document."
    )
    candidate_update.add_argument("run_id", type=int)
    candidate_update.add_argument("candidate_id", type=int)
    candidate_update.add_argument("payload_file")
    candidate_update.set_defaults(func=_run_candidate_update)
    _register_list(candidate_actions, _run_list)
    candidate_history = candidate_actions.add_parser(
        "history", help="Inspect the immutable history for one candidate."
    )
    candidate_history.add_argument("run_id", type=int)
    candidate_history.add_argument("candidate_id", type=int)
    candidate_history.set_defaults(func=_run_candidate_history)

    for family, help_text, handler in (
        (
            "tool-signal",
            "Record or list typed automatic tool signals and their candidates.",
            _run_tool_signal_record,
        ),
        (
            "discovery-pass",
            "Record or list attributed discovery-pass workflow evidence.",
            _run_discovery_pass_record,
        ),
        (
            "code-receipt",
            "Link or list exact variant and fuzz receipts against run debt.",
            _run_code_receipt_record,
        ),
    ):
        records = families.add_parser(family, help=help_text)
        record_actions = records.add_subparsers(
            dest="run_audit_action", required=True
        )
        record = record_actions.add_parser(
            "record", help="Record one JSON document."
        )
        record.add_argument("run_id", type=int)
        record.add_argument("payload_file")
        record.set_defaults(func=handler)
        _register_list(record_actions, _run_list)

    for family, help_text in (
        ("commands", "List exact command executions cited by run proof."),
        ("observed-events", "List recorded HTTP, browser, and OOB evidence."),
        ("decision-history", "List obligation and candidate transition history."),
    ):
        read_only = families.add_parser(family, help=help_text)
        read_actions = read_only.add_subparsers(
            dest="run_audit_action", required=True
        )
        _register_list(read_actions, _run_list)

    compare = families.add_parser(
        "compare", help="Compare one run with a compatible or selected baseline."
    )
    compare.add_argument("run_id", type=int)
    compare.add_argument("--baseline-run-id", type=int)
    compare.set_defaults(func=_run_compare)


def _register_list(actions, handler: Callable[[Any], None]) -> None:
    listing = actions.add_parser("list", help="List one bounded page.")
    listing.add_argument("run_id", type=int)
    listing.add_argument("--limit", type=int, default=50)
    listing.add_argument("--offset", type=int, default=0)
    listing.add_argument(
        "--paginate",
        action="store_true",
        help="Explicitly traverse every page from --offset.",
    )
    listing.set_defaults(func=handler)


def _client(args) -> tuple[Config, AssessmentClient]:
    cfg = load_config(args.engagement_dir)
    return cfg, AssessmentClient(cfg.base_url, cfg.engagement_key)


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _positive_ids(value: object) -> bool:
    return isinstance(value, list) and all(_positive_int(item) for item in value)


def _optional_positive_int(value: object) -> bool:
    return value is None or _positive_int(value)


def _same_value(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def _read_error(operation: str) -> AssessError:
    return AssessError(f"run-audit {operation}: malformed backend response")


def _write_error(operation: str) -> AssessError:
    return AssessError(
        f"run-audit {operation}: backend response did not identify the canonical "
        "durable result; the write may have committed, so inspect the relevant "
        "run-audit list/history state and do not retry automatically"
    )


# A backend row is vouched for by a sequence of checks over the whole row, so a
# cross-field relation (byte_end >= byte_start) sits in that sequence beside the
# per-field shape checks. The order is load-bearing and is the order the fields
# are listed in: a relation is only reached once both its fields are integers.
_RowCheck = Callable[[dict[str, Any]], bool]


def _field(name: str, predicate: Callable[[object], bool]) -> _RowCheck:
    return lambda row: predicate(row.get(name))


def _require_row(
    value: object,
    *,
    spec: tuple[_RowCheck, ...],
    operation: str,
    requested_run_id: int | None = None,
    requested_id: int | None = None,
    requested_source_id: int | None = None,
    write: bool = False,
    run_id_field: str = "run_id",
) -> dict[str, Any]:
    """Refuse a backend row this verb cannot vouch for, and return it intact.

    The checks run in order and stop at the first failure. A write refusal says
    the write may have committed, because the response that would have
    confirmed it is the thing that came back malformed.
    """
    valid = isinstance(value, dict)
    if valid:
        row = value
        valid = all(check(row) for check in spec)
        if requested_run_id is not None:
            valid = valid and row.get(run_id_field) == requested_run_id
        if requested_id is not None:
            valid = valid and row.get("id") == requested_id
        if requested_source_id is not None:
            valid = valid and row.get("source_id") == requested_source_id
    if not valid:
        raise _write_error(operation) if write else _read_error(operation)
    return value


_SOURCE_FIELDS: tuple[_RowCheck, ...] = (
    _field("id", _positive_int),
    _field("run_id", _positive_int),
    _field("target_key", _nonempty_string),
    _field("declared_root", _nonempty_string),
    _field("path", _nonempty_string),
    _field("content_sha256", _sha256),
    _field("byte_size", _nonnegative_int),
    _field("line_count", _nonnegative_int),
    _field("encoding", _nonempty_string),
    lambda row: row.get("inventory_status") in _INVENTORY_STATUSES,
    lambda row: isinstance(row.get("exclusion_reason"), str),
    lambda row: row.get("parser_status") in _PARSER_STATUSES,
    lambda row: isinstance(row.get("parser_error"), str),
)
_require_source = partial(_require_row, spec=_SOURCE_FIELDS)

_SOURCE_READ_FIELDS: tuple[_RowCheck, ...] = (
    _field("id", _positive_int),
    _field("run_id", _positive_int),
    _field("source_id", _positive_int),
    _field("dispatch_id", _positive_int),
    _field("dispatch_agent_id", _nonempty_string),
    _field("attempt", _positive_int),
    _field("byte_start", _nonnegative_int),
    _field("byte_end", _nonnegative_int),
    lambda row: row.get("byte_end", -1) >= row.get("byte_start", 0),
    _field("line_start", _positive_int),
    _field("line_end", _positive_int),
    lambda row: row.get("line_end", 0) >= row.get("line_start", 1),
    _field("proof_receipt_id", _optional_positive_int),
    _field("source_sha256", _sha256),
    _field("source_path", _nonempty_string),
    _field("target_key", _nonempty_string),
    _field("encoding", _nonempty_string),
)
_require_source_read = partial(_require_row, spec=_SOURCE_READ_FIELDS)

_OBLIGATION_FIELDS: tuple[_RowCheck, ...] = (
    _field("id", _positive_int),
    _field("run_id", _positive_int),
    _field("identity_key", _nonempty_string),
    _field("obligation_kind", _nonempty_string),
    _field("object_type", _nonempty_string),
    _field("object_key", _nonempty_string),
    lambda row: isinstance(row.get("hard"), bool),
    lambda row: row.get("status") in _OBLIGATION_STATUSES,
    lambda row: isinstance(row.get("resolution"), str),
    _field("proof_receipt_ids", _positive_ids),
)
_require_obligation = partial(_require_row, spec=_OBLIGATION_FIELDS)

_CANDIDATE_FIELDS: tuple[_RowCheck, ...] = (
    _field("id", _positive_int),
    _field("run_id", _positive_int),
    _field("identity_key", _nonempty_string),
    _field("target_key", _nonempty_string),
    _field("source_id", _optional_positive_int),
    _field("source_anchor", _nonempty_string),
    _field("vulnerability_family", _nonempty_string),
    _field("hypothesis", _nonempty_string),
    _field("originating_result_id", _optional_positive_int),
    _field("dispatch_id", _positive_int),
    _field("proof_receipt_ids", _positive_ids),
    lambda row: row.get("state") in _CANDIDATE_STATES,
    lambda row: isinstance(row.get("finding_slug"), str),
)
_require_candidate = partial(_require_row, spec=_CANDIDATE_FIELDS)

_TOOL_SIGNAL_FIELDS: tuple[_RowCheck, ...] = (
    _field("id", _positive_int),
    _field("run_id", _positive_int),
    _field("identity_key", _nonempty_string),
    lambda row: row.get("signal_kind")
    in {"sanitizer_violation", "reproducible_crash", "attributed_oob_callback"},
    _field("dispatch_id", _positive_int),
    _field("target_key", _nonempty_string),
    _field("source_id", _optional_positive_int),
    _field("source_anchor", _nonempty_string),
    _field("vulnerability_family", _nonempty_string),
    _field("hypothesis", _nonempty_string),
    _field("observed_signature", _nonempty_string),
    lambda row: isinstance(row.get("exact_input_sha256"), str),
    _field("command_run_id", _positive_int),
    _field("proof_receipt_ids", _positive_ids),
    _field("candidate_id", _positive_int),
    _field("record_sha256", _sha256),
    _field("created_at", _nonempty_string),
)
_require_tool_signal = partial(_require_row, spec=_TOOL_SIGNAL_FIELDS)

_DISCOVERY_PASS_FIELDS: tuple[_RowCheck, ...] = (
    _field("id", _positive_int),
    _field("run_id", _positive_int),
    _field("identity_key", _nonempty_string),
    _field("dispatch_id", _positive_int),
    _field("frontier_identity_sha256", _sha256),
    lambda row: row.get("terminal_reason")
    in {"frontier_exhausted", "no_new_candidates", "cap_reached", "interrupted", "failed"},
    lambda row: isinstance(row.get("candidate_identity_keys"), list)
    and all(
        _nonempty_string(item) and len(item) <= 1024
        for item in row["candidate_identity_keys"]
    ),
    _field("candidate_delta", _nonnegative_int),
    _field("proof_receipt_ids", _positive_ids),
    _field("record_sha256", _sha256),
    _field("created_at", _nonempty_string),
)
_require_discovery_pass = partial(_require_row, spec=_DISCOVERY_PASS_FIELDS)

_CODE_RECEIPT_FIELDS: tuple[_RowCheck, ...] = (
    _field("id", _positive_int),
    _field("run_id", _positive_int),
    lambda row: row.get("receipt_kind")
    in {"variant_check", "fuzz_decision", "fuzz_campaign"},
    _field("receipt_id", _positive_int),
    _field("target_key", _nonempty_string),
    _field("obligation_id", _positive_int),
    _field("candidate_ids", _positive_ids),
    _field("signal_ids", _positive_ids),
    _field("proof_receipt_ids", _positive_ids),
    lambda row: row.get("obligation_status") in {"resolved", "blocked"},
    _field("record_sha256", _sha256),
    _field("created_at", _nonempty_string),
)
_require_code_receipt = partial(_require_row, spec=_CODE_RECEIPT_FIELDS)


def _require_audit_receipt(
    value: object,
    *,
    operation: str,
    requested_run_id: int | None = None,
    allowed_kinds: frozenset[str],
) -> dict[str, Any]:
    valid = isinstance(value, dict)
    if valid:
        row = value
        valid = (
            _positive_int(row.get("id"))
            and _positive_int(row.get("audit_run_id"))
            and _positive_int(row.get("run_id"))
            and _positive_int(row.get("origin_run_id"))
            and _positive_int(row.get("producer_dispatch_id"))
            and _nonempty_string(row.get("producer_dispatch_agent_id"))
            and _nonempty_string(row.get("producer_dispatch_agent_role"))
            and row.get("evidence_kind") in allowed_kinds
            and isinstance(row.get("expected_result"), str)
            and isinstance(row.get("observed_result"), str)
            and _optional_positive_int(row.get("artifact_id"))
            and _optional_positive_int(row.get("source_read_id"))
            and _optional_positive_int(row.get("command_run_id"))
            and isinstance(row.get("artifact_relative_path"), str)
            and _sha256(row.get("evidence_sha256"))
            and row.get("evidence_health")
            in {"healthy", "missing", "stale", "tombstoned"}
            and (
                row.get("legacy_derivative_provenance") is None
                or isinstance(row.get("legacy_derivative_provenance"), dict)
            )
            and isinstance(row.get("tombstone_reason"), str)
            and _nonempty_string(row.get("created_at"))
        )
        if requested_run_id is not None:
            valid = valid and row.get("audit_run_id") == requested_run_id
    if not valid:
        raise _read_error(operation)
    return value


def _require_command_receipt(
    value: object, *, operation: str, requested_run_id: int | None = None
) -> dict[str, Any]:
    row = _require_audit_receipt(
        value,
        operation=operation,
        requested_run_id=requested_run_id,
        allowed_kinds=frozenset({"command"}),
    )
    command = row.get("command")
    if (
        not isinstance(command, dict)
        or not _positive_int(command.get("id"))
        or command.get("id") != row.get("command_run_id")
        or not _nonempty_string(command.get("command"))
        or not isinstance(command.get("argv"), list)
        or not _nonempty_string(command.get("status"))
    ):
        raise _read_error(operation)
    return row


def _require_observed_event(
    value: object, *, operation: str, requested_run_id: int | None = None
) -> dict[str, Any]:
    row = _require_audit_receipt(
        value,
        operation=operation,
        requested_run_id=requested_run_id,
        allowed_kinds=frozenset({"http_exchange", "browser_action", "oob_event"}),
    )
    if not _positive_int(row.get("artifact_id")) or not _nonempty_string(
        row.get("artifact_relative_path")
    ):
        raise _read_error(operation)
    return row


_DECISION_EVENT_FIELDS: tuple[_RowCheck, ...] = (
    _field("id", _nonempty_string),
    _field("audit_run_id", _positive_int),
    lambda row: row.get("object_type") in {"obligation", "candidate"},
    _field("object_id", _positive_int),
    _field("origin_run_id", _positive_int),
    lambda row: row.get("from_status") is None or _nonempty_string(row.get("from_status")),
    _field("to_status", _nonempty_string),
    lambda row: isinstance(row.get("detail"), str),
    _field("proof_receipt_ids", _positive_ids),
    _field("created_at", _nonempty_string),
)
_require_decision_event = partial(
    _require_row, spec=_DECISION_EVENT_FIELDS, run_id_field="audit_run_id"
)


_FAMILIES: dict[str, tuple[str, str, Callable[..., dict[str, Any]]]] = {
    "sources": ("sources", "run sources", _require_source),
    "source-read": ("source-reads", "source reads", _require_source_read),
    "obligation": ("obligations", "run obligations", _require_obligation),
    "candidate": ("candidates", "run candidates", _require_candidate),
    "tool-signal": ("tool-signals", "typed tool signals", _require_tool_signal),
    "discovery-pass": ("discovery-passes", "discovery passes", _require_discovery_pass),
    "code-receipt": ("code-receipts", "linked code receipts", _require_code_receipt),
    "commands": ("commands", "recorded commands", _require_command_receipt),
    "observed-events": ("observed-events", "observed events", _require_observed_event),
    "decision-history": (
        "decision-history",
        "decision history events",
        _require_decision_event,
    ),
}


def _require_page(
    value: object,
    *,
    family: str,
    run_id: int,
    limit: int,
    offset: int,
) -> tuple[list[dict[str, Any]], int, bool]:
    if not isinstance(value, dict):
        raise _read_error(f"{family} list")
    items = value.get("items")
    total = value.get("total")
    has_more = value.get("has_more")
    if (
        not isinstance(items, list)
        or not _nonnegative_int(total)
        or value.get("offset") != offset
        or value.get("limit") != limit
        or not isinstance(has_more, bool)
        or total < offset + len(items)
        or has_more != (offset + len(items) < total)
        or (has_more and not items)
    ):
        raise _read_error(f"{family} list")
    validator = _FAMILIES[family][2]
    rows = [
        validator(row, operation=f"{family} list", requested_run_id=run_id)
        for row in items
    ]
    return rows, total, has_more


def _validated_window(args) -> tuple[int, int]:
    limit = int(args.limit)
    offset = int(args.offset)
    if not 1 <= limit <= _MAX_LIST_LIMIT:
        raise AssessError(
            f"run-audit {args.run_audit_family} list: limit must be between 1 and "
            f"{_MAX_LIST_LIMIT}"
        )
    if offset < 0:
        raise AssessError(
            f"run-audit {args.run_audit_family} list: offset must be at least 0"
        )
    return limit, offset


def _run_list(args) -> None:
    family = str(args.run_audit_family)
    run_id = int(args.run_id)
    limit, offset = _validated_window(args)
    endpoint_name, noun, _ = _FAMILIES[family]
    _, client = _client(args)
    rows: list[dict[str, Any]] = []
    next_offset = offset
    expected_total: int | None = None
    try:
        while True:
            endpoint = (
                f"assessment-runs/{run_id}/{endpoint_name}?"
                f"{urlencode({'limit': limit, 'offset': next_offset})}"
            )
            page_rows, total, has_more = _require_page(
                client.get(endpoint),
                family=family,
                run_id=run_id,
                limit=limit,
                offset=next_offset,
            )
            if expected_total is not None and total != expected_total:
                raise _read_error(f"{family} list")
            expected_total = total
            rows.extend(page_rows)
            next_offset += len(page_rows)
            if not args.paginate or not has_more:
                page = ListPage(
                    rows=rows,
                    offset=offset,
                    total=total,
                    total_at_least=total,
                    has_more=has_more,
                )
                break
    finally:
        client.close()

    report_page(
        page,
        noun=noun,
        continuation_command=(
            f"vigil assess run-audit {family} list {run_id} --limit {limit} "
            f"--offset {next_offset}"
        ),
    )
    warn_untrusted_data()
    print(json.dumps(page.rows, indent=2, ensure_ascii=False))


def _load_object_file(path_text: str, *, operation: str) -> dict[str, Any]:
    path = Path(path_text).expanduser()
    if not path.is_file():
        raise AssessError(f"run-audit {operation}: JSON file not found: {path_text}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AssessError(f"run-audit {operation}: invalid JSON file {path_text}: {exc}") from exc
    if not isinstance(value, dict):
        raise AssessError(f"run-audit {operation}: JSON file must contain an object")
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source_identity_for_commitment(source: dict[str, Any]) -> dict[str, Any]:
    if set(source) != set(_SOURCE_IDENTITY_FIELDS):
        raise AssessError(
            "run-audit sources commitment: every source must contain exactly the "
            "documented inventory fields"
        )
    if not all(
        isinstance(source[field], str)
        for field in (
            "target_key",
            "declared_root",
            "path",
            "content_sha256",
            "encoding",
            "inventory_status",
            "exclusion_reason",
            "parser_status",
            "parser_error",
        )
    ):
        raise AssessError(
            "run-audit sources commitment: inventory string fields must be strings"
        )
    if not all(
        source[field].strip()
        for field in ("target_key", "declared_root", "path", "encoding")
    ):
        raise AssessError(
            "run-audit sources commitment: target, root, path, and encoding are required"
        )
    if not _sha256(source["content_sha256"]):
        raise AssessError(
            "run-audit sources commitment: content_sha256 must be lowercase SHA-256"
        )
    if (
        source["inventory_status"] not in _INVENTORY_STATUSES
        or source["parser_status"] not in _PARSER_STATUSES
    ):
        raise AssessError(
            "run-audit sources commitment: invalid inventory_status or parser_status"
        )
    for field in ("byte_size", "line_count"):
        if not _nonnegative_int(source[field]):
            raise AssessError(
                f"run-audit sources commitment: {field} must be a nonnegative integer"
            )
    return {field: source[field] for field in _SOURCE_IDENTITY_FIELDS}


def _run_sources_commitment(args) -> None:
    operation = "sources commitment"
    payload = _load_object_file(args.payload_file, operation=operation)
    requested_sources = payload.get("sources")
    if not isinstance(requested_sources, list) or not requested_sources or any(
        not isinstance(source, dict) for source in requested_sources
    ):
        raise AssessError(
            "run-audit sources commitment: JSON object must contain a non-empty sources list"
        )
    identities_by_target: dict[str, list[str]] = {}
    seen_paths: set[tuple[str, str, str]] = set()
    for source in requested_sources:
        identity = _source_identity_for_commitment(source)
        path_identity = (
            identity["target_key"],
            identity["declared_root"],
            identity["path"],
        )
        if path_identity in seen_paths:
            raise AssessError(
                "run-audit sources commitment: duplicate target/root/path inventory row"
            )
        seen_paths.add(path_identity)
        identities_by_target.setdefault(identity["target_key"], []).append(
            _canonical_sha256(identity)
        )
    commitments = []
    for target_key, identities in sorted(identities_by_target.items()):
        identities.sort()
        commitments.append(
            {
                "target_key": target_key,
                "inventory_commitment_version": _INVENTORY_COMMITMENT_VERSION,
                "inventory_count": len(identities),
                "inventory_digest": _canonical_sha256(
                    {
                        "version": _INVENTORY_COMMITMENT_VERSION,
                        "target_key": target_key,
                        "source_identity_sha256": identities,
                    }
                ),
            }
        )
    print(json.dumps(commitments, indent=2, ensure_ascii=False))


def _require_requested_fields(
    row: dict[str, Any],
    requested: dict[str, Any],
    *,
    operation: str,
    ignored: frozenset[str] = frozenset(),
) -> None:
    if any(
        field not in ignored
        and (field not in row or not _same_value(row[field], value))
        for field, value in requested.items()
    ):
        raise _write_error(operation)


def _run_sources_import(args) -> None:
    operation = "sources import"
    run_id = int(args.run_id)
    payload = _load_object_file(args.payload_file, operation=operation)
    requested_sources = payload.get("sources")
    if not isinstance(requested_sources, list) or not requested_sources or any(
        not isinstance(source, dict) for source in requested_sources
    ):
        raise AssessError(
            "run-audit sources import: JSON object must contain a non-empty sources list"
        )
    rows: list[dict[str, Any]] = []
    _, client = _client(args)
    try:
        # Read the run first: an unknown run fails before any write, and its
        # purpose decides what the imported debt does to completion.
        run = client.get(f"assessment-runs/{run_id}")
        if (
            not isinstance(run, dict)
            or run.get("id") != run_id
            or run.get("run_purpose") not in {"proof", "scan"}
        ):
            raise _read_error(operation)
        for batch_start in range(
            0, len(requested_sources), _SOURCE_IMPORT_BATCH_SIZE
        ):
            requested_batch = requested_sources[
                batch_start : batch_start + _SOURCE_IMPORT_BATCH_SIZE
            ]
            operation_batch = (
                f"{operation} batch "
                f"{batch_start // _SOURCE_IMPORT_BATCH_SIZE + 1}"
            )
            response = client.post(
                f"assessment-runs/{run_id}/sources",
                {"sources": requested_batch},
            )
            if not isinstance(response, list) or len(response) != len(
                requested_batch
            ):
                raise _write_error(operation_batch)
            for requested, value in zip(requested_batch, response, strict=True):
                row = _require_source(
                    value,
                    operation=operation_batch,
                    requested_run_id=run_id,
                    write=True,
                )
                _require_requested_fields(
                    row, requested, operation=operation_batch
                )
                rows.append(row)
    finally:
        client.close()
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    included = sum(row["inventory_status"] == "included" for row in rows)
    if included:
        consequence = (
            "completion is refused until each is fully read or released."
            if run["run_purpose"] == "proof"
            else "a completed request seals the scan partial until each is fully read."
        )
        print(
            f"run-audit sources import: {included} included "
            f"{'source is' if included == 1 else 'sources are'} now hard "
            f"source_read obligations on run {run_id}; {consequence}",
            file=sys.stderr,
        )


def _write_object(
    args,
    *,
    operation: str,
    endpoint: str,
    method: str,
    validator: Callable[..., dict[str, Any]],
    requested_id: int | None = None,
    ignored: frozenset[str] = frozenset(),
) -> None:
    payload = _load_object_file(args.payload_file, operation=operation)
    run_id = int(args.run_id)
    _, client = _client(args)
    try:
        response = getattr(client, method)(endpoint, payload)
    finally:
        client.close()
    row = validator(
        response,
        operation=operation,
        requested_run_id=run_id,
        requested_id=requested_id,
        write=True,
    )
    _require_requested_fields(row, payload, operation=operation, ignored=ignored)
    print(json.dumps(row, indent=2, ensure_ascii=False))


def _run_obligation_record(args) -> None:
    _write_object(
        args,
        operation="obligation record",
        endpoint=f"assessment-runs/{int(args.run_id)}/obligations",
        method="post",
        validator=_require_obligation,
    )


def _run_obligation_update(args) -> None:
    obligation_id = int(args.obligation_id)
    _write_object(
        args,
        operation="obligation update",
        endpoint=(
            f"assessment-runs/{int(args.run_id)}/obligations/{obligation_id}"
        ),
        method="patch",
        validator=_require_obligation,
        requested_id=obligation_id,
    )


def _run_obligation_release(args) -> None:
    operation = "obligation release"
    run_id = int(args.run_id)
    obligation_id = int(args.obligation_id)
    payload = {"dispatch_agent_id": str(args.agent_id), "reason": str(args.reason)}
    _, client = _client(args)
    try:
        response = client.post(
            f"assessment-runs/{run_id}/obligations/{obligation_id}/release", payload
        )
    finally:
        client.close()
    row = _require_obligation(
        response,
        operation=operation,
        requested_run_id=run_id,
        requested_id=obligation_id,
        write=True,
    )
    _require_requested_fields(
        row,
        {"status": "released", "resolution": payload["reason"]},
        operation=operation,
    )
    print(json.dumps(row, indent=2, ensure_ascii=False))


def _run_candidate_record(args) -> None:
    _write_object(
        args,
        operation="candidate record",
        endpoint=f"assessment-runs/{int(args.run_id)}/candidates",
        method="post",
        validator=_require_candidate,
        ignored=frozenset({"dispatch_agent_id"}),
    )


def _run_candidate_update(args) -> None:
    candidate_id = int(args.candidate_id)
    _write_object(
        args,
        operation="candidate update",
        endpoint=f"assessment-runs/{int(args.run_id)}/candidates/{candidate_id}",
        method="patch",
        validator=_require_candidate,
        requested_id=candidate_id,
        ignored=frozenset({"reason"}),
    )


def _run_tool_signal_record(args) -> None:
    _write_object(
        args,
        operation="tool-signal record",
        endpoint=f"assessment-runs/{int(args.run_id)}/tool-signals",
        method="post",
        validator=_require_tool_signal,
        ignored=frozenset({"dispatch_agent_id"}),
    )


def _run_discovery_pass_record(args) -> None:
    _write_object(
        args,
        operation="discovery-pass record",
        endpoint=f"assessment-runs/{int(args.run_id)}/discovery-passes",
        method="post",
        validator=_require_discovery_pass,
        ignored=frozenset({"dispatch_agent_id"}),
    )


def _run_code_receipt_record(args) -> None:
    _write_object(
        args,
        operation="code-receipt record",
        endpoint=f"assessment-runs/{int(args.run_id)}/code-receipts",
        method="post",
        validator=_require_code_receipt,
    )


def _source_for_id(client: AssessmentClient, *, run_id: int, source_id: int) -> dict[str, Any]:
    offset = 0
    while True:
        endpoint = (
            f"assessment-runs/{run_id}/sources?"
            f"{urlencode({'limit': _SOURCE_LOOKUP_LIMIT, 'offset': offset})}"
        )
        rows, _total, has_more = _require_page(
            client.get(endpoint),
            family="sources",
            run_id=run_id,
            limit=_SOURCE_LOOKUP_LIMIT,
            offset=offset,
        )
        matching = [row for row in rows if row["id"] == source_id]
        if matching:
            return matching[0]
        if not has_more:
            raise AssessError(
                f"run-audit source-read record: source id {source_id} is not in run {run_id}"
            )
        offset += len(rows)


def _declared_source_binding(
    cfg: Config, source: dict[str, Any], supplied_path: str
) -> tuple[Path, str]:
    operation = "run-audit source-read record"
    engagement_root = Path(cfg.engagement_dir).resolve()
    root_value = Path(str(source["declared_root"])).expanduser()
    root = root_value if root_value.is_absolute() else engagement_root / root_value
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise AssessError(f"{operation}: declared source root is unavailable") from exc
    relative = PurePosixPath(str(source["path"]))
    if relative.is_absolute() or not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise AssessError(f"{operation}: inventory source path is unsafe")
    expected = root.joinpath(*relative.parts)
    candidate = Path(supplied_path).expanduser()
    if not candidate.is_absolute():
        candidate = engagement_root / candidate
    expected_hint = (
        f"expected {PurePosixPath(str(source['declared_root'])) / relative} "
        f"(declared root {source['declared_root']!r} + inventory path "
        f"{relative.as_posix()!r}; relative paths resolve from the engagement root)"
    )
    try:
        if candidate.resolve(strict=True) != expected.resolve(strict=True):
            raise AssessError(
                f"{operation}: supplied path {supplied_path!r} does not match "
                f"source id {source['id']}; {expected_hint}"
            )
    except OSError as exc:
        raise AssessError(
            f"{operation}: supplied source path {supplied_path!r} is unavailable; "
            f"{expected_hint}"
        ) from exc
    try:
        expected.resolve(strict=True).relative_to(root)
    except ValueError as exc:
        raise AssessError(f"{operation}: source path escapes its declared root") from exc
    return root, relative.as_posix()


def _codec_and_newline(spool: BinaryIO, encoding: str) -> tuple[str | None, bytes]:
    normalized = encoding.strip().lower().replace("_", "-")
    spool.seek(0)
    bom = spool.read(4)
    if normalized in {"binary", "bytes", "base64"}:
        return None, b"\n"
    if normalized in {"utf-16", "utf16"}:
        if bom.startswith(codecs.BOM_UTF16_LE):
            return "utf-16-le", b"\n\x00"
        if bom.startswith(codecs.BOM_UTF16_BE):
            return "utf-16-be", b"\x00\n"
        raise AssessError(
            "run-audit source-read record: UTF-16 source is missing an endian BOM"
        )
    if normalized in {"utf-16-le", "utf16-le"}:
        return "utf-16-le", b"\n\x00"
    if normalized in {"utf-16-be", "utf16-be"}:
        return "utf-16-be", b"\x00\n"
    try:
        codecs.lookup(normalized)
    except LookupError as exc:
        raise AssessError(
            f"run-audit source-read record: unsupported source encoding {encoding!r}"
        ) from exc
    return normalized, b"\n"


def _range_chunks(spool: BinaryIO, start: int, end: int):
    spool.seek(start)
    remaining = end - start
    while remaining:
        chunk = spool.read(min(_STREAM_CHUNK_BYTES, remaining))
        if not chunk:
            raise AssessError("run-audit source-read record: captured source range truncated")
        remaining -= len(chunk)
        yield chunk


def _count_pattern(spool: BinaryIO, start: int, end: int, pattern: bytes) -> int:
    count = 0
    carry = b""
    for chunk in _range_chunks(spool, start, end):
        combined = carry + chunk
        count += combined.count(pattern)
        carry = combined[-(len(pattern) - 1) :] if len(pattern) > 1 else b""
    return count


def _range_ends_with(spool: BinaryIO, end: int, pattern: bytes) -> bool:
    if end < len(pattern):
        return False
    spool.seek(end - len(pattern))
    return spool.read(len(pattern)) == pattern


def _line_bounds(
    spool: BinaryIO, *, start: int, end: int, newline: bytes
) -> tuple[int, int]:
    line_start = 1 + _count_pattern(spool, 0, start, newline)
    breaks = _count_pattern(spool, start, end, newline)
    line_end = line_start + breaks
    if end > start and breaks and _range_ends_with(spool, end, newline):
        line_end -= 1
    return line_start, max(line_start, line_end)


def _validate_text_range(
    spool: BinaryIO, *, start: int, end: int, codec_name: str
) -> None:
    if codec_name.startswith("utf-16") and (start % 2 or end % 2):
        raise AssessError(
            "run-audit source-read record: UTF-16 byte ranges must use even boundaries"
        )
    decoder = codecs.getincrementaldecoder(codec_name)(errors="strict")
    try:
        for chunk in _range_chunks(spool, start, end):
            decoder.decode(chunk, final=False)
        decoder.decode(b"", final=True)
    except UnicodeError as exc:
        raise AssessError(
            "run-audit source-read record: selected bytes do not align with the source encoding"
        ) from exc


def _deliver_to_file(spool: BinaryIO, *, start: int, end: int, output: str) -> None:
    destination = Path(output).expanduser()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(destination, flags, 0o600)
    except OSError as exc:
        raise AssessError(
            f"run-audit source-read record: output must be a new safe file: {destination}"
        ) from exc
    try:
        for chunk in _range_chunks(spool, start, end):
            view = memoryview(chunk)
            while view:
                written = os.write(fd, view)
                if written < 1:
                    raise OSError("short output write")
                view = view[written:]
        os.fsync(fd)
    except Exception as exc:
        os.close(fd)
        destination.unlink(missing_ok=True)
        if isinstance(exc, AssessError):
            raise
        raise AssessError(
            "run-audit source-read record: source delivery did not complete; "
            "no read was recorded"
        ) from exc
    else:
        os.close(fd)


def _deliver_to_stdout(
    spool: BinaryIO, *, start: int, end: int, codec_name: str
) -> None:
    decoder_name = codec_name
    if start == 0 and codec_name in {"utf-16-le", "utf-16-be"}:
        decoder_name = "utf-16"
    decoder = codecs.getincrementaldecoder(decoder_name)(errors="strict")
    try:
        for chunk in _range_chunks(spool, start, end):
            sys.stdout.write(decoder.decode(chunk, final=False))
        sys.stdout.write(decoder.decode(b"", final=True))
        sys.stdout.flush()
    except (BrokenPipeError, OSError, UnicodeError) as exc:
        raise AssessError(
            "run-audit source-read record: source delivery did not complete; no read was recorded"
        ) from exc


def _run_source_read_record(args) -> None:
    operation = "source-read record"
    run_id = int(args.run_id)
    source_id = int(args.source_id)
    attempt = int(args.attempt)
    start = int(args.byte_start)
    if run_id < 1 or source_id < 1 or attempt < 1 or start < 0:
        raise AssessError(
            "run-audit source-read record: run/source/attempt must be positive and byte-start nonnegative"
        )
    if args.proof_receipt_id is not None and int(args.proof_receipt_id) < 1:
        raise AssessError("run-audit source-read record: proof receipt id must be positive")
    cfg, client = _client(args)
    try:
        source = _source_for_id(client, run_id=run_id, source_id=source_id)
        if source["inventory_status"] != "included":
            raise AssessError(
                "run-audit source-read record: only included inventory sources can be delivered"
            )
        root, relative_path = _declared_source_binding(cfg, source, args.source_path)
        try:
            with RootedSourceTree(root) as source_tree:
                captured = source_tree.capture(relative_path, retain_spool=True)
                source_tree.verify_root_identity()
        except (OSError, RuntimeError, ValueError, SourceSnapshotRaceError) as exc:
            raise AssessError(
                "run-audit source-read record: source could not be opened safely beneath its declared root"
            ) from exc
        with captured:
            if (
                captured.sha256 != source["content_sha256"]
                or captured.size != source["byte_size"]
            ):
                raise AssessError(
                    "run-audit source-read record: current source digest/size does not match the run inventory"
                )
            end = captured.size if args.byte_end is None else int(args.byte_end)
            if end < start or end > captured.size:
                raise AssessError(
                    "run-audit source-read record: requested byte range is outside the inventoried source"
                )
            codec_name, newline = _codec_and_newline(captured.spool, source["encoding"])
            line_start, line_end = _line_bounds(
                captured.spool, start=start, end=end, newline=newline
            )
            if args.output:
                _deliver_to_file(
                    captured.spool, start=start, end=end, output=str(args.output)
                )
            else:
                if codec_name is None:
                    raise AssessError(
                        "run-audit source-read record: binary source requires --output"
                    )
                _validate_text_range(
                    captured.spool, start=start, end=end, codec_name=codec_name
                )
                warn_untrusted_data()
                _deliver_to_stdout(
                    captured.spool, start=start, end=end, codec_name=codec_name
                )
        payload = {
            "source_id": source_id,
            "dispatch_agent_id": str(args.agent_id),
            "attempt": attempt,
            "byte_start": start,
            "byte_end": end,
            "line_start": line_start,
            "line_end": line_end,
            "proof_receipt_id": args.proof_receipt_id,
        }
        response = client.post(f"assessment-runs/{run_id}/source-reads", payload)
    finally:
        client.close()
    row = _require_source_read(
        response,
        operation=operation,
        requested_run_id=run_id,
        requested_source_id=source_id,
        write=True,
    )
    _require_requested_fields(row, payload, operation=operation)
    if row["source_sha256"] != source["content_sha256"]:
        raise _write_error(operation)
    rendered = json.dumps(row, indent=2, ensure_ascii=False)
    if args.output:
        print(rendered)
    else:
        print(f"recorded source read: {rendered}", file=sys.stderr)


def _require_history_row(
    value: object, *, run_id: int, candidate_id: int
) -> dict[str, Any]:
    valid = isinstance(value, dict)
    if valid:
        valid = (
            _positive_int(value.get("id"))
            and value.get("run_id") == run_id
            and value.get("candidate_id") == candidate_id
            and (
                value.get("from_state") is None
                or value.get("from_state") in _CANDIDATE_STATES
            )
            and value.get("to_state") in _CANDIDATE_STATES
            and isinstance(value.get("reason"), str)
            and _positive_ids(value.get("proof_receipt_ids"))
            and _nonempty_string(value.get("created_at"))
        )
    if not valid:
        raise _read_error("candidate history")
    return value


def _run_candidate_history(args) -> None:
    run_id = int(args.run_id)
    candidate_id = int(args.candidate_id)
    _, client = _client(args)
    try:
        response = client.get(
            f"assessment-runs/{run_id}/candidates/{candidate_id}/history"
        )
    finally:
        client.close()
    if not isinstance(response, list):
        raise _read_error("candidate history")
    rows = [
        _require_history_row(row, run_id=run_id, candidate_id=candidate_id)
        for row in response
    ]
    warn_untrusted_data()
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def _run_compare(args) -> None:
    run_id = int(args.run_id)
    baseline_id = args.baseline_run_id
    query = (
        f"?{urlencode({'baseline_run_id': int(baseline_id)})}"
        if baseline_id is not None
        else ""
    )
    _, client = _client(args)
    try:
        response = client.get(f"assessment-runs/{run_id}/comparison{query}")
    finally:
        client.close()
    valid = isinstance(response, dict)
    if valid:
        classifications = response.get("classifications")
        valid = (
            response.get("run_id") == run_id
            and _positive_int(response.get("baseline_run_id"))
            and (
                response.get("automatic_baseline") is None
                or _positive_int(response.get("automatic_baseline"))
            )
            and (
                response.get("target_compatible") is None
                or isinstance(response.get("target_compatible"), bool)
            )
            and (
                response.get("source_compatible") is None
                or isinstance(response.get("source_compatible"), bool)
            )
            and response.get("deterministic") is True
            and isinstance(classifications, dict)
            and all(
                isinstance(classifications.get(name), list)
                and all(isinstance(item, str) for item in classifications[name])
                for name in ("new", "persisting", "resolved", "unknown")
            )
        )
        if baseline_id is not None:
            valid = (
                valid
                and response.get("baseline_run_id") == int(baseline_id)
                and response.get("automatic_baseline") is None
            )
        else:
            valid = valid and _positive_int(response.get("automatic_baseline"))
    if not valid:
        raise _read_error("compare")
    warn_untrusted_data()
    print(json.dumps(response, indent=2, ensure_ascii=False))
