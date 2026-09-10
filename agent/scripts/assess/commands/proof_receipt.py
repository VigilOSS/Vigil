"""vigil assess proof-receipt — create and inspect durable proof receipts."""
from __future__ import annotations

import json
from urllib.parse import urlencode

from assess.lib.client import AssessmentClient, AssessError, require_write_result
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.list_output import ListPage, lookahead_limit, page_from_backend, report_page


_EVIDENCE_KINDS = (
    "artifact",
    "browser_action",
    "command",
    "http_exchange",
    "oob_event",
    "source_observation",
)
_EVIDENCE_HEALTH = ("healthy", "missing", "stale", "tombstoned")
_REDACTION_STATUSES = ("raw", "redacted")
_MAX_LIST_LIMIT = 1000


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "proof-receipt",
        help="Create, list, or inspect durable proof evidence receipts.",
    )
    actions = parser.add_subparsers(dest="proof_receipt_action", required=True)

    create = actions.add_parser("create", help="Record one proof receipt.")
    create.add_argument("--run-id", required=True, type=int)
    create.add_argument("--kind", required=True, choices=_EVIDENCE_KINDS)
    create.add_argument("--expected-result", default="")
    create.add_argument("--observed-result", default="")
    create.add_argument("--artifact-id", type=int)
    create.add_argument("--source-read-id", type=int)
    create.add_argument("--command-run-id", type=int)
    create.add_argument("--evidence-sha256", default="")
    create.add_argument(
        "--evidence-health", default="healthy", choices=_EVIDENCE_HEALTH
    )
    create.add_argument(
        "--redaction-status", default="raw", choices=_REDACTION_STATUSES
    )
    create.add_argument("--derivative-of-receipt-id", type=int)
    create.add_argument("--tombstone-reason", default="")
    create.set_defaults(func=_run_create)

    get = actions.add_parser("get", help="Read one proof receipt by numeric id.")
    get.add_argument("receipt_id", type=int)
    get.set_defaults(func=_run_get)

    listing = actions.add_parser("list", help="List a bounded page of proof receipts.")
    listing.add_argument("--finding", default="", help="Filter by finding slug.")
    listing.add_argument("--limit", type=int, default=50)
    listing.add_argument("--offset", type=int, default=0)
    listing.add_argument(
        "--paginate",
        action="store_true",
        help="Explicitly traverse every page from --offset.",
    )
    listing.set_defaults(func=_run_list)


def _client(args) -> AssessmentClient:
    cfg = load_config(args.engagement_dir)
    return AssessmentClient(cfg.base_url, cfg.engagement_key)


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _optional_positive_int(value: object) -> bool:
    return value is None or _positive_int(value)


def _require_receipt(
    value: object,
    *,
    operation: str,
    requested_id: int | None = None,
    requested_run_id: int | None = None,
) -> dict:
    valid = isinstance(value, dict)
    if valid:
        receipt = value
        evidence_sha256 = receipt.get("evidence_sha256")
        valid = (
            _positive_int(receipt.get("id"))
            and _positive_int(receipt.get("run_id"))
            and _positive_int(receipt.get("producer_dispatch_id"))
            and receipt.get("evidence_kind") in _EVIDENCE_KINDS
            and isinstance(receipt.get("expected_result"), str)
            and isinstance(receipt.get("observed_result"), str)
            and _optional_positive_int(receipt.get("artifact_id"))
            and _optional_positive_int(receipt.get("source_read_id"))
            and _optional_positive_int(receipt.get("command_run_id"))
            and isinstance(receipt.get("artifact_relative_path"), str)
            and isinstance(evidence_sha256, str)
            and len(evidence_sha256) == 64
            and all(character in "0123456789abcdef" for character in evidence_sha256)
            and receipt.get("evidence_health") in _EVIDENCE_HEALTH
            and receipt.get("redaction_status") in _REDACTION_STATUSES
            and _optional_positive_int(receipt.get("derivative_of_receipt_id"))
            and _positive_int(receipt.get("raw_receipt_id"))
            and receipt.get("raw_receipt_id")
            == (
                receipt.get("derivative_of_receipt_id")
                if receipt.get("derivative_of_receipt_id") is not None
                else receipt.get("id")
            )
            and isinstance(receipt.get("tombstone_reason"), str)
            and isinstance(receipt.get("created_at"), str)
            and bool(receipt["created_at"].strip())
        )
        if requested_id is not None:
            valid = valid and receipt.get("id") == requested_id
        if requested_run_id is not None:
            valid = valid and receipt.get("run_id") == requested_run_id
    if not valid:
        suffix = (
            "; the write may have committed, so inspect durable state and do not "
            "retry automatically"
            if operation == "create"
            else ""
        )
        raise AssessError(f"proof-receipt {operation}: malformed receipt response{suffix}")
    return value


def _require_receipt_rows(value: object) -> list[dict]:
    if not isinstance(value, list):
        raise AssessError("proof-receipt list: malformed receipt list response")
    return [_require_receipt(row, operation="list") for row in value]


def _run_create(args) -> None:
    payload = {
        "run_id": int(args.run_id),
        "evidence_kind": str(args.kind),
        "expected_result": str(args.expected_result),
        "observed_result": str(args.observed_result),
        "artifact_id": args.artifact_id,
        "source_read_id": args.source_read_id,
        "command_run_id": args.command_run_id,
        "evidence_sha256": str(args.evidence_sha256),
        "evidence_health": str(args.evidence_health),
        "redaction_status": str(args.redaction_status),
        "derivative_of_receipt_id": args.derivative_of_receipt_id,
        "tombstone_reason": str(args.tombstone_reason),
    }
    with _client(args) as client:
        response = client.post("proof-receipts", payload)
    expected = {
        "run_id": payload["run_id"],
        "evidence_kind": payload["evidence_kind"],
        "expected_result": payload["expected_result"],
        "observed_result": payload["observed_result"],
        "artifact_id": payload["artifact_id"],
        "source_read_id": payload["source_read_id"],
        "command_run_id": payload["command_run_id"],
        "redaction_status": payload["redaction_status"],
        "derivative_of_receipt_id": payload["derivative_of_receipt_id"],
        "tombstone_reason": payload["tombstone_reason"],
    }
    if payload["artifact_id"] is None or payload["evidence_health"] != "healthy":
        expected["evidence_health"] = payload["evidence_health"]
    if payload["evidence_sha256"] and payload["artifact_id"] is None:
        expected["evidence_sha256"] = payload["evidence_sha256"]
    require_write_result(
        response,
        operation="proof-receipt create",
        expected=expected,
        positive_ids=("id", "producer_dispatch_id"),
    )
    row = _require_receipt(
        response,
        operation="create",
        requested_run_id=int(payload["run_id"]),
    )
    print(json.dumps(row, indent=2, ensure_ascii=False))


def _run_get(args) -> None:
    receipt_id = int(args.receipt_id)
    with _client(args) as client:
        response = client.get(f"proof-receipts/{receipt_id}")
    row = _require_receipt(response, operation="get", requested_id=receipt_id)
    warn_untrusted_data()
    print(json.dumps(row, indent=2, ensure_ascii=False))


def _list_endpoint(*, finding: str, limit: int, offset: int) -> str:
    query = urlencode(
        {
            **({"finding_slug": finding} if finding else {}),
            "limit": limit,
            "offset": offset,
        }
    )
    return f"proof-receipts?{query}"


def _run_list(args) -> None:
    limit = int(args.limit)
    offset = int(args.offset)
    finding = str(args.finding).strip()
    client = _client(args)
    try:
        if args.paginate:
            rows: list[dict] = []
            next_offset = offset
            while True:
                page_rows = _require_receipt_rows(
                    client.get(
                        _list_endpoint(
                            finding=finding, limit=limit, offset=next_offset
                        )
                    )
                )
                rows.extend(page_rows)
                if len(page_rows) < limit:
                    break
                next_offset += len(page_rows)
            exact_total = offset + len(rows) if rows or offset == 0 else None
            page = ListPage(
                rows=rows,
                offset=offset,
                total=exact_total,
                total_at_least=exact_total,
                has_more=False,
            )
        else:
            request_limit, used_lookahead = lookahead_limit(
                limit, maximum=_MAX_LIST_LIMIT
            )
            rows = _require_receipt_rows(
                client.get(
                    _list_endpoint(
                        finding=finding, limit=request_limit, offset=offset
                    )
                )
            )
            page = page_from_backend(
                rows,
                limit=limit,
                offset=offset,
                used_lookahead=used_lookahead,
            )
    finally:
        client.close()

    finding_flag = f" --finding {finding}" if finding else ""
    report_page(
        page,
        noun="proof receipts",
        continuation_command=(
            f"vigil assess proof-receipt list{finding_flag} --limit {limit} "
            f"--offset {page.offset + len(page.rows)}"
        ),
        point_read_hint="`vigil assess proof-receipt get <id>`",
    )
    warn_untrusted_data()
    print(json.dumps(page.rows, indent=2, ensure_ascii=False))
