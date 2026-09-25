"""vigil assess proof-run — create, transition, and inspect shared proof runs."""
from __future__ import annotations

import json
from pathlib import Path

from assess.lib.client import AssessmentClient, AssessError, require_write_result
from assess.lib.config import load_config
from assess.lib.list_output import ListPage, lookahead_limit, page_from_backend, report_page


_RUN_KINDS = frozenset({"code", "web", "blue", "shared"})
_RUN_PURPOSES = frozenset({"proof", "scan"})
_RUN_STATUSES = frozenset(
    {"queued", "running", "partial", "completed", "failed", "interrupted", "canceled"}
)
_TERMINAL_STATUSES = tuple(sorted(_RUN_STATUSES - {"queued", "running"}))
_MAX_LIST_LIMIT = 1000


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "proof-run",
        help="Start, begin, finish, list, or inspect a shared assessment run.",
    )
    actions = parser.add_subparsers(dest="proof_run_action", required=True)

    start = actions.add_parser(
        "start", help="Create a running proof run or queued scan run."
    )
    start.add_argument("run_uuid", help="Stable caller-generated run UUID.")
    start.add_argument("--kind", required=True, choices=sorted(_RUN_KINDS))
    start.add_argument("--agent-id", required=True, help="Producing dispatch agent id.")
    start.add_argument("--purpose", choices=sorted(_RUN_PURPOSES), default="proof")
    start.add_argument(
        "--for-finding",
        dest="for_findings",
        action="append",
        metavar="SLUG",
        default=[],
        help="Finding this run is being started to verify (repeatable). Persists a "
             "proof_run association after run creation. Each slug's author "
             "is read BEFORE the run is created and refused when it is the --agent-id "
             "dispatch: the author dispatch cannot also verify, so receipts from "
             "such a run could never carry a terminal decision. Naming the findings here "
             "costs a read; discovering it at `finding verify` costs the whole proof run, "
             "target traffic included.",
    )
    start.add_argument("--target-identity-file")
    start.add_argument("--source-generations-file")
    start.add_argument("--exclusions-file")
    start.add_argument("--resume-from", type=int)
    start.set_defaults(func=_run_start)

    begin = actions.add_parser(
        "begin", help="Transition a queued scan run to running."
    )
    begin.add_argument("run_id", type=int)
    begin.set_defaults(func=_run_begin)

    finish = actions.add_parser(
        "finish", help="Transition a running proof run to a terminal status."
    )
    finish.add_argument("run_id", type=int)
    finish.add_argument("--status", required=True, choices=_TERMINAL_STATUSES)
    finish.set_defaults(func=_run_finish)

    get = actions.add_parser("get", help="Read one proof run by numeric id.")
    get.add_argument("run_id", type=int)
    get.set_defaults(func=_run_get)

    listing = actions.add_parser("list", help="List a bounded page of proof runs.")
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


def _require_run(
    value: object,
    *,
    operation: str,
    requested_id: int | None = None,
    requested_uuid: str | None = None,
    requested_status: str | None = None,
    requested_agent_id: str | None = None,
    requested_purpose: str | None = None,
) -> dict:
    if not isinstance(value, dict):
        raise AssessError(f"proof-run {operation}: malformed run response")
    run_id = value.get("id")
    producer_id = value.get("producer_dispatch_id")
    valid = (
        isinstance(run_id, int)
        and not isinstance(run_id, bool)
        and run_id > 0
        and isinstance(producer_id, int)
        and not isinstance(producer_id, bool)
        and producer_id > 0
        and isinstance(value.get("producer_dispatch_agent_id"), str)
        and bool(value["producer_dispatch_agent_id"].strip())
        and isinstance(value.get("run_uuid"), str)
        and bool(value["run_uuid"].strip())
        and value.get("run_kind") in _RUN_KINDS
        and value.get("status") in _RUN_STATUSES
    )
    if requested_id is not None:
        valid = valid and run_id == requested_id
    if requested_uuid is not None:
        valid = valid and value.get("run_uuid") == requested_uuid
    if requested_status is not None:
        valid = valid and value.get("status") == requested_status
    if requested_agent_id is not None:
        valid = (
            valid
            and value.get("producer_dispatch_agent_id") == requested_agent_id
        )
    if requested_purpose is not None:
        valid = valid and value.get("run_purpose") == requested_purpose
    if not valid:
        suffix = (
            "; the write may have committed, so inspect durable state and do not "
            "retry automatically"
            if operation in {"start", "begin", "finish"}
            else ""
        )
        raise AssessError(
            f"proof-run {operation}: backend response did not identify the canonical run{suffix}"
        )
    return value


def _require_run_rows(value: object) -> list[dict]:
    if not isinstance(value, list):
        raise AssessError("proof-run list: malformed run list response")
    return [
        _require_run(row, operation="list")
        for row in value
    ]


def _load_json_file(
    raw_path: str | None, *, description: str, expected_type: type
) -> object | None:
    if raw_path is None:
        return None
    path = Path(raw_path).expanduser()
    if not path.is_file():
        raise AssessError(f"proof-run start: {description} file not found: {raw_path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AssessError(
            f"proof-run start: invalid {description} JSON file {raw_path}: {exc}"
        ) from exc
    if not isinstance(value, expected_type):
        raise AssessError(
            f"proof-run start: {description} JSON must be a{'' if expected_type is list else 'n'} "
            f"{expected_type.__name__}"
        )
    if expected_type is list and any(not isinstance(item, dict) for item in value):
        raise AssessError(
            f"proof-run start: {description} JSON entries must be objects"
        )
    return value


def _require_independent_verifier(
    client, agent_id: str, finding_slugs: list[str]
) -> None:
    """Refuse a proof run the named findings' author would own.

    ``record_finding_verification_evidence`` enforces this at the final write,
    where it is authoritative and stays exactly as strict. By then the run has
    executed against the target, so the identical refusal is worth repeating at
    the point it costs nothing but a read.
    """

    for slug in finding_slugs:
        try:
            finding = client.get(f"findings/{slug}")
        except AssessError as exc:
            if "HTTP 404" not in str(exc):
                raise
            finding = None
        if not isinstance(finding, dict) or not finding.get("slug"):
            raise AssessError(
                f"proof-run start: --for-finding {slug} does not resolve to a finding "
                "in this engagement"
            )
        provenance = finding.get("provenance")
        author = (
            str(provenance.get("agent_id") or "").strip()
            if isinstance(provenance, dict)
            else ""
        )
        if not author:
            raise AssessError(
                f"proof-run start: REFUSED — {slug} has no durable author "
                "(provenance.agent_id), so no run can establish an independent verifier "
                "for it. Repair it once with `vigil assess finding bind-author` before "
                "spending proof effort on it."
            )
        if author == agent_id:
            raise AssessError(
                f"proof-run start: REFUSED — {slug} was authored by dispatch {author!r}, "
                "which is the dispatch this run would produce evidence under. A finding's "
                "author cannot be its own verifier, so this run's receipts could never "
                "carry a terminal decision on it. Start the run from an independent "
                "verifier dispatch, or drop --for-finding "
                f"{slug} if this run is not verifying it."
            )


def _run_start(args) -> None:
    purpose = str(args.purpose)
    payload = {
        "run_uuid": str(args.run_uuid),
        "run_kind": str(args.kind),
        "run_purpose": purpose,
        "producer_dispatch_agent_id": str(args.agent_id),
    }
    structured = (
        (
            "target_identity",
            _load_json_file(
                args.target_identity_file,
                description="target identity",
                expected_type=dict,
            ),
        ),
        (
            "source_generations",
            _load_json_file(
                args.source_generations_file,
                description="source generations",
                expected_type=list,
            ),
        ),
        (
            "exclusions",
            _load_json_file(
                args.exclusions_file,
                description="exclusions",
                expected_type=list,
            ),
        ),
    )
    for field, value in structured:
        if value is not None:
            payload[field] = value
    if args.resume_from is not None:
        if int(args.resume_from) < 1:
            raise AssessError("proof-run start: --resume-from must be positive")
        payload["resumed_from_run_id"] = int(args.resume_from)
    with _client(args) as client:
        _require_independent_verifier(
            client,
            payload["producer_dispatch_agent_id"],
            [str(slug) for slug in (getattr(args, "for_findings", None) or [])],
        )
        response = client.post("assessment-runs", payload)
    expected_status = "queued" if purpose == "scan" else "running"
    row = _require_run(
        response,
        operation="start",
        requested_uuid=payload["run_uuid"],
        requested_status=expected_status,
        requested_agent_id=payload["producer_dispatch_agent_id"],
        requested_purpose=purpose,
    )
    require_write_result(
        row,
        operation="proof-run start",
        expected={
            **payload,
            "status": expected_status,
        },
        positive_ids=("id", "producer_dispatch_id"),
    )
    for slug in dict.fromkeys(getattr(args, "for_findings", None) or []):
        link_payload = {
            "link_kind": "proof_run",
            "target_kind": "assessment_run",
            "target_id": row["id"],
        }
        try:
            with _client(args) as client:
                link = client.post(f"findings/{slug}/links", link_payload)
            if not isinstance(link, dict) or any(
                link.get(key) != value for key, value in link_payload.items()
            ):
                raise AssessError("backend did not confirm the proof_run association")
        except AssessError as exc:
            raise AssessError(
                f"proof-run start: run {row['id']} was created, but association "
                f"to {slug} is incomplete: {exc}. Inspect the durable link and "
                f"recover with `vigil assess finding link {slug} --link-kind "
                f"proof_run --target-kind assessment_run --target-id {row['id']}`"
            ) from exc
    print(json.dumps(row, indent=2, ensure_ascii=False))


def _transition_run(args, *, operation: str, status: str) -> None:
    run_id = int(args.run_id)
    with _client(args) as client:
        response = client.patch(f"assessment-runs/{run_id}", {"status": status})
    effective_status = status
    if operation == "finish" and status == "completed" and isinstance(response, dict):
        seal = response.get("seal")
        if response.get("status") == "partial" and (
            isinstance(seal, dict)
            and seal.get("requested_status") == "completed"
            and seal.get("effective_status") == "partial"
            and isinstance(seal.get("blockers"), list)
            and bool(seal["blockers"])
        ):
            effective_status = "partial"
    row = _require_run(
        response,
        operation=operation,
        requested_id=run_id,
        requested_status=effective_status,
    )
    require_write_result(
        row,
        operation=f"proof-run {operation}",
        expected={"id": run_id, "status": effective_status},
        positive_ids=("producer_dispatch_id",),
    )
    print(json.dumps(row, indent=2, ensure_ascii=False))


def _run_begin(args) -> None:
    _transition_run(args, operation="begin", status="running")


def _run_finish(args) -> None:
    _transition_run(args, operation="finish", status=str(args.status))


def _run_get(args) -> None:
    run_id = int(args.run_id)
    with _client(args) as client:
        response = client.get(f"assessment-runs/{run_id}")
    row = _require_run(response, operation="get", requested_id=run_id)
    print(json.dumps(row, indent=2, ensure_ascii=False))


def _run_list(args) -> None:
    limit = int(args.limit)
    offset = int(args.offset)
    client = _client(args)
    try:
        if args.paginate:
            rows: list[dict] = []
            next_offset = offset
            while True:
                page_rows = _require_run_rows(
                    client.get(
                        f"assessment-runs?limit={limit}&offset={next_offset}"
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
            rows = _require_run_rows(
                client.get(
                    f"assessment-runs?limit={request_limit}&offset={offset}"
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

    report_page(
        page,
        noun="proof runs",
        continuation_command=(
            f"vigil assess proof-run list --limit {limit} "
            f"--offset {page.offset + len(page.rows)}"
        ),
        point_read_hint="`vigil assess proof-run get <id>`",
    )
    print(json.dumps(page.rows, indent=2, ensure_ascii=False))
