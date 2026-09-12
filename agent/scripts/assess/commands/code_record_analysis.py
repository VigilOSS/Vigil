"""vigil assess code-record analysis — POST grouped source-review receipts."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from assess.lib.code_audit import write_json_snapshot
from assess.lib.client import AssessmentClient, AssessError, require_write_result
from assess.lib.config import load_config


def _validate_cwe_coverage(item_index: int, result: dict) -> None:
    cwe_coverage = result.get("cwe_coverage", [])
    if cwe_coverage in (None, []):
        return
    if not isinstance(cwe_coverage, list):
        print(f"Item {item_index} cwe_coverage must be a JSON array", file=sys.stderr)
        sys.exit(1)
    seen_families: set[str] = set()
    for idx, entry in enumerate(cwe_coverage):
        if not isinstance(entry, dict):
            print(f"Item {item_index} cwe_coverage entry {idx} must be a JSON object", file=sys.stderr)
            sys.exit(1)
        family = str(entry.get("family", "")).strip()
        if not family:
            print(f"Item {item_index} cwe_coverage entry {idx} is missing family", file=sys.stderr)
            sys.exit(1)
        if family in seen_families:
            print(f"Item {item_index} cwe_coverage has duplicate family: {family}", file=sys.stderr)
            sys.exit(1)
        seen_families.add(family)
        if "effort" in entry:
            try:
                float(entry.get("effort", 0))
            except (TypeError, ValueError):
                print(
                    f"Item {item_index} cwe_coverage entry {idx} has a non-numeric effort",
                    file=sys.stderr,
                )
                sys.exit(1)


def _validate_cross_file_triggers(item_index: int, result: dict) -> None:
    triggers = result.get("cross_file_triggers", [])
    if triggers in (None, []):
        return
    if not isinstance(triggers, list):
        print(f"Item {item_index} cross_file_triggers must be a JSON array", file=sys.stderr)
        sys.exit(1)
    for idx, trigger in enumerate(triggers):
        if not isinstance(trigger, dict):
            print(f"Item {item_index} cross_file_triggers entry {idx} must be a JSON object", file=sys.stderr)
            sys.exit(1)
        for field in ("file_path", "vuln_class", "reason"):
            if not str(trigger.get(field, "")).strip():
                print(
                    f"Item {item_index} cross_file_triggers entry {idx} is missing {field}",
                    file=sys.stderr,
                )
                sys.exit(1)


def _validate_source_receipt(item_index: int, result: dict) -> None:
    if "function_name" in result:
        print(
            f"Item {item_index} function_name is historical read/filter data; "
            "new writes require canonical callable_refs or reviewed_spans",
            file=sys.stderr,
        )
        sys.exit(1)
    receipt_kind = result.get("receipt_kind", "file")
    if receipt_kind not in {"file", "call_chain"}:
        print(f"Item {item_index} receipt_kind must be file or call_chain", file=sys.stderr)
        sys.exit(1)
    callable_refs = result.get("callable_refs", [])
    reviewed_spans = result.get("reviewed_spans", [])
    if not isinstance(callable_refs, list) or not isinstance(reviewed_spans, list):
        print(
            f"Item {item_index} callable_refs and reviewed_spans must be JSON arrays",
            file=sys.stderr,
        )
        sys.exit(1)
    if result.get("disposition") != "skipped" and not callable_refs and not reviewed_spans:
        print(
            f"Item {item_index} requires callable_refs or reviewed_spans",
            file=sys.stderr,
        )
        sys.exit(1)
    for collection_name, anchors, required_fields in (
        (
            "callable_refs",
            callable_refs,
            ("file_id", "name", "qualified_name", "start_line", "end_line"),
        ),
        ("reviewed_spans", reviewed_spans, ("file_id", "start_line", "end_line")),
    ):
        for anchor_index, anchor in enumerate(anchors):
            if not isinstance(anchor, dict):
                print(
                    f"Item {item_index} {collection_name} entry {anchor_index} "
                    "must be a JSON object",
                    file=sys.stderr,
                )
                sys.exit(1)
            missing = [field for field in required_fields if field not in anchor]
            if missing:
                print(
                    f"Item {item_index} {collection_name} entry {anchor_index} is missing "
                    + ", ".join(missing),
                    file=sys.stderr,
                )
                sys.exit(1)
            start_line = anchor.get("start_line")
            end_line = anchor.get("end_line")
            if (
                type(anchor.get("file_id")) is not int
                or type(start_line) is not int
                or type(end_line) is not int
                or anchor["file_id"] < 1
                or start_line < 1
                or end_line < start_line
            ):
                print(
                    f"Item {item_index} {collection_name} entry {anchor_index} "
                    "has an invalid file/span identity",
                    file=sys.stderr,
                )
                sys.exit(1)


def _require_canonical_source_receipt_response(
    response: dict, *, submitted: dict
) -> None:
    returned_refs = response.get("callable_refs")
    returned_spans = response.get("reviewed_spans")
    submitted_refs = submitted.get("callable_refs", [])
    submitted_spans = submitted.get("reviewed_spans", [])
    expected_binding_status = (
        "structural"
        if submitted_refs
        else "source_span"
        if submitted_spans
        else "skipped_unbound"
    )
    canonical_shape = isinstance(returned_refs, list) and isinstance(
        returned_spans, list
    )
    if canonical_shape:
        canonical_shape = all(
            isinstance(ref, dict)
            and isinstance(ref.get("file_path"), str)
            and bool(ref["file_path"])
            and isinstance(ref.get("callable_key"), str)
            and re.fullmatch(r"[0-9a-f]{64}", ref["callable_key"]) is not None
            for ref in returned_refs
        ) and all(
            isinstance(span, dict)
            and isinstance(span.get("file_path"), str)
            and bool(span["file_path"])
            and isinstance(span.get("label"), str)
            for span in returned_spans
        )
    submitted_ref_identities = [
        (
            ref.get("file_id"),
            ref.get("name"),
            ref.get("qualified_name"),
            ref.get("start_line"),
            ref.get("end_line"),
        )
        for ref in submitted_refs
    ]
    returned_ref_identities = (
        [
            (
                ref.get("file_id"),
                ref.get("name"),
                ref.get("qualified_name"),
                ref.get("start_line"),
                ref.get("end_line"),
            )
            for ref in returned_refs
        ]
        if isinstance(returned_refs, list)
        else []
    )
    submitted_span_identities = [
        (
            span.get("file_id"),
            span.get("start_line"),
            span.get("end_line"),
            str(span.get("label") or ""),
        )
        for span in submitted_spans
    ]
    returned_span_identities = (
        [
            (
                span.get("file_id"),
                span.get("start_line"),
                span.get("end_line"),
                span.get("label"),
            )
            for span in returned_spans
        ]
        if isinstance(returned_spans, list)
        else []
    )
    if (
        not canonical_shape
        or response.get("receipt_binding_status") != expected_binding_status
        or returned_ref_identities != submitted_ref_identities
        or returned_span_identities != submitted_span_identities
    ):
        raise AssessError(
            "record code analysis source receipt: backend did not return the "
            "canonical submitted callable_refs, reviewed_spans, and binding status; "
            "the write may have committed, so inspect durable state and do not retry "
            "automatically"
        )


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "analysis",
        help="Record grouped source-review receipts from code-vuln-hunter",
    )
    p.add_argument(
        "analysis_json",
        help="Path to JSON file with a single result object or array of result objects",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.analysis_json)
    if not json_path.is_file():
        print(f"Analysis JSON file not found: {args.analysis_json}", file=sys.stderr)
        sys.exit(1)

    raw = json.loads(json_path.read_text(encoding="utf-8"))

    # Accept either a single object or an array
    if isinstance(raw, dict):
        results = [raw]
    elif isinstance(raw, list):
        results = raw
    else:
        print("Analysis file must contain a JSON object or array", file=sys.stderr)
        sys.exit(1)

    if not results:
        print("No analysis results to submit.", file=sys.stderr)
        sys.exit(0)

    # Validate required fields
    required = {"queue_item_id", "agent_name", "lease_token", "disposition"}
    for i, result in enumerate(results):
        if not isinstance(result, dict):
            print(f"Item {i} is not a JSON object", file=sys.stderr)
            sys.exit(1)
        missing = required - set(result.keys())
        if missing:
            print(
                f"Item {i} missing required fields: {', '.join(sorted(missing))}",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            int(result["queue_item_id"])
        except (TypeError, ValueError):
            print(f"Item {i} queue_item_id must be an integer", file=sys.stderr)
            sys.exit(1)
        if result.get("file_id") is not None:
            try:
                int(result["file_id"])
            except (TypeError, ValueError):
                print(f"Item {i} file_id must be an integer when supplied", file=sys.stderr)
                sys.exit(1)
        _validate_cwe_coverage(i, result)
        _validate_cross_file_triggers(i, result)
        _validate_source_receipt(i, result)

    cfg = load_config(args.engagement_dir)
    submit_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-analysis-submit",
        label=json_path.stem,
        payload=results,
        source_path=str(json_path),
        metadata={"command": "code-record-analysis", "count": len(results)},
    )
    responses = []
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        created = 0
        for result in results:
            resp = client.post("code/analysis-results", result)
            expected = {
                "queue_item_id": int(result["queue_item_id"]),
                "agent_name": result["agent_name"],
                "lease_token": result["lease_token"],
                "disposition": result["disposition"],
                "receipt_kind": result.get("receipt_kind", "file"),
            }
            if result.get("file_id") is not None:
                expected["file_id"] = int(result["file_id"])
            require_write_result(
                resp,
                operation="record code analysis result",
                expected=expected,
                positive_ids=("id",),
            )
            _require_canonical_source_receipt_response(resp, submitted=result)
            responses.append(resp)
            created += 1
            disp = result.get("disposition", "?")
            callable_count = len(resp["callable_refs"])
            span_count = len(resp["reviewed_spans"])
            print(
                f"  Recorded: {result.get('receipt_kind', 'file')} receipt "
                f"({callable_count} callables, {span_count} spans; "
                f"binding={resp['receipt_binding_status']}) → {disp}"
            )

    response_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-analysis-response",
        label=json_path.stem,
        payload=responses,
        source_path=str(submit_snapshot),
        metadata={"command": "code-record-analysis", "count": len(results)},
    )

    print("\n=== Analysis Results Summary ===")
    print(f"Results recorded: {created}")
    print(f"Audit snapshots: {submit_snapshot.name}, {response_snapshot.name}")

    # Count dispositions
    dispositions = {}
    for r in results:
        d = r.get("disposition", "unknown")
        dispositions[d] = dispositions.get(d, 0) + 1
    for d, count in sorted(dispositions.items()):
        print(f"  {d}: {count}")
