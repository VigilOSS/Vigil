"""vigil assess code-record analysis — POST grouped source-review receipts."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from assess.lib.code_audit import write_json_snapshot
from assess.lib.client import AssessmentClient, AssessError, require_write_result
from assess.lib.config import load_config


def _validate_cwe_coverage(item_index: int, result: dict) -> list[str]:
    """Return every malformed coverage entry, for one report over the payload.

    `cwe_coverage` and `cross_file_triggers` are authored together in one file,
    so reporting all of one collection and only the first defect of the other
    still sends the author back for another read. Each validator therefore
    returns its problems and `run` reports them all once, in input order — a
    collection that is not an array is the one problem it can report, because
    nothing else about it can be walked.
    """
    cwe_coverage = result.get("cwe_coverage", [])
    if cwe_coverage in (None, []):
        return []
    if not isinstance(cwe_coverage, list):
        return [f"Item {item_index} cwe_coverage must be a JSON array"]
    seen_families: set[str] = set()
    problems: list[str] = []
    for idx, entry in enumerate(cwe_coverage):
        if not isinstance(entry, dict):
            problems.append(
                f"Item {item_index} cwe_coverage entry {idx} must be a JSON object"
            )
            continue
        family = str(entry.get("family", "")).strip()
        if not family:
            problems.append(
                f"Item {item_index} cwe_coverage entry {idx} is missing family"
            )
        elif family in seen_families:
            problems.append(
                f"Item {item_index} cwe_coverage has duplicate family: {family}"
            )
        else:
            seen_families.add(family)
        if "effort" in entry:
            try:
                float(entry.get("effort", 0))
            except (TypeError, ValueError):
                problems.append(
                    f"Item {item_index} cwe_coverage entry {idx} has a non-numeric effort"
                )
    return problems


# Keys a hunter plausibly writes in place of a canonical trigger key, mirroring
# `_CROSS_FILE_TRIGGER_KEY_ALIASES` in
# orchestrator/backend/app/services/code_analysis.py. Naming the near miss is
# what turns "missing file_path" on an entry that plainly carries a path into a
# one-read fix. They are reported, never accepted: a second accepted spelling
# would be a second vocabulary for the same durable obligation.
_TRIGGER_KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "file_path": ("target_path", "target_file_path", "path", "target", "file"),
    "vuln_class": ("vuln", "vulnerability_class", "class", "cwe", "family"),
    "reason": ("why", "rationale", "note", "notes", "description"),
}


def _validate_cross_file_triggers(item_index: int, result: dict) -> list[str]:
    """Return every malformed entry and every missing key in the collection.

    Exiting on the first problem charged one refused run per missing key per
    entry, and nothing about the payload changes between those runs — so every
    defect is knowable on the first read. Matches the backend's
    `_normalize_cross_file_triggers`, which reports them together too.
    """
    triggers = result.get("cross_file_triggers", [])
    if triggers in (None, []):
        return []
    if not isinstance(triggers, list):
        return [f"Item {item_index} cross_file_triggers must be a JSON array"]
    problems: list[str] = []
    for idx, trigger in enumerate(triggers):
        if not isinstance(trigger, dict):
            problems.append(
                f"Item {item_index} cross_file_triggers entry {idx} must be a JSON object"
            )
            continue
        for field in ("file_path", "vuln_class", "reason"):
            if str(trigger.get(field, "")).strip():
                continue
            aliases = [
                alias for alias in _TRIGGER_KEY_ALIASES[field] if alias in trigger
            ]
            hint = (
                f" (the entry carries {', '.join(repr(alias) for alias in aliases)}; "
                f"{field!r} is the one accepted spelling)"
                if aliases
                else ""
            )
            problems.append(
                f"Item {item_index} cross_file_triggers entry {idx} is missing {field}{hint}"
            )
    return problems


def _validate_source_receipt(item_index: int, result: dict) -> list[str]:
    """Return every receipt and anchor problem, and normalize what is sound.

    The anchors are authored in the same file as the collections above, so they
    answer to the same one-pass standard: every malformed anchor in both
    collections is named together. A callable ref spelled with the indexer's
    `line_start`/`line_end` is still rewritten in place to the canonical
    `start_line`/`end_line`, because `run` submits these dicts.
    """
    problems: list[str] = []
    if "function_name" in result:
        problems.append(
            f"Item {item_index} function_name is historical read/filter data; "
            "new writes require canonical callable_refs or reviewed_spans"
        )
    receipt_kind = result.get("receipt_kind", "file")
    if receipt_kind not in {"file", "call_chain"}:
        problems.append(f"Item {item_index} receipt_kind must be file or call_chain")
    callable_refs = result.get("callable_refs", [])
    reviewed_spans = result.get("reviewed_spans", [])
    if not isinstance(callable_refs, list) or not isinstance(reviewed_spans, list):
        problems.append(
            f"Item {item_index} callable_refs and reviewed_spans must be JSON arrays"
        )
        return problems
    empty_file_reviewed = result.get("empty_file_reviewed") is True
    if empty_file_reviewed and (
        result.get("disposition") != "clean" or callable_refs or reviewed_spans
    ):
        problems.append(
            f"Item {item_index} empty_file_reviewed requires clean with no anchors"
        )
    if (
        result.get("disposition") != "skipped"
        and not empty_file_reviewed
        and not callable_refs
        and not reviewed_spans
    ):
        problems.append(f"Item {item_index} requires callable_refs or reviewed_spans")
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
                problems.append(
                    f"Item {item_index} {collection_name} entry {anchor_index} "
                    "must be a JSON object"
                )
                continue
            if collection_name == "callable_refs" and (
                "line_start" in anchor or "line_end" in anchor
            ):
                if (
                    "start_line" in anchor
                    or "end_line" in anchor
                    or "line_start" not in anchor
                    or "line_end" not in anchor
                ):
                    problems.append(
                        f"Item {item_index} callable_refs entry {anchor_index} "
                        "must use one complete line range spelling"
                    )
                    continue
                anchor["start_line"] = anchor.pop("line_start")
                anchor["end_line"] = anchor.pop("line_end")
            missing = [field for field in required_fields if field not in anchor]
            if missing:
                problems.append(
                    f"Item {item_index} {collection_name} entry {anchor_index} is missing "
                    + ", ".join(missing)
                )
                continue
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
                problems.append(
                    f"Item {item_index} {collection_name} entry {anchor_index} "
                    "has an invalid file/span identity"
                )
    return problems


def _validate_supersedes(item_index: int, result: dict) -> list[str]:
    supersedes = result.get("supersedes")
    if supersedes is not None and (type(supersedes) is not int or supersedes < 1):
        return [
            f"Item {item_index} supersedes must be a positive integer analysis-result ID"
        ]
    return []


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
        else "empty_file"
        if submitted.get("empty_file_reviewed") is True
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
        "--supersede",
        type=int,
        metavar="QUEUE_ITEM_ID",
        help="Append a correction to a completed queue item's current receipt",
    )
    p.add_argument(
        "analysis_json",
        help="Path to JSON file with a single result object or array of result objects",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    supersede_queue_item_id = getattr(args, "supersede", None)
    if supersede_queue_item_id is not None and supersede_queue_item_id < 1:
        print("--supersede must be a positive queue item ID", file=sys.stderr)
        sys.exit(1)
    json_path = Path(args.analysis_json)
    if not json_path.is_file():
        print(f"Analysis JSON file not found: {args.analysis_json}", file=sys.stderr)
        sys.exit(1)

    raw = json.loads(json_path.read_text(encoding="utf-8"))

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

    # One grouped submission is one authoring sitting: item 0's missing field
    # must not hide item 7's, so every item is validated and the whole payload
    # is reported once. An item that cannot be walked contributes the one
    # problem that says so and the pass moves on to the next item.
    required = {"queue_item_id", "agent_name", "lease_token", "disposition"}
    problems: list[str] = []
    for i, result in enumerate(results):
        if not isinstance(result, dict):
            problems.append(f"Item {i} is not a JSON object")
            continue
        missing = required - set(result.keys())
        if missing:
            problems.append(
                f"Item {i} missing required fields: {', '.join(sorted(missing))}"
            )
        queue_item_id: int | None = None
        if "queue_item_id" in result:
            try:
                queue_item_id = int(result["queue_item_id"])
            except (TypeError, ValueError):
                problems.append(f"Item {i} queue_item_id must be an integer")
        if result.get("file_id") is not None:
            try:
                int(result["file_id"])
            except (TypeError, ValueError):
                problems.append(f"Item {i} file_id must be an integer when supplied")
        problems.extend(_validate_cwe_coverage(i, result))
        problems.extend(_validate_cross_file_triggers(i, result))
        problems.extend(_validate_source_receipt(i, result))
        problems.extend(_validate_supersedes(i, result))
        if (
            supersede_queue_item_id is not None
            and queue_item_id is not None
            and queue_item_id != supersede_queue_item_id
        ):
            problems.append(
                f"Item {i} queue_item_id must match --supersede {supersede_queue_item_id}"
            )
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    submit_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-analysis-submit",
        label=json_path.stem,
        payload=results,
        source_path=str(json_path),
        metadata={
            "command": "code-record analysis",
            "count": len(results),
            **({"supersede_queue_item_id": supersede_queue_item_id} if supersede_queue_item_id else {}),
        },
    )
    responses = []
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        created = 0
        current_by_queue: dict[int, list[dict]] = {}
        if supersede_queue_item_id is not None:
            current = client.get(
                f"code/analysis-results?queue_item_id={supersede_queue_item_id}"
            )
            if not isinstance(current, list) or not current:
                raise AssessError(
                    f"--supersede queue item {supersede_queue_item_id} has no current receipt"
                )
            current_by_queue[supersede_queue_item_id] = current
            if any(int(row.get("queue_item_id", -1)) != supersede_queue_item_id for row in current):
                raise AssessError("backend returned receipts for a different queue item")
        for result in results:
            submitted = dict(result)
            if supersede_queue_item_id is not None:
                current = current_by_queue[supersede_queue_item_id]
                current_ids = {int(row["id"]) for row in current}
                predecessor = submitted.get("supersedes")
                if predecessor is None:
                    if len(results) != 1 or len(current_ids) != 1:
                        raise AssessError(
                            "--supersede requires explicit supersedes IDs when correcting multiple receipts"
                        )
                    predecessor = next(iter(current_ids))
                    submitted["supersedes"] = predecessor
                if predecessor not in current_ids:
                    raise AssessError(
                        f"supersedes {predecessor} is not a current receipt for queue item {supersede_queue_item_id}"
                    )
                current_ids.remove(predecessor)
                current_by_queue[supersede_queue_item_id] = [
                    row for row in current if int(row["id"]) != predecessor
                ]
            resp = client.post("code/analysis-results", submitted)
            expected = {
                "queue_item_id": int(result["queue_item_id"]),
                "agent_name": result["agent_name"],
                "lease_token": result["lease_token"],
                "disposition": result["disposition"],
                "receipt_kind": result.get("receipt_kind", "file"),
            }
            if result.get("file_id") is not None:
                expected["file_id"] = int(result["file_id"])
            if submitted.get("supersedes") is not None:
                expected["supersedes"] = submitted["supersedes"]
            require_write_result(
                resp,
                operation="record code analysis result",
                expected=expected,
                positive_ids=("id",),
            )
            _require_canonical_source_receipt_response(resp, submitted=submitted)
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
        metadata={"command": "code-record analysis", "count": len(results)},
    )

    print("\n=== Analysis Results Summary ===")
    print(f"Results recorded: {created}")
    print(f"Audit snapshots: {submit_snapshot.name}, {response_snapshot.name}")

    dispositions = {}
    for r in results:
        d = r.get("disposition", "unknown")
        dispositions[d] = dispositions.get(d, 0) + 1
    for d, count in sorted(dispositions.items()):
        print(f"  {d}: {count}")
