"""vigil assess resolve — PATCH a surface OR a coverage item by id.

One verb with a target-kind positional (``surface`` | ``coverage-item``). It
absorbed the former ``resolve-surface`` + ``resolve-coverage-item`` — two
near-identical batch PATCH-by-id verbs differing only in target table + status
vocabulary. Post-1b (recording drains work-items + advances surfaces by default)
this is the manual-override / negative-verdict path: ``not_applicable`` /
``deferred`` / ``blocked``, or a deliberate rationale-bearing ``covered``.

Usage::

    vigil assess resolve surface <id...> --status covered --rationale "..."
    vigil assess resolve coverage-item <id...> --status not_applicable --rationale "..."

Each target-kind keeps its OWN status vocabulary and the batch/rationale
semantics (rationale required, appended to the existing rationale/notes; a
resilient per-id loop with a failure tally). ``--followup-condition`` is required
for ``surface --status partially-covered``.
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.config import load_config
from assess.lib.contracts import add_contract_subparser, render_contract_epilog
from assess.lib.surfaces import RESOLVABLE_STATUSES

# Coverage-item status vocabulary. Mirrors backend CoverageStatus (coverage.py);
# the CLI cannot import the backend, so it is kept in sync by the backend
# drift-guard test (test_coverage_probe_cli_sync) — same pattern as
# lib/surfaces.py for surface statuses.
_COVERAGE_STATUSES = ("pending", "queued", "deferred", "covered", "not_applicable", "blocked")


def register(subparsers) -> None:
    surface_statuses = ", ".join(sorted(RESOLVABLE_STATUSES))
    coverage_statuses = ", ".join(_COVERAGE_STATUSES)
    p = add_contract_subparser(
        subparsers,
        "resolve",
        contract_name="resolve",
        help="PATCH a surface or coverage-item by id (set status + rationale).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("resolve"),
    )
    p.add_argument(
        "target_kind",
        choices=("surface", "coverage-item"),
        help="What to resolve: 'surface' (assessment_surfaces) or 'coverage-item' (assessment_coverage_items).",
    )
    p.add_argument(
        "ids",
        nargs="+",
        help="One or more backend row ids. Batch: every listed id gets the same "
             "--status/--rationale/flags (resilient loop with a per-id failure tally).",
    )
    p.add_argument(
        "--status",
        required=True,
        help=(
            "New status. surface: " + surface_statuses + ". "
            "coverage-item: " + coverage_statuses + ". Case-insensitive."
        ),
    )
    p.add_argument(
        "--rationale",
        required=True,
        help="Reason for the resolution; appended to the existing rationale/notes for the audit trail. Required.",
    )
    p.add_argument(
        "--source-name",
        default="",
        help="(surface only) Optional override for source_name (defaults to keeping the existing value).",
    )
    p.add_argument(
        "--evidence-ref",
        default="",
        help="(surface only) Optional new evidence reference (e.g. command-run id, scan path).",
    )
    p.add_argument(
        "--followup-condition",
        default="",
        help=(
            "(surface only) Required when --status=partially-covered: one-line "
            "description of the condition the follow-up coverage pass must satisfy."
        ),
    )
    p.set_defaults(func=run)


def _fail(message: str) -> None:
    """Print a reasoned rejection to stderr and exit non-zero."""
    print(message, file=sys.stderr)
    sys.exit(1)


def _normalize_status(target_kind: str, raw: str) -> str:
    """Normalize a status token per target-kind, preserving each vocabulary.

    surface statuses are lowercased only (``partially-covered`` keeps its hyphen);
    coverage-item statuses additionally fold ``-`` → ``_`` (``NOT-APPLICABLE`` →
    ``not_applicable``), matching the former per-verb ``type=`` normalizers.
    """
    value = (raw or "").strip().lower()
    if target_kind == "coverage-item":
        return value.replace("-", "_")
    return value


def _validate(target_kind: str, status: str) -> None:
    if target_kind == "surface":
        valid_set = RESOLVABLE_STATUSES
        valid = ", ".join(sorted(RESOLVABLE_STATUSES))
    else:
        valid_set = frozenset(_COVERAGE_STATUSES)
        valid = ", ".join(_COVERAGE_STATUSES)
    if status not in valid_set:
        _fail(
            f"resolve {target_kind}: invalid status {status!r}. "
            f"Valid {target_kind} statuses: {valid}. "
            "See: vigil assess contract resolve."
        )


def _endpoint(target_kind: str, row_id: str) -> str:
    return f"surfaces/{row_id}" if target_kind == "surface" else f"coverage-items/{row_id}"


def _payload(target_kind: str, args, status: str) -> dict:
    if target_kind == "surface":
        payload: dict = {"status": status, "rationale": args.rationale}
        if args.source_name:
            payload["source_name"] = args.source_name
        if args.evidence_ref:
            payload["evidence_ref"] = args.evidence_ref
        if args.followup_condition:
            payload["followup_condition"] = args.followup_condition
        return payload
    # coverage-item: rationale is appended to the item's notes.
    return {"status": status, "notes": args.rationale}


def run(args) -> None:
    target_kind = args.target_kind
    status = _normalize_status(target_kind, args.status)
    _validate(target_kind, status)
    if not args.rationale.strip():
        _fail("--rationale must be non-empty")
    if (
        target_kind == "surface"
        and status == "partially-covered"
        and not args.followup_condition.strip()
    ):
        _fail(
            "--followup-condition is required when resolving a surface to "
            "partially-covered (one-line description of what the follow-up "
            "coverage pass must satisfy)"
        )
    # Surface-only flags on a coverage-item are a caller mistake; reject loudly
    # rather than silently dropping them.
    if target_kind == "coverage-item":
        for flag_val, flag_name in (
            (args.source_name, "--source-name"),
            (args.evidence_ref, "--evidence-ref"),
            (args.followup_condition, "--followup-condition"),
        ):
            if flag_val:
                _fail(f"{flag_name} is only valid for `resolve surface`, not `resolve coverage-item`")

    payload = _payload(target_kind, args, status)
    noun = "surface" if target_kind == "surface" else "item"

    cfg = load_config(args.engagement_dir)
    records: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for row_id in args.ids:
            endpoint = _endpoint(target_kind, row_id)
            try:
                record = require_write_result(
                    client.patch(endpoint, payload),
                    operation=f"resolve {target_kind} {row_id}",
                    expected={"id": int(row_id), "status": status},
                )
            except Exception as exc:  # noqa: BLE001 - one bad id must not drop the rest
                failed += 1
                print(f"resolve {target_kind}: {row_id} failed: {exc}", file=sys.stderr)
                continue
            records.append(record)

    if len(args.ids) == 1 and records:
        print(json.dumps(records[0], indent=2, ensure_ascii=False))
    else:
        for record in records:
            print(json.dumps(record, ensure_ascii=False))
        print(
            f"[resolve {target_kind}] resolved {len(records)} {noun}(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
