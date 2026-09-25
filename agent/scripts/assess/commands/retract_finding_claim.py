"""vigil assess finding retract-claim — correct a claim without erasing proof."""
from __future__ import annotations

import json
import sys
from urllib.parse import quote

from assess.lib.client import AssessmentClient, require_finding_write_response
from assess.lib.config import load_config


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "retract-claim",
        help="Replace an incorrect summary while preserving evidence and correction history",
    )
    parser.add_argument("finding_slug", help="Canonical finding slug")
    parser.add_argument(
        "--replacement-summary",
        required=True,
        help="Corrected current claim; must differ from the stored summary",
    )
    parser.add_argument(
        "--reason",
        required=True,
        help="Why the prior claim is being retracted",
    )
    parser.add_argument(
        "--retracted-text",
        help="Exact phrase to locate in current authored report text after correction "
             "(defaults to the entire prior summary)",
    )
    parser.add_argument(
        "--source-name",
        default="operator",
        help="Actor authoring the correction history entry (default: operator)",
    )
    parser.set_defaults(func=run)


def _fail(message: str) -> None:
    print(f"finding retract-claim: {message}", file=sys.stderr)
    sys.exit(1)


def _correction_history(current: dict, entry: dict) -> list:
    details = current.get("details")
    if details is None:
        details = {}
    if not isinstance(details, dict):
        _fail("backend returned malformed details; refusing to replace audit metadata")

    prior = details.get("correction_history")
    if prior in (None, ""):
        history: list = []
    elif isinstance(prior, list):
        history = list(prior)
    elif isinstance(prior, str):
        history = [prior]
    else:
        _fail(
            "stored details.correction_history is neither a string nor an array; "
            "refusing to overwrite it"
        )
    history.append(entry)
    return history


_CURRENT_REPORT_FIELDS = (
    "evidence", "impact", "exploitability", "proof", "attack_scenario",
    "steps_to_reproduce", "remediation", "poc_description",
)


def _surviving_claim_locations(finding: dict, phrase: str) -> list[str]:
    needle = phrase.casefold()
    locations: list[str] = []

    def check(path: str, value: object) -> None:
        if isinstance(value, str) and needle in value.casefold():
            excerpt = next(
                (line.strip() for line in value.splitlines() if needle in line.casefold()),
                value.strip(),
            )
            locations.append(f'{path}: "{excerpt}"')
        elif isinstance(value, list):
            for index, item in enumerate(value, start=1):
                check(f"{path} step {index}", item)

    for field in ("title", "summary"):
        check(field, finding.get(field))
    details = finding.get("details")
    if isinstance(details, dict):
        for field in _CURRENT_REPORT_FIELDS:
            check(f"details.{field}", details.get(field))
    return locations


def run(args) -> None:
    replacement = str(args.replacement_summary).strip()
    reason = str(args.reason).strip()
    source_name = str(args.source_name).strip()
    if not replacement:
        _fail("--replacement-summary must not be empty")
    if not reason:
        _fail("--reason must not be empty")
    if not source_name:
        _fail("--source-name must not be empty")
    retracted_text = str(args.retracted_text or "").strip()

    cfg = load_config(args.engagement_dir)
    requested_slug = str(args.finding_slug)
    slug = quote(requested_slug, safe="")
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        current = client.get(f"findings/{slug}")
        if not isinstance(current, dict):
            _fail("backend did not return a finding object")

        canonical_slug = str(current.get("slug") or requested_slug)
        prior_claim = current.get("summary")
        if not isinstance(prior_claim, str) or not prior_claim.strip():
            _fail("stored finding has no current summary to retract")
        if replacement == prior_claim.strip():
            _fail("--replacement-summary must differ from the current summary")
        if not retracted_text:
            retracted_text = prior_claim.strip()

        row_version = current.get("row_version")
        if (
            not isinstance(row_version, int)
            or isinstance(row_version, bool)
            or row_version < 1
        ):
            _fail("backend did not return a positive row_version")

        entry = {
            "finding_slug": canonical_slug,
            "field": "summary",
            "retracted_claim": prior_claim,
            "replacement_claim": replacement,
            "reason": reason,
            "source_name": source_name,
        }
        payload = {
            "summary": replacement,
            "details": {"correction_history": _correction_history(current, entry)},
            "details_mode": "merge",
            "reason_code": "claim_retracted",
            "reason_text": reason,
            "source_name": source_name,
            "expected_row_version": row_version,
        }
        response = require_finding_write_response(
            client.patch(f"findings/{slug}", payload),
            finding_slug=canonical_slug,
            operation="finding retract-claim",
        )

    finding = response.get("finding") if isinstance(response, dict) else None
    if isinstance(finding, dict):
        for location in _surviving_claim_locations(finding, retracted_text):
            print(
                f"finding retract-claim: current text still contains the retracted "
                f"phrase at {location}; review this field before publication",
                file=sys.stderr,
            )
    print(json.dumps(response, indent=2, ensure_ascii=False))
