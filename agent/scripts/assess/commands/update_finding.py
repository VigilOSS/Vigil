"""assess.py update-finding — finding-specific PATCH helper."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.findings import sync_finding_markdown, update_finding_count
from assess.lib.json_inputs import parse_json_argument, parse_optional_inline_json


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "update-finding",
        aliases=["patch-finding"],
        help="PATCH a finding by slug using a payload file, inline JSON, or common flags",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  assess.py update-finding FINDING-VA-001 payload.json\n"
            "  assess.py update-finding FINDING-VA-001 --status active --severity low "
            "--reason \"Manual review reduced impact\"\n"
            "  assess.py patch-finding FINDING-VA-001 --inline "
            "'{\"workflow_status\":\"draft\",\"reason_text\":\"Needs more evidence\"}'\n\n"
            "See also:\n"
            "  assess.py contract update-finding"
        ),
    )
    p.add_argument("finding_slug", help="Canonical finding slug")
    p.add_argument("payload", nargs="?", help="Path to JSON patch payload or inline JSON object")
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON patch payload")
    p.add_argument("--title")
    p.add_argument("--severity")
    p.add_argument("--workflow-status", "--status", dest="workflow_status")
    p.add_argument("--defect-family")
    p.add_argument("--root-cause-key")
    p.add_argument("--auth-context")
    p.add_argument("--canonical-location")
    p.add_argument("--summary")
    p.add_argument("--evidence-ref")
    p.add_argument("--notes")
    p.add_argument("--source-name")
    p.add_argument("--reason-code", default="")
    p.add_argument("--reason", dest="reason_text", default="")
    p.add_argument("--artifact-ref", default="")
    p.add_argument("--details-inline", help="Inline JSON object for details")
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance")
    p.set_defaults(func=run)


def _sync_findings_file(engagement_dir: str | Path, result: dict) -> None:
    findings_file = Path(engagement_dir) / "findings.md"
    finding = result.get("finding")
    if isinstance(finding, dict) and findings_file.is_file():
        sync_finding_markdown(str(findings_file), finding)
        update_finding_count(str(findings_file))


def run(args) -> None:
    raw_payload = args.inline_payload if args.inline_payload is not None else args.payload
    if raw_payload is not None:
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=args.inline_payload is not None,
                description="finding patch payload",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        try:
            details = parse_optional_inline_json(
                args.details_inline,
                default=None,
                description="details JSON",
            )
            provenance = parse_optional_inline_json(
                args.provenance_inline,
                default=None,
                description="provenance JSON",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        if details is not None and not isinstance(details, dict):
            print("details JSON must be an object", file=sys.stderr)
            sys.exit(1)
        if provenance is not None and not isinstance(provenance, dict):
            print("provenance JSON must be an object", file=sys.stderr)
            sys.exit(1)
        payload = {
            "title": args.title,
            "severity": args.severity,
            "workflow_status": args.workflow_status,
            "defect_family": args.defect_family,
            "root_cause_key": args.root_cause_key,
            "auth_context": args.auth_context,
            "canonical_location": args.canonical_location,
            "summary": args.summary,
            "evidence_ref": args.evidence_ref,
            "notes": args.notes,
            "source_name": args.source_name,
            "details": details,
            "provenance": provenance,
            "reason_code": args.reason_code,
            "reason_text": args.reason_text,
            "artifact_ref": args.artifact_ref,
        }
        payload = {key: value for key, value in payload.items() if value is not None}
        if not any(value not in ("", None) for value in payload.values()):
            print(
                "update-finding requires a payload file, --inline JSON, or at least one patch flag",
                file=sys.stderr,
            )
            sys.exit(1)

    if not isinstance(payload, dict):
        print("finding patch payload must be a JSON object", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.patch(f"findings/{args.finding_slug}", payload)
    finally:
        client.close()

    _sync_findings_file(cfg.engagement_dir, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
