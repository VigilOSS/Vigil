"""vigil assess verify-finding — dedicated verifier flow for canonical findings."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog
from assess.lib.json_inputs import parse_json_argument, parse_optional_inline_json


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "verify-finding",
        help="Verify a finding with a JSON payload file, inline JSON, or explicit flags",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("verify-finding"),
    )
    p.add_argument("finding_slug", help="Canonical finding slug to verify")
    p.add_argument("payload", nargs="?", help="Path to JSON verification payload or inline JSON object")
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON verification payload")
    p.add_argument(
        "--disposition",
        choices=("confirmed", "downgraded", "pending_runtime_proof", "blocked", "false_positive", "disputed"),
        help=(
            "Verification action when building the payload from flags. 'blocked' "
            "requires a block_reason (pass via --details-inline '{\"block_reason\": \"...\"}' "
            "or already present on the finding) and holds the finding out of the report. "
            "'disputed' sets verification_state=disputed and leaves verification_disposition "
            "at 'none' (it is never stored as a disposition)."
        ),
    )
    p.add_argument("--reason", dest="reason_text", help="Required verification rationale when building payload from flags")
    p.add_argument("--reason-code", default="", help="Optional machine-readable reason code")
    p.add_argument("--new-severity", help="Required for downgraded verification")
    p.add_argument("--evidence-ref", default="", help="Optional evidence reference")
    p.add_argument("--artifact-ref", default="", help="Optional artifact reference")
    p.add_argument(
        "--narrative",
        default="",
        help=(
            "Optional path to a verification/debate narrative (e.g. an "
            "Ideator-vs-Tracer debate doc). Registered as a "
            "kind=verification-narrative artifact linked to this finding."
        ),
    )
    p.add_argument("--notes", default="", help="Optional verification notes")
    p.add_argument("--source-name", default="", help="Optional source/agent name")
    p.add_argument("--details-inline", help="Inline JSON object merged into the details payload")
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance metadata")
    p.add_argument("--kill-reason", help="False-positive kill reason; stored as details.kill_reason")
    p.add_argument("--kill-check", type=int, help="False-positive kill check index; stored as details.kill_check")
    p.set_defaults(func=run)


_KNOWN_DISPOSITIONS = frozenset({"confirmed", "downgraded", "pending_runtime_proof", "blocked", "false_positive", "disputed"})


def run(args) -> None:
    inline_payload = getattr(args, "inline_payload", None)
    raw_payload = inline_payload if inline_payload is not None else getattr(args, "payload", None)
    if raw_payload is not None and raw_payload in _KNOWN_DISPOSITIONS:
        print(
            f"'{raw_payload}' looks like a disposition, not a payload file.\n"
            f"Use: vigil assess verify-finding {args.finding_slug} --disposition {raw_payload} --reason \"...\"",
            file=sys.stderr,
        )
        sys.exit(1)
    if raw_payload is not None:
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=inline_payload is not None,
                description="verification payload",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        if not args.disposition or not args.reason_text:
            print(
                "verify-finding requires a payload file, --inline JSON, or both --disposition and --reason",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            details = parse_optional_inline_json(
                args.details_inline,
                default={},
                description="details JSON",
            )
            provenance = parse_optional_inline_json(
                args.provenance_inline,
                default={},
                description="provenance JSON",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        if not isinstance(details, dict):
            print("details JSON must be an object", file=sys.stderr)
            sys.exit(1)
        if not isinstance(provenance, dict):
            print("provenance JSON must be an object", file=sys.stderr)
            sys.exit(1)
        if args.kill_reason:
            details["kill_reason"] = args.kill_reason
        if args.kill_check is not None:
            details["kill_check"] = args.kill_check
        payload = {
            "disposition": args.disposition,
            "reason_code": args.reason_code,
            "reason_text": args.reason_text,
            "new_severity": args.new_severity,
            "evidence_ref": args.evidence_ref,
            "artifact_ref": args.artifact_ref,
            "notes": args.notes,
            "source_name": args.source_name,
            "details": details,
            "provenance": provenance,
        }

    if not isinstance(payload, dict):
        print("verification payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    if payload.get("disposition") == "false_positive":
        details = payload.get("details") or {}
        if not isinstance(details, dict):
            print("false_positive verification details must be a JSON object", file=sys.stderr)
            sys.exit(1)
        if not details.get("kill_reason") or details.get("kill_check") is None:
            print(
                "false_positive verification requires details.kill_reason and details.kill_check",
                file=sys.stderr,
            )
            sys.exit(1)
    if payload.get("disposition") == "downgraded" and not payload.get("new_severity"):
        print("downgraded verification requires new_severity", file=sys.stderr)
        sys.exit(1)

    narrative_path = getattr(args, "narrative", "") or ""
    producer_role = str(payload.get("source_name") or getattr(args, "source_name", "") or "")

    cfg = load_config(args.engagement_dir)

    # Validate the narrative artifact path before any POST so a typo fails fast
    # instead of silently registering a dangling artifact reference. The
    # artifact endpoint resolves a relative path under the engagement root, so
    # anchor it there too — a CWD-relative check would wrongly reject the
    # supported `--engagement-dir … --narrative notes/debate.md` workflow.
    if narrative_path:
        narrative_file = Path(narrative_path)
        if not narrative_file.is_absolute():
            narrative_file = Path(cfg.engagement_dir) / narrative_path
        if not narrative_file.exists():
            print(
                f"--narrative path does not exist: {narrative_path}",
                file=sys.stderr,
            )
            sys.exit(1)

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post(f"findings/{args.finding_slug}/verify", payload)
        if narrative_path:
            narrative_payload = {
                "path": narrative_path,
                "kind": "verification-narrative",
                "related_finding_slug": args.finding_slug,
            }
            if producer_role:
                narrative_payload["producer_agent_role"] = producer_role
            result["narrative_artifact"] = client.post("artifacts", narrative_payload)

    print(json.dumps(result, indent=2, ensure_ascii=False))
