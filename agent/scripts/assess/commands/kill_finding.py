"""vigil assess kill-finding — false-positive verification helper."""
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
        "kill-finding",
        help="Verify a finding as false_positive without writing a JSON file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("kill-finding"),
    )
    p.add_argument(
        "finding_slug",
        nargs="+",
        help="One or more canonical finding slugs. Batch: every listed slug is killed with the "
             "SAME payload/flags (resilient loop with a per-slug failure tally).",
    )
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON verification payload")
    p.add_argument(
        "--payload-file",
        dest="payload_file",
        help="Path to a JSON verification payload file (replaces the removed trailing positional "
             "payload arg; use --inline for raw JSON).",
    )
    p.add_argument("--reason", dest="reason_text", help="Why the finding is a false positive")
    p.add_argument("--reason-code", default="")
    p.add_argument("--kill-reason", help="Stored as details.kill_reason")
    p.add_argument("--kill-check", type=int, help="Stored as details.kill_check")
    p.add_argument("--evidence-ref", default="")
    p.add_argument("--artifact-ref", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--source-name", default="")
    p.add_argument("--details-inline", help="Inline JSON object merged into details")
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance")
    p.set_defaults(func=run)


def _looks_like_payload(token: str) -> bool:
    """True when a positional token looks like a JSON payload rather than a slug."""
    t = (token or "").strip()
    return bool(t) and (t.startswith(("{", "[")) or t.endswith(".json") or Path(t).is_file())


def run(args) -> None:
    slugs = args.finding_slug if isinstance(args.finding_slug, list) else [args.finding_slug]
    # The trailing positional payload arg was removed (it collided with a variadic
    # slug list). Catch a legacy JSON blob passed positionally.
    for token in slugs:
        if _looks_like_payload(str(token)):
            print(
                f"'{str(token).strip()}' looks like a JSON payload, not a finding slug. The "
                f"positional payload arg was removed — pass the JSON via --inline '<json>' or "
                f"--payload-file <path>, and list only finding slugs positionally.",
                file=sys.stderr,
            )
            sys.exit(1)

    inline_payload = getattr(args, "inline_payload", None)
    payload_file = getattr(args, "payload_file", None)
    if inline_payload is not None:
        raw_payload, raw_inline = inline_payload, True
    elif payload_file:
        raw_payload, raw_inline = payload_file, False
    else:
        raw_payload, raw_inline = None, False
    if raw_payload is not None:
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=raw_inline,
                description="false-positive verification payload",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        if not args.reason_text or not args.kill_reason or args.kill_check is None:
            print(
                "kill-finding requires --reason, --kill-reason, and --kill-check unless you supply a payload",
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
        details["kill_reason"] = args.kill_reason
        details["kill_check"] = args.kill_check
        payload = {
            "disposition": "false_positive",
            "reason_code": args.reason_code,
            "reason_text": args.reason_text,
            "evidence_ref": args.evidence_ref,
            "artifact_ref": args.artifact_ref,
            "notes": args.notes,
            "source_name": args.source_name,
            "details": details,
            "provenance": provenance,
        }

    if not isinstance(payload, dict):
        print("kill-finding payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    if payload.get("disposition") != "false_positive":
        print("kill-finding payload disposition must be false_positive", file=sys.stderr)
        sys.exit(1)
    details = payload.get("details") or {}
    if not isinstance(details, dict) or not details.get("kill_reason") or details.get("kill_check") is None:
        print("kill-finding requires details.kill_reason and details.kill_check", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    results: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for slug in slugs:
            try:
                results.append(client.post(f"findings/{slug}/verify", payload))
            except Exception as exc:  # noqa: BLE001 - one bad slug must not drop the rest
                failed += 1
                print(f"kill-finding: {slug} failed: {exc}", file=sys.stderr)

    if len(slugs) == 1 and results:
        print(json.dumps(results[0], indent=2, ensure_ascii=False))
    else:
        for result in results:
            print(json.dumps(result, ensure_ascii=False))
        print(
            f"[kill-finding] killed {len(results)} finding(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
