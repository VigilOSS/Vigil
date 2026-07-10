"""vigil assess update-finding — finding-specific PATCH helper."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import SUBMISSION_STATUSES, render_contract_epilog
from assess.lib.json_inputs import parse_json_argument, parse_optional_inline_json


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "update-finding",
        help="PATCH a finding by slug using a payload file, inline JSON, or common flags",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("update-finding"),
    )
    p.add_argument(
        "finding_slug",
        nargs="+",
        help="One or more canonical finding slugs. Batch: every listed slug receives the SAME "
             "patch payload/flags (resilient loop with a per-slug failure tally).",
    )
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON patch payload")
    p.add_argument(
        "--payload-file",
        dest="payload_file",
        help="Path to a JSON patch payload file (replaces the removed trailing positional payload "
             "arg; use --inline for raw JSON).",
    )
    p.add_argument("--title")
    p.add_argument("--severity")
    p.add_argument("--workflow-status", "--status", dest="workflow_status")
    p.add_argument(
        "--submission-status",
        dest="submission_status",
        default=None,
        choices=SUBMISSION_STATUSES,
        help=(
            "External bug-bounty/program submission state. ORTHOGONAL to "
            "--workflow-status (report-inclusion): setting one never changes the "
            "other. Allowed: " + ", ".join(SUBMISSION_STATUSES) + " (default 'none')."
        ),
    )
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
    p.add_argument(
        "--expected-row-version",
        type=int,
        help="Reject the patch if the finding changed since this row_version was read.",
    )
    p.add_argument("--details-inline", help="Inline JSON object for details")
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance")
    p.add_argument(
        "--notes-replace",
        dest="notes_replace",
        action="store_true",
        help="Overwrite the notes field instead of appending. Use to scrub stale or "
             "contradicted internal text (notes is append-only by default). Pair with --notes.",
    )
    p.add_argument(
        "--details-replace",
        dest="details_replace",
        action="store_true",
        help="Overwrite the whole details object instead of merging into it. Use to "
             "remove stale or cross-contaminated detail keys (details is merge-only by "
             "default, so a merge can shadow but never delete keys). Pair with "
             "--details-inline.",
    )
    p.add_argument(
        "--evidence-type",
        dest="evidence_type",
        default=None,
        choices=("network-confirmed", "code-inferred", "theoretical", "informational"),
        help=(
            "C44: classify confirmation mode. network-confirmed = captured "
            "HTTP request/response; code-inferred = pattern present in source, "
            "no runtime proof; theoretical = chain-dependent; informational = "
            "observation without proven attack path. Nullable — existing rows "
            "stay NULL until an operator labels them."
        ),
    )
    p.set_defaults(func=run)


def _looks_like_payload(token: str) -> bool:
    """True when a positional token looks like a JSON payload rather than a slug."""
    t = (token or "").strip()
    return bool(t) and (t.startswith(("{", "[")) or t.endswith(".json") or Path(t).is_file())


def run(args) -> None:
    # --notes-replace overwrites the notes column; without --notes it would write
    # an empty string over the existing notes (silent data loss). Reject that.
    # (Runs first, before touching finding_slug, so a guard-only invocation exits here.)
    if getattr(args, "notes_replace", False) and args.notes is None:
        print("update-finding: --notes-replace requires --notes <text> (it overwrites the "
              "notes column; running it without --notes would wipe existing notes).", file=sys.stderr)
        sys.exit(1)
    inline_payload = getattr(args, "inline_payload", None)
    payload_file = getattr(args, "payload_file", None)
    if inline_payload is not None:
        raw_payload, raw_inline = inline_payload, True
    elif payload_file:
        raw_payload, raw_inline = payload_file, False
    else:
        raw_payload, raw_inline = None, False
    # --details-replace overwrites the whole details object; without a details
    # payload (--details-inline, or "details" in a file/--inline payload) it would
    # null the column. Reject that, mirroring the --notes-replace guard.
    if getattr(args, "details_replace", False) and args.details_inline is None and raw_payload is None:
        print("update-finding: --details-replace requires --details-inline <json> (it overwrites "
              "the details object; running it without details would wipe existing details).",
              file=sys.stderr)
        sys.exit(1)
    if raw_payload is not None:
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=raw_inline,
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
            # getattr fallback so callers that build args via SimpleNamespace
            # (test fixtures) don't AttributeError, mirroring evidence_type.
            "submission_status": getattr(args, "submission_status", None),
            "defect_family": args.defect_family,
            "root_cause_key": args.root_cause_key,
            "auth_context": args.auth_context,
            "canonical_location": args.canonical_location,
            "summary": args.summary,
            "evidence_ref": args.evidence_ref,
            "notes": args.notes,
            "notes_mode": "replace" if getattr(args, "notes_replace", False) else None,
            "source_name": args.source_name,
            "details": details,
            "details_mode": "replace" if getattr(args, "details_replace", False) else None,
            "provenance": provenance,
            # getattr fallback so callers that build args via SimpleNamespace
            # (test fixtures pre-dating C44) don't AttributeError.
            "evidence_type": getattr(args, "evidence_type", None),
            "reason_code": args.reason_code,
            "reason_text": args.reason_text,
            "artifact_ref": args.artifact_ref,
            "expected_row_version": getattr(args, "expected_row_version", None),
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

    # --details-replace also applies when the patch came from a file/--inline
    # payload: set the mode so the backend overwrites rather than merges. The
    # backend rejects replace without a details payload, so require one here too.
    if getattr(args, "details_replace", False):
        if payload.get("details") is None:
            print("update-finding: --details-replace requires a 'details' object in the payload "
                  "(it overwrites the details object; without details it would wipe existing details).",
                  file=sys.stderr)
            sys.exit(1)
        payload["details_mode"] = "replace"

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

    cfg = load_config(args.engagement_dir)
    results: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for slug in slugs:
            try:
                results.append(client.patch(f"findings/{slug}", payload))
            except Exception as exc:  # noqa: BLE001 - one bad slug must not drop the rest
                failed += 1
                print(f"update-finding: {slug} failed: {exc}", file=sys.stderr)

    if len(slugs) == 1 and results:
        print(json.dumps(results[0], indent=2, ensure_ascii=False))
    else:
        for result in results:
            print(json.dumps(result, ensure_ascii=False))
        print(
            f"[update-finding] updated {len(results)} finding(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
