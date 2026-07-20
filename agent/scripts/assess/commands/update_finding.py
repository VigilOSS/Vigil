"""vigil assess finding update — finding-specific PATCH helper."""
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
        "update",
        help="PATCH findings with explicit flags or one finding with a payload file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("finding update"),
    )
    p.add_argument(
        "finding_slug",
        nargs="+",
        help="One or more canonical finding slugs. Batch updates use explicit flags and a "
             "resilient per-slug loop; --payload-file accepts exactly one slug.",
    )
    p.add_argument(
        "--inline",
        dest="legacy_inline_payload",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--payload-file",
        dest="payload_file",
        help="Path to a single-finding JSON patch document",
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
    p.add_argument("--reason-code")
    p.add_argument("--reason", dest="reason_text")
    p.add_argument("--artifact-ref")
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


_CONTENT_FLAGS = (
    ("title", "--title"),
    ("severity", "--severity"),
    ("workflow_status", "--workflow-status"),
    ("submission_status", "--submission-status"),
    ("defect_family", "--defect-family"),
    ("root_cause_key", "--root-cause-key"),
    ("auth_context", "--auth-context"),
    ("canonical_location", "--canonical-location"),
    ("summary", "--summary"),
    ("evidence_ref", "--evidence-ref"),
    ("notes", "--notes"),
    ("source_name", "--source-name"),
    ("reason_code", "--reason-code"),
    ("reason_text", "--reason"),
    ("artifact_ref", "--artifact-ref"),
    ("expected_row_version", "--expected-row-version"),
    ("details_inline", "--details-inline"),
    ("provenance_inline", "--provenance-inline"),
    ("notes_replace", "--notes-replace"),
    ("details_replace", "--details-replace"),
    ("evidence_type", "--evidence-type"),
)

_PATCH_CONTROL_FIELDS = frozenset(
    {
        "expected_row_version",
        "notes_mode",
        "details_mode",
        "reason_code",
        "reason_text",
        "artifact_ref",
    }
)


def _has_patch_content(payload: dict[str, object]) -> bool:
    """Return whether a payload contains a field that can mutate a finding."""
    notes = payload.get("notes")
    if notes is not None and (notes != "" or payload.get("notes_mode") == "replace"):
        return True
    details = payload.get("details")
    if details is not None and (details != {} or payload.get("details_mode") == "replace"):
        return True
    provenance = payload.get("provenance")
    if provenance not in (None, {}):
        return True
    return any(
        key not in _PATCH_CONTROL_FIELDS
        and key not in {"notes", "details", "provenance"}
        and value not in ("", None)
        for key, value in payload.items()
    )


def _provided_content_flags(args) -> list[str]:
    provided = []
    for attr, flag in _CONTENT_FLAGS:
        value = getattr(args, attr, None)
        if value is not None and value is not False:
            provided.append(flag)
    return provided


def run(args) -> None:
    legacy_inline = getattr(args, "legacy_inline_payload", None)
    # Direct callers from before the parser rename can still construct this
    # attribute; keep the retirement fail-closed at the command boundary.
    if legacy_inline is None:
        legacy_inline = getattr(args, "inline_payload", None)
    if legacy_inline is not None:
        print(
            "finding update: --inline was removed; use explicit patch flags for small changes "
            "or --payload-file <path> for a structured single-finding patch.",
            file=sys.stderr,
        )
        sys.exit(1)

    finding_slug = getattr(args, "finding_slug", [])
    slugs = finding_slug if isinstance(finding_slug, list) else [finding_slug]
    # The trailing positional payload arg was removed (it collided with a variadic
    # slug list). Catch a legacy JSON blob passed positionally.
    for token in slugs:
        if _looks_like_payload(str(token)):
            print(
                f"'{str(token).strip()}' looks like a JSON payload, not a finding slug. The "
                "positional payload arg was removed — use --payload-file <path>, and list only "
                "finding slugs positionally.",
                file=sys.stderr,
            )
            sys.exit(1)

    payload_file = getattr(args, "payload_file", None)
    if payload_file is not None:
        if not str(payload_file).strip():
            print("finding update: --payload-file must not be empty", file=sys.stderr)
            sys.exit(1)
        provided_flags = _provided_content_flags(args)
        if provided_flags:
            print(
                "finding update: --payload-file cannot be combined with request-content flags "
                f"({', '.join(provided_flags)}); put the complete patch in the file or use "
                "explicit patch flags.",
                file=sys.stderr,
            )
            sys.exit(1)
        if len(slugs) != 1:
            print(
                "finding update: --payload-file requires exactly one finding slug; use explicit "
                "flags for batch updates.",
                file=sys.stderr,
            )
            sys.exit(1)

    # --notes-replace overwrites the notes column; without --notes it would write
    # an empty string over the existing notes (silent data loss). Reject that.
    # (Runs first, before touching finding_slug, so a guard-only invocation exits here.)
    if getattr(args, "notes_replace", False) and args.notes is None:
        print("finding update: --notes-replace requires --notes <text> (it overwrites the "
              "notes column; running it without --notes would wipe existing notes).", file=sys.stderr)
        sys.exit(1)
    raw_payload = payload_file
    # --details-replace overwrites the whole details object; without
    # --details-inline it would null the column. Payload files carry their own
    # details_mode and cannot be combined with this flag.
    if getattr(args, "details_replace", False) and args.details_inline is None and raw_payload is None:
        print("finding update: --details-replace requires --details-inline <json> (it overwrites "
              "the details object; running it without details would wipe existing details).",
              file=sys.stderr)
        sys.exit(1)
    if (
        getattr(args, "notes_replace", False)
        or getattr(args, "details_replace", False)
    ) and getattr(args, "expected_row_version", None) is None:
        print(
            "finding update: --notes-replace and --details-replace require "
            "--expected-row-version so a concurrent writer cannot be erased.",
            file=sys.stderr,
        )
        sys.exit(1)
    if raw_payload is not None:
        if not Path(raw_payload).is_file():
            print(f"finding patch payload file not found: {raw_payload}", file=sys.stderr)
            sys.exit(1)
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=False,
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
    if not isinstance(payload, dict):
        print("finding patch payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    if not _has_patch_content(payload):
        print(
            "finding update requires at least one field that updates the finding; "
            "concurrency, mode, and transition-metadata controls do not update a finding "
            "by themselves, and empty merge values are no-ops.",
            file=sys.stderr,
        )
        sys.exit(1)

    if payload_file:
        row_version = payload.get("expected_row_version")
        if (
            not isinstance(row_version, int)
            or isinstance(row_version, bool)
            or row_version < 1
        ):
            print(
                "finding update: a payload file must contain expected_row_version as a positive "
                "integer; refresh it from the successful response before the next update.",
                file=sys.stderr,
            )
            sys.exit(1)
        if "notes" in payload and payload.get("notes_mode") not in {"append", "replace"}:
            print(
                "finding update: a payload file containing notes must set notes_mode to "
                "'replace' (cumulative working document) or 'append' (deliberate checkpoint).",
                file=sys.stderr,
            )
            sys.exit(1)

    # Set the explicit-flag mode so the backend overwrites rather than merges.
    if getattr(args, "details_replace", False):
        if payload.get("details") is None:
            print("finding update: --details-replace requires a 'details' object in the payload "
                  "(it overwrites the details object; without details it would wipe existing details).",
                  file=sys.stderr)
            sys.exit(1)
        payload["details_mode"] = "replace"

    cfg = load_config(args.engagement_dir)
    results: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for slug in slugs:
            try:
                results.append(client.patch(f"findings/{slug}", payload))
            except Exception as exc:  # noqa: BLE001 - one bad slug must not drop the rest
                failed += 1
                print(f"finding update: {slug} failed: {exc}", file=sys.stderr)

    if len(slugs) == 1 and results:
        print(json.dumps(results[0], indent=2, ensure_ascii=False))
    else:
        for result in results:
            print(json.dumps(result, ensure_ascii=False))
        print(
            f"[finding update] updated {len(results)} finding(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
