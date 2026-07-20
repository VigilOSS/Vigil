"""vigil assess finding verify — dedicated verifier flow for canonical findings."""
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
        "verify",
        help="Verify findings with explicit flags or a final transition payload file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("finding verify"),
    )
    p.add_argument(
        "finding_slug",
        nargs="+",
        help="One or more canonical finding slugs to verify. Batch: every listed slug receives the "
             "SAME disposition/payload/flags (resilient loop with a per-slug failure tally).",
    )
    p.add_argument(
        "--inline",
        dest="legacy_inline_payload",
        help=argparse.SUPPRESS,
    )
    p.add_argument(
        "--payload-file",
        dest="payload_file",
        help="Path to a final JSON verification-transition payload",
    )
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
    p.add_argument("--reason-code", help="Optional machine-readable reason code")
    p.add_argument("--new-severity", help="Required for downgraded verification")
    p.add_argument("--evidence-ref", help="Optional evidence reference")
    p.add_argument("--artifact-ref", help="Optional artifact reference")
    p.add_argument(
        "--narrative",
        default="",
        help=(
            "Optional path to a verification/debate narrative (e.g. an "
            "Ideator-vs-Tracer debate doc). Registered as a "
            "kind=verification-narrative artifact linked to this finding."
        ),
    )
    p.add_argument("--notes", help="Optional verification notes")
    p.add_argument("--source-name", help="Optional source/agent name")
    p.add_argument("--details-inline", help="Inline JSON object merged into the details payload")
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance metadata")
    p.add_argument("--kill-reason", help="False-positive kill reason; stored as details.kill_reason")
    p.add_argument("--kill-check", type=int, help="False-positive kill check index; stored as details.kill_check")
    p.set_defaults(func=run)


_KNOWN_DISPOSITIONS = frozenset({"confirmed", "downgraded", "pending_runtime_proof", "blocked", "false_positive", "disputed"})

_CONTENT_FLAGS = (
    ("disposition", "--disposition"),
    ("reason_text", "--reason"),
    ("reason_code", "--reason-code"),
    ("new_severity", "--new-severity"),
    ("evidence_ref", "--evidence-ref"),
    ("artifact_ref", "--artifact-ref"),
    ("notes", "--notes"),
    ("source_name", "--source-name"),
    ("details_inline", "--details-inline"),
    ("provenance_inline", "--provenance-inline"),
    ("kill_reason", "--kill-reason"),
    ("kill_check", "--kill-check"),
)


def _looks_like_payload(token: str) -> bool:
    """True when a positional token looks like a JSON payload rather than a slug."""
    t = (token or "").strip()
    return bool(t) and (t.startswith(("{", "[")) or t.endswith(".json") or Path(t).is_file())


def _provided_content_flags(args) -> list[str]:
    provided = []
    for attr, flag in _CONTENT_FLAGS:
        value = getattr(args, attr, None)
        if value is not None and value is not False:
            provided.append(flag)
    return provided


def run(args) -> None:
    legacy_inline = getattr(args, "legacy_inline_payload", None)
    if legacy_inline is None:
        legacy_inline = getattr(args, "inline_payload", None)
    if legacy_inline is not None:
        print(
            "finding verify: --inline was removed; use --disposition/--reason and related "
            "explicit flags, or --payload-file <path> for a final transition payload.",
            file=sys.stderr,
        )
        sys.exit(1)

    slugs = args.finding_slug if isinstance(args.finding_slug, list) else [args.finding_slug]
    # The trailing positional payload arg was removed (it collided with a variadic
    # slug list). Catch a legacy JSON blob / disposition passed positionally and
    # point the caller at the flag form.
    example_slug = slugs[0] if slugs else "<slug>"
    for token in slugs:
        t = str(token).strip()
        if t in _KNOWN_DISPOSITIONS:
            print(
                f"'{t}' looks like a disposition, not a finding slug.\n"
                f"Use: vigil assess finding verify {example_slug} --disposition {t} --reason \"...\"",
                file=sys.stderr,
            )
            sys.exit(1)
        if _looks_like_payload(t):
            print(
                f"'{t}' looks like a JSON payload, not a finding slug. The positional payload arg "
                "was removed — use --payload-file <path>, and list only finding slugs "
                "positionally.",
                file=sys.stderr,
            )
            sys.exit(1)

    payload_file = getattr(args, "payload_file", None)
    if payload_file is not None:
        if not str(payload_file).strip():
            print("finding verify: --payload-file must not be empty", file=sys.stderr)
            sys.exit(1)
        provided_flags = _provided_content_flags(args)
        if provided_flags:
            print(
                "finding verify: --payload-file cannot be combined with request-content flags "
                f"({', '.join(provided_flags)}); put the complete transition in the file or use "
                "explicit verification flags. --narrative may be used with either form.",
                file=sys.stderr,
            )
            sys.exit(1)
    raw_payload = payload_file
    if raw_payload is not None:
        if not Path(raw_payload).is_file():
            print(f"verification payload file not found: {raw_payload}", file=sys.stderr)
            sys.exit(1)
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=False,
                description="verification payload",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        if not args.disposition or not args.reason_text:
            print(
                "finding verify requires --payload-file or both --disposition and --reason",
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
        payload = {key: value for key, value in payload.items() if value is not None}

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

    results: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for slug in slugs:
            try:
                result = client.post(f"findings/{slug}/verify", payload)
                if narrative_path:
                    narrative_payload = {
                        "path": narrative_path,
                        "kind": "verification-narrative",
                        "related_finding_slug": slug,
                    }
                    if producer_role:
                        narrative_payload["producer_agent_role"] = producer_role
                    result["narrative_artifact"] = client.post("artifacts", narrative_payload)
            except Exception as exc:  # noqa: BLE001 - one bad slug must not drop the rest
                failed += 1
                print(f"finding verify: {slug} failed: {exc}", file=sys.stderr)
                continue
            results.append(result)

    if len(slugs) == 1 and results:
        print(json.dumps(results[0], indent=2, ensure_ascii=False))
    else:
        for result in results:
            print(json.dumps(result, ensure_ascii=False))
        print(
            f"[finding verify] verified {len(results)} finding(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
