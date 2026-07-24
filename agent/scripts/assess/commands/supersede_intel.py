"""vigil assess intel supersede — replace an intel row with a new one.

The old row stays in the table for audit but gets ``superseded_by_id``
populated so report-writer's filter excludes it from output. Use this
when an existing intel row is wrong but the operator wants to retain the
prior observation (because changing the natural key would lose history).

Use ``update-intel`` instead for in-place edits where the prior shape was
correct and only metadata changed.

When the correct canonical row already exists (a duplicate landed under a
slightly different natural key), pass ``--to-existing <id>`` to point the stale
row at it. That skips the replacement upsert entirely, so the canonical row's
own fields are never overwritten. It is mutually exclusive with a payload.

Usage::

    vigil assess intel supersede <type> <id> <new-payload-json-file> --rationale "..."
    vigil assess intel supersede <type> <id> --inline '{...}' --rationale "..."
    vigil assess intel supersede <type> <id> --to-existing <canonical-id> --rationale "..."
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.intel_types import INTEL_TYPES
from assess.lib.json_inputs import parse_json_argument
from assess.lib.schema_validation import collect_patch_validation_errors, load_schema


# Mirrors orchestrator/backend/app/services/intel.py::_INTEL_UPDATABLE_FIELDS so
# the CLI can echo the actionable column whitelist when a payload filters down
# to nothing on the backend. Keep in sync with that map.
_INTEL_UPDATABLE_FIELDS: dict[str, set[str]] = {
    "tech-component": {
        "component", "version", "source_name", "confidence", "evidence_ref",
        "first_seen_at", "last_seen_at", "notes", "provenance",
    },
    "person": {
        "name", "role", "organization", "email", "source_name", "notes", "provenance",
    },
    "email": {
        "address", "role_hint", "linked_person_id", "source_name", "notes", "provenance",
    },
    "domain": {
        "identity", "kind", "value", "source_name", "live_status", "notes", "provenance",
    },
    "cve": {
        "cve_id", "affected_component", "affected_version_range", "cvss_score",
        "cvss_vector", "cwe_id", "poc_available", "source_name",
        "validation_status", "linked_finding_slug", "notes", "details",
        "provenance",
    },
    "dns-record": {
        "record_type", "name", "value", "first_seen", "last_seen",
        "source_name", "notes", "provenance",
    },
    "social-profile": {
        "subject_kind", "subject_ref", "platform", "handle", "url",
        "source_name", "notes", "provenance",
    },
    "breach-record": {
        "subject", "breach_name", "breach_date", "data_types", "source_name",
        "notes", "provenance",
    },
    "org-fact": {
        "fact_key", "fact_value", "source_name", "notes", "provenance",
    },
    "note": {
        "title", "body_markdown", "source_agent", "tags", "source_name", "provenance",
        "lead_status",
    },
}

_INTEL_NATURAL_KEY_FIELDS: dict[str, tuple[str, ...]] = {
    "tech-component": ("component", "version"),
    "person": ("name",),
    "email": ("address",),
    "domain": ("identity", "kind"),
    "cve": ("cve_id", "affected_component"),
    "dns-record": ("record_type", "name", "value"),
    "social-profile": ("subject_kind", "subject_ref", "platform", "handle"),
    "breach-record": ("subject", "breach_name"),
    "org-fact": ("fact_key",),
    "note": ("title",),
}


def register(subparsers) -> None:
    types_list = ", ".join(sorted(INTEL_TYPES.keys()))
    p = subparsers.add_parser(
        "supersede",
        help="Replace an intel row with a new payload; old row marked superseded",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vigil assess intel supersede tech-component 42 new.json --rationale \"banner re-fingerprinted\"\n"
            "  vigil assess intel supersede cve 17 --inline '{\"cve_id\":\"CVE-2025-1\",\"affected_component\":\"x\"}' --rationale \"prior CVE was a false match\"\n"
            "  vigil assess intel supersede tech-component 42 --to-existing 7 --rationale \"duplicate of the canonical row\"\n"
            f"\nValid types: {types_list}"
        ),
    )
    p.add_argument("intel_type", help=f"One of: {types_list}")
    p.add_argument("intel_id", type=int, help="Backend id of the intel row being superseded")
    p.add_argument(
        "payload",
        nargs="?",
        help="Path to the new intel JSON payload, or inline JSON object (omit when using --to-existing)",
    )
    p.add_argument(
        "--inline",
        dest="inline_payload",
        help="Raw JSON payload string for the new intel record",
    )
    p.add_argument(
        "--to-existing",
        dest="to_existing_id",
        type=int,
        default=None,
        metavar="ID",
        help=(
            "Point the stale row at an EXISTING same-type canonical row id "
            "instead of recording a replacement. Mutually exclusive with the "
            "payload/--inline argument."
        ),
    )
    p.add_argument(
        "--rationale",
        default="",
        help="Reason for supersede; appended to the old row's notes for audit",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    if args.intel_type not in INTEL_TYPES:
        print(
            f"unknown intel type '{args.intel_type}'. Valid: {', '.join(sorted(INTEL_TYPES))}",
            file=sys.stderr,
        )
        sys.exit(1)
    schema_name, endpoint_segment = INTEL_TYPES[args.intel_type]

    # --to-existing repoints the stale row at an already-recorded canonical row;
    # no replacement payload is sent (the backend rejects one), so skip payload
    # parsing/schema validation entirely.
    to_existing_id = getattr(args, "to_existing_id", None)
    if to_existing_id is not None:
        if args.payload is not None or args.inline_payload is not None:
            print(
                "supersede-intel: --to-existing is mutually exclusive with a "
                "payload/--inline argument (it repoints at an existing row "
                "instead of recording a replacement)",
                file=sys.stderr,
            )
            sys.exit(1)
        body = json.dumps(
            {"to_existing_id": int(to_existing_id), "rationale": args.rationale},
            ensure_ascii=True,
        ).encode("utf-8")
        record = _send_supersede(args, endpoint_segment, body)
        print(json.dumps(record, indent=2, ensure_ascii=False))
        return

    raw_payload = args.inline_payload if args.inline_payload is not None else args.payload
    if raw_payload is None:
        print(
            "supersede-intel: provide a JSON payload file path, --inline JSON, or --to-existing <id>",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        new_payload, _ = parse_json_argument(
            raw_payload,
            inline=args.inline_payload is not None,
            description="supersede payload",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(new_payload, dict) or not new_payload:
        updatable = sorted(_INTEL_UPDATABLE_FIELDS.get(args.intel_type, set()))
        msg = "supersede-intel: payload must be a non-empty JSON object"
        if updatable:
            msg += (
                f"\n  valid update fields for {args.intel_type}: "
                f"{', '.join(updatable)}"
            )
        print(msg, file=sys.stderr)
        sys.exit(1)

    # Supersede inserts a replacement row, so the new payload must carry the
    # same natural-key fields the backend uses for that intel table. Metadata-
    # only edits belong to update-intel; accepting them here only fails later
    # after a network round trip.
    schema = load_schema(schema_name)
    errors = collect_patch_validation_errors(new_payload, schema)
    natural_key = _INTEL_NATURAL_KEY_FIELDS.get(args.intel_type, ())
    missing_natural_key = [
        field for field in natural_key
        if field not in new_payload or new_payload[field] in (None, "")
    ]
    errors.extend(
        f"missing required supersede natural-key field: {field}"
        for field in missing_natural_key
    )
    if errors:
        print(f"supersede-intel {args.intel_type}: payload failed schema validation:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        sys.exit(1)

    body = json.dumps(
        {"payload": new_payload, "rationale": args.rationale},
        ensure_ascii=True,
    ).encode("utf-8")
    record = _send_supersede(args, endpoint_segment, body)

    print(json.dumps(record, indent=2, ensure_ascii=False))


def _send_supersede(args, endpoint_segment: str, body: bytes) -> dict:
    """POST a supersede request body and decode the JSON response.

    Shared by the payload path and the ``--to-existing`` path so both hit the
    same endpoint, 409 explainer, and decode fallback.
    """
    from urllib.parse import quote

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        path = (
            f"{client._engagement_prefix}/intel/{quote(endpoint_segment)}/{int(args.intel_id)}/supersede"
        )
        try:
            _, resp_body = client._request("POST", path, body=body)
        except AssessError as exc:
            _maybe_explain_409(exc)
            raise
    try:
        return json.loads(resp_body)
    except json.JSONDecodeError:
        return {"raw": resp_body}


def _maybe_explain_409(exc: AssessError) -> None:
    """If the backend returned 409, surface the actionable hint before the raw body."""
    msg = str(exc)
    if not msg.startswith("HTTP 409"):
        return
    print(
        "supersede-intel: backend rejected with HTTP 409 (natural-key collision).\n"
        "  Hint: use `vigil assess intel update <type> <id> ...` for in-place edits "
        "when the new payload's natural key matches the existing row.",
        file=sys.stderr,
    )
