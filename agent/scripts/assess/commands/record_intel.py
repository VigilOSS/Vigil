"""vigil assess intel record — multiplexed intel-type recorder.

Replaces the old ``intel.md`` append pattern. Validates payload against the
matching ``agent/schemas/intel-<type>.schema.json`` then POSTs to
``/engagements/{key}/intel/{type-plural}`` on the orchestrator backend.
Emits an ``intel.recorded`` event on success.

Usage::

    vigil assess intel record <type> <json-file>

``<type>`` is one of: tech-component, person, email, domain, cve,
dns-record, social-profile, breach-record, org-fact, note.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.intel_types import INTEL_TYPES
from assess.lib.schema_validation import collect_validation_errors, load_schema


def register(subparsers) -> None:
    types_list = ", ".join(sorted(INTEL_TYPES.keys()))
    p = subparsers.add_parser(
        "record",
        help="Record a structured intel record (replaces intel.md appends)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vigil assess intel record tech-component tech.json\n"
            "  vigil assess intel record cve cve-2024-1234.json\n"
            "  vigil assess intel record note catchall.json\n"
            "  vigil assess contract intel record tech-component   # allowed keys for a type\n"
            f"\nValid types: {types_list}"
        ),
    )
    p.add_argument("intel_type", help=f"One of: {types_list}")
    p.add_argument("json_file", help="Path to intel JSON file matching the intel-<type> schema")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the payload and print the resolved URL without POSTing",
    )
    p.set_defaults(func=run)


def _load_payload(path: Path) -> dict:
    if not path.is_file():
        print(f"intel json file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"intel json file is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(payload, dict):
        print("intel payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    return payload


def _report_validation_errors(intel_type: str, errors: list[str]) -> None:
    print(f"record-intel {intel_type}: payload failed schema validation:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    print(
        f"Run `vigil assess contract intel record {intel_type}` for the allowed keys.",
        file=sys.stderr,
    )
    sys.exit(1)


def run(args) -> None:
    intel_type = args.intel_type
    if intel_type not in INTEL_TYPES:
        print(
            f"unknown intel type '{intel_type}'. Valid: {', '.join(sorted(INTEL_TYPES))}",
            file=sys.stderr,
        )
        sys.exit(1)

    schema_name, endpoint_segment = INTEL_TYPES[intel_type]

    payload = _load_payload(Path(args.json_file))

    schema = load_schema(schema_name)
    errors = collect_validation_errors(payload, schema)
    if errors:
        _report_validation_errors(intel_type, errors)

    cfg = load_config(args.engagement_dir)
    endpoint = f"intel/{endpoint_segment}"

    if args.dry_run:
        # Print the resolved URL and validated payload so the caller can
        # verify schema + URL construction without hitting the backend.
        url = f"{cfg.base_url}/engagements/{cfg.engagement_key}/{endpoint}"
        print(f"[dry-run] would POST {url}")
        print(f"[dry-run] payload: {json.dumps(payload, ensure_ascii=False)}")
        return

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        response = client.post_engagement(endpoint, payload)

    # Emit event — fire-and-forget, outside the main call.
    record_id = response.get("id") if isinstance(response, dict) else None
    summary_title = ""
    if isinstance(response, dict):
        for key in ("component", "name", "address", "identity", "cve_id", "handle", "fact_key", "title"):
            value = response.get(key)
            if value:
                summary_title = str(value)
                break

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as event_client:
        event_client.post_event(
            {
                "event_type": "intel.recorded",
                "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
                "task_name": intel_type,
                "agent_name": payload.get("source_name")
                or (payload.get("provenance") or {}).get("agent_name")
                or "unknown",
                "summary": summary_title or intel_type,
            }
        )

    # Print a concise success marker.
    if record_id is not None:
        print(f"Recorded intel {intel_type} id={record_id}")
    else:
        # Response was not a canonical record (backend may still return
        # envelope). Print the raw body so the caller can inspect.
        print(json.dumps(response, indent=2, ensure_ascii=False))
