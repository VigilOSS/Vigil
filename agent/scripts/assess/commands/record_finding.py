"""aith assess record-finding — most complex command.

Schema validate → slug allocate → POST → emit event.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import common_mistake_hints, render_contract
from assess.lib.findings import finding_lock_path, next_finding_id
from assess.lib.locking import file_lock
from assess.lib.schema_validation import collect_validation_errors, load_schema


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "record-finding",
        help="Record a structured finding",
        epilog="See `aith assess contract record-finding` for the canonical payload shape and examples.",
    )
    p.add_argument("agent_name", help="Agent name (e.g. vulnerability-analyst)")
    p.add_argument("json_file", help="Path to finding JSON file")
    p.set_defaults(func=run)


_FINDING_SCHEMA = load_schema("finding-record.schema.json")


def _normalize_payload(payload: dict, *, agent_name: str, candidate_slug: str) -> dict:
    normalized = dict(payload)
    normalized["slug"] = candidate_slug
    normalized.setdefault("source_name", agent_name)
    normalized.setdefault("severity", "medium")
    normalized.setdefault("workflow_status", "active")
    normalized.setdefault("verification_state", "unreviewed")
    normalized.setdefault("verification_disposition", "none")
    normalized.setdefault("defect_family", normalized.get("title", candidate_slug))
    normalized.setdefault("root_cause_key", "")
    normalized.setdefault("auth_context", "anonymous")
    normalized.setdefault("canonical_location", "")
    normalized.setdefault("summary", normalized.get("title", candidate_slug))
    normalized.setdefault("evidence_ref", "")
    normalized.setdefault("notes", "")

    details = normalized.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    details.setdefault("discovered_by", agent_name)
    normalized["details"] = details

    provenance = normalized.get("provenance") or {}
    if not isinstance(provenance, dict):
        provenance = {}
    provenance.setdefault("agent_name", agent_name)
    normalized["provenance"] = provenance

    normalized.setdefault("links", [])
    return normalized


def _report_validation_errors(payload: dict, errors: list[str]) -> None:
    print("finding payload invalid after helper defaults:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)

    hints = common_mistake_hints("record-finding", payload)
    if hints:
        print("Common legacy-field fixes:", file=sys.stderr)
        for hint in hints:
            print(f"  - {hint}", file=sys.stderr)

    print("", file=sys.stderr)
    print("Run `aith assess contract record-finding` for the canonical helper contract.", file=sys.stderr)
    print("", file=sys.stderr)
    print(render_contract("record-finding"), file=sys.stderr)
    sys.exit(1)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir

    json_path = Path(args.json_file)
    if not json_path.is_file():
        print(f"finding json file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print("finding payload must be a JSON object", file=sys.stderr)
        sys.exit(1)

    agent_name = args.agent_name

    lock_path = finding_lock_path(eng_dir)
    with file_lock(lock_path):
        candidate_slug = payload.get("slug", "")
        if not candidate_slug:
            candidate_slug = next_finding_id(cfg.base_url, cfg.engagement_key, agent_name)

        payload = _normalize_payload(payload, agent_name=agent_name, candidate_slug=candidate_slug)
        validation_errors = collect_validation_errors(payload, _FINDING_SCHEMA)
        if validation_errors:
            _report_validation_errors(payload, validation_errors)

        client = AssessmentClient(cfg.base_url, cfg.engagement_key)
        try:
            response = client.post("findings", payload)
        finally:
            client.close()

        finding = response.get("finding", {})
        if not finding.get("slug") or not finding.get("title"):
            print("record-finding: orchestrator backend did not return a canonical finding record", file=sys.stderr)
            sys.exit(1)

        finding_slug = finding["slug"]

    # Emit event (outside lock)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        client.post_event({
            "event_type": "finding.created",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": finding_slug,
            "agent_name": agent_name,
            "summary": f"Recorded {finding_slug}",
        })
    finally:
        client.close()

    print(finding_slug)
