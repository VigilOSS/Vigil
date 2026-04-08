"""assess.py record-finding — most complex command.

Schema validate → slug allocate → POST → markdown sync → update count → emit event.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.findings import (
    finding_lock_path,
    next_finding_id,
    sync_finding_markdown,
    update_finding_count,
)
from assess.lib.locking import file_lock


def register(subparsers) -> None:
    p = subparsers.add_parser("record-finding", help="Record a structured finding")
    p.add_argument("agent_name", help="Agent name (e.g. vulnerability-analyst)")
    p.add_argument("json_file", help="Path to finding JSON file")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    findings_file = Path(eng_dir) / "findings.md"

    if not findings_file.is_file():
        print(f"findings.md not found in {eng_dir}", file=sys.stderr)
        sys.exit(1)

    json_path = Path(args.json_file)
    if not json_path.is_file():
        print(f"finding json file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print("finding payload must be a JSON object", file=sys.stderr)
        sys.exit(1)

    agent_name = args.agent_name

    # Acquire finding lock
    lock_path = finding_lock_path(eng_dir)
    with file_lock(lock_path):
        # Resolve slug
        candidate_slug = payload.get("slug", "")
        if not candidate_slug:
            candidate_slug = next_finding_id(eng_dir, agent_name)

        # Inject defaults
        payload["slug"] = candidate_slug
        payload.setdefault("source_name", agent_name)
        payload.setdefault("severity", "medium")
        payload.setdefault("workflow_status", "active")
        payload.setdefault("verification_state", "unreviewed")
        payload.setdefault("verification_disposition", "none")
        payload.setdefault("defect_family", payload.get("title", candidate_slug))
        payload.setdefault("root_cause_key", "")
        payload.setdefault("auth_context", "anonymous")
        payload.setdefault("canonical_location", "")
        payload.setdefault("summary", payload.get("title", candidate_slug))
        payload.setdefault("evidence_ref", "")
        payload.setdefault("notes", "")

        details = payload.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        details.setdefault("discovered_by", agent_name)
        payload["details"] = details

        provenance = payload.get("provenance") or {}
        if not isinstance(provenance, dict):
            provenance = {}
        provenance.setdefault("agent_name", agent_name)
        provenance.setdefault("artifact", "findings.md")
        payload["provenance"] = provenance

        payload.setdefault("links", [])

        # POST to backend (backend does Pydantic validation)
        client = AssessmentClient(cfg.base_url, cfg.engagement_key)
        try:
            response = client.post("findings", payload)
        finally:
            client.close()

        # Validate response
        finding = response.get("finding", {})
        if not finding.get("slug") or not finding.get("title"):
            print("record-finding: orchestrator backend did not return a canonical finding record", file=sys.stderr)
            sys.exit(1)

        finding_slug = finding["slug"]

        # Sync to findings.md
        sync_finding_markdown(str(findings_file), finding)
        update_finding_count(str(findings_file))

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
