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
    p.add_argument(
        "--allow-unindexed-evidence",
        dest="allow_unindexed_evidence",
        action="store_true",
        help="Record even when evidence_ref is prose or a non-existent path. By default "
             "record-finding rejects evidence that won't resolve to a registered artifact, "
             "so the gap is caught now (while you still have the evidence) instead of at "
             "check-report-readiness. Use for theoretical/code-inferred findings with no file.",
    )
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


def _evidence_file_exists(ref: str, eng_dir: str, engagement_key: str) -> bool:
    """True when evidence_ref resolves to a real file (so the backend will
    auto-register it). Checks the ref as-is, relative to the engagement dir, and
    the container-path form ``/engagements/<key>/...`` mapped back to the host."""
    candidates = [Path(ref)]
    if not Path(ref).is_absolute():
        candidates.append(Path(eng_dir) / ref)
    prefix = f"/engagements/{engagement_key}/"
    if ref.startswith(prefix):
        candidates.append(Path(eng_dir) / ref[len(prefix):])
    return any(c.is_file() for c in candidates)


def _validate_evidence_ref(payload: dict, *, eng_dir: str, engagement_key: str, allow_unindexed: bool) -> None:
    """Reject evidence_ref that cannot resolve to a registered artifact, at
    record time — while the capturing agent still has the evidence in hand —
    instead of surfacing ~24 blockers at the very end via check-report-readiness.

    Accepts: an existing on-disk file (auto-registered by the backend) or an
    http(s) URL pointer. Rejects: prose, or a path-shaped ref with no file.
    Empty is a warning, not an error (evidence may be attached on a later update).
    """
    if allow_unindexed:
        return
    ref = (payload.get("evidence_ref") or "").strip()
    if not ref:
        print(
            "record-finding: warning — no evidence_ref set; check-report-readiness will flag "
            "this finding as missing evidence. Set evidence_ref to a captured artifact path or "
            "URL, or pass --allow-unindexed-evidence to silence.",
            file=sys.stderr,
        )
        return
    if ref.startswith(("http://", "https://")):
        return  # URL evidence pointer — a valid reference, not a file.
    if _evidence_file_exists(ref, eng_dir, engagement_key):
        return  # existing artifact — the backend registers + links it on record.
    looks_like_path = ("/" in ref or "." in ref) and "  " not in ref
    if looks_like_path:
        print(f"record-finding: evidence_ref '{ref}' looks like a path but no file exists there.", file=sys.stderr)
    else:
        print(f"record-finding: evidence_ref '{ref}' is free-text prose, not an artifact path or URL.", file=sys.stderr)
    print("  Evidence must resolve to a real artifact so report-readiness can index it. Fix one of:", file=sys.stderr)
    print("    - point evidence_ref at an existing file (auto-registered on record),", file=sys.stderr)
    print("    - use an http(s) URL evidence pointer, or", file=sys.stderr)
    print("    - pass --allow-unindexed-evidence to record anyway (accepting a report blocker).", file=sys.stderr)
    sys.exit(1)


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

        _validate_evidence_ref(
            payload,
            eng_dir=eng_dir,
            engagement_key=cfg.engagement_key,
            allow_unindexed=getattr(args, "allow_unindexed_evidence", False),
        )

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
