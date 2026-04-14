"""assess.py launch-session — create exploit session dir + prompt."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.sessions import ensure_session_index, session_dir_path, session_index_path


def register(subparsers) -> None:
    p = subparsers.add_parser("launch-session", help="Launch an exploit session")
    p.add_argument("session_id", help="Session identifier")
    p.add_argument("slugs", nargs="+", help="Finding slug(s) to assign")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    session_id = args.session_id
    requested_slugs = args.slugs

    scope_file = Path(eng_dir) / "scope.json"
    if not scope_file.is_file():
        print(f"scope.json not found in {eng_dir}", file=sys.stderr)
        sys.exit(1)

    # Check exploit gate — use our own check-exploit-gate logic inline
    from assess.lib.scope import load_scope
    scope = load_scope(eng_dir)
    phase = scope.get("current_phase")
    policy = scope.get("exploit_policy", "pause")
    review_state = scope.get("exploit_review_state", "pending")
    approved = scope.get("approved_findings") or []

    if phase != "exploit":
        print(f"Exploit gate not active; current_phase={phase}", file=sys.stderr)
        sys.exit(1)
    if policy == "full_send":
        approved_slugs = ["*"]
    elif review_state != "approved":
        print(f"Exploit approval required; review_state={review_state}", file=sys.stderr)
        sys.exit(1)
    elif policy == "selected" and not approved:
        print("Exploit policy is selected but no approved findings were recorded", file=sys.stderr)
        sys.exit(1)
    else:
        approved_slugs = approved

    session_dir = Path(session_dir_path(eng_dir, session_id))
    ensure_session_index(eng_dir)
    index_path = Path(session_index_path(eng_dir))
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if session_dir.exists() or any(row.get("session_id") == session_id for row in index):
        print(f"session already exists: {session_id}", file=sys.stderr)
        sys.exit(1)

    # Fetch findings from backend
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        findings = client.get("findings")
    finally:
        client.close()

    findings_by_slug = {row["slug"]: row for row in findings if row.get("slug")}
    missing = [slug for slug in requested_slugs if slug not in findings_by_slug]
    if missing:
        print(f"unknown finding slug(s): {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    if approved_slugs and approved_slugs != ["*"]:
        disallowed = [slug for slug in requested_slugs if slug not in approved_slugs]
        if disallowed:
            print(f"finding slug(s) not approved for exploitation: {', '.join(disallowed)}", file=sys.stderr)
            sys.exit(1)

    # Create session directory structure
    proposals_dir = session_dir / "proposals"
    artifacts_dir = session_dir / "artifacts"
    notes_dir = session_dir / "notes"

    for d in (proposals_dir, artifacts_dir, notes_dir):
        d.mkdir(parents=True, exist_ok=True)

    proposals_file = proposals_dir / "proposals.jsonl"
    proposals_file.write_text("", encoding="utf-8")

    # Write assignment.json
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assignment = {
        "session_id": session_id,
        "created_at": timestamp,
        "status": "active",
        "assigned_findings": requested_slugs,
    }
    assignment_file = Path(session_dir) / "assignment.json"
    assignment_file.write_text(json.dumps(assignment, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Write prompt.md
    assigned_findings = [findings_by_slug[slug] for slug in requested_slugs]
    prompt_lines = [
        f"# Exploit Session {session_id}",
        "",
        "Rules:",
        "- Work only on the assigned findings below.",
        "- Use Kali MCP tools for target-facing work.",
        "- Do not edit the root report.md or scope.json.",
        "- Place artifacts in ./artifacts and notes in ./notes.",
        "- Record proposals with ./scripts/assess.py record-proposal <session-dir> <proposal-json-file>.",
        "- Use proposal type finding_record to update or add findings.",
        "- Use proposal type probe_run to submit exploit/validation evidence for merge review.",
        "",
        "Assigned findings:",
    ]
    for row in assigned_findings:
        prompt_lines.append(
            f"- {row['slug']} | {row.get('severity', '')} | {row.get('workflow_status', '')} | {row.get('title', '')}"
        )

    prompt_file = session_dir / "prompt.md"
    prompt_file.write_text("\n".join(prompt_lines) + "\n", encoding="utf-8")

    # Update session index
    index.append({
        "session_id": session_id,
        "created_at": timestamp,
        "status": "active",
        "assigned_findings": requested_slugs,
        "merge_state": "pending",
    })
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Session created: {session_dir}")
    print(f"Prompt: {prompt_file}")
