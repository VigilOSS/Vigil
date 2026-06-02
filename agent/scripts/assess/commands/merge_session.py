"""vigil assess merge-session — parse proposals → record each by type."""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.findings import finding_lock_path, next_finding_id
from assess.lib.locking import file_lock
from assess.lib.sessions import load_session_index, save_session_index, session_dir_path


def register(subparsers) -> None:
    p = subparsers.add_parser("merge-session", help="Merge exploit session proposals into canonical state")
    p.add_argument("session_id", help="Session identifier")
    p.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    session_id = args.session_id

    session_dir = session_dir_path(eng_dir, session_id)
    proposals_file = Path(session_dir) / "proposals" / "proposals.jsonl"

    if not Path(session_dir).is_dir():
        print(f"session directory not found: {session_dir}", file=sys.stderr)
        sys.exit(1)
    if not proposals_file.is_file():
        print(f"proposal file not found: {proposals_file}", file=sys.stderr)
        sys.exit(1)

    proposals = []
    counter: Counter = Counter()
    for line in proposals_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        proposal = json.loads(line)
        proposals.append(proposal)
        counter[proposal["type"]] += 1

    if not proposals:
        print("No proposals to merge.", file=sys.stderr)
        sys.exit(1)

    print(f"Merge summary for session {session_id}")
    for key in sorted(counter):
        print(f"  {key}:{counter[key]}")

    if not args.yes:
        if not sys.stdin.isatty():
            print("merge-session: confirmation required; rerun with --yes in non-interactive mode", file=sys.stderr)
            sys.exit(1)
        answer = input("Apply these proposals to canonical backend state? [y/N]: ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Merge cancelled.")
            sys.exit(1)

    session_index = load_session_index(eng_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for proposal in proposals:
            ptype = proposal["type"]
            payload = proposal["payload"]

            if ptype == "finding_record":
                lock_path = finding_lock_path(eng_dir)
                with file_lock(lock_path):
                    candidate_slug = payload.get("slug", "")
                    if not candidate_slug:
                        candidate_slug = next_finding_id(cfg.base_url, cfg.engagement_key, "exploit-developer")
                    payload["slug"] = candidate_slug
                    payload.setdefault("source_name", "exploit-developer")
                    payload.setdefault("severity", "medium")
                    payload.pop("status", None)
                    payload.setdefault("workflow_status", "active")
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
                    details.setdefault("discovered_by", "exploit-developer")
                    payload["details"] = details

                    provenance = payload.get("provenance") or {}
                    if not isinstance(provenance, dict):
                        provenance = {}
                    provenance.setdefault("agent_name", "exploit-developer")
                    payload["provenance"] = provenance
                    payload.setdefault("links", [])

                    response = client.post("findings", payload)
                    finding = response.get("finding", {})
                    if not finding.get("slug") or not finding.get("title"):
                        print("merge-session: backend did not accept finding proposal", file=sys.stderr)
                        sys.exit(1)

            elif ptype == "probe_run":
                response = client.post("probe-runs", payload)
                if not (response.get("id") or (response.get("probe_run") or {}).get("id")):
                    print(f"merge-session: backend did not accept probe proposal", file=sys.stderr)
                    sys.exit(1)

            elif ptype == "attack_chain":
                prov = payload.get("provenance") or {}
                prov.setdefault("agent_name", "exploit-developer")
                payload["provenance"] = prov
                client.post("attack-chains", payload)

            elif ptype == "credential":
                client.post("credentials", payload)

            elif ptype == "access_record":
                client.post("access-records", payload)

            else:
                print(f"Unsupported proposal type: {ptype}", file=sys.stderr)
                sys.exit(1)

    if session_index:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for row in session_index:
            if row.get("session_id") == session_id:
                row["status"] = "merged"
                row["merge_state"] = "merged"
                row["merged_at"] = timestamp
        save_session_index(eng_dir, session_index)

    print(f"Merged session {session_id} into canonical backend state.")
