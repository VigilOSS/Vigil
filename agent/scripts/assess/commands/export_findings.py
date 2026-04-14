"""assess.py export-findings — generate findings.md from backend state on demand."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.scope import load_scope

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def register(subparsers) -> None:
    p = subparsers.add_parser("export-findings", help="Generate findings.md from backend state")
    p.set_defaults(func=run)


def _render_finding(f: dict) -> str:
    slug = f["slug"]
    title = f["title"]
    severity = (f.get("severity") or "medium").upper()
    workflow_status = f.get("workflow_status") or "active"
    verification_state = f.get("verification_state") or "unreviewed"
    verification_disposition = f.get("verification_disposition") or "none"
    source_name = f.get("source_name") or f.get("discovered_by") or "unknown"
    defect_family = f.get("defect_family") or ""
    location = f.get("canonical_location") or ""
    auth_context = f.get("auth_context") or ""
    evidence = f.get("evidence_detail") or f.get("evidence_ref") or ""
    impact = f.get("impact") or f.get("summary") or ""
    owasp_category = f.get("owasp_category") or ""
    cwe_id = f.get("cwe_id") or ""
    cvss_vector = f.get("cvss_vector") or ""
    cvss_score = f.get("cvss_score")
    remediation = f.get("remediation") or ""
    steps = f.get("steps_to_reproduce") or []
    notes = (f.get("notes") or "").strip()

    request_method = ""
    details_json = f.get("details_json")
    if isinstance(details_json, str):
        try:
            details = json.loads(details_json)
            request_method = details.get("request_method") or ""
        except (json.JSONDecodeError, TypeError):
            pass

    lines = [
        f"## [{slug}] {title}",
        f"- **Discovered by**: {source_name}",
        f"- **Severity**: {severity}",
        f"- **Workflow**: {workflow_status}",
        f"- **Verification**: {verification_state} / {verification_disposition}",
    ]
    if defect_family:
        lines.append(f"- **Type**: {defect_family}")
    if owasp_category:
        lines.append(f"- **OWASP**: {owasp_category}")
    if cwe_id:
        lines.append(f"- **CWE**: {cwe_id}")
    if location:
        loc = f"{request_method} {location}" if request_method else location
        lines.append(f"- **Location**: {loc}")
    if auth_context:
        lines.append(f"- **Auth Context**: {auth_context}")
    if cvss_vector:
        score_str = f" ({cvss_score})" if cvss_score is not None else ""
        lines.append(f"- **CVSS**: {cvss_vector}{score_str}")
    if evidence:
        lines.append(f"- **Evidence**: {evidence}")
    if impact:
        lines.append(f"- **Impact**: {impact}")
    if remediation:
        lines.append(f"- **Remediation**: {remediation}")
    entry_point = f.get("entry_point") or ""
    sink = f.get("sink") or ""
    references = f.get("references") or []
    poc_code = f.get("poc_code") or ""

    if entry_point:
        lines.append(f"- **Entry Point**: {entry_point}")
    if sink:
        lines.append(f"- **Sink**: {sink}")
    if references:
        lines.append(f"- **References**: {', '.join(references)}")
    if steps:
        lines.append("")
        lines.append("**Steps to Reproduce:**")
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
    if poc_code:
        lines.append("")
        lines.append("**PoC Code:**")
        lines.append(f"```\n{poc_code}\n```")

    block = "\n".join(lines).rstrip()
    if notes:
        block = f"{block}\n\n{notes}"
    return block.strip()


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    scope = load_scope(cfg.engagement_dir)
    engagement_name = scope.get("engagement_name") or scope.get("name") or cfg.engagement_key

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        findings = client.get("report-findings")
    finally:
        client.close()

    if not isinstance(findings, list):
        print("export-findings: unexpected response from backend", file=sys.stderr)
        sys.exit(1)

    active = [f for f in findings if not f.get("merged_into_slug")]
    active.sort(key=lambda f: (
        _SEVERITY_ORDER.get((f.get("severity") or "medium").lower(), 99),
        f.get("slug", ""),
    ))

    header_lines = [
        f"# Findings — {engagement_name}",
        "",
        f"- **Finding Count**: {len(active)}",
        "",
    ]

    body_blocks = [_render_finding(f) for f in active]
    content = "\n".join(header_lines) + "\n".join(body_blocks) + "\n"

    out_path = Path(cfg.engagement_dir) / "findings.md"
    out_path.write_text(content, encoding="utf-8")
    print(f"Exported {len(active)} findings to {out_path}")
