"""aith assess export-findings — generate findings.md from backend state on demand."""
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


def _details_object(finding: dict) -> dict:
    details_json = finding.get("details_json")
    if isinstance(details_json, str):
        try:
            parsed = json.loads(details_json)
        except (json.JSONDecodeError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return details_json if isinstance(details_json, dict) else {}


def _detail_value(finding: dict, field: str, default=""):
    value = finding.get(field)
    if value not in (None, "", []):
        return value
    return _details_object(finding).get(field, default)


def _string_list(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    normalized: list[str] = []
    for value in values:
        if value in (None, ""):
            continue
        normalized.append(str(value))
    return normalized


def _header_lines(headers: object) -> list[str]:
    if isinstance(headers, dict):
        return [f"{key}: {value}" for key, value in headers.items() if key not in (None, "") and value is not None]
    if isinstance(headers, str):
        return [headers] if headers else []
    if isinstance(headers, list):
        return [str(value) for value in headers if value not in (None, "")]
    return []


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
    steps = _string_list(_detail_value(f, "steps_to_reproduce", []))
    notes = (f.get("notes") or "").strip()

    request_method = ""
    details = _details_object(f)
    request_method = details.get("request_method") or ""

    if not owasp_category:
        owasp_category = str(_detail_value(f, "owasp_category", "") or "")
    if not cwe_id:
        cwe_id = str(_detail_value(f, "cwe_id", "") or "")
    if not cvss_vector:
        cvss_vector = str(_detail_value(f, "cvss_vector", "") or "")
    if cvss_score is None:
        cvss_score = _detail_value(f, "cvss_score", None)
    if not remediation:
        remediation = str(_detail_value(f, "remediation", "") or "")
    if not impact:
        impact = str(_detail_value(f, "impact", "") or "")
    if not evidence:
        evidence = str(_detail_value(f, "evidence", "") or "")

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
    if f.get("merged_into_slug"):
        lines.append(f"- **Merged Into**: {f['merged_into_slug']}")
    root_role = f.get("root_cause_role")
    if root_role == "root":
        lines.append(f"- **Root Cause Group**: root ({f.get('sibling_count', 0)} siblings)")
    elif root_role == "sibling":
        root_slug = f.get("root_cause_slug", "")
        effect = f.get("root_cause_effect", "eliminates_finding")
        effect_label = "fixing root eliminates this finding"
        if effect == "eliminates_attack_path":
            effect_label = "fixing root eliminates this attack path; residual finding remains"
        lines.append(f"- **Root Cause Group**: sibling of {root_slug} ({effect_label})")
        if f.get("root_cause_note"):
            lines.append(f"- **Root Cause Note**: {f['root_cause_note']}")
    entry_point = str(_detail_value(f, "entry_point", "") or "")
    sink = str(_detail_value(f, "sink", "") or "")
    references = _string_list(_detail_value(f, "references", []))
    poc_code = str(_detail_value(f, "poc_code", "") or "")

    if entry_point:
        lines.append(f"- **Entry Point**: {entry_point}")
    if sink:
        lines.append(f"- **Sink**: {sink}")
    if references:
        lines.append(f"- **References**: {', '.join(references)}")
    poc_request = _detail_value(f, "poc_request")
    poc_response = _detail_value(f, "poc_response")

    if steps:
        lines.append("")
        lines.append("**Steps to Reproduce:**")
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
    if poc_code:
        lines.append("")
        lines.append("**PoC Code:**")
        lines.append(f"```\n{poc_code}\n```")
    if isinstance(poc_request, dict):
        method = poc_request.get("method", "")
        url = poc_request.get("url", "")
        req_headers = _header_lines(poc_request.get("headers"))
        req_body = poc_request.get("body", "")
        lines.append("")
        lines.append("**PoC Request:**")
        lines.append(f"```\n{method} {url}")
        lines.extend(req_headers)
        if req_body:
            lines.append(f"\n{req_body}")
        lines.append("```")
    if isinstance(poc_response, dict):
        status = poc_response.get("status", "")
        resp_headers = _header_lines(poc_response.get("headers"))
        body_excerpt = poc_response.get("body_excerpt", "")
        lines.append("")
        lines.append("**PoC Response:**")
        lines.append(f"```\nHTTP {status}")
        lines.extend(resp_headers)
        if body_excerpt:
            lines.append(f"\n{body_excerpt}")
        lines.append("```")

    block = "\n".join(lines).rstrip()
    if notes:
        block = f"{block}\n\n{notes}"
    return block.strip()


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    scope = load_scope(cfg.engagement_dir)
    engagement_name = scope.get("engagement_name") or scope.get("name") or cfg.engagement_key

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        findings = client.get("findings")
        groups = client.get("finding-groups")

    if not isinstance(findings, list):
        print("export-findings: unexpected response from backend", file=sys.stderr)
        sys.exit(1)
    if not isinstance(groups, list):
        groups = []

    finding_by_slug = {str(finding.get("slug", "")): finding for finding in findings if finding.get("slug")}
    for group in groups:
        if not isinstance(group, dict):
            continue
        root = group.get("root")
        if isinstance(root, dict):
            root_slug = str(root.get("slug", ""))
            if root_slug in finding_by_slug:
                finding_by_slug[root_slug]["root_cause_role"] = "root"
                finding_by_slug[root_slug]["sibling_count"] = group.get("sibling_count", 0)
        for sibling in group.get("siblings", []):
            if not isinstance(sibling, dict):
                continue
            sibling_slug = str(sibling.get("slug", ""))
            if sibling_slug in finding_by_slug:
                finding_by_slug[sibling_slug].update(
                    {
                        "root_cause_role": "sibling",
                        "root_cause_slug": sibling.get("root_cause_slug", ""),
                        "root_cause_effect": sibling.get("root_cause_effect", "eliminates_finding"),
                        "root_cause_note": sibling.get("root_cause_note", ""),
                        "sibling_order": sibling.get("sibling_order"),
                    }
                )

    findings.sort(key=lambda f: (
        _SEVERITY_ORDER.get((f.get("severity") or "medium").lower(), 99),
        f.get("slug", ""),
    ))

    header_lines = [
        f"# Findings — {engagement_name}",
        "",
        f"- **Finding Count**: {len(findings)}",
        "",
    ]

    body_blocks = [_render_finding(f) for f in findings]
    content = "\n".join(header_lines) + "\n".join(body_blocks) + "\n"

    out_path = Path(cfg.engagement_dir) / "findings.md"
    out_path.write_text(content, encoding="utf-8")
    print(f"Exported {len(findings)} findings to {out_path}")
