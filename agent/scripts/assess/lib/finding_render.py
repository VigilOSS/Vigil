"""Shared finding->markdown renderer.

Single source of truth for turning one persisted finding record into the
``## [slug] title`` markdown block used by both finding exporters:

  * ``vigil assess export-findings`` — concatenates these blocks into a single
    ``findings.md`` report document (one section per finding, with the
    root-cause grouping context inline). See
    ``agent/scripts/assess/commands/export_findings.py``.
  * ``vigil engagement export --format markdown-tree`` — writes the same block
    as a per-finding ``draft.md`` in a git-diff-able tree (root-cause grouping
    is rendered separately into each finding's ``report.md`` instead, so the
    draft omits it). See
    ``src/vigil_cli/engagements.py:export_engagement_tree``.

Both callers share this module so the field selection, ordering, and PoC
formatting never drift between the report doc and the diffable tree. The only
behavioural knob is ``include_root_cause_group``; the trailing newline is left
to the caller (export-findings strips and re-joins; the tree appends one).

This module lives under ``agent/scripts/assess/lib`` so the assess command
imports it directly; the ``src`` CLI package reaches it through the same
``add_assess_import_path`` bridge it already uses for ``assess.lib.client`` and
``assess.lib.db`` (see ``vigil_cli.paths``).
"""
from __future__ import annotations

import json
import re
from typing import Any

# Longest run of backticks anywhere in a string — used to pick a code fence
# that the content cannot prematurely close.
_BACKTICK_RUN = re.compile(r"`+")


def _fence_for(*parts: str) -> str:
    """Return a backtick fence guaranteed not to be closed by any of ``parts``.

    Markdown code fences must be longer than the longest backtick run inside the
    fenced content, otherwise PoC output / request bodies / response excerpts
    containing ``` (or longer runs) break out of the block. We scan every part
    and return a run one backtick longer than the maximum found (minimum 3)."""
    longest = 0
    for part in parts:
        for match in _BACKTICK_RUN.finditer(part or ""):
            longest = max(longest, len(match.group(0)))
    return "`" * max(3, longest + 1)


def details_object(finding: dict) -> dict:
    """Return the finding's structured details as a dict.

    The backend stores extended fields in a ``details_json`` text column; the
    serialized read payloads can carry it either as a JSON string or as an
    already-parsed object depending on the endpoint, so handle both.
    """
    details_json = finding.get("details_json")
    if isinstance(details_json, str):
        try:
            parsed = json.loads(details_json)
        except (json.JSONDecodeError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return details_json if isinstance(details_json, dict) else {}


def detail_value(finding: dict, key: str, default: Any = "") -> Any:
    """Prefer the top-level finding field, falling back to ``details_json``."""
    value = finding.get(key)
    if value not in (None, "", []):
        return value
    return details_object(finding).get(key, default)


def string_list(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if value not in (None, "")]


def header_lines(headers: object) -> list[str]:
    if isinstance(headers, dict):
        return [f"{key}: {value}" for key, value in headers.items() if key not in (None, "") and value is not None]
    if isinstance(headers, str):
        return [headers] if headers else []
    if isinstance(headers, list):
        return [str(value) for value in headers if value not in (None, "")]
    return []


def _root_cause_lines(finding: dict) -> list[str]:
    """Render the root-cause grouping block (export-findings only).

    ``export-findings`` flattens grouping context onto each finding before
    rendering (root/sibling role + effect + note); the markdown-tree draft
    omits this because each finding's ``report.md`` renders grouping from the
    report projection instead.
    """
    lines: list[str] = []
    root_role = finding.get("root_cause_role")
    if root_role == "root":
        lines.append(f"- **Root Cause Group**: root ({finding.get('sibling_count', 0)} siblings)")
    elif root_role == "sibling":
        root_slug = finding.get("root_cause_slug", "")
        effect = finding.get("root_cause_effect", "eliminates_finding")
        effect_label = "fixing root eliminates this finding"
        if effect == "eliminates_attack_path":
            effect_label = "fixing root eliminates this attack path; residual finding remains"
        lines.append(f"- **Root Cause Group**: sibling of {root_slug} ({effect_label})")
        if finding.get("root_cause_note"):
            lines.append(f"- **Root Cause Note**: {finding['root_cause_note']}")
    return lines


def render_finding(finding: dict, *, include_root_cause_group: bool = False) -> str:
    """Render one finding to its markdown block (no trailing newline).

    ``include_root_cause_group`` adds the root/sibling grouping bullet(s) that
    ``export-findings`` flattens onto the finding; leave it ``False`` for the
    per-finding ``draft.md`` in the markdown-tree export.

    The returned string is the stripped block; callers decide whether to append
    a trailing newline (export-findings re-joins blocks; the tree adds one).
    """
    slug = str(finding.get("slug") or "")
    title = str(finding.get("title") or "(untitled)")
    severity = str(finding.get("severity") or "medium").upper()
    workflow_status = finding.get("workflow_status") or "active"
    verification_state = finding.get("verification_state") or "unreviewed"
    verification_disposition = finding.get("verification_disposition") or "none"
    source_name = finding.get("source_name") or finding.get("discovered_by") or "unknown"
    defect_family = finding.get("defect_family") or ""
    location = finding.get("canonical_location") or ""
    auth_context = finding.get("auth_context") or ""
    evidence = finding.get("evidence_detail") or finding.get("evidence_ref") or ""
    impact = finding.get("impact") or finding.get("summary") or ""
    owasp_category = str(detail_value(finding, "owasp_category", "") or "")
    cwe_id = str(detail_value(finding, "cwe_id", "") or "")
    cvss_vector = str(detail_value(finding, "cvss_vector", "") or "")
    cvss_score = finding.get("cvss_score")
    if cvss_score is None:
        cvss_score = detail_value(finding, "cvss_score", None)
    remediation = finding.get("remediation") or str(detail_value(finding, "remediation", "") or "")
    if not impact:
        impact = str(detail_value(finding, "impact", "") or "")
    if not evidence:
        evidence = str(detail_value(finding, "evidence", "") or "")
    steps = string_list(detail_value(finding, "steps_to_reproduce", []))
    notes = (finding.get("notes") or "").strip()
    request_method = details_object(finding).get("request_method") or ""

    header = f"## [{slug}] {title}" if slug else f"## {title}"
    lines = [
        header,
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
    if finding.get("merged_into_slug"):
        lines.append(f"- **Merged Into**: {finding['merged_into_slug']}")
    if include_root_cause_group:
        lines.extend(_root_cause_lines(finding))

    entry_point = str(detail_value(finding, "entry_point", "") or "")
    sink = str(detail_value(finding, "sink", "") or "")
    references = string_list(detail_value(finding, "references", []))
    poc_code = str(detail_value(finding, "poc_code", "") or "")
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
        fence = _fence_for(poc_code)
        lines.append(f"{fence}\n{poc_code}\n{fence}")
    poc_request = detail_value(finding, "poc_request")
    if isinstance(poc_request, dict):
        lines.append("")
        lines.append("**PoC Request:**")
        req_headers = header_lines(poc_request.get("headers"))
        req_body = str(poc_request.get("body") or "")
        # Fence over every fenced part (request line + headers + body) so a
        # backtick run anywhere in the request cannot close the block early.
        fence = _fence_for(
            f"{poc_request.get('method', '')} {poc_request.get('url', '')}",
            "\n".join(req_headers),
            req_body,
        )
        lines.append(f"{fence}\n{poc_request.get('method', '')} {poc_request.get('url', '')}")
        lines.extend(req_headers)
        if poc_request.get("body"):
            lines.append(f"\n{poc_request['body']}")
        lines.append(fence)
    poc_response = detail_value(finding, "poc_response")
    if isinstance(poc_response, dict):
        lines.append("")
        lines.append("**PoC Response:**")
        resp_headers = header_lines(poc_response.get("headers"))
        resp_body = str(poc_response.get("body_excerpt") or "")
        fence = _fence_for(
            f"HTTP {poc_response.get('status', '')}",
            "\n".join(resp_headers),
            resp_body,
        )
        lines.append(f"{fence}\nHTTP {poc_response.get('status', '')}")
        lines.extend(resp_headers)
        if poc_response.get("body_excerpt"):
            lines.append(f"\n{poc_response['body_excerpt']}")
        lines.append(fence)

    block = "\n".join(lines).rstrip()
    if notes:
        block = f"{block}\n\n{notes}"
    return block.strip()
