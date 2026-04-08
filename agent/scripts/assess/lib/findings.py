"""Finding ID allocation + markdown sync — replaces lib/findings.sh."""
from __future__ import annotations

import re
from pathlib import Path

from assess.lib.locking import file_lock

_AGENT_PREFIX_MAP = {
    "exploit-developer": "EX",
    "vulnerability-analyst": "VA",
    "source-analyzer": "SA",
    "recon-specialist": "RE",
    "fuzzer": "FZ",
    "osint-analyst": "OS",
    "code-architect": "CA",
    "code-vuln-hunter": "CH",
    "code-variant-hunter": "CV",
    "code-vuln-verifier": "VF",
}

_FINDING_ID_RE = re.compile(r"FINDING-([A-Z]{2})-(\d{3})")
_FINDING_HEADING_RE = re.compile(r"^## \[FINDING-[A-Z]{2}-\d{3}\]")
_FINDING_COUNT_RE = re.compile(r"^- \*\*Finding Count\*\*:")


def finding_prefix_for_agent(agent_name: str) -> str:
    """Return the 2-letter finding prefix for an agent."""
    prefix = _AGENT_PREFIX_MAP.get(agent_name)
    if prefix is None:
        raise SystemExit(f"unknown finding prefix for agent: {agent_name}")
    return prefix


def finding_lock_path(engagement_dir: str) -> str:
    return str(Path(engagement_dir) / ".finding-id.lock")


def next_finding_id(engagement_dir: str, agent_name: str) -> str:
    """Allocate the next finding ID for an agent by scanning findings.md."""
    prefix = finding_prefix_for_agent(agent_name)
    findings_file = Path(engagement_dir) / "findings.md"
    text = findings_file.read_text(encoding="utf-8") if findings_file.is_file() else ""

    max_id = 0
    for match in _FINDING_ID_RE.finditer(text):
        if match.group(1) == prefix:
            num = int(match.group(2))
            if num > max_id:
                max_id = num

    return f"FINDING-{prefix}-{max_id + 1:03d}"


def update_finding_count(findings_file: str) -> None:
    """Update the Finding Count line in findings.md."""
    path = Path(findings_file)
    text = path.read_text(encoding="utf-8")

    count = 0
    for line in text.splitlines():
        if _FINDING_HEADING_RE.match(line):
            count += 1

    lines = text.splitlines()
    updated = False
    for i, line in enumerate(lines):
        if _FINDING_COUNT_RE.match(line):
            lines[i] = f"- **Finding Count**: {count}"
            updated = True
            break

    if not updated:
        lines.append("")
        lines.append(f"- **Finding Count**: {count}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def sync_finding_markdown(findings_file: str, finding: dict) -> None:
    """Write or update a finding block in findings.md. Matches the bash python3 block."""
    path = Path(findings_file)
    details = finding.get("details_json") or "{}"
    if isinstance(details, str):
        import json
        try:
            details = json.loads(details)
        except (json.JSONDecodeError, TypeError):
            details = {}
    if not isinstance(details, dict):
        details = {}

    slug = finding["slug"]
    title = finding["title"]
    severity = (finding.get("severity") or "medium").upper()
    status = finding.get("status") or "confirmed"
    source_name = finding.get("source_name") or details.get("discovered_by") or "unknown"
    defect_family = finding.get("defect_family") or ""
    location = finding.get("canonical_location") or details.get("parameter") or ""
    auth_context = finding.get("auth_context") or "anonymous"
    evidence = details.get("evidence") or finding.get("evidence_ref") or ""
    impact = details.get("impact") or finding.get("summary") or ""
    owasp_category = details.get("owasp_category") or ""
    cwe_id = details.get("cwe_id") or ""
    request_method = details.get("request_method") or ""
    cvss_vector = details.get("cvss_vector") or ""
    cvss_score = details.get("cvss_score")
    remediation = details.get("remediation") or ""
    steps = details.get("steps_to_reproduce") or []
    notes = (finding.get("notes") or "").strip()

    lines = [
        f"## [{slug}] {title}",
        f"- **Discovered by**: {source_name}",
        f"- **Severity**: {severity}",
        f"- **Status**: {status}",
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
    if steps:
        lines.append("")
        lines.append("**Steps to Reproduce:**")
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")

    block = "\n".join(lines).rstrip()
    if notes:
        block = f"{block}\n\n{notes}"
    block = block.strip() + "\n"

    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"(?ms)^## \[{re.escape(slug)}\].*?(?=^## \[FINDING-[A-Z]{{2}}-[0-9]{{3}}\]|\Z)"
    )
    if pattern.search(text):
        text = pattern.sub(block + "\n", text, count=1)
    else:
        text = text.rstrip() + "\n\n" + block + "\n"

    path.write_text(text, encoding="utf-8")
