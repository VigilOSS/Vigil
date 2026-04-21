"""Finding ID allocation via backend query — replaces lib/findings.sh."""
from __future__ import annotations

import re
from pathlib import Path

from assess.lib.client import AssessmentClient

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
    "surface-collector": "SC",
    "code-fuzz-engineer": "CF",
}

_FINDING_ID_RE = re.compile(r"FINDING-([A-Z]{2})-(\d{3})")


def finding_prefix_for_agent(agent_name: str) -> str:
    """Return the 2-letter finding prefix for an agent."""
    prefix = _AGENT_PREFIX_MAP.get(agent_name)
    if prefix is None:
        raise SystemExit(f"unknown finding prefix for agent: {agent_name}")
    return prefix


def finding_lock_path(engagement_dir: str) -> str:
    return str(Path(engagement_dir) / ".finding-id.lock")


def next_finding_id(base_url: str, engagement_key: str, agent_name: str) -> str:
    """Allocate the next finding ID for an agent by scanning backend slugs."""
    prefix = finding_prefix_for_agent(agent_name)
    client = AssessmentClient(base_url, engagement_key)
    try:
        findings = client.get("findings")
    finally:
        client.close()

    max_id = 0
    for finding in findings:
        slug = finding.get("slug", "")
        match = _FINDING_ID_RE.search(slug)
        if match and match.group(1) == prefix:
            num = int(match.group(2))
            if num > max_id:
                max_id = num

    return f"FINDING-{prefix}-{max_id + 1:03d}"
