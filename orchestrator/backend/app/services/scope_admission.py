"""Use the canonical agent scope matcher for execution admission, without copies.

The coverage gate deliberately expands literal roots for completeness; proof
execution must instead use the same exact-host, wildcard, and CIDR rules as Kali.
"""
from __future__ import annotations

import sys
from pathlib import Path


def admitted_host(host: str, allow: list[str], deny: list[str]) -> bool:
    agent_scripts = Path(__file__).resolve().parents[4] / 'agent' / 'scripts'
    if str(agent_scripts) not in sys.path:
        sys.path.insert(0, str(agent_scripts))
    from assess.lib.scope import classify_scope_entry, host_admitted

    allow_entries = [entry for raw in allow if (entry := classify_scope_entry(raw))]
    deny_entries = [entry for raw in deny if (entry := classify_scope_entry(raw))]
    return host_admitted(host, allow_entries, deny_entries)
