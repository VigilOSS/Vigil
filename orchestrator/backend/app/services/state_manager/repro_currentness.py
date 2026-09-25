"""Current authored reproduction identity shared by decision writes and exports."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def reproduction_sha256(finding: dict[str, Any]) -> str:
    details = finding.get("details")
    if not isinstance(details, dict):
        try:
            details = json.loads(str(finding.get("details_json") or "{}"))
        except json.JSONDecodeError:
            details = {}
    if not isinstance(details, dict):
        details = {}
    authored = {
        "steps_to_reproduce": details.get("steps_to_reproduce"),
        "repro_runs": details.get("repro_runs"),
    }
    raw = json.dumps(
        authored, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
