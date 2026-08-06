from __future__ import annotations

import hashlib
import json
from typing import Any

VARIANT_DISPATCH_ROLE = "code-variant-hunter"
VARIANT_PARENT_FINDING_SET_SCHEMA = "variant-parent-finding-set/v1"
MAX_VARIANT_PARENT_FINDINGS = 1000


def canonical_variant_parent_slugs(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(slug) for slug in value})


def variant_parent_finding_set_digest(parent_finding_slugs: list[str]) -> str:
    payload = {
        "schema": VARIANT_PARENT_FINDING_SET_SCHEMA,
        "finding_slugs": parent_finding_slugs,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
