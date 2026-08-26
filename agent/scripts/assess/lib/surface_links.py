"""Shared helper for creating surface ↔ request-variant links on the backend.

The durable cross-reference between a local ``cases.db`` work_item and backend
state is ``request_variant_id`` (the value the backend returns when a request
observation is posted) — NOT the local work_item row id, which is ephemeral and
re-created per engagement run. This helper posts that linkage to the backend so
both ``ingest-candidates`` (auto-linking from ``surface_refs``) and the
``work-buffer link-surface`` CLI command share one HTTP call site.
"""
from __future__ import annotations

from typing import Any


def create_surface_request_variant_link(
    client,
    *,
    surface_id: int,
    request_variant_id: int,
    relation: str = "",
    evidence_ref: str = "",
) -> dict[str, Any]:
    return client.post(
        "surface-request-variant-links",
        {
            "surface_id": int(surface_id),
            "request_variant_id": int(request_variant_id),
            "relation": relation,
            "evidence_ref": evidence_ref,
        },
    )
