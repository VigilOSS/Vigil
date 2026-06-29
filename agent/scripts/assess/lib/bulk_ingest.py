"""Shared helpers for high-volume assessment ingestion writes."""
from __future__ import annotations

import sys
from typing import Any

from assess.lib.client import AssessError

DEFAULT_BULK_WRITE_SIZE = 500


def _bulk_endpoint_missing(exc: AssessError) -> bool:
    message = str(exc)
    return message.startswith("HTTP 404") or message.startswith("HTTP 405")


def post_request_observations_bulk(client, observations: list[dict[str, Any]], *, warn_prefix: str) -> list[dict[str, Any]]:
    if not observations:
        return []
    try:
        response = client.post("request-observations/bulk", {"items": observations})
    except AssessError as exc:
        if not _bulk_endpoint_missing(exc):
            raise
        print(
            f"WARN {warn_prefix}: backend lacks request-observations/bulk; "
            "falling back to per-row POSTs until the orchestrator backend is upgraded.",
            file=sys.stderr,
        )
        return [client.post("request-observations", observation) for observation in observations]
    records = response.get("records") if isinstance(response, dict) else None
    if not isinstance(records, list):
        raise RuntimeError("backend bulk response missing records list")
    if len(records) != len(observations):
        raise RuntimeError(
            f"backend bulk response returned {len(records)} record(s) for "
            f"{len(observations)} observation(s)"
        )
    return records


def post_coverage_items_bulk(client, items: list[dict[str, Any]], *, warn_prefix: str) -> None:
    if not items:
        return
    try:
        client.post("coverage-items/bulk", {"items": items})
        return
    except AssessError as exc:
        if not _bulk_endpoint_missing(exc):
            print(
                f"WARN {warn_prefix}: coverage-items bulk POST failed for "
                f"{len(items)} item(s): {exc}; continuing.",
                file=sys.stderr,
            )
            return
        print(
            f"WARN {warn_prefix}: backend lacks coverage-items/bulk; "
            "falling back to per-row coverage POSTs until the orchestrator backend is upgraded.",
            file=sys.stderr,
        )
    for item in items:
        try:
            client.post("coverage-items", item)
        except Exception as exc:  # noqa: BLE001 - best-effort coverage bridge
            print(
                f"WARN {warn_prefix}: coverage-item POST failed for "
                f"{item.get('attack_family', 'unknown')}: {exc}; continuing.",
                file=sys.stderr,
            )
