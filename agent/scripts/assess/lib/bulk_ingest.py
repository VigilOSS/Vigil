"""Shared helpers for high-volume assessment ingestion writes."""
from __future__ import annotations

import sys
from typing import Any

from assess.lib.client import AssessError

DEFAULT_BULK_WRITE_SIZE = 500


def _bulk_endpoint_missing(exc: AssessError) -> bool:
    message = str(exc)
    return message.startswith("HTTP 404") or message.startswith("HTTP 405")


def _bulk_payload_error(exc: AssessError) -> bool:
    message = str(exc)
    return (
        message.startswith("HTTP 400")
        or message.startswith("HTTP 413")
        or message.startswith("HTTP 422")
    )


def _chunks(items: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    return [items[index:index + size] for index in range(0, len(items), size)]


def post_request_observations_bulk(
    client,
    observations: list[dict[str, Any]],
    *,
    warn_prefix: str,
    fallback_individual: bool = False,
) -> list[dict[str, Any] | Exception]:
    if not observations:
        return []
    try:
        response = client.post("request-observations/bulk", {"items": observations})
    except AssessError as exc:
        should_retry_individually = _bulk_endpoint_missing(exc) or (
            fallback_individual and _bulk_payload_error(exc)
        )
        if not should_retry_individually:
            raise
        print(
            f"WARN {warn_prefix}: request-observations bulk POST failed "
            f"({exc}); retrying {len(observations)} row(s) individually.",
            file=sys.stderr,
        )
        records: list[dict[str, Any] | Exception] = []
        for observation in observations:
            try:
                records.append(client.post("request-observations", observation))
            except Exception as row_exc:  # noqa: BLE001 - caller decides row policy
                if not fallback_individual:
                    raise
                records.append(row_exc)
        return records
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
    for chunk in _chunks(items, DEFAULT_BULK_WRITE_SIZE):
        try:
            client.post("coverage-items/bulk", {"items": chunk})
            continue
        except AssessError as exc:
            if not (_bulk_endpoint_missing(exc) or _bulk_payload_error(exc)):
                print(
                    f"WARN {warn_prefix}: coverage-items bulk POST failed for "
                    f"{len(chunk)} item(s): {exc}; continuing.",
                    file=sys.stderr,
                )
                continue
            print(
                f"WARN {warn_prefix}: coverage-items bulk POST failed for "
                f"{len(chunk)} item(s): {exc}; retrying individually.",
                file=sys.stderr,
            )
        for item in chunk:
            try:
                client.post("coverage-items", item)
            except Exception as exc:  # noqa: BLE001 - best-effort coverage bridge
                print(
                    f"WARN {warn_prefix}: coverage-item POST failed for "
                    f"{item.get('attack_family', 'unknown')}: {exc}; continuing.",
                    file=sys.stderr,
                )
