"""Shared helpers for high-volume assessment ingestion writes."""
from __future__ import annotations

import sys
from typing import Any

from assess.lib.client import AssessError

DEFAULT_BULK_WRITE_SIZE = 500


def _positive_id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _uncertain_receipt(operation: str, detail: str) -> AssessError:
    return AssessError(
        f"{operation}: backend response did not identify the canonical {detail}; "
        "the write may have committed, so inspect durable assessment state and "
        "do not retry automatically"
    )


def _require_observation_receipt(
    response: object,
    *,
    observation: dict[str, Any],
    operation: str,
) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise _uncertain_receipt(operation, "request observation")
    variant = response.get("request_variant")
    receipt = response.get("request_observation")
    service = response.get("service")
    if variant is None and receipt is None:
        if isinstance(service, dict) and _positive_id(service.get("id")):
            return response
        raise _uncertain_receipt(operation, "request observation")
    if not isinstance(variant, dict) or not isinstance(receipt, dict):
        raise _uncertain_receipt(operation, "request observation")
    variant_id = variant.get("id")
    receipt_id = receipt.get("id")
    expected_method = str(observation.get("method") or "GET").upper()
    if (
        not _positive_id(variant_id)
        or not _positive_id(receipt_id)
        or receipt.get("request_variant_id") != variant_id
        or receipt.get("observed_url") != observation.get("url")
        or variant.get("method") != expected_method
    ):
        raise _uncertain_receipt(operation, "request observation")
    return response


def _require_bulk_receipt(
    response: object,
    *,
    expected_count: int,
    operation: str,
    detail: str,
) -> list[object]:
    if not isinstance(response, dict):
        raise _uncertain_receipt(operation, detail)
    count = response.get("count")
    records = response.get("records")
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or count != expected_count
        or not isinstance(records, list)
        or len(records) != expected_count
    ):
        raise _uncertain_receipt(operation, detail)
    return records


def _require_coverage_receipt(
    response: object,
    *,
    item: dict[str, Any],
    operation: str,
) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise _uncertain_receipt(operation, "coverage item")
    if (
        not _positive_id(response.get("id"))
        or response.get("request_variant_id") != item.get("request_variant_id")
        or response.get("service_id") != item.get("service_id")
        or response.get("auth_context") != item.get("auth_context", "anonymous")
        or response.get("input_slot") != item.get("input_slot", "endpoint")
        or response.get("attack_family") != item.get("attack_family")
    ):
        raise _uncertain_receipt(operation, "coverage item")
    return response


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
                response = client.post("request-observations", observation)
                records.append(
                    _require_observation_receipt(
                        response,
                        observation=observation,
                        operation="record request observation",
                    )
                )
            except Exception as row_exc:  # noqa: BLE001 - caller decides row policy
                if not fallback_individual:
                    raise
                records.append(row_exc)
        return records
    records = _require_bulk_receipt(
        response,
        expected_count=len(observations),
        operation="record request observations",
        detail="request observations",
    )
    return [
        _require_observation_receipt(
            record,
            observation=observation,
            operation="record request observation",
        )
        for observation, record in zip(observations, records, strict=True)
    ]


def post_coverage_items_bulk(client, items: list[dict[str, Any]], *, warn_prefix: str) -> None:
    if not items:
        return
    for chunk in _chunks(items, DEFAULT_BULK_WRITE_SIZE):
        try:
            response = client.post("coverage-items/bulk", {"items": chunk})
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
        else:
            records = _require_bulk_receipt(
                response,
                expected_count=len(chunk),
                operation="record coverage items",
                detail="coverage items",
            )
            for item, record in zip(chunk, records, strict=True):
                _require_coverage_receipt(
                    record,
                    item=item,
                    operation="record coverage item",
                )
            continue
        for item in chunk:
            try:
                response = client.post("coverage-items", item)
            except Exception as exc:  # noqa: BLE001 - best-effort coverage bridge
                print(
                    f"WARN {warn_prefix}: coverage-item POST failed for "
                    f"{item.get('attack_family', 'unknown')}: {exc}; continuing.",
                    file=sys.stderr,
                )
                continue
            _require_coverage_receipt(
                response,
                item=item,
                operation="record coverage item",
            )
