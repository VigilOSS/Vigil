"""Client helpers for engagement-wide target-rate leases."""
from __future__ import annotations

import sys
from contextlib import contextmanager
from typing import Any, Iterator

from .client import AssessmentClient
from .config import Config
from . import scope as scope_lib


MAX_TARGET_RATE_LEASE_TTL_SECONDS = 86_400


def target_rate_lease_ttl(ttl_seconds: int) -> int:
    """Clamp a requested TTL to the backend's validated lease contract."""
    return min(max(int(ttl_seconds), 1), MAX_TARGET_RATE_LEASE_TTL_SECONDS)


def aggregate_rate_reservation(
    engagement_dir: str,
    cmd: list[str],
    tool_name: str,
    execution_policy: dict[str, Any],
) -> float | None:
    """Return the rate this target-facing run must reserve, if configured."""
    if not execution_policy.get("checked_targets") and not execution_policy.get("target_facing"):
        return None
    scope_doc = scope_lib.load_scope(engagement_dir)
    aggregate_cap = scope_lib.aggregate_rate_limit(scope_doc)
    if aggregate_cap is None:
        return None
    rate_flags = ("-rate-limit", "--rate-limit", "-rl", "--rate")
    for index, token in enumerate(cmd):
        if token in rate_flags and index + 1 < len(cmd):
            # Space-separated form: `--rate-limit 500`.
            try:
                value = float(cmd[index + 1])
            except (TypeError, ValueError):
                continue
            if value > 0:
                return value
        elif token.startswith("-") and "=" in token:
            # Attached Go/pflag form: `--rate-limit=500`, `-rl=500`. Reserving the
            # tool default here would silently admit a run above the ROE cap.
            flag, _, attached = token.partition("=")
            if flag not in rate_flags:
                continue
            try:
                value = float(attached)
            except (TypeError, ValueError):
                continue
            if value > 0:
                return value
    defaults = {"httpx": 150.0, "nuclei": 150.0, "katana": 150.0}
    return defaults.get(tool_name.lower(), aggregate_cap)


def acquire_target_rate_lease(
    *,
    config: Config,
    owner: str,
    effective_rate_rps: float,
    ttl_seconds: int,
    override_reason: str = "",
    command_run_id: int | None = None,
    client: AssessmentClient | None = None,
) -> dict[str, Any]:
    owns_client = client is None
    lease_client = client or AssessmentClient(config.base_url, config.engagement_key)
    try:
        return lease_client.post(
            "rate-leases",
            {
                "owner": owner,
                "effective_rate_rps": float(effective_rate_rps),
                "ttl_seconds": target_rate_lease_ttl(ttl_seconds),
                "override_reason": override_reason.strip(),
                "command_run_id": command_run_id,
            },
        )
    finally:
        if owns_client:
            lease_client.close()


def release_target_rate_lease(
    lease_token: str,
    *,
    config: Config | None = None,
    client: AssessmentClient | None = None,
) -> None:
    if client is None and config is None:
        raise ValueError("config is required when no AssessmentClient is supplied")
    owns_client = client is None
    lease_client = client or AssessmentClient(config.base_url, config.engagement_key)  # type: ignore[union-attr]
    try:
        lease_client.patch(f"rate-leases/{lease_token}", {"release": True})
    finally:
        if owns_client:
            lease_client.close()


@contextmanager
def target_rate_lease(
    *,
    config: Config,
    owner: str,
    effective_rate_rps: float,
    ttl_seconds: int,
    override_reason: str = "",
    command_run_id: int | None = None,
) -> Iterator[dict[str, Any]]:
    """Acquire an atomic aggregate-rate reservation and always release it.

    Callers size ``ttl_seconds`` from the execution deadline. If the caller is
    killed before ``finally`` runs, the backend stops counting the lease at its
    expiry, so a dead agent cannot reserve capacity forever.
    """
    client = AssessmentClient(config.base_url, config.engagement_key)
    try:
        lease = acquire_target_rate_lease(
            config=config,
            owner=owner,
            effective_rate_rps=effective_rate_rps,
            ttl_seconds=ttl_seconds,
            override_reason=override_reason,
            command_run_id=command_run_id,
            client=client,
        )
        try:
            yield lease
        finally:
            token = str(lease.get("lease_token") or "")
            if token:
                try:
                    release_target_rate_lease(token, client=client)
                except Exception as exc:  # noqa: BLE001 - expiry is the crash-safe release
                    print(
                        f"warning: target-rate lease release failed for {token}: {exc}; "
                        "the reservation will expire at its deadline",
                        file=sys.stderr,
                    )
    finally:
        client.close()
