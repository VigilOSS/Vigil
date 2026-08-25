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


# Rate flags, de-dashed so the single- and double-dash spellings of the same Go
# flag collapse to one name (`-rl` / `--rl`, `-rate-limit` / `--rate-limit`).
_PER_SECOND_RATE_FLAGS = frozenset({"rl", "rate-limit", "rate"})
# The per-minute family: httpx, nuclei, and katana all accept `-rlm`. A run that
# configures ONLY this one still has an explicit rate — reserving the per-second
# tool default for it is what let `httpx -rlm 60000` (1000 rps) reserve 150.
_PER_MINUTE_RATE_FLAGS = frozenset({"rlm", "rate-limit-minute"})


def _split_flag_token(token: str) -> tuple[str, str] | None:
    """Split one argv token into ``(de-dashed flag, attached value)``.

    Handles the attached Go/pflag form (``--rate-limit=500``) and returns an empty
    value for the space-separated form (``--rate-limit 500``), whose value is the
    next token.
    """
    if not token.startswith("-"):
        return None
    flag, _, attached = token.partition("=")
    return flag.lstrip("-"), attached


def _configured_rates_rps(cmd: list[str]) -> list[float]:
    """Every request rate the argv explicitly configures, in requests per second.

    Per-minute values are divided by 60: the tools implement them as a token
    bucket that refills N tokens per minute, so N/60 is the rate the run can
    sustain — which is what an engagement cap expressed in rps measures.
    """
    rates: list[float] = []
    for index, token in enumerate(cmd):
        split = _split_flag_token(token)
        if split is None:
            continue
        flag, attached = split
        if flag in _PER_SECOND_RATE_FLAGS:
            divisor = 1.0
        elif flag in _PER_MINUTE_RATE_FLAGS:
            divisor = 60.0
        else:
            continue
        raw = attached if attached else (cmd[index + 1] if index + 1 < len(cmd) else "")
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        if value > 0:
            rates.append(value / divisor)
    return rates


def aggregate_rate_reservation(
    engagement_dir: str,
    cmd: list[str],
    tool_name: str,
    execution_policy: dict[str, Any],
) -> float | None:
    """Return the rate this target-facing run must reserve, if configured."""
    if not execution_policy.get("target_facing"):
        return None
    scope_doc = scope_lib.load_scope(engagement_dir)
    aggregate_cap = scope_lib.aggregate_rate_limit(scope_doc)
    if aggregate_cap is None:
        return None
    configured = _configured_rates_rps(cmd)
    if configured:
        # An argv may carry BOTH families, and the tools do NOT agree on which one
        # wins — measured in the runtime image, not assumed: httpx and nuclei let
        # the per-minute limiter REPLACE the per-second one (`-rl 1 -rlm 600` over
        # 20 URLs finished in ~3s and ~1s, versus ~40s and ~19s for `-rl 1` alone),
        # while katana ignores `-rlm` entirely because its `-rl` carries a non-zero
        # default that wins the precedence chain (`-rl 1 -rlm 600` still crawled at
        # 1 req/s). Reserving the LARGEST configured rate is the only choice that
        # cannot under-reserve under either precedence, and under-reserving is an
        # ROE breach while over-reserving only costs a refusal the agent can
        # re-issue with a corrected argv. Vigil's own emitters are unaffected
        # either way: `kali katana` sets `-rl` alone and `web-discovery` sets
        # `-rl N -rlm N*60`, which is the same number.
        return max(configured)
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
