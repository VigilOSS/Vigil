"""Blocked-technique retry-state contract shared by storage and services."""

from __future__ import annotations


RETRY_STATES: tuple[str, ...] = (
    "pending",
    "no_retry",
    "retryable",
    "blocked",
    "blocked_on_dependency",
    "needs_authorization",
)


def map_legacy_retry_state(value: object) -> tuple[str, str]:
    """Map only reviewed values; preserve ambiguous prose for human revalidation."""

    retry_state = str(value or "")
    if retry_state in RETRY_STATES:
        return retry_state, ""
    return (
        "pending",
        f"unreviewed legacy retry_state={retry_state!r}; mapped to pending",
    )
