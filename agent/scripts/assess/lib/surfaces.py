"""Surface validation constants and helpers."""
from __future__ import annotations

# Mutable statuses for by-id resolution. ``discovered`` is the seed state
# only; agents resolve to one of the three terminal states below.
RESOLVABLE_STATUSES = frozenset({
    "covered",
    "not_applicable",
    "deferred",
})

VALID_SURFACE_TYPES = frozenset({
    "auth_entry",
    "account_recovery",
    "object_reference",
    "privileged_write",
    "file_handling",
    "dynamic_render",
    "api_documentation",
    "workflow_token",
})

VALID_STATUSES = frozenset({
    "discovered",
    "covered",
    "not_applicable",
    "deferred",
})


def validate_surface_type(surface_type: str) -> None:
    if surface_type not in VALID_SURFACE_TYPES:
        valid = ", ".join(sorted(VALID_SURFACE_TYPES))
        raise SystemExit(
            f"invalid surface_type: {surface_type}. "
            f"Valid types: {valid}"
        )


def validate_surface_status(status: str) -> None:
    if status not in VALID_STATUSES:
        valid = ", ".join(sorted(VALID_STATUSES))
        raise SystemExit(
            f"invalid surface status: {status}. "
            f"Valid statuses: {valid}"
        )


def validate_resolution_status(status: str) -> None:
    """Reject statuses that are not valid resolutions.

    ``discovered`` is the seed state — operators can only resolve a
    surface to ``covered``, ``not_applicable``, or ``deferred``.
    """
    if status not in RESOLVABLE_STATUSES:
        valid = ", ".join(sorted(RESOLVABLE_STATUSES))
        raise SystemExit(
            f"invalid resolution status: {status}. "
            f"Valid statuses: {valid}"
        )
