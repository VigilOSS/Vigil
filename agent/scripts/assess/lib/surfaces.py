"""Surface validation constants and helpers."""
from __future__ import annotations

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
