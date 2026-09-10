"""Surface validation constants and helpers."""
from __future__ import annotations

# VALID_STATUSES / RESOLVABLE_STATUSES mirror the backend ``SurfaceStatus`` enum
# (source of truth:
# ``orchestrator/backend/app/services/state_manager/coverage.py``). The CLI
# cannot import the backend, so these are kept in sync by a drift-guard test
# (test_coverage_probe_cli_sync in the backend suite) rather than shared code —
# same pattern as resolve.py for coverage statuses.
#
# Mutable statuses for by-id resolution. ``discovered`` is the seed state
# only; agents resolve to ``covered``, ``not_applicable``, ``deferred``, or
# ``partially-covered`` (when a coverage pass partially completed and a
# follow-up condition is recorded).
RESOLVABLE_STATUSES = frozenset({
    "covered",
    "not_applicable",
    "deferred",
    "partially-covered",
    "administratively-closed",
})

CATCH_ALL_SURFACE_TYPES = frozenset({
    "misconfiguration",
    "informational",
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
}) | CATCH_ALL_SURFACE_TYPES

VALID_STATUSES = frozenset({
    "discovered",
    "covered",
    "not_applicable",
    "deferred",
    "partially-covered",
    "administratively-closed",
})

# POST /surfaces seeds a row. ``partially-covered`` and
# ``administratively-closed`` are rationale-bearing transitions available only
# through PATCH/``resolve surface`` and therefore are not creatable values.
CREATABLE_STATUSES = frozenset({
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


def validate_surface_create_status(status: str) -> None:
    if status not in CREATABLE_STATUSES:
        valid = ", ".join(sorted(CREATABLE_STATUSES))
        raise SystemExit(
            f"invalid surface create status: {status}. "
            f"Valid create statuses: {valid}; use `vigil assess resolve surface` "
            "for transition-only statuses"
        )


def validate_resolution_status(status: str) -> None:
    """Reject statuses that are not valid resolutions.

    ``discovered`` is the seed state — operators can only resolve a
    surface to ``covered``, ``not_applicable``, ``deferred``, or
    ``partially-covered`` with a follow-up condition.
    """
    if status not in RESOLVABLE_STATUSES:
        valid = ", ".join(sorted(RESOLVABLE_STATUSES))
        raise SystemExit(
            f"invalid resolution status: {status}. "
            f"Valid statuses: {valid}"
        )
