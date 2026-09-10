"""Canonical ownership checks for blue tenant-reference files."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable


class TenantReferenceError(ValueError):
    """Raised when a tenant-reference path escapes its owned tree."""


def validate_tenant_reference_paths(
    paths: Iterable[str], *, agent_root: Path
) -> list[str]:
    """Return canonical regular files owned by ``references/tenants``.

    Symlinks are rejected at every component so a path that was in-tree when
    authored cannot silently redirect a dispatch to arbitrary local content.
    """
    tenant_root = agent_root / "references" / "tenants"
    try:
        canonical_root = tenant_root.resolve(strict=True)
    except OSError as exc:
        raise TenantReferenceError(
            f"tenant-reference root is unavailable: {tenant_root}: {exc}"
        ) from exc
    if tenant_root.is_symlink():
        raise TenantReferenceError(
            f"tenant-reference root must not be a symlink: {tenant_root}"
        )

    validated: list[str] = []
    for raw in paths:
        value = str(raw or "").strip()
        if not value:
            raise TenantReferenceError("tenant-reference path must be non-empty")
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = agent_root / candidate
        try:
            canonical = candidate.resolve(strict=True)
        except OSError as exc:
            raise TenantReferenceError(
                f"missing tenant reference file: {value}: {exc}"
            ) from exc
        try:
            relative = canonical.relative_to(canonical_root)
        except ValueError as exc:
            raise TenantReferenceError(
                f"tenant reference is outside owned tenant-reference root: {value}"
            ) from exc

        cursor = tenant_root
        for part in relative.parts:
            cursor /= part
            try:
                mode = os.lstat(cursor).st_mode
            except OSError as exc:
                raise TenantReferenceError(
                    f"missing tenant reference file: {value}: {exc}"
                ) from exc
            if stat.S_ISLNK(mode):
                raise TenantReferenceError(
                    f"tenant reference must not contain symlinks: {value}"
                )
        if not stat.S_ISREG(os.stat(canonical, follow_symlinks=False).st_mode):
            raise TenantReferenceError(
                f"tenant reference must be a regular file: {value}"
            )
        validated.append(str(canonical))
    return validated
