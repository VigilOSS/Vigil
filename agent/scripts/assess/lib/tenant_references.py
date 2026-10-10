"""Canonical ownership checks for blue tenant-reference files."""
from __future__ import annotations

import os
import errno
import stat
from pathlib import Path
from typing import Iterable


class TenantReferenceError(ValueError):
    """Raised when a tenant-reference path escapes its owned tree."""


def validate_tenant_reference_paths(
    paths: Iterable[str], *, tenant_root: Path, relative_root: Path | None = None
) -> list[str]:
    """Return canonical regular files owned by the private tenant-reference root.

    Symlinks are rejected at every component so a path that was in-tree when
    authored cannot silently redirect a dispatch to arbitrary local content.
    """
    from vigil_cli.install_fs import open_child_directory, open_pinned_directory

    try:
        pin = open_pinned_directory(tenant_root)
    except OSError as exc:
        raise TenantReferenceError(
            f"tenant-reference root is unavailable: {tenant_root}: {exc}"
        ) from exc
    assert pin is not None
    with pin:
        validated: list[str] = []
        for raw in paths:
            value = str(raw or "").strip()
            if not value:
                raise TenantReferenceError("tenant-reference path must be non-empty")
            candidate = Path(value).expanduser()
            if not candidate.is_absolute():
                candidate = (relative_root or tenant_root) / candidate
            if ".." in candidate.parts:
                raise TenantReferenceError(f"tenant reference is outside owned tenant-reference root: {value}")
            canonical = Path(os.path.abspath(candidate))
            try:
                relative = canonical.relative_to(pin.path)
            except ValueError as exc:
                raise TenantReferenceError(
                    f"tenant reference is outside owned tenant-reference root: {value}"
                ) from exc
            if not relative.parts:
                raise TenantReferenceError(f"tenant reference must be a regular file: {value}")
            descriptor = os.dup(pin.fd)
            try:
                for part in relative.parts[:-1]:
                    child = open_child_directory(descriptor, part, canonical)
                    os.close(descriptor)
                    descriptor = child
                flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
                source = os.open(relative.parts[-1], flags, dir_fd=descriptor)
                try:
                    if not stat.S_ISREG(os.fstat(source).st_mode):
                        raise TenantReferenceError(f"tenant reference must be a regular file: {value}")
                finally:
                    os.close(source)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise TenantReferenceError(f"tenant reference must not contain symlinks: {value}") from exc
                raise TenantReferenceError(
                    f"missing tenant reference file: {value}: {exc}"
                ) from exc
            finally:
                os.close(descriptor)
            validated.append(str(canonical))
        try:
            pin.require_attached()
        except OSError as exc:
            raise TenantReferenceError(f"tenant-reference root changed: {exc}") from exc
        return validated
