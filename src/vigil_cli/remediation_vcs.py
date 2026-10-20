"""Locate the shared remediation VCS implementation in the managed agent tree."""

from pathlib import Path

from .paths import add_assess_import_path, resolve_install_root


def adapter(install_root: Path | None = None, *, application_root: Path | None = None):
    add_assess_import_path(install_root or resolve_install_root(), application_root=application_root)
    from assess.lib import remediation_vcs  # type: ignore[import-not-found]

    return remediation_vcs
