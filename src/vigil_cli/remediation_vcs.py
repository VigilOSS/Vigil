"""Locate the shared remediation VCS implementation in the managed agent tree."""

from pathlib import Path

from .paths import add_assess_import_path, find_repo_root, resolve_install_root


def adapter(install_root: Path | None = None):
    source = find_repo_root(Path(__file__))
    root = install_root or source or resolve_install_root()
    if not (root / "agent" / "scripts" / "assess").is_dir() and source is not None:
        root = source
    add_assess_import_path(root)
    from assess.lib import remediation_vcs  # type: ignore[import-not-found]

    return remediation_vcs
