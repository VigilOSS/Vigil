"""Bridge installed CLI callers to the shared project configuration contract."""
from pathlib import Path
from .paths import add_assess_import_path, find_repo_root


def project_module(install_root: Path):
    add_assess_import_path(install_root)
    repo = find_repo_root(Path(__file__))
    if repo is not None:
        add_assess_import_path(repo)
    from assess.lib import remediation_project  # type: ignore[import-not-found]
    return remediation_project
