"""Bridge installed CLI callers to the shared project configuration contract."""
from pathlib import Path
from .paths import add_assess_import_path


def project_module(install_root: Path):
    add_assess_import_path(install_root)
    from assess.lib import remediation_project  # type: ignore[import-not-found]
    return remediation_project
