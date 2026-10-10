from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_backend_settings_keep_release_assets_separate_from_workspace(tmp_path: Path) -> None:
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    environment = {
        **os.environ,
        "VIGIL_APPLICATION_DIR": str(application),
        "VIGIL_INSTALL_DIR": str(workspace),
        "VIGIL_ENGAGEMENTS_DIR": str(workspace / "retained-engagements"),
        "VIGIL_DATA_DIR": str(workspace / "retained-state"),
    }
    result = subprocess.run(
        [sys.executable, "-c", "import json; from app.config import settings; print(json.dumps({name: str(getattr(settings, name)) for name in ('install_dir', 'data_dir', 'frontend_dist_dir', 'report_template_path', 'agent_source_dir')}))"],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    values = json.loads(result.stdout)
    assert values["frontend_dist_dir"] == str(application / "orchestrator" / "frontend" / "dist")
    assert values["report_template_path"] == str(application / "orchestrator" / "report" / "dist" / "template.html")
    assert values["agent_source_dir"] == str(application / "agent")
    assert values["data_dir"] == str(workspace / "retained-state")
    assert values["install_dir"] == str(workspace)
