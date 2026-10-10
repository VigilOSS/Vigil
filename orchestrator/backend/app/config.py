import os
from dataclasses import dataclass
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parents[1]
APPLICATION_ROOT = Path(os.environ.get("VIGIL_APPLICATION_DIR", str(REPO_ROOT)))


def env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = "Vigil Orchestrator"
    data_dir: Path = Path(os.environ.get("VIGIL_DATA_DIR", os.environ.get("REDTEAM_ORCHESTRATOR_DATA_DIR", str(BACKEND_ROOT / "data"))))
    install_dir: Path = Path(os.environ.get("VIGIL_INSTALL_DIR", str(REPO_ROOT)))
    application_dir: Path = APPLICATION_ROOT
    engagements_dir: Path | None = Path(os.environ["VIGIL_ENGAGEMENTS_DIR"]) if os.environ.get("VIGIL_ENGAGEMENTS_DIR") else None
    frontend_dist_dir: Path = APPLICATION_ROOT / "orchestrator" / "frontend" / "dist"
    report_template_path: Path = APPLICATION_ROOT / "orchestrator" / "report" / "dist" / "template.html"
    agent_source_dir: Path = APPLICATION_ROOT / "agent"
    orchestrator_public_url: str = os.environ.get("VIGIL_PUBLIC_URL", os.environ.get("ORCHESTRATOR_PUBLIC_URL", "http://127.0.0.1:18000"))
    auto_refresh_seconds: int = int(os.environ.get("VIGIL_DISCOVERY_REFRESH_SECONDS", "5"))


settings = Settings()
