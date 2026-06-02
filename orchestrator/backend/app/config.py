import os
from dataclasses import dataclass
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parents[1]


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
    frontend_dist_dir: Path = REPO_ROOT / "orchestrator" / "frontend" / "dist"
    agent_source_dir: Path = REPO_ROOT / "agent"
    orchestrator_public_url: str = os.environ.get("VIGIL_PUBLIC_URL", os.environ.get("ORCHESTRATOR_PUBLIC_URL", "http://127.0.0.1:18000"))
    auto_refresh_seconds: int = int(os.environ.get("VIGIL_DISCOVERY_REFRESH_SECONDS", "5"))


settings = Settings()
