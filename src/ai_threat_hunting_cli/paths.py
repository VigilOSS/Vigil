from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .config import get_config_value

DEFAULT_INSTALL_ROOT = Path.home() / "security-research"
CONFIG_DIR = Path.home() / ".config" / "security-research"
DEFAULT_SOURCE_REPO = "https://github.com/vigil-oss/security-research.git"
# Hardcoded fallback for ``ORCHESTRATOR_BASE_URL`` — last layer of the
# resolution chain in ``resolve_orchestrator_base_url`` and the value the
# engagement-creation flow compares against to decide whether
# ``.orchestrator.env`` needs an explicit override line.
DEFAULT_ORCHESTRATOR_BASE_URL = "http://127.0.0.1:18000"


def looks_like_repo_root(path: Path) -> bool:
    return (path / "agent").is_dir() and (path / "orchestrator").is_dir()


def find_repo_root(start: Path | None = None) -> Path | None:
    current = (start or Path(__file__)).resolve()
    for candidate in (current, *current.parents):
        if looks_like_repo_root(candidate):
            return candidate
    return None


def resolve_install_root(value: str | Path | None = None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    env_value = os.environ.get("AI_THREAT_HUNTING_INSTALL_DIR") or os.environ.get("AI_THREAT_HUNTING_DIR")
    if env_value:
        return Path(env_value).expanduser().resolve()
    config_value = get_config_value("install.root")
    if config_value:
        return Path(config_value).expanduser().resolve()
    return DEFAULT_INSTALL_ROOT.expanduser().resolve()


def resolve_source_root(value: str | Path | None = None, *, install_root: Path | None = None) -> Path:
    candidates: list[Path] = []
    if value:
        candidates.append(Path(value).expanduser())
    env_value = os.environ.get("AI_THREAT_HUNTING_SOURCE_DIR")
    if env_value:
        candidates.append(Path(env_value).expanduser())
    config_value = get_config_value("source.dir")
    if config_value:
        candidates.append(Path(config_value).expanduser())
    discovered = find_repo_root()
    if discovered is not None:
        candidates.append(discovered)
    cwd_discovered = find_repo_root(Path.cwd())
    if cwd_discovered is not None:
        candidates.append(cwd_discovered)

    for candidate in candidates:
        resolved = candidate.resolve()
        if looks_like_repo_root(resolved):
            return resolved

    cached = _ensure_cached_source()
    if cached is not None:
        return cached
    if install_root is not None:
        resolved_install_root = install_root.expanduser().resolve()
        if looks_like_repo_root(resolved_install_root):
            return resolved_install_root

    raise SystemExit(
        "Cannot locate AI Threat Hunting source files. Run from a source checkout, "
        "set AI_THREAT_HUNTING_SOURCE_DIR, pass --source, or install git so the CLI can fetch its source bundle."
    )


def _ensure_cached_source() -> Path | None:
    if os.environ.get("AI_THREAT_HUNTING_DISABLE_SOURCE_SYNC") == "1":
        return None
    if not shutil_which("git"):
        return None
    source_dir = CONFIG_DIR / "source"
    repo_url = os.environ.get("AI_THREAT_HUNTING_SOURCE_REPO") or get_config_value("source.repo", DEFAULT_SOURCE_REPO)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if source_dir.exists():
        subprocess.run(["git", "-C", str(source_dir), "pull", "--ff-only"], text=True, capture_output=True, check=False)
    else:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(source_dir)], text=True, capture_output=True, check=False)
    return source_dir.resolve() if looks_like_repo_root(source_dir) else None


def shutil_which(command: str) -> str | None:
    from shutil import which

    return which(command)


def agent_root(install_root: Path) -> Path:
    return install_root / "agent"


def engagements_root(install_root: Path) -> Path:
    return agent_root(install_root) / "engagements"


def resolve_orchestrator_data_dir(install_root: Path) -> Path:
    env_value = os.environ.get("AI_THREAT_HUNTING_DATA_DIR") or os.environ.get("REDTEAM_ORCHESTRATOR_DATA_DIR")
    if env_value:
        return Path(env_value).expanduser().resolve()
    return install_root.expanduser().resolve() / "orchestrator" / "backend" / "data"


def read_env_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        result[key.strip()] = value
    return result


def resolve_orchestrator_base_url(install_root: Path, engagement_dir: Path | None = None) -> str:
    """Resolve the orchestrator base URL through a four-layer chain.

    Precedence (highest first):

    1. ``ORCHESTRATOR_BASE_URL`` env var — explicit override always wins.
    2. ``.orchestrator.env`` files (install-root and per-engagement) —
       per-engagement overrides snapshotted at engagement creation time.
    3. ``aith config get orchestrator_base_url`` — user-set persistent
       default, so changing the port doesn't require touching code or
       fiddling with environment variables.
    4. Hardcoded fallback ``DEFAULT_ORCHESTRATOR_BASE_URL``.
    """
    if os.environ.get("ORCHESTRATOR_BASE_URL"):
        return os.environ["ORCHESTRATOR_BASE_URL"].rstrip("/")
    for path in (
        install_root / ".env",
        install_root / ".orchestrator.env",
        (engagement_dir / ".orchestrator.env") if engagement_dir else None,
    ):
        if path is None:
            continue
        value = read_env_file(path).get("ORCHESTRATOR_BASE_URL")
        if value:
            return value.rstrip("/")
    config_value = get_config_value("orchestrator_base_url")
    if config_value:
        return config_value.rstrip("/")
    return DEFAULT_ORCHESTRATOR_BASE_URL


def container_host_url(url: str) -> str:
    return url.replace("127.0.0.1", "host.docker.internal").replace("localhost", "host.docker.internal")


def add_assess_import_path(install_root: Path) -> None:
    scripts_dir = agent_root(install_root) / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
