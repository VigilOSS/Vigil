from __future__ import annotations

import os
import sys
from pathlib import Path

from .config import get_config_value

DEFAULT_INSTALL_ROOT = Path.home() / "vigil"


def default_runtime_container() -> str:
    """Shared source of truth for the runtime container name on the CLI side.

    Mirrors ``assess.lib.client.default_runtime_container`` so vigil_cli and the
    assess lib resolve the same ``VIGIL_RUNTIME_CONTAINER`` env override and can
    no longer silently drift. Default stays ``"vigil"``.
    """
    return os.environ.get("VIGIL_RUNTIME_CONTAINER", "vigil")


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


def _resolved_or_preserved(path: Path, *, preserve_path: bool) -> Path:
    expanded = path.expanduser()
    if preserve_path:
        return Path(os.path.abspath(expanded))
    return expanded.resolve()


def resolve_install_root(
    value: str | Path | None = None, *, preserve_path: bool = False
) -> Path:
    if value:
        return _resolved_or_preserved(Path(value), preserve_path=preserve_path)
    env_value = os.environ.get("VIGIL_INSTALL_DIR") or os.environ.get("VIGIL_DIR")
    if env_value:
        return _resolved_or_preserved(Path(env_value), preserve_path=preserve_path)
    config_value = get_config_value("install.root")
    if config_value:
        return _resolved_or_preserved(Path(config_value), preserve_path=preserve_path)
    return _resolved_or_preserved(DEFAULT_INSTALL_ROOT, preserve_path=preserve_path)


def resolve_source_root(
    value: str | Path | None = None,
    *,
    install_root: Path | None = None,
    preserve_path: bool = False,
) -> Path:
    """Compatibility name for explicit/imported application resolution.

    ``install_root`` selects private data and cannot be an implicit code source.
    """
    from .application import resolve_application_root

    return resolve_application_root(value, preserve_path=preserve_path)


def agent_root(install_root: Path) -> Path:
    from .application import application_root_for_workspace

    return application_root_for_workspace(install_root) / "agent"


def engagements_root(install_root: Path) -> Path:
    from .workspace import workspace_path

    return workspace_path(install_root, "engagements")


def workspace_root_for_engagement(engagement_dir: Path) -> Path:
    """Locate private ownership without assuming a fresh or adopted tree depth."""
    engagement = engagement_dir.expanduser().resolve()
    configured = resolve_install_root()
    if engagements_root(configured).resolve() == engagement.parent:
        return configured
    from .workspace import WORKSPACE_FILENAME, read_workspace

    for candidate in engagement.parents:
        if not (candidate / WORKSPACE_FILENAME).exists() and not (candidate / WORKSPACE_FILENAME).is_symlink():
            continue
        metadata = read_workspace(candidate)
        if metadata is not None and engagements_root(candidate).resolve() == engagement.parent:
            return candidate
    if engagement.parent.name == "engagements":
        owner = engagement.parent.parent
        if owner.name == "agent":
            owner = owner.parent
        # Existing metadata is authoritative, even if its root was customized.
        if read_workspace(owner) is None and engagements_root(owner).resolve() == engagement.parent:
            return owner
    raise SystemExit(f"Cannot locate the private workspace owning engagement: {engagement}")


def resolve_orchestrator_data_dir(install_root: Path) -> Path:
    env_value = os.environ.get("VIGIL_DATA_DIR") or os.environ.get("REDTEAM_ORCHESTRATOR_DATA_DIR")
    if env_value:
        return Path(env_value).expanduser().resolve()
    from .workspace import workspace_path

    return workspace_path(install_root.expanduser().resolve(), "data")


def resolve_runtime_state_dir(install_root: Path) -> Path:
    from .workspace import workspace_path

    return workspace_path(install_root, "runtime_state")


def resolve_logs_dir(install_root: Path) -> Path:
    from .workspace import workspace_path

    return workspace_path(install_root, "logs")


def tenant_references_root(install_root: Path) -> Path:
    from .workspace import workspace_path

    return workspace_path(install_root, "tenant_references")


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
    """Resolve the orchestrator base URL through a five-layer chain.

    Precedence (highest first):

    1. ``ORCHESTRATOR_BASE_URL`` env var — explicit override always wins.
    2. Per-engagement ``.orchestrator.env`` — the backend snapshot for this
       specific engagement.
    3. ``vigil config get orchestrator_base_url`` — user-set persistent
       default, so changing the port doesn't require touching code or
       fiddling with environment variables.
    4. Install-root ``.orchestrator.env`` / ``.env`` — legacy fallbacks.
    5. Hardcoded fallback ``DEFAULT_ORCHESTRATOR_BASE_URL``.
    """
    if os.environ.get("ORCHESTRATOR_BASE_URL"):
        return os.environ["ORCHESTRATOR_BASE_URL"].rstrip("/")
    if engagement_dir is not None:
        value = read_env_file(engagement_dir / ".orchestrator.env").get("ORCHESTRATOR_BASE_URL")
        if value:
            return value.rstrip("/")
    config_value = get_config_value("orchestrator_base_url")
    if config_value:
        return config_value.rstrip("/")
    for path in (install_root / ".orchestrator.env", install_root / ".env"):
        value = read_env_file(path).get("ORCHESTRATOR_BASE_URL")
        if value:
            return value.rstrip("/")
    return DEFAULT_ORCHESTRATOR_BASE_URL


def container_host_url(url: str) -> str:
    return url.replace("127.0.0.1", "host.docker.internal").replace("localhost", "host.docker.internal")


def add_assess_import_path(install_root: Path) -> None:
    scripts_dir = agent_root(install_root) / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
