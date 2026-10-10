from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__
from .config import get_config_value

DEFAULT_INSTALL_ROOT = Path.home() / "vigil"
CONFIG_DIR = Path.home() / ".config" / "vigil"
DEFAULT_SOURCE_REPO = "https://github.com/VigilOSS/Vigil.git"
SOURCE_CLONE_TIMEOUT_SECONDS = 120


def _source_cache_path(config_dir: Path, repo_url: str, source_ref: str) -> Path:
    """Return a cache path bound to the exact repository and ref strings.

    The readable ref prefix is diagnostic only. The digest prevents two repos
    sharing a tag, or refs such as ``feature/x`` and ``feature-x``, from silently
    reusing one another's checkout after filename sanitization.
    """
    label = re.sub(r"[^A-Za-z0-9._-]+", "-", source_ref).strip("-")[:48]
    label = label or "ref"
    identity = hashlib.sha256(f"{repo_url}\0{source_ref}".encode("utf-8")).hexdigest()[:16]
    return config_dir / f"source-{label}-{identity}"


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
    candidates: list[Path] = []
    if value:
        candidates.append(Path(value).expanduser())
    env_value = os.environ.get("VIGIL_SOURCE_DIR")
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
        if looks_like_repo_root(candidate):
            return _resolved_or_preserved(candidate, preserve_path=preserve_path)

    cached = _ensure_cached_source()
    if cached is not None:
        return cached
    if install_root is not None:
        if looks_like_repo_root(install_root):
            return _resolved_or_preserved(
                install_root, preserve_path=preserve_path
            )

    raise SystemExit(
        "Cannot locate Vigil source files. Run from a source checkout, "
        "set VIGIL_SOURCE_DIR, pass --source, or install git so the CLI can fetch its source bundle."
    )


def _ensure_cached_source() -> Path | None:
    if os.environ.get("VIGIL_DISABLE_SOURCE_SYNC") == "1":
        return None
    if not shutil_which("git"):
        return None
    source_ref = (
        os.environ.get("VIGIL_SOURCE_REF")
        or get_config_value("source.ref")
        or f"v{__version__}"
    )
    if source_ref == "v0.0.0+unknown":
        return None
    repo_url = (
        os.environ.get("VIGIL_SOURCE_REPO")
        or get_config_value("source.repo", DEFAULT_SOURCE_REPO)
        or DEFAULT_SOURCE_REPO
    )
    source_dir = _source_cache_path(CONFIG_DIR, repo_url, source_ref)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if looks_like_repo_root(source_dir):
        return source_dir.resolve()
    if source_dir.exists():
        return None
    with tempfile.TemporaryDirectory(prefix=".source-cache-", dir=CONFIG_DIR) as tmp:
        staging = Path(tmp) / "source"
        argv = [
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            source_ref,
            "--single-branch",
            repo_url,
            str(staging),
        ]
        try:
            completed = subprocess.run(
                argv,
                text=True,
                capture_output=True,
                check=False,
                timeout=SOURCE_CLONE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            print(
                f"[vigil] warning: source sync for {source_ref} timed out after "
                f"{SOURCE_CLONE_TIMEOUT_SECONDS} seconds",
                file=sys.stderr,
            )
            return None
        except OSError as exc:
            print(
                f"[vigil] warning: source sync could not start for {source_ref}: {exc}",
                file=sys.stderr,
            )
            return None
        if completed.returncode != 0 or not looks_like_repo_root(staging):
            detail = (
                getattr(completed, "stderr", "")
                or "git clone did not produce a Vigil source tree"
            ).strip()
            print(
                f"[vigil] warning: source sync failed for {source_ref}: {detail}",
                file=sys.stderr,
            )
            return None
        try:
            staging.rename(source_dir)
        except FileExistsError:
            if not looks_like_repo_root(source_dir):
                return None
    return source_dir.resolve() if looks_like_repo_root(source_dir) else None


def shutil_which(command: str) -> str | None:
    from shutil import which

    return which(command)


def agent_root(install_root: Path) -> Path:
    return install_root / "agent"


def engagements_root(install_root: Path) -> Path:
    return agent_root(install_root) / "engagements"


def resolve_orchestrator_data_dir(install_root: Path) -> Path:
    env_value = os.environ.get("VIGIL_DATA_DIR") or os.environ.get("REDTEAM_ORCHESTRATOR_DATA_DIR")
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
