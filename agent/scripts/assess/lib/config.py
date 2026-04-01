"""Environment and config resolution — replaces lib/orchestrator_env.sh."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    base_url: str
    engagement_dir: str
    engagement_key: str
    agent_root: str  # <install_root>/agent


def _read_env_file(path: str) -> dict[str, str]:
    """Read a KEY=VALUE env file, returning a dict."""
    result: dict[str, str] = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            # Strip surrounding quotes
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            result[key] = val
    except OSError:
        pass
    return result


def resolve_engagement_dir(cli_flag: str | None = None) -> str:
    """Resolve engagement directory: CLI flag > $ENGAGEMENT_DIR > cwd if scope.json exists."""
    if cli_flag and Path(cli_flag).is_dir():
        return str(Path(cli_flag).resolve())

    env_dir = os.environ.get("ENGAGEMENT_DIR", "")
    if env_dir and Path(env_dir).is_dir():
        return str(Path(env_dir).resolve())

    cwd = Path.cwd()
    if (cwd / "scope.json").is_file():
        return str(cwd.resolve())

    raise SystemExit("Cannot resolve engagement directory. Set --engagement-dir, $ENGAGEMENT_DIR, or run from a dir with scope.json.")


def resolve_base_url(engagement_dir: str, agent_root: str) -> str:
    """Resolve ORCHESTRATOR_BASE_URL through the env var chain."""
    url = os.environ.get("ORCHESTRATOR_BASE_URL", "")
    if url:
        return url.rstrip("/")

    install_root = str(Path(agent_root).parent)

    candidate_files = [
        os.path.join(install_root, ".env"),
        os.path.join(install_root, ".orchestrator.env"),
    ]
    # Check $ENGAGEMENT_DIR env var path (may differ from resolved engagement_dir)
    env_eng_dir = os.environ.get("ENGAGEMENT_DIR", "")
    if env_eng_dir:
        candidate_files.append(os.path.join(env_eng_dir, ".orchestrator.env"))
    # Check current working directory
    candidate_files.append(os.path.join(os.getcwd(), ".orchestrator.env"))
    # Check resolved engagement dir
    if engagement_dir:
        candidate_files.append(os.path.join(engagement_dir, ".orchestrator.env"))

    for env_file in candidate_files:
        env_vars = _read_env_file(env_file)
        val = env_vars.get("ORCHESTRATOR_BASE_URL", "")
        if val:
            return val.rstrip("/")

    return "http://127.0.0.1:18000"


def load_config(engagement_dir_flag: str | None = None) -> Config:
    """Load full config from environment and file chain."""
    eng_dir = resolve_engagement_dir(engagement_dir_flag)
    # agent_root is <eng_dir>/../../ (engagements/<key> -> agent/)
    agent_root = str(Path(eng_dir).parent.parent)
    eng_key = Path(eng_dir).name
    base_url = resolve_base_url(eng_dir, agent_root)
    return Config(
        base_url=base_url,
        engagement_dir=eng_dir,
        engagement_key=eng_key,
        agent_root=agent_root,
    )
