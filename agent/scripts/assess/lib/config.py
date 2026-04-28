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


def _candidate_env_files(engagement_dir: str, agent_root: str) -> list[str]:
    """Return the ordered list of env files the resolver searches.

    Parent-shell env var wins; among files, the resolver picks the first
    hit (the contract is that nearer-to-the-engagement files override
    install-root defaults).
    """
    install_root = str(Path(agent_root).parent)
    candidates = [
        os.path.join(install_root, ".env"),
        os.path.join(install_root, ".orchestrator.env"),
    ]
    env_eng_dir = os.environ.get("ENGAGEMENT_DIR", "")
    if env_eng_dir:
        candidates.append(os.path.join(env_eng_dir, ".orchestrator.env"))
    candidates.append(os.path.join(os.getcwd(), ".orchestrator.env"))
    if engagement_dir:
        candidates.append(os.path.join(engagement_dir, ".orchestrator.env"))
    return candidates


def resolve_base_url(engagement_dir: str, agent_root: str) -> str:
    """Resolve ORCHESTRATOR_BASE_URL through the env var chain."""
    url = os.environ.get("ORCHESTRATOR_BASE_URL", "")
    if url:
        return url.rstrip("/")

    for env_file in _candidate_env_files(engagement_dir, agent_root):
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
    cfg = Config(
        base_url=base_url,
        engagement_dir=eng_dir,
        engagement_key=eng_key,
        agent_root=agent_root,
    )
    _verify_backend(cfg)
    return cfg


def _verify_backend(cfg: Config) -> None:
    """Quick check that the backend is reachable and knows our engagement.

    Prints a warning on failure but does not abort — offline/local-only
    workflows should still work.
    """
    import http.client
    import json as _json
    import sys
    from urllib.parse import urlparse

    parsed = urlparse(cfg.base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    path = f"{(parsed.path or '').rstrip('/')}/engagements/{cfg.engagement_key}/assessment/summary"

    try:
        conn = http.client.HTTPConnection(host, port, timeout=2)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        conn.close()

        if resp.status == 404:
            print(
                f"WARNING: Backend at {cfg.base_url} returned 404 for engagement '{cfg.engagement_key}'.\n"
                f"  The engagement directory may not be visible to the backend's sync_engagements() scanner.\n"
                f"  Backend engagement root and local engagement dir may be on different install paths.\n"
                f"  Data written via the API may be lost or routed to a stale engagement.\n"
                f"  Engagement dir: {cfg.engagement_dir}",
                file=sys.stderr,
            )
        elif resp.status >= 400:
            print(
                f"WARNING: Backend at {cfg.base_url} returned HTTP {resp.status} for engagement check.\n"
                f"  Response: {body[:200]}",
                file=sys.stderr,
            )
    except Exception:
        # Backend unreachable — not fatal, local-only mode is valid
        pass
