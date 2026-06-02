"""Environment and config resolution — replaces lib/orchestrator_env.sh."""
from __future__ import annotations

import os
import json
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


def _is_engagement_root(path: Path) -> bool:
    """An engagement root is a directory containing scope.json.

    scope.json is the canonical marker the engagement key is derived from, so a
    dir without it is not an engagement root — accepting one silently derives a
    bogus key from the basename (e.g. ``scans``) and routes backend writes to a
    404'd engagement.
    """
    return path.is_dir() and (path / "scope.json").is_file()


def resolve_engagement_dir(cli_flag: str | None = None) -> str:
    """Resolve engagement directory: CLI flag > $ENGAGEMENT_DIR > cwd.

    The engagement key is the basename of whatever directory this returns, so
    every branch now requires a real engagement root (a dir with scope.json). A
    flag/env that points at a real directory WITHOUT scope.json fails loud and
    names the bad path, rather than silently deriving a key from a subdirectory
    basename — the `cd scans/ ; ENGAGEMENT_DIR=$(pwd)` → key="scans" trap.
    """
    if cli_flag:
        if _is_engagement_root(Path(cli_flag)):
            return str(Path(cli_flag).resolve())
        if Path(cli_flag).is_dir():
            raise SystemExit(
                f"--engagement-dir '{cli_flag}' has no scope.json — it is not an "
                "engagement root. Point it at the engagement directory itself, not "
                "a subdirectory (e.g. scans/)."
            )
        # Non-existent path: fall through to env/cwd (preserves prior behavior).

    env_dir = os.environ.get("ENGAGEMENT_DIR", "")
    if env_dir:
        if _is_engagement_root(Path(env_dir)):
            return str(Path(env_dir).resolve())
        if Path(env_dir).is_dir():
            raise SystemExit(
                f"$ENGAGEMENT_DIR '{env_dir}' has no scope.json — it is not an "
                "engagement root. Did you `cd` into a subdirectory (e.g. scans/) "
                "before setting ENGAGEMENT_DIR=$(pwd)? Point it at the engagement dir."
            )

    cwd = Path.cwd()
    if (cwd / "scope.json").is_file():
        return str(cwd.resolve())

    raise SystemExit("Cannot resolve engagement directory. Set --engagement-dir, $ENGAGEMENT_DIR, or run from a dir with scope.json.")


def anchor_engagement_relative(path: str, engagement_dir_flag: str | None = None) -> str:
    """Resolve a relative path against the engagement dir, not the process cwd.

    Absolute paths are returned unchanged. Relative paths (notably a bare
    ``cases.db``) are joined onto the resolved engagement root so a subagent
    whose cwd drifted between bash calls can't open or create a different,
    empty database. Raises (via :func:`resolve_engagement_dir`) when the
    engagement dir cannot be resolved, rather than silently guessing the cwd.
    """
    p = Path(path)
    if p.is_absolute():
        return path
    eng_dir = resolve_engagement_dir(engagement_dir_flag)
    return str(Path(eng_dir) / path)


def _candidate_env_files(engagement_dir: str, agent_root: str) -> list[str]:
    """Return the ordered list of env files the resolver searches.

    Parent-shell env var wins. Among env files, engagement-local config wins
    over install-root legacy defaults so an old install .env cannot retarget a
    specific engagement.
    """
    install_root = str(Path(agent_root).parent)
    candidates = []
    if engagement_dir:
        candidates.append(os.path.join(engagement_dir, ".orchestrator.env"))
    candidates.extend([
        os.path.join(install_root, ".orchestrator.env"),
        os.path.join(install_root, ".env"),
    ])
    seen: set[str] = set()
    unique: list[str] = []
    for candidate in candidates:
        normalized = str(Path(candidate).expanduser())
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(candidate)
    return unique


def _read_vigil_config_value(key: str) -> str | None:
    config_path = Path(
        os.environ.get(
            "VIGIL_CONFIG",
            str(Path.home() / ".config" / "vigil" / "config.json"),
        )
    ).expanduser()
    if not config_path.is_file():
        return None
    try:
        raw = config_path.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid vigil config JSON at {config_path}: {exc}") from exc
    except OSError:
        return None
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid vigil config at {config_path}: expected a JSON object")
    value = payload.get(key)
    return str(value) if value is not None else None


def resolve_base_url(engagement_dir: str, agent_root: str) -> str:
    """Resolve ORCHESTRATOR_BASE_URL through env, engagement, config, legacy defaults."""
    url = os.environ.get("ORCHESTRATOR_BASE_URL", "")
    if url:
        return url.rstrip("/")

    engagement_env_file = (
        os.path.join(engagement_dir, ".orchestrator.env")
        if engagement_dir else ""
    )
    if engagement_env_file:
        env_vars = _read_env_file(engagement_env_file)
        val = env_vars.get("ORCHESTRATOR_BASE_URL", "")
        if val:
            return val.rstrip("/")

    config_value = _read_vigil_config_value("orchestrator_base_url")
    if config_value:
        return config_value.rstrip("/")

    for env_file in _candidate_env_files(engagement_dir, agent_root):
        if engagement_env_file and env_file == engagement_env_file:
            continue
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
