"""Environment and config resolution — replaces lib/orchestrator_env.sh."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

SESSION_ENGAGEMENT_ENV = "VIGIL_SESSION_ENGAGEMENT_DIR"
ENGAGEMENT_BINDING_CONTRACT = (
    "Assessment state resolves from a valid explicit --engagement-dir, then the "
    "engagement tree containing CWD, then $VIGIL_SESSION_ENGAGEMENT_DIR exported "
    "by a Vigil launcher. A CWD/session disagreement fails closed. The global "
    "active pointer and $ENGAGEMENT_DIR never select assessment state."
)


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


def _walk_up_for_scope(start: Path) -> Path | None:
    """Nearest ancestor of *start* (inclusive) that is an engagement root.

    Makes "being anywhere inside the engagement tree" resolve to the engagement,
    and folds in the guard against the ``cd scans/ ; ENGAGEMENT_DIR=$(pwd)``
    basename trap — walk-up lands on the parent that actually holds scope.json.
    """
    try:
        current = start.resolve()
    except OSError:
        return None
    for candidate in (current, *current.parents):
        if _is_engagement_root(candidate):
            return candidate
    return None


def resolve_engagement_dir(cli_flag: str | None = None) -> str:
    """Resolve the engagement directory. See
    :func:`resolve_engagement_dir_with_tier` for the precedence and behaviour.
    """
    return resolve_engagement_dir_with_tier(cli_flag)[0]


def _warn_legacy_path_mismatch(resolved: Path, tier: str) -> None:
    """Warn when the artifact-path variable disagrees with assessment state."""
    legacy_raw = os.environ.get("ENGAGEMENT_DIR", "")
    if not legacy_raw:
        return
    legacy = Path(legacy_raw).expanduser()
    if not _is_engagement_root(legacy):
        return
    legacy = legacy.resolve()
    if legacy == resolved:
        return
    print(
        f"WARNING: $ENGAGEMENT_DIR points at {legacy}, but assessment state resolved "
        f"to {resolved} from {tier}. $ENGAGEMENT_DIR is only an artifact-path variable; "
        "use the resolved engagement for backend reads and writes.",
        file=sys.stderr,
    )


def resolve_engagement_dir_with_tier(cli_flag: str | None = None) -> tuple[str, str]:
    """Resolve the engagement directory and report which tier won.

    See :data:`ENGAGEMENT_BINDING_CONTRACT`. Every selector must name a real
    engagement root. An explicit flag is an intentional per-command override;
    without one, two concurrently valid but different implicit selectors are an
    error rather than a precedence contest.
    """
    # Tier 1 — explicit flag is intentional and authoritative.
    if cli_flag is not None:
        if not cli_flag.strip():
            raise SystemExit("--engagement-dir must not be empty")
        explicit_path = Path(cli_flag).expanduser()
        if _is_engagement_root(explicit_path):
            resolved = explicit_path.resolve()
            _warn_legacy_path_mismatch(resolved, "flag")
            return str(resolved), "flag"
        if explicit_path.is_dir():
            raise SystemExit(
                f"--engagement-dir '{cli_flag}' has no scope.json — it is not an "
                "engagement root. Point it at the engagement directory itself, not "
                "a subdirectory (e.g. scans/)."
            )
        raise SystemExit(f"--engagement-dir '{cli_flag}' does not exist")

    # Resolve both implicit selectors before choosing so disagreement is visible.
    walked = _walk_up_for_scope(Path.cwd())
    session_raw = os.environ.get(SESSION_ENGAGEMENT_ENV, "")
    session: Path | None = None
    if session_raw:
        session_path = Path(session_raw).expanduser()
        if _is_engagement_root(session_path):
            session = session_path.resolve()
        elif session_path.is_dir():
            raise SystemExit(
                f"${SESSION_ENGAGEMENT_ENV} '{session_raw}' has no scope.json — it is "
                "not an engagement root. Start the client through `vigil engagement "
                "start` or pass --engagement-dir explicitly."
            )
        else:
            raise SystemExit(
                f"${SESSION_ENGAGEMENT_ENV} '{session_raw}' does not exist"
            )

    if walked is not None and session is not None and walked != session:
        raise SystemExit(
            f"Assessment engagement conflict: CWD {walked} conflicts with "
            f"${SESSION_ENGAGEMENT_ENV} resolves to {session}. Return to the launched "
            "engagement tree or pass --engagement-dir explicitly."
        )
    if walked is not None:
        _warn_legacy_path_mismatch(walked, "cwd")
        return str(walked), "cwd"
    if session is not None:
        _warn_legacy_path_mismatch(session, "session")
        return str(session), "session"

    raise SystemExit(
        "Cannot resolve engagement directory. Run from an engagement tree, start the "
        "client with `vigil engagement start`, or pass --engagement-dir."
    )


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
    # agent_root is <eng_dir>/../.. (engagements/<key> -> <install_root>/agent)
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
    from urllib.parse import urlparse

    parsed = urlparse(cfg.base_url)
    host = parsed.hostname or "127.0.0.1"
    # Honour the URL scheme: an https:// base_url must be health-checked over
    # TLS (HTTPSConnection, default port 443), otherwise the plaintext probe
    # against a TLS port fails and the backend is wrongly reported unreachable.
    is_https = parsed.scheme == "https"
    port = parsed.port or (443 if is_https else 80)
    path = f"{(parsed.path or '').rstrip('/')}/engagements/{cfg.engagement_key}/assessment/summary"

    conn: http.client.HTTPConnection | None = None
    try:
        if is_https:
            conn = http.client.HTTPSConnection(host, port, timeout=2)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=2)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")

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
    finally:
        if conn is not None:
            conn.close()
