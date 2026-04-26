from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

CONFIG_ENV = "AI_THREAT_HUNTING_CONFIG"
CONFIG_DIR = Path.home() / ".config" / "security-research"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.json"

DEFAULT_RUNTIME_MEMORY_GB = 8
DEFAULT_RUNTIME_CPUS = 4
DEFAULT_RUNTIME_PIDS_LIMIT = 512
DEFAULT_RUNTIME_SHM_SIZE = "1g"


@dataclass(frozen=True, slots=True)
class RuntimeResources:
    memory_gb: int
    cpus: float
    pids_limit: int
    shm_size: str


def runtime_resources() -> RuntimeResources:
    return RuntimeResources(
        memory_gb=_int_env("AITH_RUNTIME_MEMORY_GB", DEFAULT_RUNTIME_MEMORY_GB),
        cpus=_float_env("AITH_RUNTIME_CPUS", DEFAULT_RUNTIME_CPUS),
        pids_limit=_int_env("AITH_RUNTIME_PIDS_LIMIT", DEFAULT_RUNTIME_PIDS_LIMIT),
        shm_size=os.environ.get("AITH_RUNTIME_SHM_SIZE", DEFAULT_RUNTIME_SHM_SIZE).strip() or DEFAULT_RUNTIME_SHM_SIZE,
    )


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer (got {raw!r})") from exc
    if value <= 0:
        raise SystemExit(f"{name} must be a positive integer (got {value})")
    return value


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return float(default)
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number (got {raw!r})") from exc
    if value <= 0:
        raise SystemExit(f"{name} must be positive (got {value})")
    return value


def config_path() -> Path:
    value = os.environ.get(CONFIG_ENV)
    if value:
        return Path(value).expanduser().resolve()
    return DEFAULT_CONFIG_PATH.expanduser().resolve()


def load_config(path: Path | None = None) -> dict[str, str]:
    target = path or config_path()
    if not target.exists():
        return {}
    raw = target.read_text(encoding="utf-8").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid aith config JSON at {target}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid aith config at {target}: expected a JSON object")
    return {str(key): str(value) for key, value in payload.items()}


def save_config(values: dict[str, str], path: Path | None = None) -> Path:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dict(sorted(values.items())), indent=2) + "\n", encoding="utf-8")
    return target


def get_config_value(key: str, default: str | None = None) -> str | None:
    return load_config().get(key, default)


def set_config_value(key: str, value: str) -> Path:
    values = load_config()
    values[key] = value
    return save_config(values)


def unset_config_value(key: str) -> Path:
    values = load_config()
    values.pop(key, None)
    return save_config(values)


def edit_config() -> None:
    target = config_path()
    if not target.exists():
        save_config({})
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    raise SystemExit(subprocess.call([editor, str(target)]))
