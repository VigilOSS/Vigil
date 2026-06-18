from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

CONFIG_ENV = "VIGIL_CONFIG"
CONFIG_DIR = Path.home() / ".config" / "vigil"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.json"

DEFAULT_RUNTIME_MEMORY_GB = 8
DEFAULT_RUNTIME_CPUS = 4
DEFAULT_RUNTIME_PIDS_LIMIT = 512
DEFAULT_RUNTIME_SHM_SIZE = "1g"

# Proxy URL schemes a tool's libcurl/Go-net stack understands for HTTP(S)_PROXY /
# ALL_PROXY. socks5h keeps DNS resolution on the proxy side (the privacy-correct
# choice for egress separation); plain socks5 resolves locally.
_RUNTIME_EGRESS_PROXY_SCHEMES = frozenset(
    {"http", "https", "socks5", "socks5h", "socks4", "socks4a"}
)

# Hosts that MUST bypass the egress proxy/VPN so orchestrator/backend traffic
# (host.docker.internal -> the host-gateway) never routes through the
# target-facing egress and break the audit/state pipeline. Always prepended to
# any operator-supplied NO_PROXY additions. host.docker.internal is the stable
# alias docker.HOST_GATEWAY_ARG maps to the host-gateway, so excluding the name
# covers the gateway regardless of the gateway's runtime IP.
RUNTIME_EGRESS_NO_PROXY_DEFAULTS: tuple[str, ...] = (
    "host.docker.internal",
    "localhost",
    "127.0.0.1",
    "::1",
)


@dataclass(frozen=True, slots=True)
class RuntimeResources:
    memory_gb: int
    cpus: float
    pids_limit: int
    shm_size: str


@dataclass(frozen=True, slots=True)
class RuntimeEgress:
    """Opt-in, off-by-default egress-separation knobs for the runtime container.

    All fields default to the no-egress (current) behaviour: ``proxy`` and
    ``network`` unset means the container uses Docker's default bridge and NATs
    out the host's default route — exactly as before. ``no_proxy`` always carries
    the mandatory backend/orchestrator exclusions even when a proxy is set, so
    ``vigil assess`` backend calls never traverse the target-facing proxy.
    """

    proxy: str | None
    network: str | None
    no_proxy: str

    @property
    def enabled(self) -> bool:
        return bool(self.proxy or self.network)


def runtime_resources() -> RuntimeResources:
    return RuntimeResources(
        memory_gb=_int_env("VIGIL_RUNTIME_MEMORY_GB", DEFAULT_RUNTIME_MEMORY_GB),
        cpus=_float_env("VIGIL_RUNTIME_CPUS", DEFAULT_RUNTIME_CPUS),
        pids_limit=_int_env("VIGIL_RUNTIME_PIDS_LIMIT", DEFAULT_RUNTIME_PIDS_LIMIT),
        shm_size=os.environ.get("VIGIL_RUNTIME_SHM_SIZE", DEFAULT_RUNTIME_SHM_SIZE).strip() or DEFAULT_RUNTIME_SHM_SIZE,
    )


def runtime_egress() -> RuntimeEgress:
    """Resolve the opt-in egress-separation config from the environment.

    Reads three optional vars; all unset = current no-egress behaviour:

    * ``VIGIL_RUNTIME_EGRESS_PROXY`` — upstream HTTP/HTTPS/SOCKS proxy URL wired
      into the container as HTTP(S)_PROXY / ALL_PROXY. Malformed values fail
      clearly here rather than silently dropping egress separation.
    * ``VIGIL_RUNTIME_EGRESS_NETWORK`` — a named, pre-existing Docker network to
      attach with ``--network`` (e.g. a VPN-sidecar net for a true separate IP).
    * ``VIGIL_RUNTIME_EGRESS_NO_PROXY`` — extra comma-separated NO_PROXY entries
      appended to the mandatory backend/orchestrator exclusions.
    """
    proxy = _validate_proxy_url(_str_env("VIGIL_RUNTIME_EGRESS_PROXY"))
    network = _validate_network_name(_str_env("VIGIL_RUNTIME_EGRESS_NETWORK"))
    no_proxy = _compose_no_proxy(_str_env("VIGIL_RUNTIME_EGRESS_NO_PROXY"))
    return RuntimeEgress(proxy=proxy, network=network, no_proxy=no_proxy)


def _str_env(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    raw = raw.strip()
    return raw or None


def _validate_proxy_url(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise SystemExit(
            f"VIGIL_RUNTIME_EGRESS_PROXY is not a valid URL ({value!r}): {exc}"
        ) from exc
    scheme = parts.scheme.lower()
    if scheme not in _RUNTIME_EGRESS_PROXY_SCHEMES:
        raise SystemExit(
            f"VIGIL_RUNTIME_EGRESS_PROXY scheme {parts.scheme or '(none)'!r} is not supported "
            f"(got {value!r}). Use one of: {', '.join(sorted(_RUNTIME_EGRESS_PROXY_SCHEMES))} "
            "(e.g. http://proxy:8080, socks5h://proxy:1080)."
        )
    if not parts.hostname:
        raise SystemExit(
            f"VIGIL_RUNTIME_EGRESS_PROXY is missing a host ({value!r}); "
            "expected scheme://host[:port]."
        )
    return value


def _validate_network_name(value: str | None) -> str | None:
    if value is None:
        return None
    # Docker network names are a restricted charset; reject embedded whitespace so a
    # typo can't split this single token into extra docker-run argv args.
    if any(ch.isspace() for ch in value) or any(ch in value for ch in ("\t", "\n")):
        raise SystemExit(
            f"VIGIL_RUNTIME_EGRESS_NETWORK must be a single Docker network name "
            f"(got {value!r})."
        )
    return value


def _compose_no_proxy(extra: str | None) -> str:
    entries: list[str] = list(RUNTIME_EGRESS_NO_PROXY_DEFAULTS)
    seen = {item.lower() for item in entries}
    if extra:
        for token in extra.split(","):
            token = token.strip()
            if token and token.lower() not in seen:
                entries.append(token)
                seen.add(token.lower())
    return ",".join(entries)


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
        raise SystemExit(f"Invalid vigil config JSON at {target}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid vigil config at {target}: expected a JSON object")
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
