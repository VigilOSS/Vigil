"""Exact installed-instruction identity for dispatch audit records."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .tracks import track_phases


_CLIENT_SPECIALIST_PATHS = {
    "claude": Path("agent/.claude/agents/{role}.md"),
    "codex": Path("agent/.codex/agents/{role}.toml"),
    "goose": Path("agent/.goose/recipes/{role}.yaml"),
    "opencode": Path("agent/.opencode/agent/{role}.md"),
}
_KNOWN_CLIENTS = frozenset({*_CLIENT_SPECIALIST_PATHS, "kimi"})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _operator_relative_path(engagement_dir: Path) -> Path | None:
    scope = _load_object(engagement_dir / "scope.json")
    enabled = track_phases(scope)
    mode = os.environ.get("VIGIL_OPERATOR_MODE", "").strip().lower()
    if not mode:
        mode = next(iter(enabled)) if len(enabled) == 1 else ""
    if mode not in enabled:
        return None
    name = {
        "code": "operator-core-code.md",
        "blue": "AGENTS-blue.md",
        "remediation": "operator-core-remediation.md",
    }.get(mode, "AGENTS.md")
    return Path("agent") / name


def _known_client(value: object) -> str:
    normalized = str(value).strip().lower()
    return normalized if normalized in _KNOWN_CLIENTS else "unknown"


def _launcher_effective_client(explicit: str | None) -> str:
    return _known_client(
        explicit
        or os.environ.get("VIGIL_CLIENT_NAME")
        or os.environ.get("VIGIL_CLIENT")
        or ""
    )


def _safe_role_basename(value: str) -> str | None:
    role = str(value).strip()
    if (
        not role
        or role in {".", ".."}
        or "/" in role
        or "\\" in role
        or "\x00" in role
        or Path(role).name != role
    ):
        return None
    return role


def build_dispatch_instruction_identity(
    *,
    agent_root: Path,
    engagement_dir: Path,
    agent_role: str,
    client_name: str | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return exact installed prompt hashes plus advisory health warnings.

    The hashes describe bytes actually present in the working root. Source-tree
    comparison is advisory: an unavailable checkout yields ``None`` rather than
    falsely declaring the installed instructions current or stale.
    """
    agent_root = agent_root.resolve()
    install_root = agent_root.parent
    engagement_dir = engagement_dir.resolve()
    warnings: list[str] = []
    launcher_client = _launcher_effective_client(client_name)
    requested_client = _known_client(os.environ.get("VIGIL_REQUESTED_CLIENT", ""))
    meta = _load_object(install_root / ".vigil-install-meta.json")
    raw_revision = meta.get("source_sha")
    source_revision = (
        raw_revision.strip()
        if isinstance(raw_revision, str) and raw_revision.strip()
        else "unknown"
    )
    if source_revision == "unknown":
        warnings.append("installed Vigil source revision is unavailable")

    operator_relative = _operator_relative_path(engagement_dir)
    operator_digest: str | None = None
    if operator_relative is None:
        warnings.append("operator mode is unavailable or not enabled; instruction fingerprint is unknown")
    else:
        operator_path = install_root / operator_relative
        if operator_path.is_file():
            operator_digest = _sha256(operator_path)
        else:
            warnings.append(f"installed operator instructions are missing: {operator_relative}")

    specialist_relative: Path | None = None
    specialist_digest: str | None = None
    template = _CLIENT_SPECIALIST_PATHS.get(launcher_client)
    if template is None:
        if launcher_client == "unknown":
            warnings.append(
                "client identity is unavailable; specialist instruction fingerprint is unknown"
            )
        else:
            warnings.append(
                f"client {launcher_client} does not install a specialist wrapper; "
                "specialist instruction fingerprint is unknown"
            )
    else:
        safe_role = _safe_role_basename(agent_role)
        if safe_role is None:
            warnings.append(
                "dispatch agent role is not a safe basename; "
                "specialist instruction fingerprint is unknown"
            )
        else:
            specialist_relative = Path(str(template).format(role=safe_role))
            specialist_path = install_root / specialist_relative
            if specialist_path.is_file():
                specialist_digest = _sha256(specialist_path)
            else:
                warnings.append(
                    f"installed specialist instructions are missing: {specialist_relative}"
                )

    complete = operator_digest is not None and specialist_digest is not None
    instructions_stale: bool | None = None
    raw_source_root = meta.get("source_root")
    source_root = (
        Path(raw_source_root).expanduser()
        if isinstance(raw_source_root, str) and raw_source_root.strip()
        else None
    )
    if complete and source_root is not None:
        assert operator_relative is not None
        source_operator = source_root / operator_relative
        assert specialist_relative is not None
        source_specialist = source_root / specialist_relative
        if source_operator.is_file() and source_specialist.is_file():
            instructions_stale = (
                _sha256(source_operator) != operator_digest
                or _sha256(source_specialist) != specialist_digest
            )
            if instructions_stale:
                warnings.append(
                    "installed instructions differ from the current local source tree"
                )
        else:
            warnings.append(
                "current source instructions are unavailable; staleness is unknown"
            )

    identity = {
        # ``client_name`` remains a compatible projection for older backends and
        # readers. It is launcher truth, never a provider-observed claim.
        "client_name": launcher_client,
        "requested_client": requested_client,
        "launcher_effective_client": launcher_client,
        # No supported provider currently exposes one stable, client-owned signal
        # across every launch context. Unknown is data, not a failure to guess.
        "provider_observed_client": "unknown",
        # Static role definitions prove only which instructions are installed.
        # They do not attest that this dispatch was launched or which runtime
        # arguments the client passed to that specific child invocation.
        "launcher_effective_model": None,
        "launcher_effective_reasoning": None,
        "launcher_effective_source": None,
        "source_revision": source_revision,
        "operator_instruction_path": str(operator_relative) if operator_relative is not None else None,
        "operator_instruction_sha256": operator_digest,
        "specialist_instruction_path": (
            str(specialist_relative) if specialist_relative is not None else None
        ),
        "specialist_instruction_sha256": specialist_digest,
        "instruction_identity_status": "verified" if complete else "incomplete",
        "instructions_stale": instructions_stale,
    }
    return identity, warnings
