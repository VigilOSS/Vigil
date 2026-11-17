"""OpenCode version support and launch flags shared by every Vigil OpenCode start.

Vigil supports OpenCode 2.3.0 or newer, before 3.0. ``default_agent`` in the
session's config selects the operator and the model rides the session's config
content, because the TUI takes neither ``--agent`` nor ``--model``. The TUI runs
its own server (``--standalone``) because a background service would not
inherit the session environment. Its permission skip is spelled ``--auto``; a
forwarded ``--dangerously-skip-permissions`` is passed as ``--auto``.

A new conversation's variant comes only from the per-model choice the TUI saves
in ``$XDG_STATE_HOME/opencode/model.json``; a ``#variant`` on the model is split
off and saved there before the TUI starts.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import MutableMapping, TextIO

MINIMUM = (2, 3, 0)
BOUND = (3, 0, 0)
SUPPORTED_RANGE = "OpenCode 2.3.0 or newer, before 3.0"
PROBE_TIMEOUT_SECONDS = 10
OPERATOR_AGENT = "operator"
STANDALONE = "--standalone"
SKIP_PERMISSIONS = "--auto"

SUPPORTED, UNVERIFIED, UNSUPPORTED = "supported", "unverified", "unsupported"

# One version line, as ``opencode --version`` prints it: ``opencode v2.3.0``,
# ``2.3.0``, or a pre-release such as ``2.4.0-beta.1``.
_VERSION = re.compile(r"\s*(?:opencode\s+)?v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?\s*")
_SKIP_PERMISSIONS_ALIAS = "--dangerously-skip-permissions"
_RESUME_FLAGS = ("-c", "--continue", "-s", "--session")


def resumes_session(arguments: list[str]) -> bool:
    """Whether the forwarded flags reopen an earlier conversation."""
    return any(argument in _RESUME_FLAGS or argument.startswith(("--continue=", "--session="))
               for argument in arguments)


def version_support(version: str | None) -> str:
    """How one ``opencode --version`` reading stands against SUPPORTED_RANGE.

    SUPPORTED is a stable release in the range. UNSUPPORTED is a version readable
    as outside it. A pre-release precedes its release, so one is readable as
    outside the range unless its release lies strictly inside it: ``2.3.0-beta``
    and ``3.0.0-rc.1`` are UNSUPPORTED. UNVERIFIED is anything else: a
    pre-release such as ``2.4.0-beta``, or no readable version at all.
    """
    match = _VERSION.fullmatch(version or "")
    if match is None:
        return UNVERIFIED
    release = (int(match[1]), int(match[2]), int(match[3]))
    if match[4] is None:
        return SUPPORTED if MINIMUM <= release < BOUND else UNSUPPORTED
    return UNVERIFIED if MINIMUM < release < BOUND else UNSUPPORTED


def require_supported(version: str | None) -> None:
    """Refuse a version readable as outside SUPPORTED_RANGE.

    An unreadable version is not evidence of an unsupported install, so the
    start proceeds.
    """
    if version_support(version) == UNSUPPORTED:
        match = _VERSION.fullmatch(version or "")
        assert match is not None
        raise SystemExit(f"OpenCode {match[1]}.{match[2]}.{match[3]}{match[4] or ''} is outside the "
                         f"supported range; install stable {SUPPORTED_RANGE}")


def probe_version(executable: str) -> str | None:
    """``<executable> --version`` output, or None when the bounded probe fails.

    The one reading every start and client-check uses. A non-zero exit or a
    timeout is a failed probe, not a version.
    """
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                check=False, timeout=PROBE_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or result.stderr.strip() or None


def probe_supported_version(executable: str) -> str | None:
    """The installed version, refusing one readable as outside SUPPORTED_RANGE."""
    version = probe_version(executable)
    require_supported(version)
    return version


def launcher_exec_block(skip_permissions: bool) -> str:
    """The generated launcher's exec.

    OpenCode rejects a repeated flag, so a forwarded ``--auto`` (how a Vigil
    start forwards the permission skip) replaces the launcher's own.
    """
    command = f"exec opencode {STANDALONE}"
    if not skip_permissions:
        return f'{command} "$@"'
    return (
        'for opencode_argument in "$@"; do\n'
        f'  [[ "$opencode_argument" != {SKIP_PERMISSIONS} ]] || {command} "$@"\n'
        "done\n"
        f'{command} {SKIP_PERMISSIONS} "$@"'
    )


@dataclass(frozen=True)
class Launch:
    """A validated operator launch, before any side effect."""

    arguments: list[str]
    variants: dict[str, str]
    variant_state: tuple[Path, dict] | None
    model: str | None
    config_content: str | None


def plan_operator_launch(forwarded: list[str], config_content: str | None) -> Launch:
    """Map forwarded operator flags onto the TUI's launch.

    The model moves into the session config, as its default and as the operator
    agent's model, so it outranks a model pinned in the operator wrapper. The
    start supplies ``--standalone`` itself, and each flag is passed once.
    """
    arguments: list[str] = []
    variants: dict[str, str] = {}
    model = None
    tail = iter(forwarded)
    for argument in tail:
        value = None
        for name in ("--model", "-m"):
            if argument == name:
                value = next(tail, None)
                if value is None:
                    raise SystemExit(f"OpenCode {name} requires provider/model or provider/model#variant")
            elif argument.startswith(name + "="):
                value = argument.split("=", 1)[1]
        if value is None:
            if argument == _SKIP_PERMISSIONS_ALIAS:
                argument = SKIP_PERMISSIONS
            # OpenCode rejects a repeated flag; the start itself supplies --standalone.
            if argument != STANDALONE and not (argument == SKIP_PERMISSIONS and argument in arguments):
                arguments.append(argument)
            continue
        bare, separator, variant = value.partition("#")
        if separator:
            if "/" not in bare.strip("/") or not variant or "#" in variant:
                raise SystemExit(f"OpenCode --model {value!r} must be provider/model#variant")
            variants[bare] = variant
        model = value
    return Launch(arguments, variants, _variant_state(variants), model,
                  _operator_config_content(config_content, model) if model is not None else None)


def _operator_config_content(config_content: str | None, model: str) -> str:
    try:
        content = json.loads(config_content or "{}")
    except ValueError as exc:
        raise SystemExit(f"OPENCODE_CONFIG_CONTENT is not valid JSON: {exc}") from exc
    agents = content.get("agent", {}) if isinstance(content, dict) else None
    operator = agents.get(OPERATOR_AGENT, {}) if isinstance(agents, dict) else None
    if not isinstance(operator, dict):
        raise SystemExit("OPENCODE_CONFIG_CONTENT must be a JSON object whose agent and "
                         f"agent.{OPERATOR_AGENT} fields, when present, are objects")
    assert isinstance(content, dict) and isinstance(agents, dict)
    return json.dumps({**content, "model": model,
                       "agent": {**agents, OPERATOR_AGENT: {**operator, "model": model}}})


def _variant_state(variants: dict[str, str]) -> tuple[Path, dict] | None:
    """Read OpenCode's saved model choices and apply the launch's variants."""
    if not variants:
        return None
    path = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "opencode/model.json"
    saved: object = {}
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"Cannot apply the OpenCode variant: {path} is unreadable ({exc}); "
                         "repair it or choose the variant in OpenCode") from exc
    if not isinstance(saved, dict) or not isinstance(saved.get("variant", {}), dict):
        raise SystemExit(f"Cannot apply the OpenCode variant: {path} is not a JSON object with an "
                         "object variant field; repair it or choose the variant in OpenCode")
    saved["variant"] = {**saved.get("variant", {}), **variants}
    return path, saved


def _write_variant_state(path: Path, saved: dict) -> None:
    """Replace the native choice file atomically, as the TUI's own picker would."""
    target = path.resolve() if path.exists() else path
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o644
    temporary = target.with_name(f".{target.name}.vigil-{uuid.uuid4().hex}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(saved, handle)
        os.chmod(temporary, mode)
        os.replace(temporary, target)
    except OSError as exc:
        raise SystemExit(f"Cannot apply the OpenCode variant to {target}: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def apply_launch(launch: Launch, environment: MutableMapping[str, str], *, stream: TextIO = sys.stdout) -> None:
    """Save the variant choices and the session config, reporting each."""
    if launch.config_content is not None:
        environment["OPENCODE_CONFIG_CONTENT"] = launch.config_content
        print(f"model: {launch.model} (session config)", file=stream, flush=True)
    if launch.variant_state is not None:
        _write_variant_state(*launch.variant_state)
        for model, variant in launch.variants.items():
            print(f"variant: {variant} for {model} (saved as OpenCode's choice for this model)",
                  file=stream, flush=True)
