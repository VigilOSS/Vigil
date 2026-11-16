"""OpenCode version support and launch flags shared by every Vigil OpenCode start.

Vigil supports OpenCode 1.18.10 or newer, before 3.0. The two majors take
different TUI flags. OpenCode 1 selects the operator with ``--agent operator``
and the model with ``--model``. OpenCode 2 has neither flag: ``default_agent``
in the session's config selects the operator, the model rides the session's
config content, and the TUI runs its own server (``--standalone``) because a
background service would not inherit the session environment. Its hidden
``--dangerously-skip-permissions`` alias is spelled ``--auto``.

Both majors take a new conversation's variant only from the per-model choice
the TUI saves in ``$XDG_STATE_HOME/opencode/model.json``; a ``#variant`` on the
model is split off and saved there before the TUI starts.
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

MINIMUM = (1, 18, 10)
BOUND = (3, 0, 0)
SUPPORTED_RANGE = "OpenCode 1.18.10 or newer, before 3.0"
PROBE_TIMEOUT_SECONDS = 10
OPERATOR_AGENT = "operator"

# One release line, as each major prints it: ``1.18.10`` or ``opencode v2.3.0``.
_RELEASE = re.compile(r"\s*(?:opencode\s+)?v?(\d+)\.(\d+)\.(\d+)\s*")
# The launch major is the first version token's major, read with this one POSIX
# ERE (major in group 2) by Python and by the generated shell launcher alike.
LAUNCHER_MAJOR_PATTERN = r"(^|[^0-9.])v?([0-9]+)\.[0-9]+\.[0-9]+"
_VERSION_TOKEN = re.compile(LAUNCHER_MAJOR_PATTERN)

_SKIP_PERMISSIONS = {1: "--dangerously-skip-permissions", 2: "--auto"}
_RESUME_FLAGS = ("-c", "--continue", "-s", "--session")


def resumes_session(arguments: list[str]) -> bool:
    """Whether the forwarded flags reopen an earlier conversation (same spelling on both majors)."""
    return any(argument in _RESUME_FLAGS or argument.startswith(("--continue=", "--session="))
               for argument in arguments)


def parse_release(text: str | None) -> tuple[int, int, int] | None:
    """The release ``opencode --version`` printed, or None when it is not one release line."""
    match = _RELEASE.fullmatch(text or "")
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def is_supported(release: tuple[int, int, int]) -> bool:
    return MINIMUM <= release < BOUND


def launch_major(version: str | None) -> int:
    """2 for OpenCode 2 or later; 1 otherwise, including an unreadable version."""
    match = _VERSION_TOKEN.search(version or "")
    return 2 if match is not None and int(match.group(2)) >= 2 else 1


def probe_version(executable: str) -> str | None:
    """``<executable> --version`` output, or None when the bounded probe fails."""
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                check=False, timeout=PROBE_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or result.stderr.strip() or None


def server_arguments(major: int) -> list[str]:
    """OpenCode 2 runs a private server so it inherits the launch environment."""
    return ["--standalone"] if major >= 2 else []


def operator_arguments(major: int) -> list[str]:
    """Flags that start the TUI as the Vigil operator.

    OpenCode 2 reads the operator from the session config's ``default_agent``.
    """
    return [*server_arguments(major), *(["--agent", OPERATOR_AGENT] if major < 2 else [])]


def skip_permissions_argument(major: int) -> str:
    return _SKIP_PERMISSIONS[2 if major >= 2 else 1]


def launcher_exec_block(skip_permissions: bool) -> str:
    """The generated launcher's exec: the installed major selects the flags at run time.

    OpenCode 2 rejects a repeated flag, so a forwarded ``--auto`` (how a Vigil
    start forwards the permission skip there) replaces the launcher's own.
    """
    def command(major: int, *, skip: bool = skip_permissions) -> str:
        arguments = [*operator_arguments(major), *([skip_permissions_argument(major)] if skip else [])]
        return " ".join(["exec opencode", *arguments, '"$@"'])

    forwarded_skip = (
        '  for opencode_argument in "$@"; do\n'
        f'    [[ "$opencode_argument" != {_SKIP_PERMISSIONS[2]} ]] || {command(2, skip=False)}\n'
        "  done\n"
    ) if skip_permissions else ""
    return (
        'opencode_version="$(opencode --version 2>/dev/null || true)"\n'
        f"opencode_major_pattern='{LAUNCHER_MAJOR_PATTERN}'\n"
        'if [[ "$opencode_version" =~ $opencode_major_pattern ]] && (( 10#${BASH_REMATCH[2]} >= 2 )); then\n'
        f"{forwarded_skip}"
        f"  {command(2)}\n"
        "fi\n"
        f"{command(1)}"
    )


@dataclass(frozen=True)
class Launch:
    """A validated operator launch, before any side effect."""

    major: int
    arguments: list[str]
    variants: dict[str, str]
    variant_state: tuple[Path, dict] | None
    model: str | None
    config_content: str | None


def plan_operator_launch(version: str | None, forwarded: list[str], config_content: str | None) -> Launch:
    """Map 1.x-style operator flags onto the installed major.

    OpenCode 1 keeps ``--model`` without its ``#variant``. OpenCode 2 moves the
    model into the session config, as its default and as the operator agent's
    model, which outranks a model pinned in the operator wrapper exactly as
    ``--model`` does on 1.x.
    """
    major = launch_major(version)
    arguments: list[str] = []
    variants: dict[str, str] = {}
    model = None
    tail = iter(forwarded)
    for argument in tail:
        flag, value = argument, None
        for name in ("--model", "-m"):
            if argument == name:
                value = next(tail, None)
                if value is None:
                    raise SystemExit(f"OpenCode {name} requires provider/model or provider/model#variant")
            elif argument.startswith(name + "="):
                flag, value = name + "=", argument.split("=", 1)[1]
        if value is None:
            if major >= 2 and argument == _SKIP_PERMISSIONS[1]:
                argument = _SKIP_PERMISSIONS[2]
            # OpenCode 2 rejects a repeated flag; the start itself supplies --standalone.
            if major < 2 or (argument not in server_arguments(major)
                             and not (argument == _SKIP_PERMISSIONS[2] and argument in arguments)):
                arguments.append(argument)
            continue
        bare, separator, variant = value.partition("#")
        if separator:
            if "/" not in bare.strip("/") or not variant or "#" in variant:
                raise SystemExit(f"OpenCode --model {value!r} must be provider/model#variant")
            variants[bare] = variant
        if major >= 2:
            model = value
        else:
            arguments.extend([flag + bare] if flag.endswith("=") else [flag, bare])
    return Launch(major, arguments, variants, _variant_state(variants), model,
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
