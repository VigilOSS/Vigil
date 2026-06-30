"""vigil assess kali tool-help <tool> — print a runtime tool's live --help.

A maintenance verb (NOT a probe): it runs ``<tool> -h`` (then ``--help`` as a
fallback) inside the runtime container and prints the output, so the operator/LLM
can read the EXACT flag set the *installed* version supports before composing an
invocation — instead of guessing version-specific flags into ``--extra-args``.

Like ``sweep-orphans``, this verb does NOT call ``add_required_kali_flags``: it
sends no traffic to any target and writes no audit row, so the five audit flags
(``--technique``/``--intent``/``--probe-kind``/``--phase``/``--timeout``) do not
apply. It only execs the tool's own help text inside the sandboxed container.
"""
from __future__ import annotations

import re
import subprocess
import sys

from assess.lib.client import AssessError, default_runtime_container
from assess.lib.kali_runtime_exec import _check_container_running

# A tool name is a bare binary token only — no shell metacharacters, no spaces,
# no path traversal. argv is passed as a list (never through a shell), but this
# keeps the exec target unambiguous and rejects anything that is not a plausible
# binary name.
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Help flags to try in order. Most ProjectDiscovery / Go tools answer ``-h``;
# Python/Ruby tools usually answer ``--help``. ``-h`` first, ``--help`` on a
# non-answer, so one call covers both ecosystems.
_HELP_FLAGS = ("-h", "--help")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "tool-help",
        help="Print a runtime tool's live --help (no audit flags; maintenance, not a probe).",
    )
    p.add_argument("tool", help="Tool binary name to query (e.g. katana, nuclei, arjun).")
    p.add_argument(
        "--help-flag",
        dest="help_flag",
        default="",
        help="Force a specific help flag (e.g. '-h' or '--help'). Default: try -h then --help.",
    )
    p.add_argument(
        "--container-name",
        dest="container_name",
        default="",
        help="Override the runtime container name (default: the configured runtime container).",
    )
    p.set_defaults(func=run)


def _run_help(container: str, tool: str, flag: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 — argv list, no shell; tool is regex-validated
        ["docker", "exec", container, tool, flag],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def run(args) -> None:
    tool = (args.tool or "").strip()
    if not _TOOL_NAME_RE.match(tool):
        print(
            f"tool-help: '{tool}' is not a valid tool name (allowed: letters, digits, "
            "'.', '_', '-').",
            file=sys.stderr,
        )
        raise AssessError("invalid tool name")

    container = (args.container_name or "").strip() or default_runtime_container()
    # Raises AssessError with a clear message if the runtime is not up.
    _check_container_running(container)

    flags = (args.help_flag,) if args.help_flag else _HELP_FLAGS
    last: subprocess.CompletedProcess | None = None
    for flag in flags:
        try:
            proc = _run_help(container, tool, flag)
        except FileNotFoundError as exc:
            raise AssessError(f"docker not found: {exc}") from exc
        except subprocess.TimeoutExpired:
            print(f"tool-help: '{tool} {flag}' timed out after 30s.", file=sys.stderr)
            raise AssessError("tool-help timed out")
        last = proc
        out = proc.stdout or ""
        err = proc.stderr or ""
        # Many CLIs print help to stdout with rc 0; some print to stderr and/or
        # exit non-zero on a bare help flag. Accept the first attempt that yields
        # any text on either stream.
        if out.strip() or err.strip():
            if out.strip():
                sys.stdout.write(out if out.endswith("\n") else out + "\n")
            if err.strip():
                sys.stderr.write(err if err.endswith("\n") else err + "\n")
            return

    # No attempt produced output — surface the last rc/stderr for diagnosis.
    rc = last.returncode if last is not None else "n/a"
    print(
        f"tool-help: '{tool}' produced no help output (last rc={rc}). The tool may not "
        "be installed in the runtime, or it uses a non-standard help flag — try "
        "--help-flag, or `vigil assess kali exec ... -- {tool} --help`.".replace("{tool}", tool),
        file=sys.stderr,
    )
    raise AssessError("no help output")
