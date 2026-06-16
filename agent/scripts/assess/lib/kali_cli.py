"""argparse scaffolding shared by every ``vigil assess kali <verb>`` command.

These helpers are pure CLI-glue: register the audit/lifecycle flags
(``--technique``, ``--intent``, ``--probe-kind``, ``--phase``, ``--timeout``,
``--destructive``, ``--force``, ``--agent-name``, ``--container-name``) +
the optional ``--extra-args`` passthrough, parse them off an argparse
Namespace into a kwargs dict suitable for ``kali_exec(**kwargs)``, and
emit the final ``KaliResult`` as a single JSON object on stdout. Lives
here (not in ``kali.py``) so the verb-registration files only depend on
argparse helpers, not on the orchestrator's deeper imports.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from .audit_enums import PROBE_KIND_ENUM, TECHNIQUE_ENUM
from .client import AssessError, default_runtime_container
from .kali_audit import (
    ALLOWED_PHASES,
    _INTENT_MAX_LEN,
    _enum_reject_message,
    _resolve_agent_name,
)
from .kali_output import KaliResult


# Maps each enum-bearing audit flag back to its allowed-value tuple so the
# parse-time argparse "invalid choice" rejection can be re-rendered through the
# SAME scoped formatter the post-parse AssessError path uses. Keep this in lock-
# step with the choices= wired into add_required_kali_flags / kali_job.
_ENUM_FLAG_TO_VALUES: dict[str, tuple[str, ...]] = {
    "--technique": TECHNIQUE_ENUM,
    "--probe-kind": PROBE_KIND_ENUM,
    "--phase": ALLOWED_PHASES,
}

# argparse renders an enum miss as:
#   argument --probe-kind: invalid choice: 'BOGUS' (choose from 'a', 'b', ...)
# Capture the flag and the offending value so we can rebuild a scoped message.
_INVALID_CHOICE_RE = re.compile(
    r"argument\s+(?P<flag>-\S+):\s+invalid choice:\s+'(?P<value>.*?)'\s+\(choose from",
    re.DOTALL,
)


class ScopedErrorParser(argparse.ArgumentParser):
    """ArgumentParser that re-renders enum ``invalid choice`` errors as scoped
    did-you-mean text and suppresses the multi-line top-level usage dump for a
    subcommand enum miss.

    Stock argparse prints the full ``usage: ...`` block plus a terse
    ``invalid choice: 'X' (choose from ...)`` and exits 2. For a 46-value
    ``--technique`` (and the lowercase ``--probe-kind`` / ``--phase`` enums)
    that buries the value the operator actually meant. This subclass intercepts
    only the enum-miss case, routes it through :func:`_enum_reject_message` (the
    same formatter the post-parse AssessError path uses, so every site agrees),
    and emits a single ``ERROR:`` line with no usage block. Every other parser
    error (missing required flag, unrecognized argument, bad int) keeps the
    default argparse behavior unchanged.
    """

    def error(self, message: str) -> None:  # noqa: D102 - argparse override
        match = _INVALID_CHOICE_RE.search(message or "")
        if match:
            flag = match.group("flag")
            value = match.group("value")
            allowed = _ENUM_FLAG_TO_VALUES.get(flag)
            if allowed is not None:
                # Scoped, single-line rejection — no usage dump. Exit 2 keeps
                # parity with argparse's own parse-error exit code (the
                # AssessError path through cli.main exits 1; this is a parse-time
                # SystemExit, deliberately distinct).
                print(
                    f"ERROR: {_enum_reject_message(flag, value, allowed)}",
                    file=sys.stderr,
                )
                self.exit(2)
        # Not an enum miss we own — fall back to argparse's default rendering
        # (usage block + message) so missing-required / unrecognized-arg errors
        # behave exactly as before.
        super().error(message)


def add_required_kali_flags(parser) -> None:
    """Register the audit/lifecycle flags every kali_* subcommand needs.

    Author note: every flag here is intentionally `required=True` so the LLM
    cannot accidentally skip the audit context. Per-tool flags layer on top
    via the calling subcommand's argparse spec.
    """
    parser.add_argument(
        "--technique",
        required=True,
        help=(
            "Vulnerability-class technique tag (e.g. RECON, SSRF, SQLI). "
            "Case- and separator-insensitive (ssrf / open_redirect resolve). "
            f"Allowed: {', '.join(TECHNIQUE_ENUM) if TECHNIQUE_ENUM else 'see audit_enums.py'}"
        ),
    )
    parser.add_argument(
        "--intent",
        required=True,
        help=f"One-line purpose of this command (max {_INTENT_MAX_LEN} chars).",
    )
    parser.add_argument(
        "--probe-kind",
        required=True,
        dest="probe_kind",
        type=str.lower,
        choices=list(PROBE_KIND_ENUM) if PROBE_KIND_ENUM else None,
        help="fingerprint | baseline | payload | exploit | replay | cleanup (case-insensitive)",
    )
    parser.add_argument(
        "--phase",
        required=True,
        type=str.lower,
        choices=list(ALLOWED_PHASES),
        help=(
            "Phase the dispatching agent was authorized for. No env-var "
            "fallback — pass explicitly. Case-insensitive."
        ),
    )
    parser.add_argument(
        "--destructive",
        action="store_true",
        help="Mark this command as destructive (writes/edits/deletes on the target).",
    )
    parser.add_argument(
        "--timeout",
        required=True,
        type=int,
        help="Wall-clock budget in seconds. Suggested baseline: 1800.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Suppress the dedup warning entirely. The subprocess still runs in either "
            "case — dedup hits no longer block, only warn — but --force also tells the "
            "backend to skip the supersede-link record on the new row."
        ),
    )
    parser.add_argument(
        "--agent-name",
        dest="kali_agent_name",
        default=None,
        help=(
            "Dispatching agent name. Defaults to --agent-id / $AGENT_NAME / "
            "$VIGIL_AGENT_NAME / 'operator'; specialists should pass this explicitly "
            "if wrapper env is missing."
        ),
    )
    parser.add_argument(
        "--agent-id",
        dest="kali_agent_id",
        default=None,
        help=(
            "Dispatch agent_id (e.g. va-7f3) from your Runtime Identity block. "
            "Companion to --agent-name: when --agent-name is omitted, the agent_id "
            "is used verbatim as the deterministic audit attribution (no backend "
            "lookup) so the run is tied to your dispatch instead of 'operator'."
        ),
    )
    parser.add_argument(
        "--identity",
        dest="identity",
        default=None,
        help=(
            "Named identity from auth.json to run AND stamp as (e.g. user_a, "
            "user_b, admin). Selects that identity's auth material and records "
            "it as the probe's auth_context so cross-identity access-control "
            "(IDOR/BOLA/BFLA) depth is measurable. Omit for the active identity "
            "/ legacy single-identity behavior."
        ),
    )
    # Resolve VIGIL_RUNTIME_CONTAINER once at parse time (not bound to a frozen
    # import-time constant) and reuse it for both the default and the help text,
    # so a single parse can never report a default that disagrees with itself.
    container_default = default_runtime_container()
    parser.add_argument(
        "--container-name",
        dest="container_name",
        default=container_default,
        help=f"Docker container to exec into (default: {container_default}).",
    )


def add_passthrough_args_flag(parser) -> None:
    """Adds the optional --extra-args raw-passthrough flag.

    The string is shlex-split and appended to the command argv after the
    typed-flag-derived arguments. Use for flags the typed verb does not
    yet model — the audit row still records the full argv, and --destructive
    still applies if the extra args toggle a destructive mode.
    """
    parser.add_argument(
        "--extra-args",
        default="",
        help="Raw additional CLI args appended to the underlying tool. shlex-split. Use sparingly; prefer typed flags.",
    )


def extend_cmd_with_extra_args(
    cmd: list[str],
    args,
    *,
    typed_short_flags: set[str] | None = None,
) -> list[str]:
    """Append shlex-split extra args to cmd if the namespace has any.

    When ``typed_short_flags`` is provided, scan the split tokens for short
    flags (``-x``) that overlap with the verb's typed argparse spec and emit
    a stderr WARN so the operator notices the silent override. Passthrough
    is still permitted — duplicate flags are common when a typed verb does
    not yet model every option.
    """
    extra = getattr(args, "extra_args", "") or ""
    if not extra:
        return cmd
    try:
        split = shlex.split(extra)
    except ValueError as exc:
        raise AssessError(f"--extra-args: invalid shell quoting: {exc}") from exc
    if typed_short_flags:
        seen_collisions: set[str] = set()
        for token in split:
            if token in typed_short_flags and token not in seen_collisions:
                print(
                    f"warning: --extra-args contains '{token}' which is also a typed flag on this verb; "
                    "the passthrough value will be appended after the typed value.",
                    file=sys.stderr,
                )
                seen_collisions.add(token)
    cmd.extend(split)
    return cmd


def kali_args_to_kwargs(args) -> dict[str, Any]:
    """Pull the audit/lifecycle flag values off an argparse Namespace.

    Returned dict can be splatted into kali_exec(**kwargs) directly. Includes
    `engagement_dir` so a per-call `--engagement-dir <path>` (root-parser
    flag, hoisted by `assess.cli._hoist_root_flags`) reaches kali_exec.
    Without this thread-through, --engagement-dir on a kali verb silently
    falls back to `$ENGAGEMENT_DIR` / cwd scope.json and the operator hits
    "Cannot resolve engagement directory" even when they passed it.
    """
    explicit_dir = getattr(args, "engagement_dir", None)
    # Resolve the audit attribution here (where --phase is in scope) so the
    # CR-35 deterministic carrier (--agent-name > --agent-id > env > operator)
    # and the specialist-phase WARN run exactly once per CLI invocation. The
    # resolved value is passed to kali_exec as `agent_name`; kali_exec re-runs
    # the resolver, but on a now-explicit value that is a no-op passthrough.
    resolved_agent_name = _resolve_agent_name(
        getattr(args, "kali_agent_name", None),
        agent_id=getattr(args, "kali_agent_id", None),
        phase=getattr(args, "phase", None),
        warn=True,
    )
    kwargs: dict[str, Any] = {
        "technique": args.technique,
        "intent": args.intent,
        "probe_kind": args.probe_kind,
        "phase": args.phase,
        "destructive": bool(getattr(args, "destructive", False)),
        "timeout": int(args.timeout),
        "agent_name": resolved_agent_name,
        "force": bool(getattr(args, "force", False)),
        "container_name": getattr(args, "container_name", None),
        "identity": getattr(args, "identity", None),
    }
    if explicit_dir:
        kwargs["engagement_dir"] = Path(explicit_dir).expanduser().resolve()
    return kwargs


def emit_result(result: KaliResult) -> None:
    """Print a compact result summary suitable for both humans and `jq -R`.

    Stdout is one JSON object. Stderr already carries any warnings emitted
    during the run (dedup hit, audit failure, finalize failure).
    """
    print(
        json.dumps(
            {
                "run_id": result.run_id,
                "status": result.status,
                "return_code": result.return_code,
                "duration_ms": result.duration_ms,
                "stdout_path": result.stdout_path,
                "stderr_path": result.stderr_path,
                "peak_rss_bytes": result.peak_rss_bytes,
                "timed_out": result.timed_out,
                "partial_results": result.partial_results,
                "stdout_preview": result.stdout_preview,
                "stderr_preview": result.stderr_preview,
            },
            ensure_ascii=False,
        )
    )
