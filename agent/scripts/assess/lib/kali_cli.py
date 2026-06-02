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

import json
import shlex
import sys
from pathlib import Path
from typing import Any

from .audit_enums import PROBE_KIND_ENUM, TECHNIQUE_ENUM
from .client import AssessError
from .kali_audit import ALLOWED_PHASES, _INTENT_MAX_LEN
from .kali_output import KaliResult
from .kali_runtime_exec import _DEFAULT_CONTAINER_NAME


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
        choices=list(PROBE_KIND_ENUM) if PROBE_KIND_ENUM else None,
        help="fingerprint | baseline | payload | exploit | replay | cleanup",
    )
    parser.add_argument(
        "--phase",
        required=True,
        choices=list(ALLOWED_PHASES),
        help=(
            "Phase the dispatching agent was authorized for. No env-var "
            "fallback — pass explicitly."
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
            "Dispatching agent name. Defaults to $AGENT_NAME / $VIGIL_AGENT_NAME / "
            "'operator'; specialists should pass this explicitly if wrapper env is missing."
        ),
    )
    parser.add_argument(
        "--container-name",
        dest="container_name",
        default=_DEFAULT_CONTAINER_NAME,
        help=f"Docker container to exec into (default: {_DEFAULT_CONTAINER_NAME}).",
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
    kwargs: dict[str, Any] = {
        "technique": args.technique,
        "intent": args.intent,
        "probe_kind": args.probe_kind,
        "phase": args.phase,
        "destructive": bool(getattr(args, "destructive", False)),
        "timeout": int(args.timeout),
        "agent_name": getattr(args, "kali_agent_name", None),
        "force": bool(getattr(args, "force", False)),
        "container_name": getattr(args, "container_name", _DEFAULT_CONTAINER_NAME),
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
