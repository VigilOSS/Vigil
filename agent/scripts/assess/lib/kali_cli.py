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

    Every flag here is intentionally ``required=True`` so the audit context
    cannot be omitted. Per-tool flags layer on top via the calling
    subcommand's argparse spec.
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
            "Named identity from the credential store to run AND stamp as (e.g. user_a, "
            "user_b, admin). Selects that identity's auth material and records "
            "it as the probe's auth_context so cross-identity access-control "
            "(IDOR/BOLA/BFLA) depth is measurable. Omit for anonymous/no "
            "credential injection."
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
                # The argv that ACTUALLY ran inside the container, after the
                # transparent header / --resolve-pin / exclude-tags injections —
                # so the operator sees what executed, not just what it typed.
                "resolved_argv": result.resolved_argv,
                "stdout_preview": result.stdout_preview,
                "stderr_preview": result.stderr_preview,
            },
            ensure_ascii=False,
        )
    )


# Safe-by-default crawler rate. A deep crawl (katana -d 5) must NOT ride the
# tool's built-in 150 req/s default, which is the "depth 5 at a stupid rate"
# foot-gun. These bound the request rate so depth and politeness stay decoupled:
# go as deep as you like, but never faster than CRAWL_RATE_HARD_CAP unless the
# operator opts in explicitly, and always under any program ceiling.
CRAWL_RATE_DEFAULT = 10
CRAWL_RATE_HARD_CAP = 20


def resolve_crawl_rate_limit(
    requested,
    *,
    rate_cap: float | None,
    default: int = CRAWL_RATE_DEFAULT,
    hard_cap: int = CRAWL_RATE_HARD_CAP,
    allow_fast: bool = False,
    warn=None,
) -> int:
    """Resolve a crawler's ``-rl`` (req/s) for a deep, safe crawl.

    Precedence (most-binding wins):
      1. A configured program ceiling (``scope.rate_limit`` → ``rate_cap``)
         ALWAYS clamps DOWN — it is the program's legal/politeness hard ceiling.
      2. An unset ``requested`` resolves to ``default`` (10): a deep crawl must
         never inherit the tool's built-in 150 req/s default.
      3. An operator value above ``hard_cap`` (20) is clamped to ``hard_cap``
         with a warning, UNLESS ``allow_fast`` (the operator deliberately opted
         into a faster crawl via ``--allow-fast-crawl``).

    ``warn`` is an optional ``(str) -> None`` sink for the clamp notices (stderr
    in production). Returns an int ≥ 1.
    """
    try:
        base = int(requested) if requested not in (None, "") else default
    except (TypeError, ValueError):
        base = default
    if base < 1:
        base = default

    resolved = base
    if not allow_fast and resolved > hard_cap:
        if warn is not None:
            warn(
                f"crawl rate -rl {resolved} exceeds the {hard_cap} req/s safety cap; "
                f"clamping to {hard_cap}. A deep crawl stays polite by capping rate, "
                "not depth. Pass --allow-fast-crawl to override, or lower -rl."
            )
        resolved = hard_cap

    if rate_cap is not None:
        capped = max(1, min(resolved, int(rate_cap)))
        if capped < resolved and warn is not None:
            warn(
                f"crawl rate -rl {resolved} clamped DOWN to the engagement's "
                f"configured program ceiling ({int(rate_cap)} req/s)."
            )
        resolved = capped

    return max(1, resolved)


# A list-based tool (arjun -i, nuclei -l, httpx -l, sqlmap -m, ...) given ONE
# wall-clock --timeout silently truncates when the list is large or per-target
# cost is high: it is SIGTERM-killed after a fraction of the list, and an empty
# or partial result then reads as a clean negative — which it is NOT. These two
# helpers convert that silent partial into an explicit "incomplete, re-run"
# signal so a timed-out run is never mistaken for "tested, found nothing".
_LIST_PROGRESS_RE = re.compile(
    r"(?:scanning|processing|progress|target)[^0-9]{0,12}(\d+)\s*/\s*(\d+)",
    re.IGNORECASE,
)


def count_list_targets(path) -> int:
    """Count non-empty, non-comment lines in a tool's -i/-l list file.

    Returns 0 when the path is empty/unreadable, so the caller skips the
    incompleteness check rather than asserting a wrong target count.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, TypeError, ValueError):
        return 0
    return sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))


def parse_list_progress(text: str) -> tuple[int, int] | None:
    """Best-effort ``(processed, total)`` from a list tool's progress output.

    Matches ``Scanning 12/134``, ``Processing: 3 / 50`` and similar; returns the
    LAST (highest) processed count seen, or None when no marker is present.
    """
    best: tuple[int, int] | None = None
    for m in _LIST_PROGRESS_RE.finditer(text or ""):
        done, total = int(m.group(1)), int(m.group(2))
        if best is None or done > best[0]:
            best = (done, total)
    return best


def incomplete_list_run_warning(
    *,
    tool: str,
    total_targets: int,
    timed_out: bool,
    return_code,
    stdout_preview: str = "",
    stderr_preview: str = "",
) -> str:
    """Return a loud INCOMPLETE-run warning, or ``""`` when the run looks complete.

    Fires only when (a) the run did NOT finish cleanly (timed_out, or killed /
    non-zero rc) AND (b) the list held >1 target — a single-target timeout is a
    different problem the operator already sees. When the tool's progress output
    is parseable, the message names ``~K of N`` actually processed.
    """
    killed = bool(timed_out) or (return_code not in (0, None))
    if not killed or total_targets <= 1:
        return ""
    progress = parse_list_progress(f"{stdout_preview or ''}\n{stderr_preview or ''}")
    if progress is not None:
        done, total = progress
        scope = f"~{done} of {total or total_targets} targets"
    else:
        scope = f"a list of {total_targets} targets"
    return (
        f"INCOMPLETE: {tool} did not finish — it was timed-out/killed after "
        f"processing {scope}. An empty or partial result is NOT a clean negative; "
        "the list was not fully scanned (and any 'not found' / 'dead' verdict for "
        "the unscanned remainder is unsafe). Re-run on a smaller/curated list "
        "and/or with a larger --timeout (or a faster per-tool config) sized to "
        "actually finish before treating any absence as a verdict."
    )
