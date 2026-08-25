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
import math
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
from .kali_output import KaliResult, kali_exit_code


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
        "--rate-override-reason",
        dest="rate_override_reason",
        default="",
        help=(
            "Recorded justification for exceeding scope.rate_limit_aggregate_rps. "
            "Without it, aggregate-cap conflicts are refused before execution."
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
    parser.add_argument(
        "--identity-scope",
        dest="identity_scope",
        default="",
        help=(
            "Logical liveness scope used when --identity names a scoped alias. "
            "This is never inferred from the target URL because engagement scopes "
            "may be application- or workflow-specific."
        ),
    )
    parser.add_argument(
        "--identity-target",
        dest="identity_target",
        default="",
        help=(
            "Name the tool whose header convention this argv follows, when the "
            "command head is one Vigil cannot classify (a wrapper binary, a "
            "renamed HTTP client) and --identity would otherwise be refused. "
            "Ignored for a `bash /path/script.sh` shape, where an appended flag "
            "would become the script's $1 — inline those requests as "
            "`bash -c '<curl …>'` instead."
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
        help=(
            "Raw additional CLI args appended to the underlying tool. shlex-split. Use sparingly; "
            "prefer typed flags. Example: --extra-args '-mr admin'"
        ),
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
    Without this thread-through, --engagement-dir on a kali verb is lost before
    the shared assessment-binding resolver sees it and the operator gets a
    misleading "Cannot resolve engagement directory" failure.
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
        "identity_scope": getattr(args, "identity_scope", "") or "",
        "identity_target": getattr(args, "identity_target", "") or "",
        "rate_override_reason": getattr(args, "rate_override_reason", "") or "",
    }
    if explicit_dir is not None:
        if not str(explicit_dir).strip():
            raise AssessError("--engagement-dir must not be empty")
        kwargs["engagement_dir"] = Path(explicit_dir).expanduser().resolve()
    return kwargs


def emit_result(result: KaliResult) -> None:
    """Print a compact result summary suitable for both humans and `jq -R`.

    Stdout is one JSON object. Stderr already carries any warnings emitted
    during the run (dedup hit, audit failure, finalize failure).

    Then map the run's terminal status onto the PROCESS EXIT CODE
    (``kali_output.KALI_EXIT_CODES``) so a caller that never parses the JSON
    still learns that the run did not produce a usable result — before this,
    a timed-out run with zero artifacts exited 0 exactly like a clean negative.
    The exit happens here, not in ``cli.main``, because this is the single
    funnel every ``kali <verb>`` run() ends on: it lands the contract for all of
    them at once instead of half-landing on whichever verbs got edited, and it
    keeps the mapping next to the JSON that reports the same status. A
    ``completed`` (or ``waf_challenge``) run returns normally with exit 0, so
    documented ``kali a && kali b`` chains keep working.
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
    code = kali_exit_code(result.status)
    if code:
        sys.exit(code)


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


def _anchor_list_path(path, engagement_dir) -> str:
    """Map a tool's -i/-l value to a HOST-readable path.

    The value the operator passes is the path the tool sees INSIDE the container —
    typically ``/engagements/<key>/scans/...`` or an engagement-relative path. Read
    host-side, that path does not exist, so a naive read returns 0 lines and
    silently disables the incompleteness guard for the very container-path case
    that motivated it. With ``engagement_dir`` known, translate it; a bare
    host-absolute path or an unknown engagement is returned unchanged.
    """
    s = str(path or "")
    if not s or not engagement_dir:
        return s
    if s.startswith("/engagements/"):
        parts = s.split("/")
        # /engagements/<key>/<rest...> -> <engagement_dir>/<rest...>
        return str(Path(engagement_dir).joinpath(*parts[3:])) if len(parts) >= 4 else s
    if not s.startswith("/"):
        return str(Path(engagement_dir) / s)
    return s


def safe_engagement_dir(args) -> str | None:
    """Best-effort resolve the engagement dir for path-anchoring; never raises."""
    try:
        from assess.lib.config import load_config

        return load_config(getattr(args, "engagement_dir", None)).engagement_dir
    except (Exception, SystemExit):  # noqa: BLE001 — anchoring is best-effort
        return None


def count_list_targets(path, engagement_dir=None) -> int:
    """Count non-empty, non-comment lines in a tool's -i/-l list file.

    Pass ``engagement_dir`` so a container/relative path is anchored to the host
    before reading (see :func:`_anchor_list_path`); without it the guard silently
    no-ops on the in-container path the tool actually receives. Returns 0 when the
    path is empty/unreadable, so the caller skips the incompleteness check rather
    than asserting a wrong target count.
    """
    try:
        text = Path(_anchor_list_path(path, engagement_dir)).read_text(
            encoding="utf-8", errors="replace"
        )
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


# --------------------------------------------------------------------------- #
# Pre-flight internal-budget vs --timeout guard (I-9b#1 + I-20(b)).
#
# The POST-run guard above turns a *finished* truncation into an explicit
# signal. This is the complementary PRE-flight check: a crawl/discovery/param-
# sweep whose OWN runtime budget already exceeds the wrapper --timeout is going
# to be SIGTERM-killed mid-run, and its truncated output then reads as a clean
# negative — so catch the self-contradiction at DISPATCH, before the run, not in
# the audit row afterward (the I-9 katana run 36937 was `--timeout 180` while its
# own crawl budget was 10 min; the I-20 arjun run did 2 of 134 targets before the
# kill). Two flavors, chosen by the caller:
#   * a verb with an EXACT declared budget — a real tool flag that caps total
#     runtime (katana -crawl-duration, ffuf -maxtime) — auto-RAISES --timeout to
#     fit it (boost-only) and warns, so the run can actually finish.
#   * a verb whose runtime can only be ESTIMATED (arjun/nuclei list sweeps,
#     sqlmap heavy configs) WARNs with a sizing hint and never silently changes
#     the budget — a worst-case estimate is a heads-up, not a contract.
# --------------------------------------------------------------------------- #


def coerce_float(value, default: float = 0.0) -> float:
    """Best-effort float of a CLI flag string; ``default`` when empty/unparseable.

    Verb knobs arrive as argparse strings (``""`` when unset). This resolves a
    knob to a number with its per-tool default so the estimators below get clean
    inputs without each call site re-implementing the try/except.
    """
    try:
        if value in (None, ""):
            return float(default)
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def estimate_list_sweep_seconds(
    *,
    targets: int,
    passes: int,
    per_request_seconds: float,
    workers: int = 1,
    rate_limit: float | None = None,
) -> float:
    """Worst-case seconds for a per-target list sweep (arjun ``-i`` / nuclei ``-l``).

    Models the I-9b/I-20 truncation failure: each of ``targets`` targets needs
    ``passes`` request-rounds, a dead/slow target burns the FULL
    ``per_request_seconds`` each round (the dominant cost on a junk list — a dead
    .nsf 301 eats the whole -T), and the run retires those rounds across at most
    ``effective`` workers in parallel. Parallelism is bounded BOTH by the worker
    pool (``workers`` — arjun ``-t`` / nuclei ``-c``) AND the politeness rate
    (``rate_limit`` req/s), whichever is smaller — a ``--rate-limit 6`` cannot
    sustain more than ~6 concurrent retirements regardless of the thread count.

    Returns ``0.0`` for ≤1 target (a single slow target is a different, already-
    visible problem — same skip the post-run guard uses) so the caller no-ops.
    """
    if targets <= 1 or passes <= 0 or per_request_seconds <= 0:
        return 0.0
    effective = max(1, int(workers))
    if rate_limit and rate_limit > 0:
        effective = max(1, min(effective, int(math.ceil(rate_limit))))
    return targets * passes * float(per_request_seconds) / effective


def preflight_timeout_guard(
    *,
    verb: str,
    internal_budget_s: float,
    timeout,
    warn,
    auto_raise: bool = False,
    exact: bool = False,
    sizing_hint: str = "",
):
    """Compare a verb's internal runtime budget to the wrapper ``--timeout``.

    Returns the (possibly raised) timeout so the caller can write it back. When
    ``internal_budget_s`` exceeds ``timeout``: emit a WARN through ``warn`` and,
    only when ``auto_raise``, return ``ceil(internal_budget_s)`` so a DECLARED
    budget is never truncated by a smaller wall-clock (boost-only; it never
    shrinks the budget). With ``auto_raise`` False the timeout is returned
    unchanged (warn-only). ``exact`` only tunes the wording (declared vs
    estimated). A missing/unparseable ``timeout`` (e.g. a unit-test namespace
    with no ``--timeout``) is returned untouched and never warns.
    """
    try:
        budget = float(internal_budget_s)
        wall = int(timeout)
    except (TypeError, ValueError):
        return timeout
    if budget <= 0 or wall <= 0 or budget <= wall:
        return timeout
    needed = int(math.ceil(budget))
    kind = "declared" if exact else "estimated worst-case"
    hint = sizing_hint or (
        f"Raise --timeout to ≥{needed}s, or shrink the run so it finishes in time."
    )
    if auto_raise:
        warn(
            f"{verb}: {kind} internal runtime budget ≈ {needed}s exceeds --timeout "
            f"{wall}s — the run would be SIGTERM-killed mid-flight and its truncated "
            f"output misread as a clean negative. Auto-raising --timeout to {needed}s "
            f"(boost-only) so the run can finish. {hint}"
        )
        return needed
    warn(
        f"{verb}: {kind} internal runtime budget ≈ {needed}s exceeds --timeout "
        f"{wall}s — this run will likely be SIGTERM-killed before it finishes, and a "
        f"partial/empty result is NOT a clean negative. {hint}"
    )
    return wall
