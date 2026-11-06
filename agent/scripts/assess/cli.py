"""argparse root + subcommand registration for the assess CLI."""
from __future__ import annotations

import argparse
import os
import re
import sys
from typing import NoReturn

from vigil_cli.argv import passthrough_boundary

_ROOT_FLAGS_WITH_VALUE = {"--engagement-dir", "--actor-kind"}
_ROOT_FLAG_PREFIXES = ("--engagement-dir=", "--actor-kind=")
_ACTOR_KIND_CONSUMERS = frozenset({"log"})

# 128 + SIGPIPE, the status a shell reports for a process the signal killed.
# Distinct from every status this CLI already owns: 0 / 1 (Vigil refused) /
# 2 (argparse) and `kali_output.KALI_EXIT_CODES` (3 failed, 4 timed_out,
# 5 killed, 6 transport_error).
_SIGPIPE_EXIT_CODE = 141


def _flush_buffered_output() -> None:
    """Flush buffered stdout while the SIGPIPE guard is still on the stack.

    Output that never reached a closed consumer fails on its LAST flush. Left to
    the interpreter at shutdown that failure cannot be caught: it prints
    ``Exception ignored while flushing sys.stdout`` to a stream whose reader has
    already gone and replaces the command's status with its own finalization
    code. Flushing HERE puts the failure inside the guard.

    stdout only. stderr is line-buffered, so a ``print(..., file=sys.stderr)``
    has already attempted its write — and failed inside the guard if it was
    going to — leaving no residue for shutdown to trip over.
    """
    stream = sys.stdout
    if stream is not None:
        stream.flush()


def _stream_flush_failure(stream) -> BaseException | None:
    """The failure ONE stream raises when its residue is flushed again.

    Per-stream, because the two output streams fail independently and the
    answers are not interchangeable: a stdout whose consumer has gone needs its
    descriptor taken off the interpreter's hands, while a stderr that is still
    the operator's terminal must keep it — redirecting that one would discard
    the diagnostic the command just wrote.
    """
    if stream is None:
        return None
    try:
        stream.flush()
    except (OSError, ValueError) as exc:
        return exc
    return None


def _failed_output_flush() -> BaseException | None:
    """The failure stdout or stderr raises when its residue is flushed again,
    or ``None`` when both streams flush clean.

    A failed write leaves its bytes in the stream's buffer, so flushing again
    raises again — that residue is the only positive evidence available about
    what went wrong. ``os.write(fd, b"")`` cannot stand in for it: a
    zero-length write to a pipe with no reader returns 0 rather than ``EPIPE``.
    A stream that is ``None`` holds no residue at all; ``print`` to it was a
    no-op.

    Swallowed rather than propagated, because both callers ask while another
    exception is already being handled and raising here would replace it.

    Two different decisions read this, and they need different answers:

    * whether the interpreter's shutdown flush will fail again — and so needs
      :func:`_silence_closed_output` to stop it replacing the command's status
      with its own finalization code — turns only on residue EXISTING, whatever
      caused it;
    * whether the SIGPIPE exit status may be claimed turns on the cause being a
      departed reader, which only ``BrokenPipeError`` proves.
    """
    for stream in (sys.stdout, sys.stderr):
        failure = _stream_flush_failure(stream)
        if failure is not None:
            return failure
    return None


def _output_stream_is_broken() -> bool:
    """Whether stdout or stderr is demonstrably a pipe with no reader.

    ``BrokenPipeError`` and nothing wider. Any other output failure —
    ``ENOSPC`` on a full disk, ``EIO``, ``EBADF``, a ``ValueError`` from a
    closed file — is a different fault that the SIGPIPE exit status would
    misreport as "your reader went away", burying the cause the operator has to
    act on. The status only answers for what the residue proves.

    Deliberately conservative, and it errs in the safe direction. Answering
    "broken" wrongly requires the output stream to really be a dead pipe, in
    which case exiting quietly is right anyway; answering "fine" wrongly only
    keeps the existing behaviour of a propagating exception.
    """
    return isinstance(_failed_output_flush(), BrokenPipeError)


def _exit_for_undelivered_output(failure: BaseException, own_status: int) -> NoReturn:
    """THE RULE for a command whose output could not be delivered.

    One owner, read by every branch of the guard in :func:`main`, because a
    status that depended on which branch the command happened to leave through
    reported the same lost pipeline as 1 or 141 according to nothing the caller
    could see. ``failure`` is always what flushing THIS process's own stdout or
    stderr residue raised — never a verb's own ``OSError``, which keeps
    propagating as the loud failure it is.

    * A departed reader — ``BrokenPipeError``, and nothing wider — exits
      ``_SIGPIPE_EXIT_CODE`` whatever status the command would otherwise have
      used: a refusal, any of the 515 ``sys.exit(N)`` sites, a documented kali
      status whose ``.status`` lives in the JSON that never arrived, or a clean
      return. The shell's convention is the one answer a caller in a broken
      pipeline can act on, and a diagnostic that reached stderr still stands
      beside it.
    * Any other output failure (``ENOSPC`` on a full disk, ``EIO``, a
      descriptor closed underneath the process) keeps the command's own status,
      because 141 would tell the operator their reader went away and bury the
      cause they have to act on. A would-be 0 becomes 1: output that never
      arrived is not success, and a pipeline that reads status alone must not
      take a truncated answer for a complete one.

    Either way the residue comes off the interpreter's hands first, or its
    finalization code answers for the command with its own 120.
    """
    _silence_closed_output()
    if isinstance(failure, BrokenPipeError):
        sys.exit(_SIGPIPE_EXIT_CODE)
    sys.exit(own_status or 1)


def _silence_closed_output() -> None:
    """Point the descriptor of each UNWRITABLE output stream at ``os.devnull``.

    The undelivered bytes are still in Python's buffers, so without this the
    interpreter's own shutdown flush fails a second time, prints
    ``Exception ignored while flushing sys.stdout`` to a stream whose reader has
    already gone, and replaces the command's exit status with its finalization
    failure. Redirecting the descriptor lets that last flush land in /dev/null.

    Only the streams that actually fail. A healthy stderr is where the refusal
    and every other diagnostic has just been written, and pointing it at
    /dev/null would throw that away — which is what happened whenever stdout
    was CLOSED rather than a dead pipe (``vigil assess … >&-``): ``os.open``
    hands back the LOWEST free descriptor, so it returned fd 1 itself, and
    ``dup2(1, 2)`` then silenced a stderr nothing was wrong with.

    That same collision is why the descriptor is not closed when it IS one of
    the targets: fd 1 is already open on /dev/null at that point, and closing
    it would hand it back to nothing — leaving the shutdown flush to fail again
    and replace the status after all, the one outcome this function exists to
    prevent.
    """
    targets = [
        stream
        for stream in (sys.stdout, sys.stderr)
        if _stream_flush_failure(stream) is not None
    ]
    if not targets:
        return
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        return
    close_devnull = True
    for stream in targets:
        try:
            descriptor = stream.fileno()
        except (OSError, ValueError, AttributeError):
            continue
        if descriptor == devnull:
            close_devnull = False
            continue
        try:
            os.dup2(devnull, descriptor)
        except (OSError, ValueError):
            continue
    if close_devnull:
        try:
            os.close(devnull)
        except OSError:
            pass

# Action spellings a caller reaches for that no group registers, mapped to the
# action that does the job. `finding show` is the motivating case: difflib
# scores 'show' against 'get' at zero, so the route has to be curated, exactly
# as `schema_validation._suggest_close_match` curates a detail-key alias and
# lets the table answer alone when difflib cannot. Every value is filtered
# against the group's REAL action roster before it is offered, so an entry can
# never name an action a group does not have. Read/list/create/update intents
# only — nothing here routes a caller to a destructive verb they did not name.
_GROUP_ACTION_SYNONYMS = {
    "show": "get",
    "view": "get",
    "read": "get",
    "inspect": "get",
    "describe": "get",
    "ls": "list",
    "add": "record",
    "create": "record",
    "new": "record",
    "edit": "update",
    "modify": "update",
    "patch": "update",
    "set": "update",
}

# argparse renders an unknown group action as:
#   argument finding_action: invalid choice: 'show' (choose from record, ...)
# The dest is matched by the parser that owns the action, so the pattern only
# has to recover the offending value; the roster comes from the live subparser.
_INVALID_ACTION_RE = re.compile(r"invalid choice:\s*'(?P<value>.*?)'", re.DOTALL)


def _unknown_action_message(prog: str, value: str, actions: tuple[str, ...]) -> str:
    """One scoped line: the near match first, then the full action roster.

    Mirrors the kali enum rejection (`_enum_reject_message`) — suggestion first,
    allowed list always appended after it so the suggestion is additive and
    never a replacement — and reuses the same `difflib` behaviour every other
    did-you-mean door in the CLI uses, so one typo cannot get two answers.
    """
    from assess.lib.schema_validation import suggest_close_match

    head = f"{prog}: '{value}' is not an action of this command."
    synonym = _GROUP_ACTION_SYNONYMS.get(value)
    suggestion = (
        synonym if synonym in actions else suggest_close_match(value, list(actions))
    )
    if suggestion:
        head += f" Did you mean: {suggestion}? Run `{prog} {suggestion} --help`."
    return head + f" (actions: {', '.join(actions)})"


class _GroupActionParser(argparse.ArgumentParser):
    """Group parser that answers an unknown action with the closest real one.

    A grouped verb's action list is an argparse ``choices`` enum, so a near miss
    (``finding show`` for ``finding get``) rendered as a multi-line usage block
    plus the whole roster and pointed at nothing — the same failure the kali
    verbs fixed with ``ScopedErrorParser``. This intercepts only the
    invalid-action case, keyed on the group's own ``dest``; every other parse
    error keeps argparse's default rendering.

    The leaves registered under a group inherit this class (``add_subparsers``
    defaults ``parser_class`` to ``type(self)``) but set no ``group_action_dest``,
    so their errors fall straight through to argparse.
    """

    group_action_dest: str = ""
    group_actions: tuple[str, ...] = ()

    def error(self, message: str) -> None:  # noqa: D102 - argparse override
        text = message or ""
        dest = self.group_action_dest
        if dest and text.startswith(f"argument {dest}:") and "invalid choice:" in text:
            match = _INVALID_ACTION_RE.search(text)
            if match is not None and self.group_actions:
                print(
                    "ERROR: "
                    + _unknown_action_message(
                        self.prog, match.group("value"), self.group_actions
                    ),
                    file=sys.stderr,
                )
                self.exit(2)
        super().error(message)


def _hoist_root_flags(argv: list[str]) -> list[str]:
    """Move `--engagement-dir <path>` / `--actor-kind <kind>` to the front of
    argv regardless of their original position, but stop at the first `--`
    token so user-supplied command argv to `kali exec`/`kali job start` is
    never mutated.

    argparse defines `--engagement-dir` and `--actor-kind` on the root parser,
    so they only parse cleanly *before* the subcommand name. Operators
    routinely write `vigil assess kali nmap-scan --engagement-dir <path>` and
    hit `unrecognized arguments`. This pre-pass hoists the flag (and any
    `--flag=value` form) to the very front so the original argparse contract
    is preserved without duplicating the flag on every subparser.

    Edge cases (P3 #14/#15/#16):
    - Reject `--engagement-dir <flag-shaped-value>` so the operator notices
      a missing path rather than silently passing the next flag as the dir.
    - Reject duplicate `--engagement-dir` occurrences (any mix of `--flag x`
      and `--flag=x`); the first wins in argparse's normal flow but a
      duplicate signals an operator mistake worth surfacing.
    """
    hoisted: list[str] = []
    rest: list[str] = []
    boundary = passthrough_boundary(argv)
    seen_engagement_dir = 0
    i = 0
    while i < len(argv):
        token = argv[i]
        if i < boundary and token in _ROOT_FLAGS_WITH_VALUE and i + 1 < len(argv):
            value = argv[i + 1]
            if token == "--engagement-dir":
                if not value:
                    sys.exit(
                        "--engagement-dir: value is empty; pass an absolute or relative path"
                    )
                if value.startswith("-"):
                    sys.exit(
                        f"--engagement-dir: value '{value}' looks like a flag; "
                        "pass an absolute or relative path"
                    )
                seen_engagement_dir += 1
                if seen_engagement_dir > 1:
                    sys.exit("--engagement-dir was specified more than once")
            hoisted.extend([token, value])
            i += 2
            continue
        if i < boundary and any(token.startswith(prefix) for prefix in _ROOT_FLAG_PREFIXES):
            if token.startswith("--engagement-dir="):
                value = token.split("=", 1)[1]
                if not value:
                    sys.exit("--engagement-dir: value is empty; pass an absolute or relative path")
                if value.startswith("-"):
                    sys.exit(
                        f"--engagement-dir: value '{value}' looks like a flag; "
                        "pass an absolute or relative path"
                    )
                seen_engagement_dir += 1
                if seen_engagement_dir > 1:
                    sys.exit("--engagement-dir was specified more than once")
            hoisted.append(token)
            i += 1
            continue
        rest.append(token)
        i += 1
    return hoisted + rest


def _root_command_index(argv: list[str]) -> int | None:
    i = 0
    while i < len(argv):
        token = argv[i]
        if token in _ROOT_FLAGS_WITH_VALUE:
            i += 2
            continue
        if any(token.startswith(prefix) for prefix in _ROOT_FLAG_PREFIXES):
            i += 1
            continue
        return i
    return None


def _register_subcommand_group(sub, *, name, help_text, dest, leaf_modules) -> None:
    """Register a grouped subcommand (`vigil assess <name> <action> ...`).

    Creates the parent parser + its action subparser, then lets each leaf module
    register its short action name onto that subparser (each keeps its exact
    argument parser — pure re-parent). Running the bare parent with no action
    prints the group help and exits non-zero, mirroring the `kali` dispatcher.

    The parent is a `_GroupActionParser` so an unknown action gets the near
    match instead of a usage dump. argparse binds the parser class at
    `add_subparsers(parser_class=...)` time, so the one parser opts in through a
    temporary factory swap — the same mechanism
    `contracts.add_contract_subparser` uses for a single leaf.
    """
    saved_parser_class = sub._parser_class
    sub._parser_class = _GroupActionParser
    try:
        parent = sub.add_parser(name, help=help_text)
    finally:
        sub._parser_class = saved_parser_class
    action_sub = parent.add_subparsers(dest=dest)
    action_sub.required = False
    for mod in leaf_modules:
        mod.register(action_sub)
    parent.group_action_dest = dest
    parent.group_actions = tuple(action_sub.choices)

    def _print_group_help(_args) -> None:
        parent.print_help()
        sys.exit(1)

    parent.set_defaults(func=_print_group_help)


def main(argv: list[str] | None = None) -> None:
    from assess.lib.client import AssessError
    from assess.lib.config import ENGAGEMENT_BINDING_CONTRACT

    parser = argparse.ArgumentParser(
        prog="vigil assess",
        description="Vigil — assessment coordination CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Discovery:\n"
            "  vigil assess list-commands            # every verb, grouped by phase\n"
            "  vigil assess list-commands --phase consume-test\n"
            "  vigil assess contract <verb>          # the full contract for one verb "
            "(examples, required fields, common mistakes)\n\n"
            f"Engagement binding:\n  {ENGAGEMENT_BINDING_CONTRACT}\n"
        ),
    )
    parser.add_argument(
        "--engagement-dir",
        dest="engagement_dir",
        default=None,
        help=(
            "Explicit assessment engagement override. Without it, resolve from the "
            "engagement tree containing CWD or $VIGIL_SESSION_ENGAGEMENT_DIR; "
            "conflicting implicit selectors fail closed. Accepted before or after "
            "the subcommand name."
        ),
    )
    parser.add_argument(
        "--actor-kind",
        dest="actor_kind",
        default=None,
        choices=["operator", "agent", "hook", "system"],
        help="Actor kind for commands that write activity entries (currently log)",
    )

    sub = parser.add_subparsers(dest="command")

    from assess.commands import (
        agent,
        anomaly_score,
        app_unit,
        approve_proposal,
        arjun_select,
        arjun_sweep,
        artifact,
        auth_cmd,
        block_technique,
        bind_finding_author,
        check_phase_readiness,
        classify_payload,
        contract,
        coverage,
        dns_discovery,
        egress_check,
        code_coverage,
        code_dependencies,
        code_dispatch,
        code_history,
        code_index,
        code_ingest,
        code_lead,
        code_record,
        code_size_summary,
        code_sourcemap_extract,
        emit_event,
        exploit,
        export_findings,
        export_reply,
        export_submission,
        export_triage_packet,
        export_surfaces,
        fetch,
        finding_history,
        fixture_identity,
        gau,
        get_command_run,
        get_finding,
        get_intel,
        host_exec,
        http_cmd,
        ingest,
        js_mining,
        kali_alterx,
        kali_arjun,
        kali_asnmap,
        kali_bbot,
        kali_browser,
        kali_cero,
        kali_dalfox,
        kali_dnsx,
        kali_exec,
        kali_ffuf,
        kali_gau,
        kali_gf,
        kali_httpx,
        kali_job,
        kali_katana,
        kali_nikto,
        kali_nmap,
        kali_nuclei,
        kali_puredns,
        kali_robots,
        kali_sqlmap,
        kali_subfinder,
        kali_sweep,
        kali_sweep_orphans,
        kali_tlsx,
        kali_tool_help,
        kali_wafw00f,
        kali_whatweb,
        list_command_runs,
        list_commands,
        list_findings,
        list_intel,
        list_mindsets,
        list_references,
        list_report_findings,
        list_skills,
        link_finding,
        log_entry,
        merge_finding,
        operator_checkpoint,
        resolve,
        resume_brief,
        post,
        prompt_census,
        proof_receipt,
        proof_run,
        proof_work,
        recon,
        recon_status,
        record_chain,
        record_finding,
        record_intel,
        record_probe,
        record_reply,
        record_surface,
        relocate_finding,
        retract_finding_claim,
        run_audit,
        scaffold_probe,
        scope,
        supersede_intel,
        update_finding,
        update_intel,
        transition_phase,
        verify_finding,
        web_discovery,
        work_buffer,
    )

    for mod in (
        fetch,
        scope,
        resume_brief,
        prompt_census,
        artifact,
        fixture_identity,
        post,
        proof_receipt,
        proof_run,
        proof_work,
        run_audit,
        resolve,
        emit_event,
        log_entry,
        record_reply,
        record_surface,
        record_chain,
        record_probe,
        block_technique,
        operator_checkpoint,
        agent,
        app_unit,
        auth_cmd,
        work_buffer,
        arjun_select,
        arjun_sweep,
        ingest,
        dns_discovery,
        web_discovery,
        recon,
        recon_status,
        coverage,
        js_mining,
        egress_check,
        gau,
        classify_payload,
        anomaly_score,
        list_commands,
        list_mindsets,
        list_references,
        list_skills,
        check_phase_readiness,
        exploit,
        scaffold_probe,
        approve_proposal,
        host_exec,
        http_cmd,
        code_ingest,
        code_index,
        code_record,
        code_dispatch,
        code_lead,
        code_coverage,
        code_dependencies,
        code_history,
        code_size_summary,
        code_sourcemap_extract,
        contract,
        transition_phase,
    ):
        mod.register(sub)

    # Grouped namespacing: re-shelve finding / intel / export / command-run
    # verbs under a subcommand parent, mirroring the `kali` / `work-buffer`
    # pattern (see _register_subcommand_group above). Behavior is unchanged —
    # a pure re-parent, each leaf keeping its exact argument parser.
    _register_subcommand_group(
        sub,
        name="finding",
        help_text="Finding lifecycle: record, update, verify, relocate, retract-claim, merge, link, list, get, history, report.",
        dest="finding_action",
        leaf_modules=(
            record_finding,
            bind_finding_author,
            update_finding,
            verify_finding,
            relocate_finding,
            retract_finding_claim,
            merge_finding,
            link_finding,
            list_findings,
            get_finding,
            finding_history,
            list_report_findings,
        ),
    )
    _register_subcommand_group(
        sub,
        name="intel",
        help_text="Structured intel: record, update, list, get, supersede.",
        dest="intel_action",
        leaf_modules=(
            record_intel,
            update_intel,
            list_intel,
            get_intel,
            supersede_intel,
        ),
    )
    _register_subcommand_group(
        sub,
        name="export",
        help_text="Render findings.md, a platform submission/reply, a blind-triage packet, or surfaces.jsonl.",
        dest="export_kind",
        leaf_modules=(
            export_findings,
            export_submission,
            export_reply,
            export_triage_packet,
            export_surfaces,
        ),
    )
    _register_subcommand_group(
        sub,
        name="command-run",
        help_text="Inspect `vigil assess kali` command-run audit records: list, get.",
        dest="command_run_action",
        leaf_modules=(list_command_runs, get_command_run),
    )

    from assess.lib.kali import KALI_EXIT_CODES, ScopedErrorParser

    kali = sub.add_parser(
        "kali",
        help="Run Kali tools via host-side docker exec with audit recording.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes (also reported as `.status` in the JSON on stdout):\n"
            "  0  completed, or waf_challenge — a usable result came back. A WAF\n"
            "     interstitial IS a complete exchange; it is loud on stderr and in\n"
            "     `.status`, and its remedy is `kali browser`, not aborting the chain.\n"
            + "".join(
                f"  {code}  {status} — no complete output exists to interpret\n"
                for status, code in sorted(KALI_EXIT_CODES.items(), key=lambda kv: kv[1])
            )
            + "  1  Vigil refused the run (scope/policy/audit); 2  argparse rejected the flags.\n"
            + f"  {_SIGPIPE_EXIT_CODE}  the reader of this stdout went away, so the JSON above\n"
            "     never arrived; it replaces every status in this list, and a\n"
            "     refusal that reached stderr still stands.\n"
        ),
    )
    # parser_class makes every `kali <verb>` subparser a ScopedErrorParser so a
    # parse-time enum miss (--technique/--probe-kind/--phase invalid choice) is
    # re-rendered as a single scoped did-you-mean ERROR line instead of the stock
    # multi-line top-level usage dump.
    kali_sub = kali.add_subparsers(dest="kali_verb", parser_class=ScopedErrorParser)
    kali_sub.required = False
    for kali_mod in (
        kali_alterx,
        kali_arjun,
        kali_asnmap,
        kali_bbot,
        kali_browser,
        kali_cero,
        kali_dalfox,
        kali_dnsx,
        kali_exec,
        kali_ffuf,
        kali_gau,
        kali_gf,
        kali_httpx,
        kali_job,
        kali_katana,
        kali_nikto,
        kali_nmap,
        kali_nuclei,
        kali_puredns,
        kali_robots,
        kali_sqlmap,
        kali_subfinder,
        kali_sweep,
        kali_sweep_orphans,
        kali_tlsx,
        kali_tool_help,
        kali_wafw00f,
        kali_whatweb,
    ):
        kali_mod.register(kali_sub)

    def _print_kali_help(_args) -> None:
        kali.print_help()
        sys.exit(1)

    kali.set_defaults(func=_print_kali_help)

    # `vigil assess` execs this module (vigil_cli/main.py -> agent/scripts/
    # assess.py -> main()), so this is the outermost Python frame for every
    # verb — the one place a departed output consumer can be answered once
    # instead of at each of the hundreds of sites that write to stdout. The
    # guard opens before the first write of any kind: the two `print_help()`
    # paths and `maybe_print_action_help` below put real bytes on stdout and
    # then exit, exactly as a verb does.
    try:
        try:
            if argv is None:
                argv = sys.argv[1:]
            argv = _hoist_root_flags(list(argv))
            command_index = _root_command_index(argv)
            if command_index is not None and command_index < len(argv):
                if argv[command_index] == "code-dispatch":
                    code_dispatch.maybe_print_action_help(argv[command_index + 1 :])
                elif argv[command_index] == "work-buffer":
                    work_buffer.maybe_print_action_help(argv[command_index + 1 :])
            args = parser.parse_args(argv)
            if not args.command:
                parser.print_help()
                sys.exit(1)

            # --actor-kind only feeds activity-entry writers (currently `log`);
            # warn when the operator passes it for a subcommand that ignores
            # the value rather than silently dropping it.
            if (
                getattr(args, "actor_kind", None)
                and args.command not in _ACTOR_KIND_CONSUMERS
            ):
                print(
                    f"WARN --actor-kind={args.actor_kind} ignored: subcommand "
                    f"'{args.command}' does not record activity entries; consumers: "
                    f"{', '.join(sorted(_ACTOR_KIND_CONSUMERS))}",
                    file=sys.stderr,
                )

            args.func(args)
            try:
                _flush_buffered_output()
            except (OSError, ValueError) as flush_failure:
                # A verb that returned normally still wrote a body, and this is
                # where a body nobody could receive fails. `_SIGPIPE_EXIT_CODE`
                # and the quiet both belong to the departed-reader case only, so
                # the one rule decides; a `BrokenPipeError` from here used to
                # reach the handler below and an `EBADF` used to reach nobody.
                _exit_for_undelivered_output(flush_failure, 0)
        except AssessError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            # The refusal reached stderr, so the refusal is the outcome and 1
            # is the command's own status — but only `_exit_for_undelivered_output`
            # decides what happens when the body never arrived, exactly as it
            # does for the clean return above and the `sys.exit(N)` below. A
            # refusal is not special here: the reasoning that once kept status 1
            # over a dead pipe applies word for word to the 515 `sys.exit(N)`
            # call sites the branch below counts, and keeping it in one branch
            # only made the status depend on which way the command left the
            # guard. The probe flushes stdout itself, so the buffered body is
            # dealt with here too, and `sys.exit` from inside this handler is
            # not re-entered by the `except SystemExit` below.
            failure = _failed_output_flush()
            if failure is not None:
                _exit_for_undelivered_output(failure, 1)
            sys.exit(1)
        except SystemExit as exit_request:
            # A verb that ends in `sys.exit(N)` — 515 call sites across 78
            # modules under agent/scripts/assess do — raises straight past the
            # flush above, so its buffered body would be left to the
            # interpreter's uncatchable shutdown flush: `Exception ignored
            # while flushing sys.stdout` on stderr and status 120 in place of
            # the verb's own.
            # Flush HERE instead, then re-raise the SAME SystemExit so N is
            # what exits when the body WAS delivered. When it was not, the one
            # rule decides instead, and N is what it keeps or replaces. A
            # try/finally around the flush would reach this path too, but it
            # would also fire while AssessError was propagating and replace the
            # refusal with its own BrokenPipeError before the `ERROR:` line was
            # ever written.
            try:
                _flush_buffered_output()
            except (OSError, ValueError) as flush_failure:
                code = exit_request.code
                _exit_for_undelivered_output(
                    flush_failure, code if isinstance(code, int) else 1
                )
            raise
    except BrokenPipeError as broken:
        if not _output_stream_is_broken():
            # EPIPE from something other than the output stream — a socket
            # write, a worker pipe — is a genuine failure. Reporting it as a
            # departed reader would bury it under a status that says the caller
            # simply stopped reading, so it keeps propagating.
            raise
        # Proven to be this process's own output stream, so the one rule
        # answers for it as it does for every branch above.
        _exit_for_undelivered_output(broken, 1)
