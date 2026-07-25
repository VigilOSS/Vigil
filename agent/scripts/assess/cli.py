"""argparse root + subcommand registration for the assess CLI."""
from __future__ import annotations

import argparse
import sys


_ROOT_FLAGS_WITH_VALUE = {"--engagement-dir", "--actor-kind"}
_ROOT_FLAG_PREFIXES = ("--engagement-dir=", "--actor-kind=")
_ACTOR_KIND_CONSUMERS = frozenset({"log"})


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
    found_double_dash = False
    seen_engagement_dir = 0
    i = 0
    while i < len(argv):
        token = argv[i]
        if not found_double_dash and token == "--":
            found_double_dash = True
            rest.append(token)
            i += 1
            continue
        if not found_double_dash and token in _ROOT_FLAGS_WITH_VALUE and i + 1 < len(argv):
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
        if not found_double_dash and any(token.startswith(prefix) for prefix in _ROOT_FLAG_PREFIXES):
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
    """
    parent = sub.add_parser(name, help=help_text)
    action_sub = parent.add_subparsers(dest=dest)
    action_sub.required = False
    for mod in leaf_modules:
        mod.register(action_sub)

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

    # Import subcommand modules; registration follows below.
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
        check_phase_readiness,
        classify_payload,
        contract,
        coverage,
        dns_discovery,
        egress_check,
        code_coverage,
        code_dispatch,
        code_index,
        code_ingest,
        code_record,
        code_size_summary,
        code_sourcemap_extract,
        emit_event,
        exploit,
        export_findings,
        export_reply,
        export_submission,
        export_surfaces,
        fetch,
        gau,
        get_command_run,
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
        resolve,
        resume_brief,
        post,
        recon,
        recon_status,
        record_chain,
        record_finding,
        record_intel,
        record_probe,
        record_reply,
        record_surface,
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
        artifact,
        post,
        resolve,
        emit_event,
        log_entry,
        record_reply,
        record_surface,
        record_chain,
        record_probe,
        block_technique,
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
        code_coverage,
        code_size_summary,
        code_sourcemap_extract,
        contract,
        transition_phase,
    ):
        mod.register(sub)

    # Grouped namespacing: re-shelve finding / intel / export / command-run
    # verbs under a subcommand parent (mirrors the `kali` / `work-buffer` pattern).
    # Each leaf module registers its short action name (`record`, `verify`, …)
    # onto the parent's action subparser; behavior is unchanged (pure re-parent).
    _register_subcommand_group(
        sub,
        name="finding",
        help_text="Finding lifecycle: record, update, verify, merge, link, list, report.",
        dest="finding_action",
        leaf_modules=(
            record_finding,
            update_finding,
            verify_finding,
            merge_finding,
            link_finding,
            list_findings,
            list_report_findings,
        ),
    )
    _register_subcommand_group(
        sub,
        name="intel",
        help_text="Structured intel: record, update, list, supersede.",
        dest="intel_action",
        leaf_modules=(record_intel, update_intel, list_intel, supersede_intel),
    )
    _register_subcommand_group(
        sub,
        name="export",
        help_text="Render findings.md, a platform submission, a program reply, or surfaces.jsonl.",
        dest="export_kind",
        leaf_modules=(
            export_findings,
            export_submission,
            export_reply,
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

    from assess.lib.kali import ScopedErrorParser

    kali = sub.add_parser(
        "kali",
        help="Run Kali tools via host-side docker exec with audit recording.",
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

    if argv is None:
        argv = sys.argv[1:]
    argv = _hoist_root_flags(list(argv))
    command_index = _root_command_index(argv)
    if command_index is not None and command_index < len(argv):
        if argv[command_index] == "agent":
            agent.maybe_print_action_help(argv[command_index + 1 :])
        elif argv[command_index] == "work-buffer":
            work_buffer.maybe_print_action_help(argv[command_index + 1 :])
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # --actor-kind only feeds activity-entry writers (currently `log`); warn
    # when the operator passes it for a subcommand that ignores the value
    # rather than silently dropping it.
    if getattr(args, "actor_kind", None) and args.command not in _ACTOR_KIND_CONSUMERS:
        print(
            f"WARN --actor-kind={args.actor_kind} ignored: subcommand "
            f"'{args.command}' does not record activity entries; consumers: "
            f"{', '.join(sorted(_ACTOR_KIND_CONSUMERS))}",
            file=sys.stderr,
        )

    try:
        args.func(args)
    except AssessError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
