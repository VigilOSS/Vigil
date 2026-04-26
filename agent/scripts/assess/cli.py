"""argparse root + subcommand registration for the assess CLI."""
from __future__ import annotations

import argparse
import sys


_ROOT_FLAGS_WITH_VALUE = {"--engagement-dir", "--actor-kind"}
_ROOT_FLAG_PREFIXES = ("--engagement-dir=", "--actor-kind=")


def _hoist_root_flags(argv: list[str]) -> list[str]:
    """Move `--engagement-dir <path>` / `--actor-kind <kind>` to the front of
    argv regardless of their original position, but stop at the first `--`
    token so user-supplied command argv to `kali exec`/`kali job start` is
    never mutated.

    argparse defines `--engagement-dir` and `--actor-kind` on the root parser,
    so they only parse cleanly *before* the subcommand name. Operators
    routinely write `aith assess kali nmap-scan --engagement-dir <path>` and
    hit `unrecognized arguments`. This pre-pass hoists the flag (and any
    `--flag=value` form) to the very front so the original argparse contract
    is preserved without duplicating the flag on every subparser.
    """
    hoisted: list[str] = []
    rest: list[str] = []
    found_double_dash = False
    i = 0
    while i < len(argv):
        token = argv[i]
        if not found_double_dash and token == "--":
            found_double_dash = True
            rest.append(token)
            i += 1
            continue
        if not found_double_dash and token in _ROOT_FLAGS_WITH_VALUE and i + 1 < len(argv):
            hoisted.extend([token, argv[i + 1]])
            i += 2
            continue
        if not found_double_dash and any(token.startswith(prefix) for prefix in _ROOT_FLAG_PREFIXES):
            hoisted.append(token)
            i += 1
            continue
        rest.append(token)
        i += 1
    return hoisted + rest


def main(argv: list[str] | None = None) -> None:
    from assess.lib.client import AssessError

    parser = argparse.ArgumentParser(
        prog="aith assess",
        description="AI Threat Hunting — assessment coordination CLI",
    )
    parser.add_argument(
        "--engagement-dir",
        dest="engagement_dir",
        default=None,
        help=(
            "Engagement directory (default: $ENGAGEMENT_DIR or cwd if it contains "
            "scope.json). Accepted in either position: before or after the "
            "subcommand name."
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

    # Import and register every subcommand
    from assess.commands import (
        approve_exploit,
        check_coverage,
        check_exploit_gate,
        check_report_readiness,
        check_scope_coverage,
        classify_work,
        contract,
        code_classify,
        code_coverage,
        code_dispatch,
        code_index,
        code_index_sync,
        code_ingest,
        code_record_analysis,
        code_record_modules,
        code_record_threat_model,
        dispatch,
        emit_event,
        export_findings,
        export_surfaces,
        fetch,
        filter_scope,
        get_command_run,
        ingest_endpoints,
        ingest_spec,
        kali_alterx,
        kali_bbot,
        kali_cero,
        kali_dnsx,
        kali_exec,
        kali_ffuf,
        kali_gau,
        kali_httpx,
        kali_job,
        kali_katana,
        kali_nikto,
        kali_nmap,
        kali_nuclei,
        kali_puredns,
        kali_sqlmap,
        kali_subfinder,
        kali_wafw00f,
        kali_whatweb,
        kill_finding,
        launch_session,
        list_clusters,
        list_command_runs,
        list_findings,
        list_intel,
        log_entry,
        merge_finding,
        merge_session,
        patch,
        reset_finding,
        post,
        record_chain,
        record_finding,
        record_intel,
        record_proposal,
        record_surface,
        review_exploits,
        update_finding,
        verify_finding,
    )

    for mod in (
        fetch,
        filter_scope,
        list_command_runs,
        get_command_run,
        list_findings,
        list_intel,
        post,
        patch,
        update_finding,
        reset_finding,
        verify_finding,
        kill_finding,
        emit_event,
        log_entry,
        record_finding,
        record_intel,
        record_surface,
        record_chain,
        merge_finding,
        dispatch,
        ingest_endpoints,
        ingest_spec,
        classify_work,
        list_clusters,
        check_coverage,
        check_scope_coverage,
        check_report_readiness,
        review_exploits,
        check_exploit_gate,
        approve_exploit,
        launch_session,
        record_proposal,
        merge_session,
        export_findings,
        export_surfaces,
        code_ingest,
        code_index,
        code_index_sync,
        code_classify,
        code_record_threat_model,
        code_record_modules,
        code_dispatch,
        code_record_analysis,
        code_coverage,
        contract,
    ):
        mod.register(sub)

    kali = sub.add_parser(
        "kali",
        help="Run Kali tools via host-side docker exec with audit recording.",
    )
    kali_sub = kali.add_subparsers(dest="kali_verb")
    kali_sub.required = False
    for kali_mod in (
        kali_alterx,
        kali_bbot,
        kali_cero,
        kali_dnsx,
        kali_exec,
        kali_ffuf,
        kali_gau,
        kali_httpx,
        kali_job,
        kali_katana,
        kali_nikto,
        kali_nmap,
        kali_nuclei,
        kali_puredns,
        kali_sqlmap,
        kali_subfinder,
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
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        args.func(args)
    except AssessError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
