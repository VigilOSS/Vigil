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


def main(argv: list[str] | None = None) -> None:
    from assess.lib.client import AssessError

    parser = argparse.ArgumentParser(
        prog="vigil assess",
        description="Vigil — assessment coordination CLI",
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
        agent,
        anomaly_score,
        approve_exploit,
        approve_proposal,
        artifact,
        auth_status,
        check_coverage,
        check_exploit_gate,
        check_intel_readiness,
        check_report_readiness,
        check_scope_coverage,
        classify_payload,
        classify_work,
        contract,
        dns_discovery,
        egress_check,
        eval_capture,
        code_classify,
        code_coverage,
        code_dispatch,
        code_index,
        code_index_sync,
        code_ingest,
        code_record_analysis,
        code_record_modules,
        code_record_threat_model,
        code_size_summary,
        emit_event,
        export_findings,
        export_surfaces,
        fetch,
        filter_scope,
        gau_endpoints,
        gau_js_endpoints,
        gau_secrets,
        get_command_run,
        host_exec,
        ingest_candidates,
        ingest_endpoints,
        ingest_httpx,
        ingest_spec,
        kali_alterx,
        kali_asnmap,
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
        kali_sweep_orphans,
        kali_wafw00f,
        kali_whatweb,
        kill_finding,
        launch_session,
        list_clusters,
        list_command_runs,
        list_finding_group,
        list_findings,
        list_intel,
        list_references,
        list_report_findings,
        list_skills,
        link_finding,
        log_entry,
        merge_finding,
        merge_session,
        patch,
        reset_finding,
        resolve_surface,
        resume_brief,
        post,
        record_chain,
        record_finding,
        record_intel,
        record_proposal,
        record_surface,
        review_exploits,
        scaffold_probe,
        supersede_intel,
        update_finding,
        update_intel,
        transition_phase,
        validate_dispatch_contract,
        verify_finding,
        web_discovery,
        work_buffer,
    )

    for mod in (
        fetch,
        filter_scope,
        list_command_runs,
        resume_brief,
        artifact,
        get_command_run,
        list_findings,
        list_intel,
        post,
        patch,
        update_finding,
        update_intel,
        supersede_intel,
        resolve_surface,
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
        link_finding,
        list_finding_group,
        list_report_findings,
        agent,
        auth_status,
        work_buffer,
        ingest_candidates,
        ingest_endpoints,
        ingest_httpx,
        ingest_spec,
        dns_discovery,
        web_discovery,
        egress_check,
        gau_endpoints,
        gau_secrets,
        gau_js_endpoints,
        classify_work,
        classify_payload,
        anomaly_score,
        list_clusters,
        list_references,
        list_skills,
        check_coverage,
        check_scope_coverage,
        check_report_readiness,
        check_intel_readiness,
        review_exploits,
        scaffold_probe,
        check_exploit_gate,
        approve_exploit,
        approve_proposal,
        launch_session,
        record_proposal,
        host_exec,
        merge_session,
        export_findings,
        export_surfaces,
        eval_capture,
        code_ingest,
        code_index,
        code_index_sync,
        code_classify,
        code_record_threat_model,
        code_record_modules,
        code_dispatch,
        code_record_analysis,
        code_coverage,
        code_size_summary,
        contract,
        transition_phase,
        validate_dispatch_contract,
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
        kali_asnmap,
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
        kali_sweep_orphans,
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
