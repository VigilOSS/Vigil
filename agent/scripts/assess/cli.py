"""argparse root + subcommand registration for the assess CLI."""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> None:
    from assess.lib.client import AssessError

    parser = argparse.ArgumentParser(
        prog="assess.py",
        description="AI Threat Hunting — assessment coordination CLI",
    )
    parser.add_argument(
        "--engagement-dir",
        dest="engagement_dir",
        default=None,
        help="Engagement directory (default: $ENGAGEMENT_DIR or cwd if it contains scope.json)",
    )

    sub = parser.add_subparsers(dest="command")

    # Import and register every subcommand
    from assess.commands import (
        approve_exploit,
        check_coverage,
        check_exploit_gate,
        check_report_readiness,
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
        ingest_endpoints,
        ingest_spec,
        kill_finding,
        launch_session,
        list_findings,
        log_entry,
        merge_finding,
        merge_session,
        patch,
        reset_finding,
        post,
        record_chain,
        record_finding,
        record_proposal,
        record_surface,
        review_exploits,
        update_finding,
        verify_finding,
    )

    for mod in (
        fetch,
        list_findings,
        post,
        patch,
        update_finding,
        reset_finding,
        verify_finding,
        kill_finding,
        emit_event,
        log_entry,
        record_finding,
        record_surface,
        record_chain,
        merge_finding,
        dispatch,
        ingest_endpoints,
        ingest_spec,
        check_coverage,
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

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        args.func(args)
    except AssessError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
