"""vigil assess code-coverage — display code analysis coverage and gate status."""
from __future__ import annotations

from collections import Counter
import json
import sys
from pathlib import Path

# `code-dispatch` owns the lease vocabulary these verbs share; importing its age
# renderer keeps one reading of "silent for" across the queue table, this report
# projection, and the resume brief.
from assess.commands.code_dispatch import _format_lease_age
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.phases import CODE_PHASES, TERMINAL_PHASE
from assess.lib.treesitter_index import FUNCTION_SCOPED_DIMENSIONS

EFFORT_THRESHOLDS = {
    "critical": 70,
    "high": 50,
    "medium": 30,
}

READINESS_TARGETS = (
    "classify-map",
    "hunt",
    "verify-variant",
    "fuzz",
    "complete",
)

_STRUCTURAL_DEBT_PREVIEW_LIMIT = 10


def _coerce_effort(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _format_effort(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


def _is_not_applicable_cwe_entry(entry: dict) -> bool:
    if entry.get("not_applicable") is True:
        return True
    disposition = str(entry.get("disposition", entry.get("status", ""))).strip().lower()
    return disposition in {"not_applicable", "not-applicable", "n/a", "na"}


def register(subparsers) -> None:
    p = subparsers.add_parser("code-coverage", help="Display code analysis coverage summary")
    p.add_argument("--repo-id", default=None, help="Filter by repository ID")
    p.add_argument(
        "--require-gate-pass",
        action="store_true",
        help=(
            "Exit non-zero when self-reported CWE effort or coverage-integrity "
            "warnings remain; structural transition readiness is separate"
        ),
    )
    p.add_argument(
        "--require-transition-ready",
        choices=READINESS_TARGETS,
        metavar="TARGET_PHASE",
        help=(
            "Fetch backend readiness for the target code phase and exit non-zero "
            "when structural or lifecycle blockers remain"
        ),
    )
    p.add_argument(
        "--cwe-matrix",
        action="store_true",
        help="Display per-file CWE effort coverage matrix",
    )
    p.add_argument(
        "--debt-paths", action="store_true",
        help="List every path behind the next structural review debt gate",
    )
    p.set_defaults(func=run)


def _next_code_gate(engagement_dir: str) -> str | None:
    scope_path = Path(engagement_dir) / "scope.json"
    if not scope_path.is_file():
        return None
    try:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(scope, dict):
        return None
    engagement_type = scope.get("engagement_type")
    if engagement_type not in {"code", "both"}:
        return None
    phase_key = "code_phase" if engagement_type == "both" else "current_phase"
    current = scope.get(phase_key, "ingest")
    if current == TERMINAL_PHASE:
        return None
    if current not in CODE_PHASES:
        return None
    index = CODE_PHASES.index(current)
    return (*CODE_PHASES, TERMINAL_PHASE)[index + 1]


def _debt_counts(readiness: dict) -> tuple[Counter, Counter, Counter]:
    classifications: Counter = Counter()
    statuses: Counter = Counter()
    truncated: Counter = Counter()
    for item in readiness.get("structural_debt", []):
        if not isinstance(item, dict):
            continue
        classifications[str(item.get("classification") or "unclassified")] += 1
        statuses[str(item.get("structural_analysis_status") or "unknown")] += 1
        if item.get("structural_artifact_truncated") is True:
            truncated["truncated"] += 1
    return classifications, statuses, truncated


def _print_debt_summary(readiness: dict, *, show_all: bool) -> None:
    debt = readiness.get("structural_debt")
    if not isinstance(debt, list):
        return
    count = readiness.get("structural_debt_count", len(debt))
    classifications, statuses, truncated = _debt_counts(readiness)
    class_text = ", ".join(
        f"{name}={classifications[name]}" for name in sorted(classifications)
    ) or "none"
    status_text = ", ".join(
        f"{name}={statuses[name]}" for name in sorted(statuses)
    ) or "none"
    print(f"  debt by classification: {class_text}")
    print(f"  debt by structural status: {status_text}; truncated={truncated['truncated']}")
    limit = len(debt) if show_all else _STRUCTURAL_DEBT_PREVIEW_LIMIT
    shown = debt[:limit]
    if shown:
        if len(debt) > len(shown):
            print(f"  debt files (showing {len(shown)} of {count}; use --debt-paths for all):")
        else:
            print("  debt files:")
        for item in shown:
            if not isinstance(item, dict):
                continue
            print(
                f"    repo {item.get('repo_id', '?')}: {item.get('file_path', '?')} "
                f"classification={item.get('classification') or 'unclassified'} "
                f"structural={item.get('structural_analysis_status') or 'unknown'}"
                f"{' truncated' if item.get('structural_artifact_truncated') is True else ''}"
            )


def _print_next_gate(target: str, readiness: dict, *, debt_paths: bool) -> None:
    ready = readiness.get("target_phase") == target and readiness.get("transition_ready") is True
    print(f"\nNext hard gate ({target}): {'READY' if ready else 'BLOCKED'}")
    blockers = readiness.get("blockers")
    if isinstance(blockers, list) and blockers:
        codes = [str(item.get("code")) for item in blockers if isinstance(item, dict)]
        print(f"  blockers: {', '.join(codes[:3])}" + (f" +{len(codes) - 3} more" if len(codes) > 3 else ""))
    debt_count = readiness.get("structural_debt_count")
    if isinstance(debt_count, int):
        print(f"  structural debt: {debt_count} file(s)")
    _print_debt_summary(readiness, show_all=debt_paths)
    print(f"  full gate: vigil assess code-coverage --require-transition-ready {target}")


def _readiness_endpoint(target: str) -> str:
    return f"code/readiness?target_phase={target}&include_debt_paths=true"


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    readiness_target = getattr(args, 'require_transition_ready', None)
    next_target = None if readiness_target else _next_code_gate(
        getattr(cfg, "engagement_dir", getattr(args, "engagement_dir", ""))
    )

    if getattr(args, 'cwe_matrix', False):
        quality_passed = _run_cwe_matrix(cfg, args)
        failed = bool(getattr(args, 'require_gate_pass', False) and not quality_passed)
        if readiness_target:
            with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
                readiness = client.get(_readiness_endpoint(readiness_target))
            if not isinstance(readiness, dict):
                print(
                    f"Transition Readiness ({readiness_target}): UNKNOWN\n"
                    "  - [invalid_code_readiness] Backend returned a non-object response"
                )
                failed = True
            else:
                _print_transition_readiness(
                    readiness_target, readiness,
                    debt_paths=bool(getattr(args, "debt_paths", False)),
                )
                if (
                    readiness.get('target_phase') != readiness_target
                    or readiness.get('transition_ready') is not True
                ):
                    failed = True
        if failed:
            sys.exit(1)
        return

    endpoint = 'code/coverage'
    if args.repo_id:
        endpoint = f'code/coverage?repo_id={args.repo_id}'

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(endpoint)
        readiness = (
            client.get(_readiness_endpoint(readiness_target or next_target))
            if readiness_target or next_target
            else None
        )

    if not isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if getattr(args, 'require_gate_pass', False) or readiness_target:
            sys.exit(1)
        return

    _print_coverage(
        result,
        structural_debt_by_classification=(
            _debt_counts(readiness)[0] if isinstance(readiness, dict) else Counter()
        ),
        include_review_quality=False,
    )
    _print_vuln_class_summary(result)
    if next_target:
        if isinstance(readiness, dict):
            _print_next_gate(
                next_target, readiness, debt_paths=bool(getattr(args, "debt_paths", False))
            )
        else:
            print(f"\nNext hard gate ({next_target}): UNKNOWN")

    failed = False
    if getattr(args, 'require_gate_pass', False):
        quality_passed, _ = _review_quality(result)
        if not quality_passed:
            failed = True

    if readiness_target:
        if not isinstance(readiness, dict):
            print(
                f"Transition Readiness ({readiness_target}): UNKNOWN\n"
                "  - [invalid_code_readiness] Backend returned a non-object response"
            )
            failed = True
        else:
            _print_transition_readiness(
                readiness_target, readiness,
                debt_paths=bool(getattr(args, "debt_paths", False)),
            )
            if (
                readiness.get('target_phase') != readiness_target
                or readiness.get('transition_ready') is not True
            ):
                failed = True

    _print_review_quality(result)
    print()

    if failed:
        sys.exit(1)


def _repo_selector(repo_id: object) -> str:
    return f"--repo-id {repo_id}" if repo_id not in (None, '') else "--repo-id <repo-id>"


# The repair verb for each integrity blocker an operator can actually clear.
# Without these the blocker reads as "no repair path exists" and the operator
# reaches for a re-ingest, which advances the generation and invalidates every
# generation-bound review, index, and threat model.
_BLOCKER_REPAIRS = {
    'structural_index_stale': lambda repo_id: (
        f"vigil assess code-index build <snapshot-dir>/source {_repo_selector(repo_id)} "
        f"then vigil assess code-index sync {_repo_selector(repo_id)} "
        "(rebinds the existing generation; neither advances it)"
    ),
    'structural_index_metadata_incomplete': lambda repo_id: (
        f"vigil assess code-index build <snapshot-dir>/source {_repo_selector(repo_id)} "
        f"then vigil assess code-index sync {_repo_selector(repo_id)} "
        "(rebinds the existing generation; neither advances it)"
    ),
    'threat_model_stale': lambda repo_id: (
        "vigil assess code-record threat-model for the current generation"
    ),
    'admitted_files_unqueued': lambda repo_id: (
        "vigil assess code-dispatch queue <queue-items-json-file> — one row per "
        "admitted file, including skip-tier; "
        f"vigil assess code-dispatch list {_repo_selector(repo_id)} shows what is "
        "already loaded. If this repository is host/framework source nobody is "
        "reviewing, re-ingest it with --role reference instead: it stays indexed "
        "and citable and stops owing coverage"
    ),
    'source_snapshot_unverified': lambda repo_id: (
        "vigil assess code-ingest <repo-path> --repo-key <key> — a verified "
        "re-ingest, which advances the generation by design"
    ),
    'code_leads_unresolved': lambda repo_id: (
        # The blocker counts every binding whose note is open OR in_progress and
        # does not exclude stale ones, so a narrower read dead-ends the operator
        # on a gate that is still firing.
        f"`vigil assess code-lead list {_repo_selector(repo_id)} --include-superseded` "
        "shows each unanswered prior-art lead and where it points; "
        "`vigil assess code-lead queue` turns any bound file with no queue row "
        "into analysis work. Close each lead on the note itself: `vigil assess "
        "intel update note <lead-id> --inline '{\"lead_status\": \"ruled_out\"}'` "
        "(or resolved when it led to a finding)"
    ),
}


def _print_transition_readiness(
    target_phase: str, readiness: dict, *, debt_paths: bool = False
) -> None:
    bound_target = readiness.get('target_phase')
    ready = bound_target == target_phase and readiness.get('transition_ready') is True
    print(f"Transition Readiness ({target_phase}): {'READY' if ready else 'BLOCKED'}")

    blockers = readiness.get('blockers', [])
    if isinstance(blockers, list):
        for blocker in blockers:
            if not isinstance(blocker, dict):
                continue
            code = blocker.get('code', 'unknown')
            message = blocker.get('message', 'Unnamed readiness blocker')
            integrity = " [integrity; non-overrideable]" if blocker.get('overrideable') is False else ""
            # With several repos in scope, a blocker without its repo_id names
            # no repair target.
            repo_id = blocker.get('repo_id')
            scope = f" (repo {repo_id})" if repo_id not in (None, '') else ""
            print(f"  - [{code}]{scope} {message}{integrity}")
            repair = _BLOCKER_REPAIRS.get(str(code))
            if repair:
                print(f"      repair: {repair(repo_id)}")

    quality = readiness.get('quality_gate')
    if isinstance(quality, dict):
        warnings = quality.get('warnings', [])
        quality_passed = quality.get('passed') is True
        if not quality_passed or warnings:
            print(
                "Readiness Advisories: "
                f"{'PASS' if quality_passed else 'NEEDS ATTENTION'}"
            )
            if isinstance(warnings, list):
                for warning in warnings:
                    print(f"  - {warning}")
    _print_debt_summary(readiness, show_all=debt_paths)
    print()


def _run_cwe_matrix(cfg, args) -> bool:
    """Fetch and display the per-file CWE effort matrix; return its quality verdict."""
    endpoint = 'code/coverage?detail=cwe'
    if args.repo_id:
        endpoint = f'code/coverage?detail=cwe&repo_id={args.repo_id}'

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(endpoint)

    if not isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return False

    files = result.get('files', [])
    if not files:
        print("NOTE: No CWE coverage data available from backend.\n")
        _print_coverage(result)
        quality_passed, _ = _review_quality(result)
        return quality_passed

    _print_cwe_matrix(files)
    _print_open_leases(result)
    _print_review_quality(result)

    quality_passed, _ = _review_quality(result)
    return quality_passed


def _print_cwe_matrix(files: list[dict]) -> None:
    """Print the per-file CWE effort matrix table."""
    all_families: list[str] = []
    seen: set[str] = set()
    for f in files:
        for fam in f.get('applicable_families', []):
            if fam and fam not in seen:
                all_families.append(fam)
                seen.add(fam)
    for f in files:
        for cwe in f.get('cwe_coverage', []):
            fam = cwe.get('family', '')
            if fam and fam not in seen:
                all_families.append(fam)
                seen.add(fam)

    if not all_families:
        print("NOTE: No CWE effort data found in coverage response.\n")
        return

    col_width = 11
    headers = [fam[:col_width] for fam in all_families]

    name_width = 28
    struct_width = 22
    print("=== CWE Coverage Matrix ===")
    header_line = f"{'File':<{name_width}} {'Funcs/EP/Sinks':^{struct_width}}"
    for h in headers:
        header_line += f" | {h:^{col_width}}"
    print(header_line)
    print("-" * len(header_line))

    for f in files:
        classification = f.get('classification', '')
        file_path = f.get('file_path', f.get('file_name', '?'))
        display_name = file_path.rsplit('/', 1)[-1] if '/' in file_path else file_path
        if classification:
            abbr = classification[:4]
            display_name = f"{display_name} ({abbr})"
        display_name = display_name[:name_width]

        effort_map: dict[str, float] = {}
        not_applicable: set[str] = set()
        for cwe in f.get('cwe_coverage', []):
            fam = cwe.get('family', '')
            if _is_not_applicable_cwe_entry(cwe):
                not_applicable.add(fam)
                continue
            effort_map[fam] = _coerce_effort(cwe.get('effort', 0))

        applicable = f.get('applicable_families', set())
        if isinstance(applicable, list):
            applicable = set(applicable)

        threshold = EFFORT_THRESHOLDS.get(classification, 0)

        total_funcs = f.get('total_functions', 0)
        total_ep = f.get('total_entry_points', 0)
        total_sinks = f.get('total_sinks', 0)
        has_structural = total_funcs or total_ep or total_sinks
        struct_cell = f"{total_funcs}/{total_ep}/{total_sinks}" if has_structural else "--"

        row = f"{display_name:<{name_width}} {struct_cell:^{struct_width}}"
        for fam in all_families:
            if applicable and fam not in applicable:
                cell = "--"
            elif fam in not_applicable:
                cell = "N/A"
            elif fam in effort_map:
                val = effort_map[fam]
                marker = "!" if threshold > 0 and val < threshold else ""
                cell = f"{_format_effort(val)}{marker}"
            else:
                cell = "0!" if threshold > 0 else "0"
            row += f" | {cell:^{col_width}}"
        print(row)

    _print_structural_verification(files)
    print()


def _unscanned_structural_scope(file_row: dict) -> bool:
    """Whether the index declares this file's function-scoped readers unmeasured.

    `FUNCTION_SCOPED_DIMENSIONS` is imported rather than restated: the indexer
    that publishes the list owns what belongs in it.
    """
    unavailable = file_row.get('structural_unavailable_dimensions') or []
    return bool(set(unavailable) & FUNCTION_SCOPED_DIMENSIONS)


def _print_structural_verification(files: list[dict]) -> None:
    """Cross-check analysed functions against the index, and name what it never read.

    The count check only means anything where there are functions to count, so
    a file whose scan scope covered no source is reported on its own terms
    instead of falling through the comparison into the all-clear.
    """
    unscanned = [f for f in files if _unscanned_structural_scope(f)]
    has_structural = any(f.get('total_functions', 0) > 0 for f in files)
    if not has_structural and not unscanned:
        return

    print("\n--- Structural Verification ---")
    gaps: list[str] = []
    for f in files:
        total_funcs = f.get('total_functions', 0)
        if total_funcs == 0:
            continue

        funcs_analyzed = 0
        for cwe in f.get('cwe_coverage', []):
            fa = cwe.get('functions_analyzed', 0)
            try:
                fa = int(fa)
            except (TypeError, ValueError):
                fa = 0
            funcs_analyzed = max(funcs_analyzed, fa)

        file_path = f.get('file_path', '?')
        display = file_path.rsplit('/', 1)[-1] if '/' in file_path else file_path
        classification = f.get('classification', '')

        if funcs_analyzed < total_funcs:
            pct = (funcs_analyzed / total_funcs * 100) if total_funcs > 0 else 0
            gaps.append(
                f"  {display} ({classification}): {funcs_analyzed}/{total_funcs} functions analyzed ({pct:.0f}%)"
            )

    if gaps:
        print(f"Files with unanalyzed functions: {len(gaps)}")
        for g in gaps:
            print(g)
    if unscanned:
        # Zero functions means zero scanned spans, so the function-count check
        # above has nothing to compare and silently passed these files over.
        print(f"Files whose structural scan scope covered no source: {len(unscanned)}")
        for f in unscanned:
            file_path = f.get('file_path', '?')
            classification = f.get('classification', '')
            print(
                f"  {file_path} ({classification}): "
                f"{', '.join(f.get('structural_unavailable_dimensions') or [])} "
                "not measured — only whole-file source review can cover it"
            )
    if not gaps and not unscanned:
        # max(functions_analyzed) across CWE families matches total_functions,
        # but overlapping functions between families are not deduplicated —
        # this is count-based coverage, not identity-based.
        print("All indexed files report function-count coverage matching structural index.")


def _review_quality(data: dict) -> tuple[bool, list[str]]:
    """Derive the advisory quality verdict from its two canonical inputs only."""
    gate = data.get('gate')
    if not isinstance(gate, dict):
        return False, ["Review-quality metadata is unavailable"]

    effort_warnings = gate.get('effort_warnings')
    integrity = gate.get('coverage_integrity')
    if not isinstance(effort_warnings, list) or not isinstance(integrity, list):
        return False, ["Review-quality metadata is incomplete"]

    warnings = [str(warning) for warning in effort_warnings]
    for item in integrity:
        if not isinstance(item, dict):
            return False, ["Review-quality metadata is invalid"]
        item_warnings = item.get('warnings', [])
        if not isinstance(item_warnings, list):
            return False, ["Review-quality metadata is invalid"]
        for warning in item_warnings:
            warnings.append(f"{item.get('file_path', 'unknown file')}: {warning}")
    warnings = list(dict.fromkeys(warnings))
    return not warnings, warnings


def _print_review_quality(data: dict) -> None:
    passed, warnings = _review_quality(data)
    print(f"\nReview Quality: {'PASS' if passed else 'NEEDS ATTENTION'}")
    for warning in warnings:
        print(f"  - {warning}")


def _print_vuln_class_summary(data: dict) -> None:
    """Print a vulnerability class coverage summary from CWE effort data."""
    files = data.get('files', [])
    if not files:
        return

    total = 0
    full_coverage = 0
    shallow_gaps = 0
    zero_tested = 0

    for f in files:
        classification = f.get('classification', '')
        if classification == 'skip':
            continue
        total += 1

        cwe_coverage = f.get('cwe_coverage', [])
        applicable = f.get('applicable_families', [])

        if not cwe_coverage and not applicable:
            # No data for this file — treat as zero-tested if it has a classification
            if classification in ('critical', 'high', 'medium', 'low'):
                zero_tested += 1
            continue

        effort_map: dict[str, float] = {}
        not_applicable: set[str] = set()
        for cwe in cwe_coverage:
            fam = cwe.get('family', '')
            if _is_not_applicable_cwe_entry(cwe):
                not_applicable.add(fam)
                continue
            effort_map[fam] = _coerce_effort(cwe.get('effort', 0))

        threshold = EFFORT_THRESHOLDS.get(classification, 0)
        has_zero = False
        has_shallow = False

        families_to_check = set(applicable) if applicable else set(effort_map.keys())
        for fam in families_to_check:
            if fam in not_applicable:
                continue
            effort = effort_map.get(fam, 0)
            if effort == 0:
                has_zero = True
            elif threshold > 0 and effort < threshold:
                has_shallow = True

        if has_zero:
            zero_tested += 1
        elif has_shallow:
            shallow_gaps += 1
        else:
            full_coverage += 1

    if total > 0:
        print("Vulnerability Class Coverage:")
        print(f"  Files at full coverage: {full_coverage}/{total}")
        print(f"  Files with shallow gaps: {shallow_gaps}/{total}")
        print(f"  Files with zero-tested classes: {zero_tested}/{total}")
        print()


_ANALYSIS_STATUS_ORDER = (
    'analyzed', 'in_progress', 'needs_context', 'queued', 'classified', 'pending',
)


def _print_analysis_status(data: dict) -> None:
    """Render the per-file analysis-status census the backend already computes.

    Without it, a repo whose files were classified but never queued shows only
    "0 analyzed" against a full classification table — indistinguishable from
    lost work, when the real state is "the queue was never populated".
    """
    by_status = data.get('by_status')
    if not isinstance(by_status, dict) or not by_status:
        return
    print("\nBy Analysis Status:")
    for status in _ANALYSIS_STATUS_ORDER:
        if status in by_status:
            print(f"  {status:14s}: {by_status.get(status, 0):>5}")
    for status, count in sorted(by_status.items()):
        if status not in _ANALYSIS_STATUS_ORDER:
            print(f"  {str(status):14s}: {count:>5}")

    classified = int(by_status.get('classified', 0) or 0)
    queued = int(by_status.get('queued', 0) or 0)
    if classified > 0 and queued == 0:
        print(
            f"  NOTE: {classified} file(s) classified but never queued — run "
            "`vigil assess code-dispatch queue <queue-items-json-file>`; "
            "`analyzed` counts require queue receipts."
        )


def _print_source_identity(data: dict) -> None:
    """Surface per-repo binding state here, where it is cheap to discover.

    The structural-index binding is written by exactly one verb (`code-index
    sync`) and read as a hard gate by a much later one (`agent start`), so
    without this block the gap is only discovered at dispatch-composition time.
    """
    repos = data.get('repos')
    if not isinstance(repos, list) or not repos:
        return
    print("\nSource Identity:")
    for repo in repos:
        if not isinstance(repo, dict):
            continue
        repo_id = repo.get('repo_id', '?')
        generation = repo.get('active_generation', '?')
        quality = repo.get('source_snapshot_quality') or 'unknown'
        structural_bound = bool(repo.get('structural_index_bound'))
        threat_bound = bool(repo.get('threat_model_bound'))
        print(
            f"  repo {repo_id}: generation {generation} | snapshot {quality} | "
            f"structural index {'bound' if structural_bound else 'UNBOUND'} | "
            f"threat model {'bound' if threat_bound else 'unbound'}"
        )
        if not structural_bound:
            print(f"      {_BLOCKER_REPAIRS['structural_index_stale'](repo_id)}")


def _print_open_leases(data: dict) -> None:
    """Name the claimed attempts that never closed, oldest lease first.

    "Queue items still pending or processing" is a count; this is the item-level
    form of it, because a dispatch that died mid-file is indistinguishable from
    live work until you can see how long its lease has been silent and how many
    receipts would be thrown away by resetting it.
    """
    leases = data.get("open_leases")
    if not isinstance(leases, list) or not leases:
        return
    total = data.get("open_leases_count", len(leases))
    print(f"\nOpen Analysis Leases ({total}):")
    for lease in leases:
        if not isinstance(lease, dict):
            continue
        receipts = int(lease.get("current_result_count", 0) or 0)
        print(
            f"  item {lease.get('queue_item_id', '?')} "
            f"{lease.get('file_path', '?')} ({lease.get('classification', '?')}): "
            f"held by {lease.get('agent_name') or '-'} / "
            f"{lease.get('lease_token') or '-'}, silent for "
            f"{_format_lease_age(lease.get('heartbeat_age_seconds'))}, "
            f"{receipts} receipt(s) recorded"
        )
        for adopted in lease.get("adopted_leases") or []:
            if isinstance(adopted, dict):
                print(
                    f"      adopted from {adopted.get('agent_name', '?')} / "
                    f"{adopted.get('lease_token', '?')}"
                )
    if isinstance(total, int) and total > len(leases):
        # The backend already bounds the embedded list; the count is absolute.
        print(f"  ... showing {len(leases)} of {total}")
    print(
        "  Recover each with `vigil assess code-dispatch progress <item-id>` "
        "then `code-dispatch adopt-lease` (keeps the receipts) or "
        "`code-dispatch reset-stale <minutes>` (discards them)."
    )


def _print_coverage(
    data: dict,
    *,
    structural_debt_by_classification: Counter | None = None,
    include_review_quality: bool = True,
) -> None:
    total_files = data.get('total_files', 0)

    print("=== Code Analysis Coverage ===")
    print(f"Total files: {total_files}")

    # A reference repository's files are deliberately absent from every count
    # above. Naming them keeps the smaller denominator explicit instead of
    # letting an operator read it as a shrinking inventory.
    reference_repos = data.get('reference_repos') or []
    if isinstance(reference_repos, list) and reference_repos:
        print("\nReference repositories (readable; no coverage obligation):")
        for repo in reference_repos:
            if not isinstance(repo, dict):
                continue
            name = repo.get('name') or repo.get('repo_key') or 'unknown'
            print(
                f"  {name} (repo {repo.get('repo_id', '?')}): "
                f"{repo.get('admitted_files', 0)} indexed file(s)"
            )

    by_class = data.get('by_classification', {})
    if by_class:
        print("\nBy Classification:")
        for tier in ('critical', 'high', 'medium', 'low', 'skip'):
            tier_data = by_class.get(tier, {})
            if isinstance(tier_data, dict):
                count = tier_data.get('count', 0)
                analyzed = tier_data.get('analyzed', 0)
                if tier == 'skip':
                    debt = (structural_debt_by_classification or Counter()).get(tier, 0)
                    print(
                        f"  {tier:10s}: {count:>4} files | {analyzed:>4} reviewed | "
                        f"structural debt: {debt}"
                    )
                elif count > 0:
                    pct = (analyzed / count) * 100.0
                    print(f"  {tier:10s}: {count:>4} files | {analyzed:>4} analyzed | {pct:5.1f}%")
                else:
                    print(f"  {tier:10s}: {count:>4} files |    0 analyzed |   0.0%")
            elif isinstance(tier_data, int):
                print(f"  {tier:10s}: {tier_data:>4} files")

    _print_analysis_status(data)
    _print_open_leases(data)
    _print_source_identity(data)

    func_level = data.get('function_level', {})
    if func_level:
        total_ctx = func_level.get('total_contexts', 0)
        analyzed_ctx = func_level.get('analyzed', 0)
        needs_ctx = func_level.get('needs_context', 0)
        pending_ctx = func_level.get('pending', 0)
        print("\nFunction-Level:")
        print(f"  Total contexts: {total_ctx}")
        print(f"  Analyzed: {analyzed_ctx} | Needs context: {needs_ctx} | Pending: {pending_ctx}")

    findings = data.get('findings_summary', {})
    if findings:
        total_findings = findings.get('total_code_findings', 0)
        by_severity = findings.get('by_severity', {})
        f_critical = by_severity.get('critical', 0)
        f_high = by_severity.get('high', 0)
        f_medium = by_severity.get('medium', 0)
        f_low = by_severity.get('low', 0)
        print(f"\nFindings: {total_findings} total ({f_critical} critical, {f_high} high, {f_medium} medium, {f_low} low)")
        variant_count = findings.get('variant_count', 0)
        if variant_count:
            print(f"Variants: {variant_count}")

    triggers = data.get('trigger_summary', {})
    if triggers:
        accepted = (
            triggers.get('external_context_unavailable', 0)
            + triggers.get('source_equivalent_analyzed', 0)
            + triggers.get('not_applicable', 0)
        )
        print(
            "\nCross-File Triggers: "
            f"{triggers.get('pending', 0)} pending, "
            f"{triggers.get('queued', 0)} queued, "
            f"{triggers.get('resolved', 0)} resolved, "
            f"{accepted} accepted gap"
        )

    if include_review_quality:
        _print_review_quality(data)
    print()
