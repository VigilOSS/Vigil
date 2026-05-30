"""aith assess code-coverage — display code analysis coverage and gate status."""
from __future__ import annotations

import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


EFFORT_THRESHOLDS = {
    "critical": 70,
    "high": 50,
    "medium": 30,
}


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
        help="Exit non-zero unless the coverage gate explicitly passes",
    )
    p.add_argument(
        "--cwe-matrix",
        action="store_true",
        help="Display per-file CWE effort coverage matrix",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

    if getattr(args, 'cwe_matrix', False):
        _run_cwe_matrix(cfg, args)
        return

    endpoint = 'code/coverage'
    if args.repo_id:
        endpoint = f'code/coverage?repo_id={args.repo_id}'

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(endpoint)

    if not isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0)

    _print_coverage(result)
    _print_vuln_class_summary(result)

    if args.require_gate_pass:
        gate = result.get('gate', {})
        if isinstance(gate, dict):
            passed = gate.get('passed')
            if passed is not True:
                sys.exit(1)


def _run_cwe_matrix(cfg, args) -> None:
    """Fetch and display the per-file CWE effort coverage matrix."""
    endpoint = 'code/coverage?detail=cwe'
    if args.repo_id:
        endpoint = f'code/coverage?detail=cwe&repo_id={args.repo_id}'

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(endpoint)

    if not isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0)

    files = result.get('files', [])
    if not files:
        print("NOTE: No CWE coverage data available from backend.\n")
        _print_coverage(result)
        if args.require_gate_pass:
            gate = result.get('gate', {})
            if isinstance(gate, dict) and gate.get('passed') is not True:
                sys.exit(1)
        return

    _print_cwe_matrix(files)

    gate_failed = False
    if args.require_gate_pass:
        gate = result.get('gate', {})
        if isinstance(gate, dict):
            gate_failed = gate.get('passed') is not True

    # Exit non-zero if any critical file has effort below threshold, or if the
    # caller requires the backend gate to pass for non-effort reasons.
    has_gap = _check_effort_gaps(files)
    if has_gap or gate_failed:
        sys.exit(1)


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


def _print_structural_verification(files: list[dict]) -> None:
    """Cross-check functions_analyzed against total_functions from structural index."""
    has_structural = any(f.get('total_functions', 0) > 0 for f in files)
    if not has_structural:
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
            if fa > funcs_analyzed:
                funcs_analyzed = fa

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
    else:
        # max(functions_analyzed) across CWE families matches total_functions,
        # but overlapping functions between families are not deduplicated —
        # this is count-based coverage, not identity-based.
        print("All indexed files report function-count coverage matching structural index.")


def _check_effort_gaps(files: list[dict]) -> bool:
    """Return True if any critical-classified file has effort below threshold."""
    for f in files:
        classification = f.get('classification', '')
        threshold = EFFORT_THRESHOLDS.get(classification, 0)
        if threshold == 0:
            continue

        applicable = f.get('applicable_families', [])
        if isinstance(applicable, list):
            applicable = set(applicable)

        effort_map: dict[str, float] = {}
        not_applicable: set[str] = set()
        for cwe in f.get('cwe_coverage', []):
            fam = cwe.get('family', '')
            if _is_not_applicable_cwe_entry(cwe):
                not_applicable.add(fam)
                continue
            effort_map[fam] = _coerce_effort(cwe.get('effort', 0))

        for fam in applicable:
            if fam in not_applicable:
                continue
            effort = effort_map.get(fam, 0)
            if effort < threshold:
                return True
    return False


def _print_vuln_class_summary(data: dict) -> None:
    """Print a vulnerability class coverage summary from CWE effort data."""
    files = data.get('files', [])
    if not files:
        # No per-file CWE data — gracefully skip
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
        print(f"Vulnerability Class Coverage:")
        print(f"  Files at full coverage: {full_coverage}/{total}")
        print(f"  Files with shallow gaps: {shallow_gaps}/{total}")
        print(f"  Files with zero-tested classes: {zero_tested}/{total}")
        print()


def _print_coverage(data: dict) -> None:
    total_files = data.get('total_files', 0)

    print(f"=== Code Analysis Coverage ===")
    print(f"Total files: {total_files}")

    # By Classification
    by_class = data.get('by_classification', {})
    if by_class:
        print(f"\nBy Classification:")
        for tier in ('critical', 'high', 'medium', 'low', 'skip'):
            tier_data = by_class.get(tier, {})
            if isinstance(tier_data, dict):
                count = tier_data.get('count', 0)
                analyzed = tier_data.get('analyzed', 0)
                if tier == 'skip':
                    print(f"  {tier:10s}: {count:>4} files |   -- skipped  |   --")
                elif count > 0:
                    pct = (analyzed / count) * 100.0
                    print(f"  {tier:10s}: {count:>4} files | {analyzed:>4} analyzed | {pct:5.1f}%")
                else:
                    print(f"  {tier:10s}: {count:>4} files |    0 analyzed |   0.0%")
            elif isinstance(tier_data, int):
                # Simple count format
                print(f"  {tier:10s}: {tier_data:>4} files")

    # Function-Level
    func_level = data.get('function_level', {})
    if func_level:
        total_ctx = func_level.get('total_contexts', 0)
        analyzed_ctx = func_level.get('analyzed', 0)
        needs_ctx = func_level.get('needs_context', 0)
        pending_ctx = func_level.get('pending', 0)
        print(f"\nFunction-Level:")
        print(f"  Total contexts: {total_ctx}")
        print(f"  Analyzed: {analyzed_ctx} | Needs context: {needs_ctx} | Pending: {pending_ctx}")

    # Findings
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

    # Coverage Gate
    gate = data.get('gate', {})
    if isinstance(gate, dict):
        passed = gate.get('passed')
        if passed is True:
            print(f"\nCoverage Gate: PASS")
        elif passed is False:
            print(f"\nCoverage Gate: FAIL")
            reasons = gate.get('reasons', [])
            if reasons:
                for reason in reasons:
                    print(f"  - {reason}")
        else:
            print(f"\nCoverage Gate: UNKNOWN")
    print()
