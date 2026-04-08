"""assess.py code-coverage — display code analysis coverage and gate status."""
from __future__ import annotations

import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


# Source of truth: which vulnerability classes apply to which slot types.
SLOT_VULN_CLASSES = {
    "NETWORK-INPUT": {
        "native": ["buffer-overflow", "integer-overflow", "format-string"],
        "managed": ["web-app-injection", "web-app-auth", "ssrf", "open-redirect", "path-traversal"],
    },
    "PROTOCOL-FIELD": {
        "native": ["buffer-overflow", "integer-overflow", "format-string"],
        "managed": ["web-app-injection", "web-app-auth", "race-condition"],
    },
    "URL-COMPONENT": {"all": ["injection", "auth-bypass", "ssrf", "open-redirect", "web-app-auth"]},
    "FILE-CONTENT": {"all": ["injection", "buffer-overflow", "type-confusion", "path-traversal", "xxe", "file-upload"]},
    "CMD-ARGUMENT": {"all": ["injection", "format-string", "path-traversal"]},
    "CALLBACK-DATA": {"all": ["use-after-free", "race-condition", "type-confusion", "deserialization"]},
    "ENV-VARIABLE": {"all": ["injection", "path-traversal"]},
    "_crypto": {"all": ["crypto-misuse"]},
    "_auth": {"all": ["auth-bypass", "web-app-auth"]},
    "_error": {"all": ["error-handling"]},
}

EFFORT_THRESHOLDS = {
    "critical": 70,
    "high": 50,
    "medium": 30,
}


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

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.get(endpoint)
    finally:
        client.close()

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

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.get(endpoint)
    finally:
        client.close()

    if not isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0)

    files = result.get('files', [])
    if not files:
        print("NOTE: No CWE coverage data available from backend.\n")
        _print_coverage(result)
        return

    _print_cwe_matrix(files)

    # Exit non-zero if any critical file has effort below threshold
    has_gap = _check_effort_gaps(files)
    if has_gap:
        sys.exit(1)


def _print_cwe_matrix(files: list[dict]) -> None:
    """Print the per-file CWE effort matrix table."""
    # Collect all vuln families across files.
    # First: collect from applicable_families (the ground truth of what SHOULD be tested)
    all_families: list[str] = []
    seen: set[str] = set()
    for f in files:
        for fam in f.get('applicable_families', []):
            if fam and fam not in seen:
                all_families.append(fam)
                seen.add(fam)
    # Second: add any reported families not already in the set (covers ad-hoc testing)
    for f in files:
        for cwe in f.get('cwe_coverage', []):
            fam = cwe.get('family', '')
            if fam and fam not in seen:
                all_families.append(fam)
                seen.add(fam)

    if not all_families:
        print("NOTE: No CWE effort data found in coverage response.\n")
        return

    # Truncate family names for column headers (max 11 chars)
    col_width = 11
    headers = [fam[:col_width] for fam in all_families]

    # Build header
    name_width = 28
    print("=== CWE Coverage Matrix ===")
    header_line = f"{'File':<{name_width}}"
    for h in headers:
        header_line += f" | {h:^{col_width}}"
    print(header_line)
    print("-" * len(header_line))

    for f in files:
        classification = f.get('classification', '')
        file_path = f.get('file_path', f.get('file_name', '?'))
        # Use just the filename for display
        display_name = file_path.rsplit('/', 1)[-1] if '/' in file_path else file_path
        if classification:
            abbr = classification[:4]
            display_name = f"{display_name} ({abbr})"
        display_name = display_name[:name_width]

        # Build effort lookup for this file
        effort_map: dict[str, int] = {}
        for cwe in f.get('cwe_coverage', []):
            effort_map[cwe.get('family', '')] = cwe.get('effort', 0)

        # Determine applicable families for this file
        applicable = f.get('applicable_families', set())
        if isinstance(applicable, list):
            applicable = set(applicable)

        threshold = EFFORT_THRESHOLDS.get(classification, 0)

        row = f"{display_name:<{name_width}}"
        for fam in all_families:
            if applicable and fam not in applicable:
                cell = "--"
            elif fam in effort_map:
                val = effort_map[fam]
                marker = "!" if threshold > 0 and val < threshold else ""
                cell = f"{val}{marker}"
            else:
                # Family is applicable but untested
                cell = "0!" if threshold > 0 else "0"
            row += f" | {cell:^{col_width}}"
        print(row)

    print()


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

        effort_map: dict[str, int] = {}
        for cwe in f.get('cwe_coverage', []):
            effort_map[cwe.get('family', '')] = cwe.get('effort', 0)

        for fam in applicable:
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

        effort_map: dict[str, int] = {}
        for cwe in cwe_coverage:
            effort_map[cwe.get('family', '')] = cwe.get('effort', 0)

        threshold = EFFORT_THRESHOLDS.get(classification, 0)
        has_zero = False
        has_shallow = False

        families_to_check = set(applicable) if applicable else set(effort_map.keys())
        for fam in families_to_check:
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
