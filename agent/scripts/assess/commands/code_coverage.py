"""assess.py code-coverage — display code analysis coverage and gate status."""
from __future__ import annotations

import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("code-coverage", help="Display code analysis coverage summary")
    p.add_argument("--repo-id", default=None, help="Filter by repository ID")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

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

    # Exit code based on gate status
    gate = result.get('gate', {})
    if isinstance(gate, dict) and gate.get('passed') is False:
        sys.exit(1)


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
                count = tier_data.get('total', 0)
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
    contexts = data.get('contexts', {})
    if contexts:
        total_ctx = contexts.get('total', 0)
        analyzed_ctx = contexts.get('analyzed', 0)
        needs_ctx = contexts.get('needs_context', 0)
        pending_ctx = contexts.get('pending', 0)
        print(f"\nFunction-Level:")
        print(f"  Total contexts: {total_ctx}")
        print(f"  Analyzed: {analyzed_ctx} | Needs context: {needs_ctx} | Pending: {pending_ctx}")

    # Findings
    findings = data.get('findings', {})
    if findings:
        total_findings = findings.get('total', 0)
        f_critical = findings.get('critical', 0)
        f_high = findings.get('high', 0)
        f_medium = findings.get('medium', 0)
        f_low = findings.get('low', 0)
        print(f"\nFindings: {total_findings} total ({f_critical} critical, {f_high} high, {f_medium} medium, {f_low} low)")

    # Variants
    variants = data.get('variants', 0)
    if variants:
        print(f"Variants: {variants}")

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
