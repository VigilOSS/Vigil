"""Load and pre-check the runtime proof plan file (`--next-test-file`).

The backend owns the contract (``FindingNextTestRequest``) and remains the
authority; this check exists so a command fails before its first write — in
particular so ``finding record --pending-runtime-proof`` cannot record a finding
and then fail to park it for want of a plan. The plan is sent byte-for-byte as
authored: nothing is stripped, defaulted, or rewritten.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .contract_registry import NEXT_TEST_FIELDS, NEXT_TEST_ROUTE_HINTS

_FIELDS = tuple(name for name, _domain, _meaning in NEXT_TEST_FIELDS)
# Hand-kept mirrors of ``FindingNextTestRequest``'s defaults and length bound;
# test_finding_next_test_contract_mirror.py fails when they drift.
OPTIONAL_NEXT_TEST_FIELDS = frozenset({"prerequisites"})
NEXT_TEST_TEXT_MAX_LENGTH = 4096


def next_test_problems(plan: Any) -> list[str]:
    """Every way ``plan`` misses the next_test contract; empty when it fits."""
    if not isinstance(plan, dict):
        return ["next_test must be a JSON object"]
    problems = [f"next_test.{key} is not a next_test field" for key in plan if key not in _FIELDS]
    for name in _FIELDS:
        if name not in plan:
            if name not in OPTIONAL_NEXT_TEST_FIELDS:
                problems.append(f"next_test.{name} is required")
            continue
        value = plan[name]
        if not isinstance(value, str):
            problems.append(f"next_test.{name} must be a string")
        elif len(value) > NEXT_TEST_TEXT_MAX_LENGTH:
            problems.append(
                f"next_test.{name} exceeds {NEXT_TEST_TEXT_MAX_LENGTH} characters"
            )
        elif name not in OPTIONAL_NEXT_TEST_FIELDS and not value.strip():
            problems.append(f"next_test.{name} must not be blank")
    route = plan.get("route_hint")
    if isinstance(route, str) and route.strip() and route not in NEXT_TEST_ROUTE_HINTS:
        problems.append(
            f"next_test.route_hint must be one of: {', '.join(NEXT_TEST_ROUTE_HINTS)}"
        )
    return problems


def load_next_test_file(path: str) -> dict[str, Any]:
    """Return the plan object, or raise ValueError naming every problem."""
    try:
        plan = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"next_test file not found: {path}") from exc
    except (OSError, ValueError) as exc:
        raise ValueError(f"next_test file is not readable JSON: {exc}") from exc
    problems = next_test_problems(plan)
    if problems:
        raise ValueError("; ".join(problems))
    return plan
