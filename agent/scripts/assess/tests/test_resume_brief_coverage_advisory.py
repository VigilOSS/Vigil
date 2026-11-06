"""The resume brief states a coverage gap that passes the gate.

The coverage quality gate has two channels. `reasons` is what refuses it, and
only critical and high files reach it. `advisories` is the harness channel --
review effort still owed on a medium file lands there and nowhere else, so the
gate reads PASS while work remains ([ADR 0001](../../../../docs/adr/0001-coverage-as-harness-not-gate.md):
the depth machinery steers rather than stops).

Rendering `reasons` alone made a medium-only gap invisible in the one document
an operator reads on resume, which turns "advisory" into "silent". These pin
that the brief carries both channels and keeps them distinguishable, because a
reader who cannot tell them apart either over-trusts a PASS or treats an
advisory as a blocker.
"""
from __future__ import annotations

from assess.commands import resume_brief


def _gate_line(coverage_gate: dict) -> str:
    rendered = resume_brief._render_markdown(
        {"code_analysis": {"queue_count": 0, "coverage_gate": coverage_gate}}
    )
    lines = [ln for ln in rendered.splitlines() if "coverage quality gate" in ln]
    assert len(lines) == 1, rendered
    return lines[0]


def test_a_medium_only_gap_is_stated_even_though_the_gate_passes() -> None:
    line = _gate_line(
        {
            "passed": True,
            "reasons": [],
            "advisories": [
                "Medium file src/parser.py: family 'algorithmic-dos' effort 10 < 30"
            ],
        }
    )

    assert "PASS" in line
    # The gap itself, not merely a count: the operator has to know which file.
    assert "src/parser.py" in line
    assert "advisory" in line


def test_a_blocking_reason_stays_distinguishable_from_an_advisory() -> None:
    line = _gate_line(
        {
            "passed": False,
            "reasons": [
                "Critical file src/auth.py: family 'authorization' effort 10 < 70"
            ],
            "advisories": [
                "Medium file src/parser.py: family 'algorithmic-dos' effort 10 < 30"
            ],
        }
    )

    assert "NEEDS ATTENTION" in line
    # Both present, and the advisory marked as such so neither reads as the other.
    assert "src/auth.py" in line
    assert "src/parser.py" in line
    assert line.index("src/auth.py") < line.index("advisory")


def test_a_gate_with_nothing_owed_renders_no_advisory_marker() -> None:
    line = _gate_line({"passed": True, "reasons": [], "advisories": []})

    assert "PASS" in line
    assert "advisory" not in line
