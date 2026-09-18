"""A5 (CLI half): the unqueued-files blocker must name its repair verb.

`code-coverage --require-transition-ready hunt` is where an operator meets the
new gate. Without a repair line the blocker reads as "no repair path exists"
and the operator reaches for a re-ingest, which advances the generation and
invalidates every generation-bound review.
"""
from __future__ import annotations

from assess.commands import code_coverage


def test_unqueued_blocker_names_the_queue_load_command(capsys):
    code_coverage._print_transition_readiness(
        "hunt",
        {
            "target_phase": "hunt",
            "transition_ready": False,
            "blockers": [
                {
                    "code": "admitted_files_unqueued",
                    "message": "Repository has 584 admitted file(s) with no current-generation analysis queue row.",
                    "overrideable": True,
                    "repo_id": 3,
                }
            ],
        },
    )

    out = capsys.readouterr().out
    assert "[admitted_files_unqueued] (repo 3)" in out
    assert "repair: vigil assess code-dispatch queue" in out
