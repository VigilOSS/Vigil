"""The CLI's gated decision-kind list matches the backend's, kind for kind.

`agent decision --kind` help and its contract name these kinds as the ones a
backend gate reads; a kind the backend gates but the CLI omits would go
unadvertised, and one the CLI lists but the backend does not gate would be
advertised as validated when it is not.
"""
from __future__ import annotations


def test_cli_gated_decision_kinds_mirror_the_backend() -> None:
    from assess.lib.contract_registry import GATED_DECISION_KINDS as CLI_KINDS
    from app.api.assessment_operator import GATED_DECISION_KINDS

    assert sorted(CLI_KINDS) == sorted(GATED_DECISION_KINDS)
    assert len(set(CLI_KINDS)) == len(CLI_KINDS)
