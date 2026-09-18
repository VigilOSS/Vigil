"""One dispatch, one model/reasoning provenance warning.

`agent start` used to print three warnings about the same uncertainty: one for a
missing requested_model, one for a missing requested_reasoning, and one — on every
dispatch, without exception — saying launcher-effective values are unavailable.
stderr is the channel real failures arrive on, and a constant that fires on every
successful run teaches operators to skim past all of it. The actionable part
(values the caller can still supply) aggregates into a single warning; the
permanent part (this CLI never observes launcher-effective identity) belongs in
the contract, which is read once.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from assess.commands import agent
from assess.lib import contracts


def _recipe_warnings(warnings: list[str]) -> list[str]:
    return [
        warning
        for warning in warnings
        if "model" in warning.lower() or "reasoning" in warning.lower()
    ]


def test_missing_model_and_reasoning_produce_one_aggregated_warning() -> None:
    _errors, warnings = contracts.validate_specialist_dispatch_contract(
        {
            "agent_role": "code-vuln-hunter",
            "dispatch_mode": "item-iterating",
            "skills": "code-vulnerability-analysis",
        }
    )

    recipe = _recipe_warnings(warnings)
    assert len(recipe) == 1, recipe
    assert "requested_model" in recipe[0]
    assert "requested_reasoning" in recipe[0]


def test_a_supplied_recipe_warns_about_nothing() -> None:
    _errors, warnings = contracts.validate_specialist_dispatch_contract(
        {
            "agent_role": "code-vuln-hunter",
            "dispatch_mode": "item-iterating",
            "skills": "code-vulnerability-analysis",
            "requested_model": "claude-opus-4-8",
            "requested_reasoning": "high",
        }
    )

    assert _recipe_warnings(warnings) == []


def test_only_the_unset_recipe_field_is_named() -> None:
    _errors, warnings = contracts.validate_specialist_dispatch_contract(
        {
            "agent_role": "code-vuln-hunter",
            "dispatch_mode": "item-iterating",
            "skills": "code-vulnerability-analysis",
            "model": "claude-opus-4-8",
        }
    )

    (recipe,) = _recipe_warnings(warnings)
    assert "requested_reasoning" in recipe
    assert "requested_model" not in recipe


def test_provenance_attach_adds_no_constant_launcher_warning(tmp_path: Path) -> None:
    # Stripping caller-attested identity is the enforcement; repeating "the
    # launcher told us nothing" on every single dispatch is not.
    engagement_dir = tmp_path / "engagements" / "e1"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")
    payload = {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "requested_model": "claude-opus-4-8",
        "requested_reasoning": "high",
        "actual_model": "caller-forged-model",
        "launcher_effective_model": "caller-forged-model",
    }

    warnings = agent._attach_dispatch_provenance(
        payload,
        SimpleNamespace(
            agent_root=str(tmp_path / "agent"),
            engagement_dir=str(engagement_dir),
        ),
    )

    assert "actual_model" not in payload
    assert "launcher_effective_model" not in payload
    assert not any("launcher-effective" in warning for warning in warnings), warnings


def test_the_contract_carries_the_permanent_provenance_limit() -> None:
    rendered = contracts.render_contract("agent start")

    assert "launcher-effective" in rendered
    assert "requested_model" in rendered
