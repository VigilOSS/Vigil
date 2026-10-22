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


def test_explicit_unknown_skill_is_rejected(monkeypatch, tmp_path):
    skill_root = tmp_path / "skills"
    (skill_root / "known").mkdir(parents=True)
    (skill_root / "known/SKILL.md").write_text("# Known")
    monkeypatch.setattr(contracts, "_agent_skills_root", lambda: skill_root)
    errors, _ = contracts.validate_specialist_dispatch_contract(
        {"role": "code-vuln-hunter", "skills": ["known", "typo"]}
    )
    assert any("typo" in error and "list-skills" in error for error in errors)


def test_explicit_skill_requires_available_catalogue(monkeypatch, tmp_path):
    monkeypatch.setattr(contracts, "_agent_skills_root", lambda: tmp_path / "missing")
    errors, _ = contracts.validate_specialist_dispatch_contract(
        {"role": "code-vuln-hunter", "skills": "known"}
    )
    assert any("skill catalogue" in error for error in errors)


def test_agent_start_rejects_typo_before_contacting_backend(monkeypatch, tmp_path, capsys):
    import pytest
    from assess.commands.dispatch import agent as dispatch_agent

    root = tmp_path / "skills"
    root.mkdir()
    monkeypatch.setattr(contracts, "_agent_skills_root", lambda: root)
    calls = []
    monkeypatch.setattr(dispatch_agent, "_client_for", lambda _: calls.append("backend"))
    args = SimpleNamespace(agent_role="recon-specialist", agent_id="acme-recon",
        task="Inspect the authorized surface", skills="typo", no_target_traffic=True)
    with pytest.raises(SystemExit, match="1"):
        dispatch_agent._register_dispatch(args)
    assert calls == []
    assert "unknown skill 'typo'" in capsys.readouterr().err


def test_omitted_skills_work_without_catalogue(monkeypatch, tmp_path):
    monkeypatch.setattr(contracts, "_agent_skills_root", lambda: tmp_path / "missing")
    errors, warnings = contracts.validate_specialist_dispatch_contract({"role": "code-vuln-hunter"})
    assert errors == []
    assert any("skills not set" in warning for warning in warnings)
