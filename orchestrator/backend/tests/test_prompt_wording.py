from pathlib import Path


def test_operator_prompt_outputs_drop_old_ctf_and_cases_db_authority_language():
    repo_root = Path(__file__).resolve().parents[3]
    files = [
        repo_root / "agent" / "operator-core.md",
        repo_root / "agent" / "AGENTS.md",
        repo_root / "agent" / "CLAUDE.md",
        repo_root / "agent" / "scripts" / "render-operator-prompts.sh",
    ]

    for path in files:
        text = path.read_text(encoding="utf-8")
        assert "LOCAL LAB/CTF" not in text
        assert "CTF/lab" not in text
        assert "cases.db IS the state" not in text


def test_operator_prompt_outputs_require_realistic_lab_wording_and_skill_first_behavior():
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    agents_prompt = (repo_root / "agent" / "AGENTS.md").read_text(encoding="utf-8")

    assert "realistic lab" in operator_core.lower()
    assert "if a relevant skill exists" in operator_core.lower()
    assert "orchestrator backend is canonical" in operator_core.lower()
    assert "record_finding.sh" in operator_core
    assert "append_finding.sh" in operator_core
    assert "rejects markdown" in operator_core.lower()
    assert "schemas/finding-record.schema.json" in operator_core
    assert "exploit_policy=pause" in operator_core.lower()
    assert "approve_exploitation.sh" in operator_core
    assert "launch_exploit_session.sh" in operator_core
    assert "record_session_proposal.sh" in operator_core
    assert "merge_exploit_session.sh" in operator_core
    assert "realistic lab" in agents_prompt.lower()


def test_docs_and_skills_drop_run_tool_and_rtcurl_examples():
    repo_root = Path(__file__).resolve().parents[3]
    paths = [
        repo_root / "README.md",
        *sorted((repo_root / "agent" / "skills").rglob("*.md")),
        *sorted((repo_root / "agent" / "references").rglob("*.md")),
    ]

    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "run_tool " not in text, f"run_tool reference remained in {path}"
        assert "rtcurl" not in text, f"rtcurl reference remained in {path}"


def test_operator_prompt_outputs_require_kali_mcp_for_target_facing_work():
    repo_root = Path(__file__).resolve().parents[3]
    files = [
        repo_root / "agent" / "operator-core.md",
        repo_root / "agent" / "AGENTS.md",
        repo_root / "agent" / "CLAUDE.md",
        repo_root / "README.md",
    ]

    for path in files:
        text = path.read_text(encoding="utf-8").lower()
        assert "kali mcp" in text

    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8").lower()
    assert "command-execution" in operator_core
    assert "target-facing" in operator_core


def test_phase_two_methodology_guidance_is_present_in_skills_and_references():
    repo_root = Path(__file__).resolve().parents[3]

    engagement_methodology = (
        repo_root / "agent" / "references" / "runtime-guides" / "engagement-methodology.md"
    ).read_text(encoding="utf-8")
    web_recon = (repo_root / "agent" / "skills" / "web-recon" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    osint_recon = (repo_root / "agent" / "skills" / "osint-recon" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    athena_skill = (
        repo_root / "agent" / "skills" / "athena-log-investigation" / "SKILL.md"
    ).read_text(encoding="utf-8")
    api04 = (
        repo_root / "agent" / "references" / "api-security" / "API04-resource-consumption.md"
    ).read_text(encoding="utf-8")
    install_script = (repo_root / "install.sh").read_text(encoding="utf-8")

    assert "read between the lines" in engagement_methodology.lower()
    assert "prove it in stages" in engagement_methodology.lower()
    assert "hypothesis" in web_recon.lower()
    assert "durable backend" in osint_recon.lower()
    assert "optional final phase" in athena_skill.lower()
    assert "ctf scope" not in api04.lower()
    assert "authorized realistic lab" in install_script.lower()
