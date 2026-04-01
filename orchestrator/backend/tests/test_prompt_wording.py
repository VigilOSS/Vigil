from pathlib import Path
import subprocess

def test_operator_prompt_outputs_define_default_model_policy():
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8").lower()
    agents_prompt = (repo_root / "agent" / "AGENTS.md").read_text(encoding="utf-8").lower()
    claude_prompt = (repo_root / "agent" / "CLAUDE.md").read_text(encoding="utf-8").lower()

    for text in (operator_core, agents_prompt, claude_prompt):
        assert "gpt-5.4" in text
        assert "high" in text
        assert "opus 4.6" in text
        assert "sonnet 4.6" in text


def test_rendered_operator_prompts_match_operator_core():
    repo_root = Path(__file__).resolve().parents[3]
    script = repo_root / "agent" / "scripts" / "render-operator-prompts.sh"
    agent_names = [
        "operator",
        "recon-specialist",
        "source-analyzer",
        "vulnerability-analyst",
        "exploit-developer",
        "fuzzer",
        "osint-analyst",
        "report-writer",
    ]

    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        subprocess.run(
            ["bash", str(script), "repo", str(tmp_path)],
            check=True,
            cwd=repo_root / "agent",
        )

        expected_outputs = {
            repo_root / "agent" / "AGENTS.md": tmp_path / "AGENTS.md",
            repo_root / "agent" / "CLAUDE.md": tmp_path / "CLAUDE.md",
        }
        for agent_name in agent_names:
            expected_outputs[repo_root / "agent" / ".codex" / "agents" / f"{agent_name}.toml"] = (
                tmp_path / ".codex" / "agents" / f"{agent_name}.toml"
            )
            expected_outputs[repo_root / "agent" / ".claude" / "agents" / f"{agent_name}.md"] = (
                tmp_path / ".claude" / "agents" / f"{agent_name}.md"
            )

        for committed_path, rendered_path in expected_outputs.items():
            assert committed_path.read_text(encoding="utf-8") == rendered_path.read_text(encoding="utf-8")


def test_docs_and_skills_drop_run_tool_and_rtcurl_examples():
    repo_root = Path(__file__).resolve().parents[3]
    paths = [
        repo_root / "README.md",
        repo_root / "agent" / "SKILL.md",
        *sorted((repo_root / "agent" / "rules").rglob("*.md")),
        *sorted((repo_root / "agent" / "agents").rglob("*.md")),
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
    assert "canonical destination" in osint_recon.lower()
    assert "optional final phase" in athena_skill.lower()
    assert "ctf scope" not in api04.lower()
    assert "authorized realistic lab" in install_script.lower()


def test_specialist_agent_sources_exist_for_public_roster():
    repo_root = Path(__file__).resolve().parents[3]
    agent_dir = repo_root / "agent" / "agents"

    expected = {
        "recon-specialist.md",
        "source-analyzer.md",
        "vulnerability-analyst.md",
        "exploit-developer.md",
        "fuzzer.md",
        "osint-analyst.md",
        "report-writer.md",
    }

    assert expected <= {path.name for path in agent_dir.glob("*.md")}
