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
        "surface-collector",
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
        "surface-collector.md",
        "vulnerability-analyst.md",
        "exploit-developer.md",
        "fuzzer.md",
        "osint-analyst.md",
        "report-writer.md",
    }

    assert expected <= {path.name for path in agent_dir.glob("*.md")}


def test_code_analysis_prompt_uses_current_cli_contracts():
    repo_root = Path(__file__).resolve().parents[3]
    operator_prompt = (repo_root / "agent" / "operator-core-code.md").read_text(encoding="utf-8")
    architect_prompt = (repo_root / "agent" / "agents" / "code-architect.md").read_text(encoding="utf-8")
    for text in (operator_prompt, architect_prompt):
        assert "fetch code-files" not in text
        assert "code-dispatch <db> queue" not in text

    assert 'fetch "code/files' in operator_prompt
    assert "code-record-threat-model <repo-id> <threat-model-json>" in operator_prompt
    assert "code-record-modules <repo-id> <modules-json>" in operator_prompt
    assert "code-dispatch done <item-id> <clean|finding|suspicious> <cwe-coverage-json>" in operator_prompt
    assert "Pass repo-relative file paths and artifact paths instead of pasting large JSON blobs" in operator_prompt
    assert "code-dispatch needs-context" in operator_prompt
    assert "no pending triggers" in operator_prompt
    assert "--require-gate-pass" in operator_prompt
    assert "applicable_vuln_classes" in operator_prompt
    assert "Every `critical` and `high` file has at least one slot-type annotation" in architect_prompt


def test_code_analysis_agents_use_current_phase_numbers():
    repo_root = Path(__file__).resolve().parents[3]
    architect_prompt = (repo_root / "agent" / "agents" / "code-architect.md").read_text(encoding="utf-8")
    hunter_prompt = (repo_root / "agent" / "agents" / "code-vuln-hunter.md").read_text(encoding="utf-8")
    verifier_prompt = (repo_root / "agent" / "agents" / "code-vuln-verifier.md").read_text(encoding="utf-8")

    assert "enables multi-function reasoning in Phase 2" in architect_prompt
    assert "moving\nto Phase 4" not in hunter_prompt
    assert "to Phase 3." in hunter_prompt
    assert "Phase 3 hunters" not in verifier_prompt
    assert "Phase 2 hunters" in verifier_prompt


def test_code_analysis_skills_use_current_phase_numbers_and_tools():
    repo_root = Path(__file__).resolve().parents[3]
    verification_skill = (
        repo_root / "agent" / "skills" / "code-finding-verification" / "SKILL.md"
    ).read_text(encoding="utf-8")
    variant_skill = (
        repo_root / "agent" / "skills" / "code-variant-analysis" / "SKILL.md"
    ).read_text(encoding="utf-8")

    assert "Phase 4 of code analysis pipeline" not in verification_skill
    assert "Runs on confirmed findings from Phase 2" in verification_skill
    assert "Phase 4 of code analysis pipeline" not in variant_skill
    assert "`cat`" not in variant_skill
    assert "`find`" not in variant_skill
    assert "`Read`" in variant_skill
    assert "`Glob`" in variant_skill


def test_code_variant_hunter_example_matches_record_finding_contract():
    repo_root = Path(__file__).resolve().parents[3]
    hunter_prompt = (repo_root / "agent" / "agents" / "code-variant-hunter.md").read_text(
        encoding="utf-8"
    )

    assert "Include `details.impact` in every finding payload" in hunter_prompt
    assert '"impact": "Remote attackers can trigger heap corruption in the FTP path parser with an overlong path"' in hunter_prompt


def test_kali_mcp_audit_and_reuse_wording_is_present():
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    operator_agents = (repo_root / "agent" / "AGENTS.md").read_text(encoding="utf-8")
    operator_claude = (repo_root / "agent" / "CLAUDE.md").read_text(encoding="utf-8")
    shared_web = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")
    shared_code = (repo_root / "agent" / "shared-constraints-code.md").read_text(encoding="utf-8")

    # Operator source + rendered wrappers describe the audit channel and the
    # reuse-search CLI so an operator reading any of the three sees both.
    for text in (operator_core, operator_agents, operator_claude):
        assert "engagement_key" in text
        assert "agent_name" in text
        assert "phase" in text
        assert "list-command-runs" in text
        assert "Kali MCP Audit and Reuse" in text
        assert "command history checked" in text.lower()

    # Shared-constraints: both modes mention the reuse rule so specialists see
    # it on first load.
    for text in (shared_web, shared_code):
        assert "list-command-runs" in text
        assert "command-history-auditing.md" in text


def test_kali_specialist_prompts_document_history_check():
    repo_root = Path(__file__).resolve().parents[3]
    expectations = {
        "recon-specialist.md": "recon-specialist",
        "surface-collector.md": "surface-collector",
        "vulnerability-analyst.md": "vulnerability-analyst",
        "exploit-developer.md": "exploit-developer",
        "fuzzer.md": "fuzzer",
        "osint-analyst.md": "osint-analyst",
        "code-fuzz-engineer.md": "code-fuzz-engineer",
    }
    for filename, role in expectations.items():
        path = repo_root / "agent" / "agents" / filename
        text = path.read_text(encoding="utf-8")
        assert "list-command-runs" in text, f"{filename} missing list-command-runs reference"
        assert f"--agent-name {role}" in text, f"{filename} missing --agent-name {role}"
        assert "command-history-auditing.md" in text, f"{filename} missing reuse reference"


def test_command_history_reference_guide_exists():
    repo_root = Path(__file__).resolve().parents[3]
    path = repo_root / "agent" / "references" / "runtime-guides" / "command-history-auditing.md"
    text = path.read_text(encoding="utf-8")
    assert "Reuse Decision Table" in text
    assert "output_retention_status" in text
    assert "list-command-runs" in text
    index = (repo_root / "agent" / "references" / "INDEX.md").read_text(encoding="utf-8")
    assert "runtime-guides/command-history-auditing.md" in index


def test_code_analysis_codex_wrappers_exist():
    repo_root = Path(__file__).resolve().parents[3]
    codex_dir = repo_root / "agent" / ".codex" / "agents"

    expected = {
        "code-architect.toml",
        "code-variant-hunter.toml",
        "code-vuln-hunter.toml",
        "code-vuln-verifier.toml",
    }

    assert expected <= {path.name for path in codex_dir.glob("*.toml")}


def test_exploit_developer_prompt_uses_backend_exploit_candidates_for_context():
    repo_root = Path(__file__).resolve().parents[3]
    exploit_prompt = (repo_root / "agent" / "agents" / "exploit-developer.md").read_text(encoding="utf-8")

    assert '.status | IN("confirmed","exploited","draft")' not in exploit_prompt
    assert '.workflow_status | IN("active","exploited","draft")' not in exploit_prompt
    assert "./scripts/assess.py fetch exploit-candidates" in exploit_prompt
    assert "candidate_reason" in exploit_prompt
    assert "verified findings at nearby endpoints" in exploit_prompt


def test_code_agent_prompts_use_current_finding_lifecycle_contracts():
    repo_root = Path(__file__).resolve().parents[3]
    hunter_prompt = (repo_root / "agent" / "agents" / "code-vuln-hunter.md").read_text(encoding="utf-8")
    verifier_prompt = (repo_root / "agent" / "agents" / "code-vuln-verifier.md").read_text(encoding="utf-8")
    operator_prompt = (repo_root / "agent" / "operator-core-code.md").read_text(encoding="utf-8")
    verification_skill = (
        repo_root / "agent" / "skills" / "code-finding-verification" / "SKILL.md"
    ).read_text(encoding="utf-8")

    assert '"status": "confirmed|draft"' not in hunter_prompt
    assert "status: false_positive" not in verifier_prompt
    assert "record-finding code-vuln-verifier <updated-finding-json>" not in verifier_prompt
    assert "record-finding code-vuln-verifier <updated-finding-json>" not in operator_prompt
    assert "verify-finding <slug> <verification-json>" in verifier_prompt
    assert "kill-finding <slug>" in verifier_prompt
    assert "verify-finding <slug> <verification-json>" in operator_prompt
    assert "kill-finding <slug>" in operator_prompt
    assert "reset-finding <slug>" in verifier_prompt
    assert "reset-finding <slug>" in operator_prompt
    assert "reset-finding <slug>" in verification_skill


def test_operator_prompt_outputs_reference_helper_contracts_for_findings():
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    agents_prompt = (repo_root / "agent" / "AGENTS.md").read_text(encoding="utf-8")
    claude_prompt = (repo_root / "agent" / "CLAUDE.md").read_text(encoding="utf-8")

    for text in (operator_core, agents_prompt, claude_prompt):
        assert "assess.py contract record-finding" in text
        assert "reset-finding" in text


def test_prompt_stack_uses_current_report_and_dedup_contracts():
    repo_root = Path(__file__).resolve().parents[3]
    shared_constraints = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")
    shared_constraints_code = (repo_root / "agent" / "shared-constraints-code.md").read_text(
        encoding="utf-8"
    )
    vuln_analyst = (repo_root / "agent" / "agents" / "vulnerability-analyst.md").read_text(
        encoding="utf-8"
    )
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    operator_core_code = (repo_root / "agent" / "operator-core-code.md").read_text(
        encoding="utf-8"
    )
    handoff = (repo_root / "agent" / "references" / "handoff-protocols.md").read_text(
        encoding="utf-8"
    )
    report_skill = (repo_root / "agent" / "skills" / "report-generation" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    report_writer = (repo_root / "agent" / "agents" / "report-writer.md").read_text(
        encoding="utf-8"
    )

    assert "fetch report-findings" not in shared_constraints
    assert "fetch findings" in shared_constraints
    assert "fetch report-findings" not in shared_constraints_code
    assert "fetch findings" in shared_constraints_code
    assert "fetch report-findings" not in vuln_analyst
    assert "fetch findings" in vuln_analyst
    assert "drive HIGH findings to exploitation before investing in medium/low" not in operator_core
    assert "check-report-readiness" in operator_core
    assert "report-findings?mode=final" in operator_core
    assert "report-findings?mode=draft" in operator_core
    assert "review-and-fix mode" in operator_core
    assert "Publication before QA passes creates false workflow state" in operator_core
    assert "check-report-readiness" in operator_core_code
    assert "report-findings?mode=final" in operator_core_code
    assert "review-and-fix QA" in operator_core_code
    assert "QA PASS" in operator_core_code
    assert "belongs after Verify in Phase 5" in handoff
    assert "review-and-fix QA mode" in handoff
    assert "check-report-readiness" in report_skill
    assert 'fetch "report-findings?mode=final"' in report_skill
    assert 'fetch "report-findings?mode=draft"' in report_skill
    assert "Do not emit `report.generated` or mark findings `reported` during draft generation" in report_skill
    assert "Review-and-Fix QA Mode" in report_skill
    assert "Publish After QA Pass" in report_skill
    assert 'fetch "report-findings?mode=final"' in report_writer
    assert "Review-and-fix QA mode" in report_writer
    assert "Publish mode" in report_writer
