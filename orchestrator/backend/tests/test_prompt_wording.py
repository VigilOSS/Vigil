from pathlib import Path
import re
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


def test_operator_prompt_outputs_require_aith_assess_kali_for_target_facing_work():
    # The 2026-04-26 runtime cutover replaced "Kali MCP" with `aith assess kali` across the
    # prompt corpus. This test pins the new vocabulary in the operator source plus the two
    # rendered wrappers, plus the three-layer discovery sentence (skill / --help / contract),
    # and asserts a regression-style absence of the old "Kali MCP" / `mcp__kali__` strings so
    # future renders that drift back to the old wording fail CI.
    repo_root = Path(__file__).resolve().parents[3]
    operator_files = [
        repo_root / "agent" / "operator-core.md",
        repo_root / "agent" / "AGENTS.md",
        repo_root / "agent" / "CLAUDE.md",
    ]

    for path in operator_files:
        text = path.read_text(encoding="utf-8")
        text_lower = text.lower()
        # Positive pins — new vocabulary must be present.
        assert "aith assess kali" in text_lower, f"{path}: missing 'aith assess kali' vocabulary"
        assert "target-facing" in text_lower, f"{path}: missing 'target-facing' framing"
        # Three-layer discovery: skill, --help, contract.
        assert "agent/skills/kali-exec/skill.md" in text_lower, (
            f"{path}: missing kali-exec skill discovery pointer"
        )
        assert "aith assess kali --help" in text_lower, (
            f"{path}: missing live --help discovery pointer"
        )
        assert "aith assess contract kali" in text_lower, (
            f"{path}: missing contract introspection pointer"
        )
        # Regression — the old wording must not reappear after re-rendering.
        assert "kali mcp" not in text_lower, (
            f"{path}: 'Kali MCP' wording drifted back into the prompt corpus"
        )
        assert "mcp__kali__" not in text, (
            f"{path}: 'mcp__kali__*' tool name drifted back into the prompt corpus"
        )

    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")

    # Pin the renamed sections so future drift flips the test.
    assert "## Kali Execution" in operator_core
    assert "### Kali CLI Troubleshooting" in operator_core
    assert "### Kali Command Audit — Shape Dispatches From Coverage" in operator_core


def test_shared_constraints_pins_kali_cli_required_phase_and_half_phases():
    # shared-constraints.md §2 is the always-loaded specialist contract layer. The
    # `--phase` REQUIRED rule and the half-phase tag rationale are load-bearing —
    # losing them lets agents silently fall back to a stale env-var phase or skip
    # the audit-row classification, so pin them here.
    repo_root = Path(__file__).resolve().parents[3]
    shared = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")
    shared_lower = shared.lower()

    # New rule heading and core wording.
    assert "## 2. `aith assess kali` for All Target Work" in shared
    assert "aith assess kali" in shared_lower

    # `--phase` is REQUIRED on every dispatch.
    assert "**`--phase <enum>`**" in shared
    assert "REQUIRED on every call" in shared

    # Half-phase tag rationale and explicit allowed values.
    assert "recon-pivot" in shared
    assert "exploit-recon" in shared
    assert "operate **between phases**" in shared
    assert "newly-surfaced host" in shared
    assert "additional fingerprinting during exploit phase" in shared

    # Audit-flag set replaced X-* headers — pin the CLI-flag value tables exist.
    for flag in ("--technique", "--intent", "--probe-kind", "--destructive", "--timeout"):
        assert flag in shared, f"shared-constraints missing audit flag {flag}"

    # Regression — the X-* header vocabulary must not reappear in this file.
    for header in ("X-Technique", "X-Intent", "X-Probe-Kind", "X-Destructive"):
        assert header not in shared, (
            f"shared-constraints.md still references old MCP header {header}"
        )
    assert "kali mcp" not in shared_lower, (
        "shared-constraints.md still references 'Kali MCP'"
    )


def test_skill_index_lists_kali_exec_foundational_skill():
    repo_root = Path(__file__).resolve().parents[3]
    skill_index = (repo_root / "agent" / "SKILL.md").read_text(encoding="utf-8")
    assert "agent/skills/kali-exec/SKILL.md" in skill_index, (
        "agent/SKILL.md must list kali-exec as a foundational skill"
    )
    # The index entry must say the skill is always-loaded paired with shared-constraints.
    assert "Always — every target-facing call uses `aith assess kali ...`" in skill_index
    assert "Foundational, paired with `shared-constraints.md`" in skill_index


def test_kali_exec_skill_and_kali_cli_runtime_guide_exist():
    repo_root = Path(__file__).resolve().parents[3]
    kali_exec = (repo_root / "agent" / "skills" / "kali-exec" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    # Verb count + audit-flag mapping + half-phase tags are the load-bearing sections.
    assert "## Verb menu" in kali_exec
    assert "kali nmap-scan" in kali_exec
    assert "kali job <start" in kali_exec
    assert "## Audit-flag mapping" in kali_exec
    assert "## Phase tags (including half-phase tags)" in kali_exec
    assert "recon-pivot" in kali_exec
    assert "exploit-recon" in kali_exec

    kali_cli = (repo_root / "agent" / "references" / "runtime-guides" / "kali-cli.md").read_text(
        encoding="utf-8"
    )
    assert "Kali CLI Troubleshooting" in kali_cli
    assert "aith assess kali --help" in kali_cli
    # Old MCP troubleshooting file must not still exist.
    old_mcp_file = repo_root / "agent" / "references" / "runtime-guides" / "kali-mcp-troubleshooting.md"
    assert not old_mcp_file.exists(), (
        "kali-mcp-troubleshooting.md should have been renamed to kali-cli.md"
    )

    # INDEX.md should list the new file and the new nikto.md row, and not the old MCP file.
    index = (repo_root / "agent" / "references" / "INDEX.md").read_text(encoding="utf-8")
    assert "runtime-guides/kali-cli.md" in index
    assert "runtime-guides/kali-mcp-troubleshooting.md" not in index
    assert "tools/recon/nikto.md" in index


def test_no_kali_mcp_drift_in_prompt_corpus():
    # Load-bearing regression: after the cutover, `Kali MCP` and `mcp__kali__*` must not
    # appear anywhere in the prompt corpus we author (skills, agents, operator prompts,
    # shared constraints, references, generated wrappers). Phase-2-owned helper scripts
    # under `agent/scripts/assess/commands/` and per-engagement bootstrap files under
    # `agent/engagements/` are excluded — they are not part of the prompt corpus.
    repo_root = Path(__file__).resolve().parents[3]
    paths: list[Path] = []
    for sub in (
        "skills",
        "agents",
        "rules",
        "references",
    ):
        paths.extend(sorted((repo_root / "agent" / sub).rglob("*.md")))
    for name in ("operator-core.md", "operator-core-code.md",
                 "shared-constraints.md", "shared-constraints-code.md",
                 "AGENTS.md", "CLAUDE.md", "SKILL.md"):
        paths.append(repo_root / "agent" / name)
    paths.extend(sorted((repo_root / "agent" / ".claude" / "agents").rglob("*.md")))
    paths.extend(sorted((repo_root / "agent" / ".codex" / "agents").rglob("*.toml")))

    offenders: list[str] = []
    for path in paths:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for needle in ("Kali MCP", "mcp__kali__"):
            if needle in text:
                offenders.append(f"{path}: contains {needle!r}")
    assert not offenders, (
        "Prompt corpus still references the retired Kali MCP vocabulary:\n"
        + "\n".join(offenders)
    )


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
    cli_main = (repo_root / "src" / "ai_threat_hunting_cli" / "main.py").read_text(encoding="utf-8")

    assert "read between the lines" in engagement_methodology.lower()
    assert "prove it in stages" in engagement_methodology.lower()
    assert "hypothesis" in web_recon.lower()
    assert "canonical destination" in osint_recon.lower()
    assert "optional final phase" in athena_skill.lower()
    assert "ctf scope" not in api04.lower()
    assert "aith" in cli_main.lower()


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


def test_kali_command_audit_and_reuse_wording_is_present():
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    operator_agents = (repo_root / "agent" / "AGENTS.md").read_text(encoding="utf-8")
    operator_claude = (repo_root / "agent" / "CLAUDE.md").read_text(encoding="utf-8")
    shared_web = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")
    shared_code = (repo_root / "agent" / "shared-constraints-code.md").read_text(encoding="utf-8")

    # Operator source + rendered wrappers describe the audit channel and the
    # coverage-search CLI so an operator reading any of the three sees both,
    # under the current coverage-map framing (not the old reuse-gate framing).
    # The 2026-04-26 cutover renamed the section heading from "Kali MCP Audit"
    # to "Kali Command Audit".
    for text in (operator_core, operator_agents, operator_claude):
        assert "engagement_key" in text
        assert "agent_name" in text
        assert "phase" in text
        assert "list-command-runs" in text
        assert "### Kali Command Audit — Shape Dispatches From Coverage" in text
        assert "variant that hasn't been tried" in text

    # Shared-constraints: both modes mention the reuse rule so specialists see
    # it on first load.
    for text in (shared_web, shared_code):
        assert "list-command-runs" in text
        assert "command-history-auditing.md" in text


def test_kali_specialist_prompts_document_history_check():
    repo_root = Path(__file__).resolve().parents[3]
    filenames = [
        "recon-specialist.md",
        "surface-collector.md",
        "vulnerability-analyst.md",
        "exploit-developer.md",
        "fuzzer.md",
        "osint-analyst.md",
        "code-fuzz-engineer.md",
    ]
    for filename in filenames:
        path = repo_root / "agent" / "agents" / filename
        text = path.read_text(encoding="utf-8")
        assert "list-command-runs" in text, f"{filename} missing list-command-runs reference"
        assert "--q <" in text, f"{filename} missing broad command-history search example"
        assert "unscoped" in text.lower(), f"{filename} missing unscoped search default"
        assert "narrow with `--agent-name`/`--phase` only if swamped" in text, (
            f"{filename} missing coverage-map scoping guidance"
        )
        assert "coverage map" in text.lower(), f"{filename} missing coverage-map framing"
        assert "command-history-auditing.md" in text, f"{filename} missing history-guide reference"


def test_command_history_reference_guide_exists():
    repo_root = Path(__file__).resolve().parents[3]
    path = repo_root / "agent" / "references" / "runtime-guides" / "command-history-auditing.md"
    text = path.read_text(encoding="utf-8")
    assert "Coverage-vs-duplicate decision table" in text
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
    assert "aith assess fetch exploit-candidates" in exploit_prompt
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
        assert "aith assess contract record-finding" in text
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


def _prompt_corpus_paths(repo_root: Path) -> list[Path]:
    """Collect the prompt corpus paths used for static cross-file drift checks."""
    agent_dir = repo_root / "agent"
    paths: list[Path] = []
    paths.extend(sorted((agent_dir / "skills").rglob("*.md")))
    paths.extend(sorted((agent_dir / "references").rglob("*.md")))
    paths.extend(sorted((agent_dir / "agents").rglob("*.md")))
    paths.extend(sorted((agent_dir / "rules").rglob("*.md")))
    for name in (
        "operator-core.md",
        "operator-core-code.md",
        "shared-constraints.md",
        "shared-constraints-code.md",
        "CLAUDE.md",
        "AGENTS.md",
    ):
        candidate = agent_dir / name
        if candidate.exists():
            paths.append(candidate)
    paths.extend(sorted((agent_dir / ".claude" / "agents").rglob("*.md")))
    paths.extend(sorted((agent_dir / ".codex" / "agents").rglob("*.toml")))
    return paths


def test_no_bare_engagement_path_in_prompts():
    """The runtime mount is `/engagements/$KEY/...` (trailing s). Any bare `/engagement/`
    (with a literal trailing slash and no trailing s on `engagement`) left behind in the
    prompt corpus means an agent will try to write to a dead path inside Kali. The
    mitmproxy container has its own `/engagement` mount and is the only allowed exception
    — it lives outside the Kali MCP runtime path namespace."""
    repo_root = Path(__file__).resolve().parents[3]
    # Match `/engagement/` as a literal path prefix but not `/engagements/`. The
    # negative lookahead on `s/` keeps `/engagements/` out; anchoring on the trailing
    # slash keeps unrelated substrings like `engagement-methodology.md`,
    # `engagement.pot`, or `path/to/engagement` out too — those are not path prefixes.
    pattern = re.compile(r"/engagement/")
    offenders: list[str] = []
    for path in _prompt_corpus_paths(repo_root):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Bare `/engagement/` references remain in the prompt corpus. Rewrite to "
        "`/engagements/$ENGAGEMENT_KEY/...` — the Kali runtime bind-mounts `engagements/` "
        "at `/engagements` (with trailing s). The mitmproxy container has its own "
        "`/engagement` mount and is excluded from this check.\n" + "\n".join(offenders)
    )


def test_no_status_pending_surface_examples():
    """`pending` is not a valid surface status — valid values are
    `discovered|covered|not_applicable|deferred`. A `--status pending` example in the
    prompt corpus teaches agents to pass an invalid enum to record-surface."""
    repo_root = Path(__file__).resolve().parents[3]
    offenders: list[str] = []
    for path in _prompt_corpus_paths(repo_root):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "--status pending" in line:
                offenders.append(f"{path}:{lineno}: {line.strip()}")
    assert not offenders, (
        "`--status pending` appears in the prompt corpus. Valid surface statuses are "
        "`discovered`, `covered`, `not_applicable`, `deferred`. Use `discovered` for "
        "newly-found surfaces.\n" + "\n".join(offenders)
    )


def test_no_tar_base64_ferry_blocks():
    """The `/engagements` bind mount removed the need for tar+base64 ferries between the
    host and Kali. Any remaining ferry blocks mean the skill is still writing through a
    container filesystem boundary that no longer exists."""
    repo_root = Path(__file__).resolve().parents[3]
    agent_dir = repo_root / "agent"
    # Two directions: outbound encoding and inbound decoding.
    outbound = re.compile(r"tar\s+c[zx]f\s+-.*\|\s*base64")
    inbound = re.compile(r"base64\s+-d.*\|\s*tar\s+[zx]f")
    offenders: list[str] = []
    targets = [
        *sorted((agent_dir / "skills").rglob("*.md")),
        *sorted((agent_dir / "references").rglob("*.md")),
    ]
    for path in targets:
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if outbound.search(line) or inbound.search(line):
                offenders.append(f"{path}:{lineno}: {line.strip()}")
    assert not offenders, (
        "tar+base64 ferry blocks remain in the prompt corpus. The `/engagements` bind "
        "mount lets skills write directly to `/engagements/$KEY/...` — remove the ferry "
        "step.\n" + "\n".join(offenders)
    )


def test_reactive_nuclei_wording_present():
    """The reactive-sweep rule lives in two places on purpose: the operator rule in
    `operator-core.md` and the skill procedure in `nuclei-scanning/SKILL.md`. Losing
    either header means the rule can silently disappear from an operator's context."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    nuclei_skill = (
        repo_root / "agent" / "skills" / "nuclei-scanning" / "SKILL.md"
    ).read_text(encoding="utf-8")
    assert "## Reactive Nuclei on URL Discovery" in operator_core, (
        "operator-core.md is missing the `Reactive Nuclei on URL Discovery` section header"
    )
    assert "Reactive Sweep" in nuclei_skill, (
        "nuclei-scanning/SKILL.md is missing the `Reactive Sweep` section — the operator "
        "rule points at the skill for mechanics, so both must stay in sync"
    )


def test_phase_1a_1b_1c_structure_present():
    """Phase 1 was restructured into 1a (wildcard enum) / 1b (parallel recon+source) /
    1c (reactive nuclei sweep). Losing any of the sub-phase headers collapses the
    ordering back to the pre-refactor single-step Phase 1."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    # Sub-phase headers in operator-core.md are rendered as `**1a.`, `**1b.`, `**1c.`
    # — the numeric-letter-dot form is the load-bearing marker, not the phrase
    # "Phase 1a". Also verify the descriptive labels survive so a partial rename
    # (e.g. renaming just one sub-phase) is caught.
    markers = {
        "1a.": "wildcard enum sub-phase header",
        "1b.": "parallel recon+source sub-phase header",
        "1c.": "reactive nuclei sub-phase header",
        "Wildcard subdomain enumeration": "1a descriptive label",
        "Parallel recon + source analysis": "1b descriptive label",
        "Reactive nuclei sweep": "1c descriptive label",
    }
    for substring, label in markers.items():
        assert substring in operator_core, (
            f"operator-core.md is missing `{substring}` ({label}) — Phase 1 structure has drifted"
        )


def test_scope_coverage_gates_present():
    """`check-scope-coverage` is the phase-gate CLI; its `--require-stage enum` and
    `--require-stage collection` flags are what make the Phase 1->2 and Phase 2->3 exit
    gates enforceable. Dropping either invocation silently disables the corresponding
    gate."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    assert "check-scope-coverage --require-stage enum" in operator_core, (
        "operator-core.md is missing the Phase 1 exit gate "
        "`check-scope-coverage --require-stage enum`"
    )
    assert "check-scope-coverage --require-stage collection" in operator_core, (
        "operator-core.md is missing the Phase 2 exit gate "
        "`check-scope-coverage --require-stage collection`"
    )


def test_priority_dispatch_wired_into_prompts():
    """`classify-work`, `list-clusters`, `dispatch defer-cluster`, and
    `dispatch fetch-by-priority` are the priority-mode CLIs. Without them referenced in
    the operator loop and the case-dispatching skill, the priority-score columns on
    `work_items` stay populated but unused, which is worse than not having them."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    case_dispatching = (
        repo_root / "agent" / "skills" / "case-dispatching" / "SKILL.md"
    ).read_text(encoding="utf-8")

    # classify-work must be called after Phase 2 ingestion and inside the priority-mode
    # branch of the consumption loop.
    assert "classify-work" in operator_core, (
        "operator-core.md must call `aith assess classify-work` after Phase 2 ingestion "
        "so Phase 3 priority-mode dispatch has scored rows to sort"
    )
    assert "classify-work" in case_dispatching, (
        "case-dispatching/SKILL.md must document `classify-work` in the priority-mode "
        "branch of the consumption loop"
    )

    # Priority-first dispatch branch wired in both files.
    assert "fetch-by-priority" in operator_core, (
        "operator-core.md must document the priority-first dispatch branch via "
        "`dispatch fetch-by-priority`"
    )
    assert "fetch-by-priority" in case_dispatching, (
        "case-dispatching/SKILL.md must document `dispatch fetch-by-priority` for "
        "buffer-size-triggered priority dispatch"
    )

    # Cluster review + deferral CLIs.
    assert "list-clusters" in case_dispatching, (
        "case-dispatching/SKILL.md must reference `list-clusters` so operators can "
        "inspect cluster manifests before dispatching"
    )
    assert "defer-cluster" in case_dispatching, (
        "case-dispatching/SKILL.md must reference `dispatch defer-cluster` so "
        "operators can drop low-signal clusters before specialist dispatch"
    )

    # Volume threshold: small buffer stays type-based; large buffer switches to priority.
    assert "2000" in operator_core, (
        "operator-core.md must state the 2000-pending threshold that switches between "
        "type-based and priority-based dispatch"
    )
