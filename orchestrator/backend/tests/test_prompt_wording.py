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


def test_vendor_saas_and_egress_checkpoints_present():
    """1C.5 + 1G.1 — operator-core.md Phase 1 must carry both the Vendor-SaaS
    scope checkpoint and the Egress reputation checkpoint sub-bullets, and the
    cdn-ip-blocking.md cross-references must resolve from the recon skills and
    the references INDEX.md."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")

    # Operator-core checkpoint sub-bullets.
    assert "Vendor-SaaS scope checkpoint" in operator_core, (
        "operator-core.md is missing the `Vendor-SaaS scope checkpoint` sub-bullet"
    )
    assert "Egress reputation checkpoint" in operator_core, (
        "operator-core.md is missing the `Egress reputation checkpoint` sub-bullet"
    )
    # Vendor-SaaS sub-bullet must point at the host classifier helper so the
    # operator's check is mechanical, not a guess.
    assert "host_is_vendor_saas" in operator_core, (
        "operator-core.md must reference `host_is_vendor_saas` so the operator's"
        " vendor-SaaS check is mechanical, not a guess"
    )
    # Egress sub-bullet must point at the runtime guide for the four
    # mitigation options and the give-up-vs-escalate rule.
    assert "agent/references/runtime-guides/cdn-ip-blocking.md" in operator_core, (
        "operator-core.md must reference `cdn-ip-blocking.md` for the four egress"
        " mitigation options and the give-up-vs-escalate rule"
    )
    # The runtime guide itself exists and carries the four numbered mitigation
    # subsections plus the egress reputation curl script.
    cdn_guide = repo_root / "agent" / "references" / "runtime-guides" / "cdn-ip-blocking.md"
    assert cdn_guide.is_file(), "agent/references/runtime-guides/cdn-ip-blocking.md is missing"
    cdn_text = cdn_guide.read_text(encoding="utf-8")
    for needle in (
        "egress_block_pct",
        "Request IP allowlisting",
        "residential proxy",
        "browser-based tool",
        "Accept the limited coverage",
    ):
        assert needle in cdn_text, (
            f"cdn-ip-blocking.md is missing `{needle}`"
        )

    # Web-recon skill carries the egress reputation step right after wafw00f.
    web_recon = (repo_root / "agent" / "skills" / "web-recon" / "SKILL.md").read_text(encoding="utf-8")
    assert "Egress reputation check" in web_recon, (
        "web-recon/SKILL.md is missing the `Egress reputation check` step"
    )
    assert "cdn-ip-blocking.md" in web_recon, (
        "web-recon/SKILL.md must cross-reference `cdn-ip-blocking.md`"
    )

    # Subdomain-enumeration skill cross-links to the egress reputation check
    # because DNS resolution success-rate parallels the egress reputation
    # problem.
    subenum = (repo_root / "agent" / "skills" / "subdomain-enumeration" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    assert "cdn-ip-blocking.md" in subenum, (
        "subdomain-enumeration/SKILL.md must cross-link to `cdn-ip-blocking.md`"
    )

    # INDEX.md registers the new runtime guide.
    index = (repo_root / "agent" / "references" / "INDEX.md").read_text(encoding="utf-8")
    assert "runtime-guides/cdn-ip-blocking.md" in index, (
        "agent/references/INDEX.md must register `runtime-guides/cdn-ip-blocking.md`"
    )

    # Recon-specialist self-check pins the two new gates. Round 5 softened
    # the vendor-SaaS framing from "must record decision before dispatch" to
    # "warn the operator and record a pending row" so the bullet wording is
    # less directive but still anchors the check.
    recon_specialist = (repo_root / "agent" / "agents" / "recon-specialist.md").read_text(
        encoding="utf-8"
    )
    assert "Vendor-SaaS hosts warned to the operator" in recon_specialist, (
        "recon-specialist.md self-check must include the vendor-SaaS warning item"
    )
    assert "Egress reputation check run" in recon_specialist, (
        "recon-specialist.md self-check must include the egress reputation check item"
    )


def test_no_broad_pkill_rule_present_in_shared_constraints():
    """1A.4 — the no-broad-`pkill` rule lives in `agent/shared-constraints.md` so every
    specialist loads it on first dispatch. The rule and the safe alternatives must stay
    pinned, while the engagement-specific citation has been stripped (drift guard 1Z.19)."""
    repo_root = Path(__file__).resolve().parents[3]
    shared = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")

    # Section heading for the new rule.
    assert "### Process cleanup — no broad `pkill`/`killall` by binary name" in shared, (
        "shared-constraints.md is missing the process-cleanup rule heading"
    )
    # Core prohibition wording.
    assert "Agents MUST NOT use `pkill`, `killall`, or `kill -9 -f <binary>`" in shared, (
        "shared-constraints.md is missing the no-broad-pkill prohibition sentence"
    )
    # Mechanism / lesson must survive even after the dated citation was stripped.
    assert "kills sibling agents'" in shared, (
        "shared-constraints.md is missing the sibling-kill consequence sentence"
    )
    assert "cascades SIGTERM→SIGKILL" in shared, (
        "shared-constraints.md is missing the timeout-cascade rationale"
    )
    # The safe alternatives every specialist needs to know. The `kali job start` /
    # `kali job stop` lifecycle wording is wrapped across lines in the canonical
    # placement, so squash whitespace before the substring check.
    shared_squashed = " ".join(shared.split())
    assert "kali job start" in shared_squashed, (
        "shared-constraints.md is missing the `kali job start` lifecycle alternative"
    )
    assert "kali job stop" in shared_squashed, (
        "shared-constraints.md is missing the `kali job stop` cleanup alternative"
    )
    assert "/tmp/aith-pid-<run_uuid>" in shared, (
        "shared-constraints.md is missing the run_uuid PID-file pattern for synchronous cleanup"
    )
    assert "cp /usr/bin/nmap" in shared, (
        "shared-constraints.md is missing the per-agent binary copy last-resort recipe"
    )
    assert "Timeout-related cleanup is automatic" in shared, (
        "shared-constraints.md is missing the timeout-cascade automatic-cleanup statement"
    )

    # The kali-cli runtime guide carries the exact-step recipes.
    kali_cli = (repo_root / "agent" / "references" / "runtime-guides" / "kali-cli.md").read_text(
        encoding="utf-8"
    )
    assert "## Process cleanup discipline" in kali_cli, (
        "kali-cli.md is missing the `Process cleanup discipline` section header"
    )
    assert "kali job stop" in kali_cli, (
        "kali-cli.md is missing the `kali job stop` recipe"
    )
    assert "/tmp/aith-pid-<run_uuid>" in kali_cli, (
        "kali-cli.md is missing the run_uuid PID-file recipe"
    )

    # Skill files must carry the per-tool reminder so dispatched specialists see it on the
    # parallel-scan / rate-limit step they're already reading.
    for skill_path in (
        "skills/web-recon/SKILL.md",
        "skills/port-scanning/SKILL.md",
        "skills/nuclei-scanning/SKILL.md",
        "skills/directory-fuzzing/SKILL.md",
        "skills/subdomain-enumeration/SKILL.md",
    ):
        text = (repo_root / "agent" / skill_path).read_text(encoding="utf-8")
        assert "kali job start" in text, (
            f"{skill_path} is missing the parallel-scan `kali job start` lifecycle reminder"
        )
        assert "kali-cli.md" in text and "Process cleanup discipline" in text, (
            f"{skill_path} is missing the cross-reference to kali-cli.md `Process cleanup discipline`"
        )


def test_web_recon_mandatory_tool_ordering_is_pinned():
    """N3 / N6 — the default tool ordering must be DOCUMENTED in the web-recon skill at the
    concept level (the seven canonical tools appear in the right relative order). The literal
    arrow string and the prohibition substring are no longer pinned: the ordering is now a
    default heuristic with a documented declare-alternate clause, and skipping a step is
    permitted when the dispatch context authorizes it."""
    repo_root = Path(__file__).resolve().parents[3]

    recon_specialist = (repo_root / "agent" / "agents" / "recon-specialist.md").read_text(
        encoding="utf-8"
    )
    web_recon = (repo_root / "agent" / "skills" / "web-recon" / "SKILL.md").read_text(
        encoding="utf-8"
    )

    # Concept-level ordering: the seven canonical tools appear, in this relative order,
    # somewhere in the web-recon skill. We scan once and confirm each tool is found in
    # the expected sequence position.
    expected_order = ["wafw00f", "nmap", "httpx", "whatweb", "nuclei", "ffuf", "nikto"]
    last_index = -1
    for tool in expected_order:
        idx = web_recon.find(tool, last_index + 1)
        assert idx != -1, (
            f"web-recon/SKILL.md must mention `{tool}` after the prior tool in the default "
            f"ordering (looked for it after position {last_index})"
        )
        last_index = idx

    # Recon-specialist still names the mandatory tools by concept in the self-check so the
    # operator can verify per-tool coverage. Drop the literal arrow + the
    # "only when the target clearly warrants it" prohibition; the declare-alternate clause
    # is the new escape valve.
    for needle in (
        "**wafw00f** ran first",
        "**nmap** port + service scan completed",
        "**httpx** fingerprint pass",
        "**whatweb** ran on each live web target",
        "**nuclei** reactive sweep ran",
        "**ffuf / feroxbuster** directory fuzz",
        "**nikto** trigger evaluation completed",
    ):
        assert needle in recon_specialist, (
            f"recon-specialist.md pre-output self-check is missing the `{needle}` item"
        )

    # The default-heuristic framing must be present (not the older "non-negotiable" lock).
    assert "default" in web_recon.lower(), (
        "web-recon/SKILL.md must frame the ordering as a default heuristic"
    )
    assert "Declare-alternate-ordering" in web_recon, (
        "web-recon/SKILL.md must carry the `Declare-alternate-ordering` clause documenting "
        "when an alternate ordering is permissible"
    )


def test_nmap_port_data_assertion_pinned():
    """1B.3 — the per-host port-data presence assertion (text-output + xmllint XPath)
    must appear in the port-scanning skill, the nmap reference, and the recon-specialist
    self-check. A future rewrite that reverts to the weaker `</nmaprun>` / scan-report
    line gate fails CI."""
    repo_root = Path(__file__).resolve().parents[3]

    port_scanning = (repo_root / "agent" / "skills" / "port-scanning" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    nmap_ref = (repo_root / "agent" / "references" / "tools" / "recon" / "nmap.md").read_text(
        encoding="utf-8"
    )
    recon_specialist = (repo_root / "agent" / "agents" / "recon-specialist.md").read_text(
        encoding="utf-8"
    )

    # The two-layer assertion is the load-bearing language.
    for needle in (
        'open_ports=$(grep -cE \'^[0-9]+/(tcp|udp).*open\' "$f")',
        '--xpath \'//host[@status="up"]/ports\'',
        "GAP: $hostname (scan started but timed out — port data empty)",
    ):
        assert needle in port_scanning, (
            f"port-scanning/SKILL.md is missing assertion fragment `{needle}`"
        )

    # XML-closure trap must be documented in the nmap reference.
    assert "XML closure means the nmap binary exited normally" in nmap_ref, (
        "nmap.md is missing the XML-closure trap explanation"
    )
    assert "Use the port-data presence check, not XML closure or scan-report line." in nmap_ref, (
        "nmap.md is missing the corrective `Use the port-data presence check ...` sentence"
    )

    # The recon-specialist pre-output self-check item must reference per-host nmap
    # port-data presence (case-insensitive). It must also mention the port-scanning
    # skill's two-layer assertion, since the assertion procedure lives in that skill.
    assert "per-host nmap port-data presence" in recon_specialist.lower(), (
        "recon-specialist.md self-check is missing the per-host nmap port-data presence "
        "verification item"
    )
    assert "two-layer assertion" in recon_specialist.lower(), (
        "recon-specialist.md self-check must reference the port-scanning skill's "
        "`two-layer assertion` so the gate points at the canonical procedure"
    )

    # Upstream-filtering kill-evidence path stays pinned.
    assert "upstream filtering" in port_scanning.lower(), (
        "port-scanning/SKILL.md is missing the upstream-filtering kill-evidence path"
    )
    assert "-T2 --host-timeout 1500-1800s" in port_scanning, (
        "port-scanning/SKILL.md is missing the slower retry profile"
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


def test_recon_dispatch_resource_policy_section_present():
    """The Recon Dispatch Resource Policy lives in two places after Fix #8:
    - `agent/operator-core.md` keeps the section header and the tier-pick / step-down
      prose (operator-side decisions).
    - `agent/references/recon/rate-calibration.md` carries the per-target rate
      calibration trait rows. Recon-class roles load it on first use; the table
      was extracted from `shared-constraints.md` §14 to keep the every-specialist
      load lighter for non-recon roles.
    """
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (
        repo_root / "agent" / "operator-core.md"
    ).read_text(encoding="utf-8")
    rate_cal = (
        repo_root / "agent" / "references" / "recon" / "rate-calibration.md"
    ).read_text(encoding="utf-8")

    assert "## Recon Dispatch Resource Policy" in operator_core, (
        "operator-core.md is missing the `Recon Dispatch Resource Policy` section header"
    )
    # All five canonical trait rows must appear in the new reference file.
    for row_marker in (
        "Cloud-fronted",
        "Origin / single-server",
        "WAF-protected",
        "High-friction policy / regulated",
        "Vendor SaaS",
    ):
        assert row_marker in rate_cal, (
            f"references/recon/rate-calibration.md per-target rate calibration "
            f"table is missing the `{row_marker}` trait row"
        )
    # operator-core points at the new reference path.
    assert "agent/references/recon/rate-calibration.md" in operator_core, (
        "operator-core.md must point at the extracted rate-calibration reference"
    )
    # The selection prose stays operator-side.
    assert "Resource-safety preflight" in operator_core, (
        "operator-core.md is missing the `Resource-safety preflight` rule heading"
    )
    assert "Picking a tier" in operator_core, (
        "operator-core.md is missing the `Picking a tier` selection rule"
    )
    assert "When to step down a tier" in operator_core, (
        "operator-core.md is missing the `When to step down a tier` rule"
    )
    assert "DNS bruteforce gating" in operator_core, (
        "operator-core.md is missing the DNS-bruteforce gating cross-reference"
    )


def test_recon_specialist_load_first_marks_lazy_skills():
    """Fix #8 — recon-specialist Load First splits into MANDATORY (load before any
    target work) and LOAD-ON-FIRST-USE (lazy). Holding nuclei-scanning and
    directory-fuzzing out of the first-load set keeps the bootstrap lighter for
    hypothesis-driven dispatches that never reach those steps. The mandatory
    set keeps web-recon, port-scanning, shared-constraints, and the new
    rate-calibration reference."""
    repo_root = Path(__file__).resolve().parents[3]
    role = (
        repo_root / "agent" / "agents" / "recon-specialist.md"
    ).read_text(encoding="utf-8")

    assert "**MANDATORY (load before any target work):**" in role, (
        "recon-specialist.md missing MANDATORY load-first heading"
    )
    assert "**LOAD-ON-FIRST-USE" in role, (
        "recon-specialist.md missing LOAD-ON-FIRST-USE lazy-load heading"
    )
    # Rate-calibration reference must be in the mandatory set.
    assert "agent/references/recon/rate-calibration.md" in role, (
        "recon-specialist.md must reference the new rate-calibration extracted file"
    )
    # The two skills the lazy section gates.
    for fragment in (
        "load when the dispatch is about to run step 5",
        "load when the dispatch is about to run step 6",
    ):
        assert fragment in role, (
            f"recon-specialist.md missing lazy-load gating phrase: {fragment!r}"
        )


def test_kali_exec_resource_policy_cross_reference_resolves():
    """1Z.22 — the kali-exec skill cross-references the Recon Dispatch Resource Policy.
    Verify the section name appears verbatim in operator-core.md so the link resolves."""
    repo_root = Path(__file__).resolve().parents[3]
    kali_exec = (
        repo_root / "agent" / "skills" / "kali-exec" / "SKILL.md"
    ).read_text(encoding="utf-8")
    operator_core = (
        repo_root / "agent" / "operator-core.md"
    ).read_text(encoding="utf-8")

    assert "Recon Dispatch Resource Policy" in kali_exec, (
        "kali-exec/SKILL.md must reference `Recon Dispatch Resource Policy`"
    )
    assert "## Recon Dispatch Resource Policy" in operator_core, (
        "operator-core.md must define the `Recon Dispatch Resource Policy` section "
        "exactly so the kali-exec cross-reference resolves"
    )


def test_no_dot_gov_profile_body_text_in_recon_skills():
    """1Z.18 / N11 — the `.gov profile` / `.gov rate` / `the .gov` jurisdictional-label
    drift must stay stripped from recon-class skills, agent prompts, and runtime references.
    The matrix in operator-core.md keeps `.gov` as a row label (a real target trait), but
    the methodology body uses trait language ("cautious-tier", "CDN-fronted",
    "WAF-protected"). Legitimate substrings like `usa.gov` in URL examples are not
    jurisdictional labels — they are domain examples — so we only reject the three
    canonical body-text label phrases."""
    repo_root = Path(__file__).resolve().parents[3]
    skill_paths = [
        repo_root / "agent" / "skills" / "web-recon" / "SKILL.md",
        repo_root / "agent" / "skills" / "port-scanning" / "SKILL.md",
        repo_root / "agent" / "skills" / "kali-exec" / "SKILL.md",
        repo_root / "agent" / "skills" / "subdomain-enumeration" / "SKILL.md",
    ]
    # Round 2 fixed agents/ and references/ already; the guard scope now covers them too
    # so a future drift back into those files fails CI.
    skill_paths.extend(sorted((repo_root / "agent" / "agents").glob("*.md")))
    skill_paths.extend(sorted((repo_root / "agent" / "references").rglob("*.md")))

    forbidden_labels = (".gov profile", ".gov rate", "the .gov")
    for path in skill_paths:
        text = path.read_text(encoding="utf-8")
        for forbidden in forbidden_labels:
            assert forbidden not in text, (
                f"{path}: still references `{forbidden}` — the body should describe the "
                f"trait (cautious-tier / CDN-fronted / WAF-protected), not the jurisdiction. "
                f"Legitimate URL examples like `usa.gov` are unaffected; only the three "
                f"canonical jurisdictional-label phrases are rejected."
            )


def test_specialist_wrappers_carry_context_isolation_paragraph():
    """Every rendered specialist wrapper (Claude `.md` + Codex `.toml`) carries the
    SPECIALIST CONTEXT ISOLATION paragraph: do NOT read agent/AGENTS.md or agent/CLAUDE.md,
    cross-cutting context lives in agent/shared-constraints.md (already in Load First)."""
    repo_root = Path(__file__).resolve().parents[3]
    claude_dir = repo_root / "agent" / ".claude" / "agents"
    codex_dir = repo_root / "agent" / ".codex" / "agents"

    specialist_names = [
        "recon-specialist",
        "source-analyzer",
        "surface-collector",
        "vulnerability-analyst",
        "exploit-developer",
        "fuzzer",
        "osint-analyst",
        "report-writer",
        "code-architect",
        "code-vuln-hunter",
        "code-variant-hunter",
        "code-vuln-verifier",
    ]

    for name in specialist_names:
        for wrapper in (claude_dir / f"{name}.md", codex_dir / f"{name}.toml"):
            assert wrapper.exists(), f"specialist wrapper missing: {wrapper}"
            text = wrapper.read_text(encoding="utf-8")
            assert "SPECIALIST CONTEXT ISOLATION" in text, (
                f"{wrapper}: missing SPECIALIST CONTEXT ISOLATION paragraph"
            )
            squashed = " ".join(text.split())
            # Forbid is restored: do NOT read AGENTS.md / CLAUDE.md.
            assert "Do NOT read" in squashed and "AGENTS.md" in squashed and "CLAUDE.md" in squashed, (
                f"{wrapper}: SPECIALIST CONTEXT ISOLATION must forbid reading agent/AGENTS.md "
                "and agent/CLAUDE.md"
            )
            # The forbid points at shared-constraints.md as the cross-cutting home.
            assert "shared-constraints.md" in squashed, (
                f"{wrapper}: must direct specialists to agent/shared-constraints.md for "
                "cross-cutting context (audit-flag tables, listener URL conventions, "
                "runtime tier table, half-phase tag definitions)"
            )

    # The render script itself must carry the forbid so the next render produces it.
    render_script = (repo_root / "agent" / "scripts" / "render-operator-prompts.sh").read_text(
        encoding="utf-8"
    )
    assert "SPECIALIST CONTEXT ISOLATION" in render_script
    assert "Do NOT read" in render_script
    assert "shared-constraints.md" in render_script


def test_cross_cutting_audit_flag_tables_in_shared_constraints():
    """Cross-cutting context that specialists rely on MUST live in
    agent/shared-constraints.md so the per-role Load First pulls it without
    having specialists read the operator bootstrap prompt."""
    repo_root = Path(__file__).resolve().parents[3]
    sc = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")

    # Audit-flag value tables.
    for needle in (
        "--technique",
        "--probe-kind",
        "--phase",
        "--timeout",
        "--destructive",
        "fingerprint",
        "baseline",
        "payload",
        "exploit",
        "replay",
        "cleanup",
        "recon-pivot",
        "exploit-recon",
    ):
        assert needle in sc, (
            f"shared-constraints.md must carry the audit-flag value table item `{needle}`"
        )

    # Listener URL contract.
    assert ".listener_url" in sc and ".oob_url" in sc, (
        "shared-constraints.md must carry the listener URL contract (.listener_url / .oob_url)"
    )

    # Kali execution + finding prefix table.
    assert "aith assess kali" in sc
    for prefix in ("EX-001", "VA-001", "SA-001", "RE-001", "FZ-001", "OS-001", "SC-001"):
        assert prefix in sc, f"shared-constraints.md must carry the {prefix} prefix example"

    # Intel recording rules.
    assert "record-intel" in sc, "shared-constraints.md must cover record-intel"

    # Per-target rate calibration table now lives in the recon-class reference,
    # not shared-constraints. Verify the pointer is present and the rate file exists.
    repo_root_for_pointer = Path(__file__).resolve().parents[3]
    rate_cal_path = repo_root_for_pointer / "agent" / "references" / "recon" / "rate-calibration.md"
    assert rate_cal_path.is_file(), (
        "agent/references/recon/rate-calibration.md must exist (extracted from §14)"
    )
    assert "agent/references/recon/rate-calibration.md" in sc, (
        "shared-constraints.md §14 must point at the extracted rate-calibration reference"
    )
    rate_cal = rate_cal_path.read_text(encoding="utf-8")
    for needle in (
        "Cloud-fronted",
        "Origin / single-server",
        "WAF-protected",
        "Vendor SaaS",
        "polite-CDN-fronted-target",
        "polite-residential",
        "bursty-OK",
    ):
        assert needle in rate_cal, (
            f"references/recon/rate-calibration.md must carry the per-target rate calibration row `{needle}`"
        )


def test_operator_core_does_not_duplicate_specialist_content():
    """Cross-cutting sections moved out of operator-core.md must not silently reappear.
    The drift this guards against: a future edit that pastes the audit-flag value tables
    or the per-target rate calibration row table back into operator-core, creating two
    copies that drift apart over time."""
    repo_root = Path(__file__).resolve().parents[3]
    oc = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")

    # operator-core may MENTION the audit flags but must not redeclare the value enum
    # table. The strongest tell: the full prose enum list (`SSRF`, `XSS`, ... `OTHER`).
    assert "RECON, DISCOVERY, FUZZ, OSINT" not in oc, (
        "operator-core.md must not redeclare the technique enum — it lives in "
        "agent/shared-constraints.md `Command Metadata`"
    )

    # The per-target rate calibration TABLE rows live in shared-constraints. operator-core
    # may keep tier-pick prose, but the row prose with `polite-CDN-fronted-target` only
    # belongs in shared-constraints.
    assert "polite-CDN-fronted-target | runtime-tier" not in oc, (
        "operator-core.md must not duplicate the per-target rate calibration table rows — "
        "they live in agent/shared-constraints.md"
    )

    # The finding prefix table is shared-constraints content. The example prefix list
    # (RE-001 / FZ-001 / OS-001 / SC-001 lined up) should not appear in operator-core.
    assert "RE-001" not in oc and "FZ-001" not in oc, (
        "operator-core.md must not duplicate the finding prefix table — it lives in "
        "agent/shared-constraints.md §4"
    )


def test_specialist_dispatch_contract_present_in_operator_core():
    """N11 — operator-core.md keeps the Specialist Dispatch Contract section and its field
    list (role, model, reasoning, files_allowed, files_forbidden, permission,
    command_budget, output, dispatch_mode). The literal "read-only by default" phrase is
    no longer pinned; the contract-driven permission concept is what we lock down."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")

    assert "### Specialist Dispatch Contract" in operator_core, (
        "operator-core.md is missing the `### Specialist Dispatch Contract` section heading"
    )
    for field in (
        "`role`",
        "`model`",
        "`reasoning`",
        "`files_allowed`",
        "`files_forbidden`",
        "`permission`",
        "`command_budget`",
        "`output`",
        "`dispatch_mode`",
    ):
        assert field in operator_core, (
            f"Specialist Dispatch Contract section is missing the {field} field"
        )
    # Contract-driven permission gate must be present at the concept level.
    assert "permission >= passive-probe" in operator_core, (
        "operator-core.md must show the contract-driven permission gate "
        "(`permission >= passive-probe`)"
    )


def test_phase_1_dispatch_only_guardrail_present():
    """N2 — Phase 1a/1b dispatch is non-negotiable for ANALYSIS/COVERAGE work. The operator
    keeps a documented carve-out list (credential auto-use validation, tier-pick smoke,
    runtime health smoke, backend-write helpers) so mechanical pipeline checks do not
    consume a full specialist context. The literal "MUST NOT run target-facing tools
    directly, even for 'quick checks'" phrasing is no longer pinned; the carve-outs replace
    the blanket prohibition."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")

    assert "Phase 1a/1b dispatch is non-negotiable for ANALYSIS/COVERAGE" in operator_core, (
        "operator-core.md must scope the Phase 1a/1b non-negotiable rule to ANALYSIS/COVERAGE"
    )
    # The carve-out list must be present so mechanical pipeline checks do not silently get
    # routed to a specialist (or worse, dropped on the floor).
    operator_core_squashed = " ".join(operator_core.split())
    for carve_out_marker in (
        "credential auto-use validation",
        "tier-pick",
        "runtime health smoke",
        "backend-write helpers",
    ):
        assert carve_out_marker in operator_core_squashed.lower(), (
            f"operator-core.md must document the `{carve_out_marker}` operator carve-out so "
            f"mechanical pipeline checks have an explicit operator-side path"
        )
    # The blocker-record contract must be explicit so blockers do not silently fall back to the
    # operator loop.
    assert "dispatch_blocked" in operator_core, (
        "operator-core.md is missing the `dispatch_blocked` registry record kind for blocked dispatches"
    )
    assert "surfaced_to_user" in operator_core, (
        "operator-core.md is missing the `surfaced_to_user` flag in the blocker-record contract"
    )


def test_dispatch_completion_gate_includes_stderr_log_inspection():
    """1C.3 — when a specialist reports "no findings", the operator must inspect the actual
    stderr artifact before accepting the headline. Reactive nuclei sweeps in particular emit
    "templates loaded" lines on stderr that prove the tool ran successfully even when the
    summary says zero hits."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")

    assert "Stderr-log inspected when \"no results\" is the headline finding" in operator_core, (
        "Dispatch Completion Gate must include the stderr-log inspection bullet"
    )
    # The bullet must point at the canonical lookup commands so operators don't guess.
    assert "aith assess get-command-run" in operator_core
    assert "Templates loaded for current scan" in operator_core, (
        "stderr-log inspection bullet must name the `Templates loaded for current scan` "
        "marker so operators know what to look for in the nuclei false-alarm pattern"
    )


def test_dispatch_mode_declaration_table_present():
    """N9 — operator-core.md must define the four dispatch modes and concept-level
    item-budget ranges. The literal "30–100 hard cap" framing is no longer pinned: the
    item-iterating cap can rise to 200 when items cluster on a stable cluster_key, and the
    dispatch context may override the cap with a stated rationale."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")

    assert "### Dispatch-Mode Declaration" in operator_core, (
        "operator-core.md is missing the `### Dispatch-Mode Declaration` section heading"
    )
    for mode in ("hypothesis-driven", "item-iterating", "deep-manual", "variant-rotation"):
        assert f"`{mode}`" in operator_core, (
            f"Dispatch-Mode Declaration table is missing the `{mode}` mode"
        )
    # Concept-level budget ranges that establish the rule of thumb. The exact hard-cap
    # phrasing is intentionally not pinned anymore — cluster-aware overrides are allowed.
    assert "200–1000" in operator_core or "200-1000" in operator_core
    assert "30–100" in operator_core or "30-100" in operator_core
    assert "10–30" in operator_core or "10-30" in operator_core
    assert "1–3 hosts" in operator_core or "1-3 hosts" in operator_core
    # Cluster-override clause — operator may override the item-iterating cap with rationale.
    operator_core_squashed = " ".join(operator_core.split()).lower()
    assert "cluster_key" in operator_core_squashed, (
        "operator-core.md Dispatch-Mode Declaration must reference cluster_key so the "
        "cluster-aware override is documented"
    )
    assert "rationale" in operator_core_squashed, (
        "operator-core.md Dispatch-Mode Declaration must reference the rationale clause "
        "for operator overrides of the item-iterating cap"
    )


def test_specialist_agents_declare_modes_accepted():
    """1C.4 — every specialist role file declares which dispatch modes it accepts and the
    default mode when the operator omits the field. Without the declaration, the operator has
    no canonical place to read role-default pairings."""
    repo_root = Path(__file__).resolve().parents[3]
    agent_dir = repo_root / "agent" / "agents"

    specialists = [
        "recon-specialist",
        "source-analyzer",
        "surface-collector",
        "vulnerability-analyst",
        "exploit-developer",
        "fuzzer",
        "osint-analyst",
        "report-writer",
        "code-architect",
        "code-vuln-hunter",
        "code-variant-hunter",
        "code-vuln-verifier",
    ]
    for name in specialists:
        path = agent_dir / f"{name}.md"
        text = path.read_text(encoding="utf-8")
        assert "**Modes accepted:**" in text, (
            f"{path}: missing `**Modes accepted:**` field"
        )
        assert "**Default when omitted:**" in text, (
            f"{path}: missing `**Default when omitted:**` field"
        )


def test_subagent_registry_schema_carries_contract_fields():
    """1C.1 / 1C.4 — the registry schema MUST document every contract field so the registry
    record captures both what was dispatched and what the dispatch was authorized to do."""
    repo_root = Path(__file__).resolve().parents[3]
    registry = (
        repo_root / "agent" / "references" / "runtime-guides" / "subagent-registry.md"
    ).read_text(encoding="utf-8")

    assert "## Contract Schema" in registry, (
        "subagent-registry.md is missing the `## Contract Schema` heading"
    )
    for field in (
        "`model`",
        "`reasoning`",
        "`files_allowed`",
        "`files_forbidden`",
        "`permission`",
        "`command_budget`",
        "`output`",
        "`dispatch_mode`",
    ):
        assert field in registry, f"subagent-registry.md is missing the {field} contract field"
    # Blocker-record kind must be documented so dispatch_blocked entries land in the right shape.
    assert "dispatch_blocked" in registry
    assert "surfaced_to_user" in registry


def test_engagements_py_pins_specialist_isolation_invariant():
    """The per-engagement AGENTS.md/CLAUDE.md helper points at operator instructions.
    The code comment must record the seeding invariant so a future change that lands
    specialists at this cwd does not silently re-introduce the operator-banner leak."""
    repo_root = Path(__file__).resolve().parents[3]
    engagements_py = (
        repo_root / "src" / "ai_threat_hunting_cli" / "engagements.py"
    ).read_text(encoding="utf-8")

    assert "Specialist context isolation invariant" in engagements_py, (
        "engagements.py must carry the `Specialist context isolation invariant` comment so "
        "the per-engagement AGENTS.md/CLAUDE.md seeding rule is documented inline"
    )
    # The comment must explicitly point at the registered wrappers as the carrier of the
    # forbid.
    assert "registered wrappers" in engagements_py
    # The forbid is restored: specialists must NOT read agent/AGENTS.md or agent/CLAUDE.md.
    assert "NOT read" in engagements_py and "AGENTS.md" in engagements_py and "CLAUDE.md" in engagements_py, (
        "engagements.py invariant comment must restate the wrapper-side forbid (do NOT read "
        "agent/AGENTS.md or agent/CLAUDE.md)"
    )
    # The cross-cutting home must be named so future readers know where the moved content
    # lives.
    assert "shared-constraints.md" in engagements_py, (
        "engagements.py invariant comment must point at agent/shared-constraints.md as the "
        "cross-cutting home that replaces the AGENTS/CLAUDE bleed"
    )
    # Banner-bleed remains the load-bearing failure mode this guards against.
    assert "banner" in engagements_py.lower()


def test_no_dated_engagement_citations_in_methodology():
    """1Z.19 — engagement citations dated 2026-04-2X (e.g., "SSA VDP 2026-04-26",
    "engagement 2026-04-26", "2026-04-24 SSA engagement") must not appear in methodology
    files. The lesson is timeless; the provenance is not.

    Allowed exceptions: `agent/skills/google-workspaces/SKILL.md` uses 2026-04-2X dates as
    example date ranges in command-line examples, not as engagement provenance."""
    repo_root = Path(__file__).resolve().parents[3]
    pattern = re.compile(r"2026-04-2[0-9]")
    paths: list[Path] = []
    paths.extend(sorted((repo_root / "agent" / "skills").rglob("*.md")))
    paths.extend(sorted((repo_root / "agent" / "references").rglob("*.md")))
    paths.extend(sorted((repo_root / "agent" / "agents").rglob("*.md")))
    for name in ("operator-core.md", "shared-constraints.md"):
        candidate = repo_root / "agent" / name
        if candidate.exists():
            paths.append(candidate)

    # google-workspaces skill uses these dates as command-line example date ranges, not
    # as engagement provenance — exclude it from the drift check.
    excluded = {repo_root / "agent" / "skills" / "google-workspaces" / "SKILL.md"}

    offenders: list[str] = []
    for path in paths:
        if path in excluded:
            continue
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Dated engagement citations (2026-04-2X) remain in the methodology corpus. "
        "Strip the provenance and keep the lesson in neutral, timeless prose.\n"
        + "\n".join(offenders)
    )


def test_osint_recon_pins_org_name_pattern_enumeration_section():
    """1H.3 — osint-recon SKILL.md must carry the org-name pattern enumeration
    methodology and link to the github-osint reference. Org-name single-name
    lookups miss sibling orgs; the pattern enumeration section is what keeps the
    methodology aware of literal-name + parent-name + contractor variants."""
    repo_root = Path(__file__).resolve().parents[3]
    skill = (repo_root / "agent" / "skills" / "osint-recon" / "SKILL.md").read_text(
        encoding="utf-8"
    )

    assert "Org-name Pattern Enumeration" in skill, (
        "osint-recon/SKILL.md must carry the `Org-name Pattern Enumeration` heading"
    )
    # Each pillar of the enumeration must be present so an agent reading the
    # skill cannot collapse the methodology back to a single-name lookup.
    for fragment in (
        "Variants on the literal org name",
        "Variants on the parent agency or parent corporation name",
        "Cross-search public code for discovered org names",
        "public members and recent commit author emails",
        "contractor and vendor names",
    ):
        assert fragment in skill, (
            f"osint-recon/SKILL.md missing org-name pattern fragment: {fragment!r}"
        )
    assert "agent/references/tools/recon/github-osint.md" in skill, (
        "osint-recon/SKILL.md must cross-link to the github-osint reference"
    )


def test_osint_recon_pins_exact_version_triangulation_section():
    """1H.4 — osint-recon SKILL.md must carry the exact-version triangulation
    methodology (source-map APP_VERSION + sister-package dates + vendor
    changelog + Sentry release tag), and the source-analysis SKILL must carry
    the corresponding APP_VERSION extraction grep recipes that feed it."""
    repo_root = Path(__file__).resolve().parents[3]
    osint = (repo_root / "agent" / "skills" / "osint-recon" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    source_analysis = (
        repo_root / "agent" / "skills" / "source-analysis" / "SKILL.md"
    ).read_text(encoding="utf-8")

    # osint-recon side: the triangulation section names every cross-check.
    assert "Exact-version Triangulation" in osint, (
        "osint-recon/SKILL.md must carry the `Exact-version Triangulation` heading"
    )
    for fragment in (
        "Source-map APP_VERSION",
        "Package registry sister-package publish dates",
        "Vendor public release notes",
        "Vendor security bulletins",
        "Sentry release tag",
        "registry.npmjs.org",
        "pypi.org/pypi",
        "search.maven.org",
    ):
        assert fragment in osint, (
            f"osint-recon/SKILL.md missing exact-version triangulation fragment: {fragment!r}"
        )
    assert "agent/references/payloads/version-fingerprint-probes.md" in osint, (
        "osint-recon/SKILL.md must cross-link to the version-fingerprint-probes payload"
    )

    # source-analysis side: APP_VERSION / BUILD_HASH / Sentry-release grep recipes.
    assert "APP_VERSION" in source_analysis, (
        "source-analysis/SKILL.md must extract APP_VERSION constants"
    )
    for fragment in (
        "BUILD_HASH",
        "__GIT_SHA__",
        "Sentry",
    ):
        assert fragment in source_analysis, (
            f"source-analysis/SKILL.md missing version-extraction fragment: {fragment!r}"
        )
    assert "agent/skills/osint-recon/SKILL.md" in source_analysis, (
        "source-analysis/SKILL.md must cross-link back to osint-recon for triangulation"
    )


def test_osint_recon_pins_aith_assess_kali_wrap_rule():
    """Fix #3 — osint-recon SKILL.md must carry a load-bearing top-of-Methodology
    rule that every illustrative shell example wraps in `aith assess kali exec --`
    with the audit envelope. Without this pin, a future edit could re-introduce
    bare host-side `searchsploit`/`theHarvester`/`bbot`/`curl` examples that bypass
    the audit pipeline.
    """
    repo_root = Path(__file__).resolve().parents[3]
    osint = (repo_root / "agent" / "skills" / "osint-recon" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    # Load-bearing rule sentence at the top of Methodology.
    assert "Audit envelope is mandatory" in osint, (
        "osint-recon/SKILL.md missing the top-of-Methodology audit-envelope rule"
    )
    # Every section must be addressed by the rule, not just one.
    for fragment in (
        "Every command in sections 1–6 below is illustrative shell",
        "aith assess kali exec --",
        "--technique OSINT",
        "--probe-kind fingerprint",
    ):
        assert fragment in osint, (
            f"osint-recon/SKILL.md missing audit-envelope rule fragment: {fragment!r}"
        )
    # At least one wrapped example per section 1-4 anchoring the pattern.
    for canonical in (
        "searchsploit lookup for <component>",
        "theHarvester email + subdomain enum",
        "WHOIS lookup for <domain>",
        "theHarvester linkedin/google enumeration",
    ):
        assert canonical in osint, (
            f"osint-recon/SKILL.md missing canonical wrapped example: {canonical!r}"
        )


def test_surface_collection_pins_per_host_url_budget_formula():
    """1D.2 — surface-collection SKILL.md must carry the per-host URL budget
    formula (1000 content-rich / 1000 API-tier / 2000 sitemap-bearing) and
    the recovery flow that re-runs gau on a host with --budget-override
    when classify-work scores deferred clusters above the default cap.

    Round 5 raised the API-tier cap from 200 to 1000 because the lower cap
    silently truncated legitimate microservice surface."""
    repo_root = Path(__file__).resolve().parents[3]
    skill = (
        repo_root / "agent" / "skills" / "surface-collection" / "SKILL.md"
    ).read_text(encoding="utf-8")

    assert "Per-host URL Budget" in skill, (
        "surface-collection/SKILL.md must carry the `Per-host URL Budget` heading"
    )
    # The two numeric tiers must be named explicitly so the formula cannot
    # silently drift. (API-tier shares the 1000 default after Round 5.)
    for fragment in (
        "1000 URLs / host",
        "2000 URLs / host",
        "content-rich",
        "API-tier",
        "sitemap-bearing",
        "--budget-override",
        "deferred:per-host-budget-exceeded",
    ):
        assert fragment in skill, (
            f"surface-collection/SKILL.md missing per-host budget fragment: {fragment!r}"
        )
    # Recovery flow must reference dispatch peek (Wave 3 1D.1).
    assert "dispatch" in skill and "peek" in skill, (
        "surface-collection/SKILL.md must reference `aith assess dispatch peek` for recovery"
    )


def test_references_index_registers_new_files_for_1h3_and_1h4():
    """1H.3 + 1H.4 — INDEX.md must register the github-osint and
    version-fingerprint-probes references so agents can find them via the
    canonical reference library lookup."""
    repo_root = Path(__file__).resolve().parents[3]
    index = (repo_root / "agent" / "references" / "INDEX.md").read_text(encoding="utf-8")

    # 1H.3 — github-osint
    assert "tools/recon/github-osint.md" in index, (
        "INDEX.md must register tools/recon/github-osint.md (1H.3)"
    )
    # 1H.4 — version-fingerprint-probes
    assert "payloads/version-fingerprint-probes.md" in index, (
        "INDEX.md must register payloads/version-fingerprint-probes.md (1H.4)"
    )


def test_osint_analyst_self_check_carries_org_pattern_and_version_triangulation():
    """1H.3 + 1H.4 — osint-analyst.md must carry the Pre-Output Self-Check
    items for org-name pattern enumeration AND exact-version triangulation."""
    repo_root = Path(__file__).resolve().parents[3]
    text = (repo_root / "agent" / "agents" / "osint-analyst.md").read_text(encoding="utf-8")

    assert "Pre-Output Self-Check" in text, (
        "osint-analyst.md must carry the `Pre-Output Self-Check` heading"
    )
    # 1H.3 self-check
    assert "Org-name pattern enumeration" in text, (
        "osint-analyst.md self-check must include Org-name pattern enumeration item (1H.3)"
    )
    assert "commit-author emails" in text, (
        "osint-analyst.md self-check must include commit-author email mining item (1H.3)"
    )
    # 1H.4 self-check
    assert "Exact-version triangulation" in text, (
        "osint-analyst.md self-check must include Exact-version triangulation item (1H.4)"
    )


def test_source_analyzer_self_check_carries_app_version_extraction():
    """1H.4 — source-analyzer.md self-check must include the APP_VERSION /
    BUILD_HASH / Sentry-release extraction step and the handoff to
    osint-analyst for triangulation."""
    repo_root = Path(__file__).resolve().parents[3]
    text = (repo_root / "agent" / "agents" / "source-analyzer.md").read_text(encoding="utf-8")

    assert "APP_VERSION" in text, (
        "source-analyzer.md self-check must include APP_VERSION extraction item (1H.4)"
    )
    assert "Sentry-release" in text or "Sentry release" in text, (
        "source-analyzer.md self-check must reference Sentry release-tag extraction (1H.4)"
    )
    assert "osint-analyst" in text, (
        "source-analyzer.md self-check must mention the handoff to osint-analyst (1H.4)"
    )


def test_surface_collector_accepts_per_host_budget_override():
    """1D.2 — surface-collector.md must document accepting `--budget-override`
    from operator dispatch context."""
    repo_root = Path(__file__).resolve().parents[3]
    text = (repo_root / "agent" / "agents" / "surface-collector.md").read_text(
        encoding="utf-8"
    )
    assert "Per-host URL Budget" in text, (
        "surface-collector.md must document the per-host URL budget"
    )
    assert "--budget-override" in text, (
        "surface-collector.md must accept --budget-override from the operator (1D.2)"
    )


def test_vendor_platform_enum_skill_registered():
    """1H.1 — `vendor-platform-enum` skill must be registered in the skill index, and the
    four paired payload references must be listed in the references INDEX. The skill
    deep-enumerates Salesforce SObjects, ServiceNow GlideRecord rows, Drupal JSON:API
    entities, and Pexip admin-API namespaces when one read primitive surfaces; without
    the registration entries, the operator and specialists cannot discover it."""
    repo_root = Path(__file__).resolve().parents[3]
    skill_index = (repo_root / "agent" / "SKILL.md").read_text(encoding="utf-8")
    references_index = (repo_root / "agent" / "references" / "INDEX.md").read_text(
        encoding="utf-8"
    )
    skill_path = (
        repo_root / "agent" / "skills" / "vendor-platform-enum" / "SKILL.md"
    )
    assert skill_path.exists(), (
        "agent/skills/vendor-platform-enum/SKILL.md must exist as the deep-enum skill (1H.1)"
    )

    # Skill index registration with paired references list.
    assert "agent/skills/vendor-platform-enum/SKILL.md" in skill_index, (
        "agent/SKILL.md must register `vendor-platform-enum` (1H.1)"
    )
    for payload in (
        "salesforce-aura-payloads.md",
        "servicenow-glide-payloads.md",
        "drupal-jsonapi-payloads.md",
        "pexip-admin-api-payloads.md",
    ):
        assert payload in skill_index, (
            f"agent/SKILL.md vendor-platform-enum entry must list `{payload}` as a paired "
            f"reference (1H.1)"
        )
        assert payload in references_index, (
            f"agent/references/INDEX.md must list `payloads/{payload}` (1H.1)"
        )

    # Skill body must document the four playbooks plus the IDOR boundedness test that is
    # the load-bearing severity-decision input.
    skill_text = skill_path.read_text(encoding="utf-8")
    assert "Salesforce Aura" in skill_text
    assert "ServiceNow GlideRecord" in skill_text
    assert "Drupal JSON:API" in skill_text
    assert "Pexip" in skill_text
    assert "bounded-vs-systemic" in skill_text.lower(), (
        "vendor-platform-enum/SKILL.md must document the bounded-vs-systemic IDOR test (1H.1)"
    )


def test_csp_default_grep_methodology_present():
    """1H.2 — vendor-template CSP/CORS re-baseline check must appear in web-recon and
    source-analysis skills (so both recon-specialist and source-analyzer fire it when a
    vendor product fingerprints), and the csp-default-grep payload reference must be
    registered in the references INDEX."""
    repo_root = Path(__file__).resolve().parents[3]
    web_recon = (repo_root / "agent" / "skills" / "web-recon" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    source_analysis = (
        repo_root / "agent" / "skills" / "source-analysis" / "SKILL.md"
    ).read_text(encoding="utf-8")
    references_index = (repo_root / "agent" / "references" / "INDEX.md").read_text(
        encoding="utf-8"
    )
    payload_path = (
        repo_root / "agent" / "references" / "payloads" / "csp-default-grep.md"
    )
    assert payload_path.exists(), (
        "agent/references/payloads/csp-default-grep.md must exist (1H.2)"
    )

    # web-recon must carry the vendor-template re-baseline step and reference the payload.
    assert "Vendor-template CSP/CORS re-baseline" in web_recon, (
        "web-recon/SKILL.md must add the `Vendor-template CSP/CORS re-baseline` step (1H.2)"
    )
    assert "csp-default-grep.md" in web_recon, (
        "web-recon/SKILL.md must cross-link `csp-default-grep.md` (1H.2)"
    )

    # source-analysis must carry the vendor-product CSP re-baseline step.
    assert "Vendor-product CSP / CORS re-baseline" in source_analysis or (
        "Vendor-product CSP/CORS re-baseline" in source_analysis
    ), (
        "source-analysis/SKILL.md must add the vendor-product CSP/CORS re-baseline step (1H.2)"
    )
    assert "csp-default-grep.md" in source_analysis, (
        "source-analysis/SKILL.md must cross-link `csp-default-grep.md` (1H.2)"
    )

    # Reference registered in INDEX.
    assert "payloads/csp-default-grep.md" in references_index, (
        "references/INDEX.md must list `payloads/csp-default-grep.md` (1H.2)"
    )

    # info-disclosure-testing carries the cross-link.
    info_disc = (
        repo_root / "agent" / "skills" / "info-disclosure-testing" / "SKILL.md"
    ).read_text(encoding="utf-8")
    assert "csp-default-grep.md" in info_disc, (
        "info-disclosure-testing/SKILL.md must cross-link `csp-default-grep.md` (1H.2)"
    )


def test_cross_host_tls_san_methodology_present():
    """1H.5 — multi-time DNS resolution + cross-host SAN collision detection + vhost-cert
    mismatch must appear in web-recon, the openssl-sans recipe must exist and be
    registered, port-scanning must cross-link, and subdomain-enumeration must add the
    `TLS SAN extraction as a primary source` section."""
    repo_root = Path(__file__).resolve().parents[3]
    web_recon = (repo_root / "agent" / "skills" / "web-recon" / "SKILL.md").read_text(
        encoding="utf-8"
    )
    port_scanning = (
        repo_root / "agent" / "skills" / "port-scanning" / "SKILL.md"
    ).read_text(encoding="utf-8")
    subdomain_enum = (
        repo_root / "agent" / "skills" / "subdomain-enumeration" / "SKILL.md"
    ).read_text(encoding="utf-8")
    references_index = (repo_root / "agent" / "references" / "INDEX.md").read_text(
        encoding="utf-8"
    )
    recipe_path = (
        repo_root / "agent" / "references" / "tools" / "recon" / "openssl-sans.md"
    )
    assert recipe_path.exists(), (
        "agent/references/tools/recon/openssl-sans.md must exist (1H.5)"
    )

    # web-recon must add the multi-time DNS, cross-host SAN collision, and vhost-mismatch
    # methodology. The exact loop signature is the load-bearing pin.
    assert "Multi-time DNS resolution" in web_recon, (
        "web-recon/SKILL.md must add the `Multi-time DNS resolution` step (1H.5)"
    )
    assert "for i in 1 2 3 4 5; do dig +short" in web_recon, (
        "web-recon/SKILL.md must show the `for i in 1 2 3 4 5; do dig +short ...` "
        "multi-time DNS loop (1H.5)"
    )
    assert "Cross-host SAN collision" in web_recon, (
        "web-recon/SKILL.md must add the `Cross-host SAN collision` step (1H.5)"
    )
    assert "vhost-cert mismatch" in web_recon.lower(), (
        "web-recon/SKILL.md must add the vhost-cert mismatch step (1H.5)"
    )
    assert "openssl-sans.md" in web_recon, (
        "web-recon/SKILL.md must cross-link `openssl-sans.md` (1H.5)"
    )

    # port-scanning carries the multi-time DNS cross-link.
    assert "Multi-time DNS resolution" in port_scanning, (
        "port-scanning/SKILL.md must add the multi-time DNS cross-link (1H.5)"
    )
    assert "openssl-sans.md" in port_scanning, (
        "port-scanning/SKILL.md must cross-link `openssl-sans.md` (1H.5)"
    )

    # subdomain-enumeration carries the SAN-as-primary section.
    assert "TLS SAN extraction as a primary source" in subdomain_enum, (
        "subdomain-enumeration/SKILL.md must add the `TLS SAN extraction as a primary "
        "source` section (1H.5)"
    )
    assert "openssl-sans.md" in subdomain_enum, (
        "subdomain-enumeration/SKILL.md must cross-link `openssl-sans.md` (1H.5)"
    )

    # Reference registered in INDEX.
    assert "tools/recon/openssl-sans.md" in references_index, (
        "references/INDEX.md must list `tools/recon/openssl-sans.md` (1H.5)"
    )


def test_recon_specialist_self_check_pins_san_and_dns_items():
    """1H.5 — recon-specialist.md self-check must include per-host TLS SAN extraction,
    multi-time DNS resolution, and cross-host SAN collision check items."""
    repo_root = Path(__file__).resolve().parents[3]
    text = (repo_root / "agent" / "agents" / "recon-specialist.md").read_text(
        encoding="utf-8"
    )
    assert "Per-host TLS SAN extracted" in text, (
        "recon-specialist.md self-check must include the per-host TLS SAN extraction "
        "item (1H.5)"
    )
    assert "Multi-time DNS resolution run" in text, (
        "recon-specialist.md self-check must include the multi-time DNS resolution "
        "item (1H.5)"
    )
    assert "Cross-host SAN collision check run" in text, (
        "recon-specialist.md self-check must include the cross-host SAN collision check "
        "item (1H.5)"
    )


def test_source_analyzer_self_check_pins_vendor_deep_enum_and_csp_recheck():
    """1H.1 + 1H.2 — source-analyzer.md self-check must include the vendor-platform
    deep-enum playbook trigger and the vendor-template CSP/CORS re-baseline check."""
    repo_root = Path(__file__).resolve().parents[3]
    text = (repo_root / "agent" / "agents" / "source-analyzer.md").read_text(
        encoding="utf-8"
    )
    assert "Vendor-platform deep-enum playbook run" in text, (
        "source-analyzer.md self-check must include the vendor-platform deep-enum "
        "playbook trigger (1H.1)"
    )
    assert "Vendor-template CSP / CORS re-baseline" in text or (
        "Vendor-template CSP/CORS re-baseline" in text
    ), (
        "source-analyzer.md self-check must include the vendor-template CSP/CORS "
        "re-baseline check (1H.2)"
    )


def test_vulnerability_analyst_self_check_pins_vendor_deep_enum():
    """1H.1 — vulnerability-analyst.md must include the vendor-platform deep-enum
    playbook trigger in its Pre-Output self-check."""
    repo_root = Path(__file__).resolve().parents[3]
    text = (repo_root / "agent" / "agents" / "vulnerability-analyst.md").read_text(
        encoding="utf-8"
    )
    assert "Vendor-platform deep-enum playbook run" in text, (
        "vulnerability-analyst.md self-check must include the vendor-platform deep-enum "
        "playbook trigger (1H.1)"
    )


# ──────────────────────────────────────────────────────────────────────────
# Wave 2 — methodology drift guards (F13 / F18 / F19 / F22)
# ──────────────────────────────────────────────────────────────────────────


def _wave2_methodology_paths():
    """Files that must stay aligned with the canonical Wave 2 settings.
    Includes skills, agent role files, recon-tool references, and operator-core."""
    repo_root = Path(__file__).resolve().parents[3]
    paths: list[Path] = []
    paths.extend(sorted((repo_root / "agent" / "skills").rglob("*.md")))
    paths.extend(
        sorted((repo_root / "agent" / "references" / "tools" / "recon").rglob("*.md"))
    )
    paths.extend(sorted((repo_root / "agent" / "agents").rglob("*.md")))
    paths.append(repo_root / "agent" / "operator-core.md")
    # Filter to existing files; the rglob covers the live tree but defensive.
    return [p for p in paths if p.exists()]


def test_dated_engagement_drift_guard_is_broad_enough():
    """F18 — the engagement-citation drift guard catches ISO dates that look
    like engagement provenance (not just 2026-04-2X), and catches named-engagement
    patterns like `SSA engagement` / `CMS VDP` so the lesson stays timeless and
    the provenance does not bleed back in over time.

    The original 1Z.19 guard scanned only `2026-04-2[0-9]` — too narrow when
    a Wave 2 specialist sneaks in a `2026-05-01` date. We broaden to any
    ISO date that appears in an engagement-provenance context:
      - "engagement <date>" / "VDP <date>" / "<date> engagement"
      - "<acronym> engagement <date>" / "engagement on <date>"
      - lines that already match a named-engagement pattern (SSA / CMS / VA / HHS).

    Cloud-metadata `api-version=YYYY-MM-DD` strings, breach-published dates
    in JSON examples, and other legitimate ISO-date prose are NOT engagement
    provenance and are left alone.
    """
    repo_root = Path(__file__).resolve().parents[3]
    iso = r"\d{4}-\d{2}-\d{2}"
    # Engagement-provenance-shaped ISO dates: paired with words like
    # "engagement", "VDP", "assessment", or with a named federal agency.
    provenance_patterns = [
        re.compile(rf"\b(engagement|assessment|VDP)\s+{iso}\b", re.IGNORECASE),
        re.compile(rf"\b{iso}\s+(engagement|assessment|VDP)\b", re.IGNORECASE),
        re.compile(rf"\bengagement\s+(?:on|of|dated)\s+{iso}\b", re.IGNORECASE),
        re.compile(rf"\b(SSA|CMS|VA|HHS)\b[^\n]*\b{iso}\b"),
        re.compile(rf"\b{iso}\b[^\n]*\b(SSA|CMS|VA|HHS)\b"),
    ]
    named_engagement_pattern = re.compile(
        r"\b(SSA|CMS|VA|HHS)\b\s+(engagement|VDP)", re.IGNORECASE
    )

    # google-workspaces uses ISO date ranges in command-line examples (not
    # engagement provenance) — same allowlist as the 1Z.19 test.
    excluded = {repo_root / "agent" / "skills" / "google-workspaces" / "SKILL.md"}
    # The osint-recon SKILL legitimately references `breach-record` published
    # dates in field examples and is allowed to embed example dates.
    osint_skill = repo_root / "agent" / "skills" / "osint-recon" / "SKILL.md"
    if osint_skill.exists():
        excluded.add(osint_skill)

    iso_offenders: list[str] = []
    named_offenders: list[str] = []
    for path in _wave2_methodology_paths():
        if path in excluded:
            continue
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern in provenance_patterns:
                if pattern.search(line):
                    iso_offenders.append(f"{path}:{lineno}: {line.strip()}")
                    break
            if named_engagement_pattern.search(line):
                named_offenders.append(f"{path}:{lineno}: {line.strip()}")

    assert not iso_offenders, (
        "ISO-date engagement provenance in methodology corpus (F18). "
        "Strip the date and keep the lesson timeless.\n" + "\n".join(iso_offenders)
    )
    assert not named_offenders, (
        "Named-engagement provenance (e.g. `SSA engagement`, `CMS VDP`) in "
        "methodology corpus (F18). Strip the brand and keep the lesson neutral.\n"
        + "\n".join(named_offenders)
    )


def test_dns_brute_rates_are_canonical_tier_values():
    """F19 — DNS-brute `--rate-limit` values for puredns/shuffledns must be one
    of {800, 2500, 5000} (polite-CDN-fronted-target / polite-residential /
    bursty-OK). Pre-Wave-2 drift left `--rate-limit 1000` and `--rate-limit 8000`
    strewn across SKILLs and references; this guard pins the canonical tier set.

    Scope: only the puredns/shuffledns long-form `--rate-limit` flag is
    constrained. dnsx uses `-rl <int>` on a different scale (per-resolver vs.
    overall), and per-resolver examples like `-rl 10` are intentionally low
    and outside the canonical-profile set; this guard does not constrain them.
    """
    rate_pattern = re.compile(r"--rate-limit\s+(\d+)\b")
    canonical_puredns_rates = {"800", "2500", "5000"}

    offenders: list[str] = []
    for path in _wave2_methodology_paths():
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip().lower()
            # --rate-limit applies to puredns / nuclei / shuffledns. Filter to
            # puredns/shuffledns/dns-brute mentions on the same line; nuclei
            # `--rate-limit 30/100/150` is its own scale and lives in a
            # different tier table.
            for match in rate_pattern.finditer(line):
                rate = match.group(1)
                is_dns_context = (
                    "puredns" in stripped
                    or "shuffledns" in stripped
                    or "dns brute" in stripped
                    or "dns-brute" in stripped
                )
                if is_dns_context and rate not in canonical_puredns_rates:
                    offenders.append(
                        f"{path}:{lineno}: --rate-limit {rate} (must be "
                        f"one of {sorted(canonical_puredns_rates)} for puredns/shuffledns)"
                    )

    assert not offenders, (
        "DNS-brute rates drifted from the canonical tier set (F19). "
        "Update to a tier value or fix the tier table.\n" + "\n".join(offenders)
    )


def test_nuclei_template_set_uses_http_prefix_and_comma_join():
    """F13 — the curated nuclei template set must use the comma-joined
    `-t http/cves/,http/misconfiguration/,...` shape. The `-t cves/ -t exposures/`
    shape from older skills uses repeated -t flags AND drops the `http/` prefix
    so non-HTTP variants leak in. Operator-core has the canonical form; this
    guard pins web-recon and recon-specialist to the same shape.
    """
    repo_root = Path(__file__).resolve().parents[3]
    files = (
        repo_root / "agent" / "skills" / "web-recon" / "SKILL.md",
        repo_root / "agent" / "agents" / "recon-specialist.md",
    )
    drift_pattern = re.compile(r"-t\s+(?!http/)(cves|exposures|misconfiguration|default-logins|exposed-panels|technologies)/")
    offenders: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if drift_pattern.search(line):
                offenders.append(f"{path}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Nuclei template drift (F13): `-t <category>/` without the `http/` prefix "
        "leaks non-HTTP variants. Use the comma-joined "
        "`-t http/cves/,http/misconfiguration/,...` form.\n" + "\n".join(offenders)
    )


def test_subdomain_enum_preflight_binary_order_is_alphabetical():
    """F22 — operator-core, the subdomain-enumeration SKILL, and the runtime
    tooling contract test all reference the same preflight binary list. Pin
    the order to alphabetical so future drift in any one of the three is
    caught loudly."""
    repo_root = Path(__file__).resolve().parents[3]
    canonical = "alterx asnmap bbot cero dnsx massdns puredns shuffledns subfinder"

    skill = (
        repo_root / "agent" / "skills" / "subdomain-enumeration" / "SKILL.md"
    ).read_text(encoding="utf-8")
    assert canonical in skill, (
        "subdomain-enumeration/SKILL.md preflight binary list is not alphabetical "
        f"(F22). Canonical order: `{canonical}`."
    )

    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    assert canonical in operator_core, (
        "operator-core.md preflight binary list is not alphabetical (F22). "
        f"Canonical order: `{canonical}`."
    )


def test_raw_kali_exec_examples_put_audit_flags_before_separator():
    """Raw `kali exec` examples must put audit flags before the `--` separator.

    argparse treats everything after `--` as the user command, so examples such
    as `aith assess kali exec -- tail ... --technique RECON` fail before a row
    is recorded. Pin the source corpus plus rendered wrappers against that
    regression.
    """
    repo_root = Path(__file__).resolve().parents[3]
    paths = [
        repo_root / "agent" / "operator-core.md",
        repo_root / "agent" / "AGENTS.md",
        repo_root / "agent" / "CLAUDE.md",
        repo_root / "agent" / "shared-constraints.md",
    ]
    for subdir in ("agents", "skills", "references"):
        paths.extend(sorted((repo_root / "agent" / subdir).rglob("*.md")))

    invalid_raw_separator = re.compile(r"aith assess kali exec\s+--\s+(?!technique\b)")
    offenders: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if invalid_raw_separator.search(line):
                offenders.append(f"{path}:{lineno}: {line.strip()}")

    assert not offenders, (
        "`aith assess kali exec` examples must put audit flags before the raw "
        "`-- <command>` separator.\n" + "\n".join(offenders)
    )


def test_shared_constraints_lists_non_attack_kali_techniques():
    repo_root = Path(__file__).resolve().parents[3]
    shared = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")
    for technique in ("META", "HEALTH", "LOG-READ"):
        assert technique in shared, (
            "shared-constraints.md must list the operator-side technique enum "
            f"{technique}; otherwise agents fall back to OTHER for valid maintenance runs"
        )


def test_scan_type_pseudo_values_removed_from_skills():
    """F1 drift guard — `--scan-type top-1000` / `full-tcp` / `udp-top` /
    `targeted` / `ports-only` were old skill-text drift values that the
    nmap-scan wrapper has never accepted. Re-introducing one of them silently
    fails argparse downstream; pin them out of the skill corpus."""
    repo_root = Path(__file__).resolve().parents[3]
    drift_pattern = re.compile(r"--scan-type\s+(top-1000|full-tcp|udp-top|targeted|ports-only)\b")
    offenders: list[str] = []
    paths = sorted((repo_root / "agent" / "skills").rglob("*.md")) + sorted(
        (repo_root / "agent" / "agents").rglob("*.md")
    ) + sorted((repo_root / "agent" / "references" / "tools" / "recon").rglob("*.md"))
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if drift_pattern.search(line):
                offenders.append(f"{path}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Drift values for `--scan-type` (F1) — the wrapper restricts "
        "`--scan-type` to nmap technique flags (sS/sT/sU/sV/sn). Use `--ports "
        "<value>` for port specs.\n" + "\n".join(offenders)
    )


def test_operator_core_pins_render_handoff_helper_in_cross_dispatch_continuity():
    """Fix #7: operator-core's "Cross-Dispatch Continuity" must lead with the
    `render-handoff` helper so operators stop pasting transcript excerpts.

    Pinning this here keeps the rendered operator/specialist wrappers honest
    when the wave-end re-render runs — if the helper sentence regresses out
    of operator-core, the wrappers regenerate without it and parallel
    continuation dispatches drift back to unbounded transcript pastes."""
    repo_root = Path(__file__).resolve().parents[3]
    operator_core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")

    # The Cross-Dispatch Continuity section must contain the explicit helper
    # invocation. This is the load-bearing sentence — without it the section
    # reverts to "keep handoff prompts bounded" prose discipline.
    assert (
        "aith assess dispatch render-handoff <agent-id>" in operator_core
    ), "operator-core.md no longer references `aith assess dispatch render-handoff <agent-id>`"
    assert (
        "paste its output into the next dispatch" in operator_core
    ), "operator-core.md no longer instructs operators to paste the rendered blob"

    # The next-step recording must call out next_step explicitly so the
    # registry-write step covers the field the renderer always emits.
    assert "next_step" in operator_core, (
        "operator-core.md no longer mentions the registry's `next_step` field; "
        "the renderer reads it directly so the registry-write instruction "
        "must name it."
    )


def test_handoff_schema_reference_exists_and_indexed():
    """Round 9 — the handoff JSON schema lives in
    `agent/references/runtime-guides/handoff-schema.md` and must be registered in
    the references INDEX. Every specialist role file points at this file from its
    Mandatory Closing Sequence; if the file or the index entry drifts away the
    pointer breaks."""
    repo_root = Path(__file__).resolve().parents[3]
    schema = (
        repo_root / "agent" / "references" / "runtime-guides" / "handoff-schema.md"
    )
    assert schema.exists(), "agent/references/runtime-guides/handoff-schema.md must exist"
    text = schema.read_text(encoding="utf-8")
    # Top-level structure markers.
    for needle in (
        "## Schema",
        "## Field-by-field guidance",
        "## Per-role examples",
        "## CLI usage",
    ):
        assert needle in text, f"handoff-schema.md is missing the `{needle}` section"
    # Required schema fields.
    for field in (
        "agent_id",
        "agent_role",
        "phase",
        "summary",
        "confidence",
        "finding_slugs",
        "coverage_gaps",
        "next_steps",
        "runtime_issues",
        "working_artifacts",
        "open_questions",
        "recommended_next_agent",
        "extras",
    ):
        assert f"`{field}`" in text, f"handoff-schema.md is missing the `{field}` field"
    # CLI usage names the canonical helper.
    assert "aith assess dispatch record-handoff --from-json" in text, (
        "handoff-schema.md must document the `record-handoff --from-json` CLI"
    )
    # INDEX.md registers the new file.
    index = (repo_root / "agent" / "references" / "INDEX.md").read_text(encoding="utf-8")
    assert "runtime-guides/handoff-schema.md" in index, (
        "agent/references/INDEX.md must register `runtime-guides/handoff-schema.md`"
    )


def test_subagent_registry_documents_backend_tables():
    """Round 9 — `agent/references/runtime-guides/subagent-registry.md` was rewritten
    to document the three backend dispatch tables (assessment_dispatches,
    assessment_dispatch_handoffs, assessment_dispatch_decisions) and their CLI
    verbs. The previous JSON-file framing (`$DIR/agent-registry.json`) is removed
    as the canonical mechanism — the file mention may remain only in the
    "previous file is removed" sentence."""
    repo_root = Path(__file__).resolve().parents[3]
    text = (
        repo_root / "agent" / "references" / "runtime-guides" / "subagent-registry.md"
    ).read_text(encoding="utf-8")

    # Backend table names appear.
    for table in (
        "assessment_dispatches",
        "assessment_dispatch_handoffs",
        "assessment_dispatch_decisions",
    ):
        assert table in text, f"subagent-registry.md must document the `{table}` table"
    # CLI verbs are documented.
    for verb in (
        "dispatch register",
        "dispatch update-status",
        "dispatch list",
        "dispatch get",
        "dispatch record-decision",
        "dispatch record-handoff",
        "dispatch render-handoff",
    ):
        assert verb in text, f"subagent-registry.md must document the `aith assess {verb}` verb"
    # Decision kinds appear.
    for kind in ("scope_decision", "egress_decision", "dispatch_blocked"):
        assert kind in text, f"subagent-registry.md must document the `{kind}` decision kind"


def test_shared_constraints_carries_output_hygiene_section():
    """Round 9b — the "Output Hygiene — Backend Is Canonical" section in
    `agent/shared-constraints.md` keeps the backend-canonical rule and the
    mandatory closing sequence, but the prescriptive minimal-output template
    Round 9 introduced was walked back per Anthropic's April 2026 postmortem
    (https://www.anthropic.com/engineering/april-23-postmortem) — restrictive
    response-shape instructions degraded reasoning quality. The section heading
    and the record-handoff step remain; the "Wrote to backend / ≤200 chars /
    That's it" template is gone."""
    repo_root = Path(__file__).resolve().parents[3]
    sc = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")

    # Section header — heading stays.
    assert "Output Hygiene" in sc, (
        "shared-constraints.md must carry the `Output Hygiene` section heading"
    )
    assert "Backend Is Canonical" in sc, (
        "shared-constraints.md `Output Hygiene` section must carry the "
        "`Backend Is Canonical` framing"
    )

    # Mandatory-closing-sequence anchor must stay.
    assert "Mandatory closing sequence" in sc or "Mandatory Closing Sequence" in sc, (
        "shared-constraints.md `Output Hygiene` section must keep the "
        "mandatory closing sequence list"
    )
    assert "render-handoff" in sc, (
        "shared-constraints.md `Output Hygiene` section must reference "
        "`render-handoff` so operators know how to read canonical state"
    )

    # The closing-sequence step list ends on record-handoff.
    assert "aith assess dispatch record-handoff --from-json" in sc, (
        "shared-constraints.md `Output Hygiene` section must reference the "
        "`aith assess dispatch record-handoff --from-json` closing step"
    )

    # The handoff schema reference resolves to the new file.
    assert "agent/references/runtime-guides/handoff-schema.md" in sc, (
        "shared-constraints.md `Output Hygiene` section must point at the "
        "handoff-schema.md reference"
    )

    # Positive guard: the softened framing must explicitly preserve reasoning
    # quality. This is the Round 9b walk-back signal — without it, the section
    # could drift back toward terse-response prescriptions.
    assert "Reasoning quality" in sc or "Don't truncate" in sc, (
        "shared-constraints.md `Output Hygiene` section must carry the "
        "softened `Reasoning quality > response brevity` framing (Round 9b)"
    )

    # Anti-pattern guard: the prescriptive Round 9 template literals must NOT
    # reappear. They contradict Anthropic's published prompting guidance and
    # caused observable reasoning degradation in Round 10 testing.
    forbidden = (
        "≤200 chars",
        "That's it",
        "**Wrote to backend:**",
    )
    offenders = [needle for needle in forbidden if needle in sc]
    assert not offenders, (
        "shared-constraints.md `Output Hygiene` section must NOT carry the "
        "Round 9 prescriptive template fragments (Anthropic April 2026 "
        f"postmortem walk-back); found: {offenders}"
    )


def test_specialist_role_files_carry_mandatory_closing_sequence():
    """Round 9 — every specialist role file must carry a `Mandatory Closing
    Sequence` section that ends on `aith assess dispatch record-handoff
    --from-json`. Without it, the role drifts back to writing markdown sections
    that duplicate backend state."""
    repo_root = Path(__file__).resolve().parents[3]
    agent_dir = repo_root / "agent" / "agents"
    specialists = [
        "recon-specialist",
        "source-analyzer",
        "surface-collector",
        "vulnerability-analyst",
        "exploit-developer",
        "fuzzer",
        "osint-analyst",
        "report-writer",
        "code-architect",
        "code-vuln-hunter",
        "code-variant-hunter",
        "code-vuln-verifier",
    ]
    for name in specialists:
        path = agent_dir / f"{name}.md"
        text = path.read_text(encoding="utf-8")
        assert "## Mandatory Closing Sequence" in text, (
            f"{name}.md must carry a `## Mandatory Closing Sequence` section"
        )
        assert "aith assess dispatch record-handoff --from-json" in text, (
            f"{name}.md `Mandatory Closing Sequence` must reference "
            "`aith assess dispatch record-handoff --from-json`"
        )
        assert "agent/references/runtime-guides/handoff-schema.md" in text, (
            f"{name}.md must point at the handoff-schema.md reference"
        )
        # Round 9c — every role file's closing sequence must point specialists
        # at the incremental-checkpoint pattern, so they call record-handoff
        # after each major step rather than only at the end. Either word is
        # acceptable; the schema doc owns the per-role cadence.
        lower = text.lower()
        assert ("idempotent" in lower) or ("checkpoint" in lower), (
            f"{name}.md `Mandatory Closing Sequence` must reference "
            "`idempotent` or `checkpoint` so the agent calls record-handoff "
            "incrementally, not just at the end "
            "(see `agent/references/runtime-guides/handoff-schema.md` "
            "\"Checkpointing\")"
        )


def test_handoff_schema_doc_carries_checkpointing_section():
    """Round 9c — `agent/references/runtime-guides/handoff-schema.md` is the
    single owner of the incremental-checkpoint pattern and per-role cadence.
    The role files reference it; this test ensures the section actually exists
    so those references don't dangle."""
    repo_root = Path(__file__).resolve().parents[3]
    schema = (
        repo_root / "agent" / "references" / "runtime-guides" / "handoff-schema.md"
    ).read_text(encoding="utf-8")
    assert "## Checkpointing" in schema, (
        "handoff-schema.md must carry a `## Checkpointing` section that "
        "documents the incremental-checkpoint pattern"
    )
    # Positive guard for cadence guidance — the section names per-role cadence.
    assert "checkpoint after each" in schema.lower(), (
        "handoff-schema.md `Checkpointing` section must describe the "
        "after-each-step cadence"
    )
    # The section must call out idempotent semantics so agents understand a
    # repeat call replaces (not duplicates) the prior row.
    assert "idempotent" in schema.lower(), (
        "handoff-schema.md `Checkpointing` section must call out that "
        "record-handoff is idempotent"
    )


def test_shared_constraints_section_16_points_at_checkpoint_pattern():
    """Round 9c — `shared-constraints.md` §16 is the always-loaded layer that
    every specialist sees on dispatch. The mandatory-closing-sequence list
    there must reference the checkpoint pattern documented in
    handoff-schema.md so agents discover it."""
    repo_root = Path(__file__).resolve().parents[3]
    sc = (repo_root / "agent" / "shared-constraints.md").read_text(encoding="utf-8")
    assert "agent/references/runtime-guides/handoff-schema.md" in sc, (
        "shared-constraints.md must link to handoff-schema.md"
    )
    # The pointer to the Checkpointing pattern should explicitly call it out.
    lower = sc.lower()
    assert "incrementally" in lower or "checkpoint" in lower, (
        "shared-constraints.md §16 must reference incremental checkpointing"
    )


def test_no_strace_or_dedup_block_in_owned_corpus():
    """Round 9 — `--strace` and `KALI_AUDIT_DEDUP_BLOCK` were removed from kali.py
    by the parallel backend cutover. The prompt corpus this PR owns (skills,
    agents, references, shared-constraints, operator-core, .env.example) must
    not reference either."""
    repo_root = Path(__file__).resolve().parents[3]
    paths: list[Path] = []
    for sub in ("skills", "agents", "references"):
        paths.extend(sorted((repo_root / "agent" / sub).rglob("*.md")))
    for name in (
        "operator-core.md",
        "operator-core-code.md",
        "shared-constraints.md",
        "shared-constraints-code.md",
        ".env.example",
    ):
        candidate = repo_root / "agent" / name
        if candidate.exists():
            paths.append(candidate)

    offenders: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if "--strace" in text:
            offenders.append(f"{path}: contains `--strace`")
        if "KALI_AUDIT_DEDUP_BLOCK" in text:
            offenders.append(f"{path}: contains `KALI_AUDIT_DEDUP_BLOCK`")
    assert not offenders, (
        "Round 9 cleanup — `--strace` and `KALI_AUDIT_DEDUP_BLOCK` are no longer "
        "supported by the kali CLI. Drop both from the prompt corpus.\n"
        + "\n".join(offenders)
    )


def test_kali_verb_count_consistent_across_operator_facing_docs():
    """Verb-count drift guard. The operator-facing docs (operator-core / rendered
    AGENTS / rendered CLAUDE / kali-cli runtime guide / kali-exec skill) all cite a
    verb count for `aith assess kali`. A future refactor that adds a verb to
    `agent/scripts/assess/cli.py` but forgets to update one of these docs leaves
    the operator with stale guidance — exactly the drift this branch caught (19 /
    19 / 19 / 15 / 20 across the five docs before the fix). Pin them together so
    the next add-a-verb refactor cannot diverge without tripping CI.

    The truth is the count of `kali_*.py` modules registered in
    `agent/scripts/assess/cli.py` (each module is one verb). Read that count
    and assert every operator-facing doc cites the same number."""
    repo_root = Path(__file__).resolve().parents[3]

    cli_path = repo_root / "agent" / "scripts" / "assess" / "cli.py"
    cli_text = cli_path.read_text(encoding="utf-8")

    # Extract the kali-verb registration block: every name in the
    # `for kali_mod in ( kali_alterx, ..., kali_whatweb ): kali_mod.register(kali_sub)`
    # tuple maps to one registered verb. Module names include digits (kali_wafw00f),
    # so [a-z0-9_] not [a-z_].
    block_match = re.search(
        r"for kali_mod in \(([^)]+)\)",
        cli_text,
        re.DOTALL,
    )
    assert block_match is not None, (
        "could not locate the kali-verb registration block in "
        "agent/scripts/assess/cli.py — the verb-count drift guard cannot run"
    )
    registered_modules = re.findall(r"kali_[a-z0-9_]+", block_match.group(1))
    expected_count = len(registered_modules)
    assert expected_count > 0, (
        "no kali_* modules found in cli.py registration block"
    )

    docs_to_check = [
        repo_root / "agent" / "operator-core.md",
        repo_root / "agent" / "AGENTS.md",
        repo_root / "agent" / "CLAUDE.md",
        repo_root / "agent" / "references" / "runtime-guides" / "kali-cli.md",
        repo_root / "agent" / "skills" / "kali-exec" / "SKILL.md",
    ]

    # Match phrases like:
    #   "should list 20 verbs"
    #   "lists all 20 verbs"
    #   "20 verbs total"
    # — case-insensitive and whitespace-tolerant.
    citation_re = re.compile(
        r"(?:should\s+list|lists\s+all|list)\s+(\d{1,3})\s+verbs"
        r"|(\d{1,3})\s+verbs\s+total",
        re.IGNORECASE,
    )

    offenders: list[str] = []
    citations: list[tuple[Path, int]] = []
    for path in docs_to_check:
        text = path.read_text(encoding="utf-8")
        matches = citation_re.findall(text)
        if not matches:
            offenders.append(
                f"{path}: missing a verb-count citation (need a phrase like "
                f"'list {expected_count} verbs' or '{expected_count} verbs total')"
            )
            continue
        for cite_a, cite_b in matches:
            cited = int(cite_a or cite_b)
            citations.append((path, cited))
            if cited != expected_count:
                offenders.append(
                    f"{path}: cites {cited} verbs, expected {expected_count} "
                    f"(from cli.py registration block)"
                )

    assert not offenders, (
        f"Verb-count drift across operator-facing docs (truth = {expected_count} "
        f"from cli.py):\n" + "\n".join(offenders)
    )


def test_code_map_typed_verb_inventory_complete():
    """CODE-MAP.md enumerates the typed kali verbs inline (`kali_alterx, ...,
    kali_whatweb — N typed verbs`). The `aith assess kali` registration block in
    `agent/scripts/assess/cli.py` is the truth: every typed verb module must appear
    in the CODE-MAP enumeration, and the cited "N typed verbs" count must match the
    actual typed-module count. The other operator-facing docs cite a total verb
    count (`20 verbs`); CODE-MAP cites the typed subcount, so the existing
    cross-doc drift guard cannot catch this — hence the dedicated test.

    Truth derivation:
    - Typed verbs = `kali_*.py` registration entries minus the three non-typed
      modules (`kali_exec` raw passthrough, `kali_job` async lifecycle,
      `kali_sweep_orphans` host-side maintenance).
    """
    repo_root = Path(__file__).resolve().parents[3]

    cli_text = (repo_root / "agent" / "scripts" / "assess" / "cli.py").read_text(
        encoding="utf-8"
    )
    block_match = re.search(r"for kali_mod in \(([^)]+)\)", cli_text, re.DOTALL)
    assert block_match is not None
    registered_modules = set(re.findall(r"kali_[a-z0-9_]+", block_match.group(1)))
    non_typed = {"kali_exec", "kali_job", "kali_sweep_orphans"}
    typed_modules = registered_modules - non_typed
    expected_typed_count = len(typed_modules)

    code_map = (repo_root / "CODE-MAP.md").read_text(encoding="utf-8")

    # Cited typed-verb count.
    typed_count_match = re.search(r"(\d{1,3})\s+typed\s+verbs", code_map)
    assert typed_count_match is not None, (
        "CODE-MAP.md is missing the '<N> typed verbs' citation that names the "
        "typed-kali subcount; the verb-count drift guard cannot run"
    )
    cited = int(typed_count_match.group(1))
    assert cited == expected_typed_count, (
        f"CODE-MAP.md cites {cited} typed verbs; truth is {expected_typed_count} "
        f"(from cli.py registration block minus the 3 non-typed modules). "
        f"Missing from the inline list: "
        f"{sorted(typed_modules - set(re.findall(r'kali_[a-z0-9_]+', code_map)))}"
    )

    # Every typed module name must appear in the enumeration.
    code_map_modules = set(re.findall(r"kali_[a-z0-9_]+", code_map))
    missing = typed_modules - code_map_modules
    assert not missing, (
        f"CODE-MAP.md inline kali-verb enumeration is missing "
        f"{sorted(missing)} — add them so the doc stays accurate as new typed "
        f"verbs are registered in cli.py"
    )
