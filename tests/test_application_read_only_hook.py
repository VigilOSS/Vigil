"""Executable contract for the application-read-only PreToolUse hook (ADR 0048).

An engagement session reads the Vigil application tree but never changes it. These tests run the
real hook as each client invokes it — hook JSON on stdin, exit status and stderr inspected —
against a throwaway application tree with an engagement beside it, plus the registrations that
bind it (and the Claude post-compaction resume hook) in the generated client settings.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from vigil_cli import client_rosters


REPO_ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = REPO_ROOT / "agent" / "scripts" / "hooks"
CLAUDE_SETTINGS = REPO_ROOT / "agent" / ".claude" / "settings.json"
CODEX_CONFIG = REPO_ROOT / "agent" / ".codex" / "config.toml"
OPENCODE_PLUGIN = REPO_ROOT / "agent" / ".opencode" / "plugin" / "standard-hooks.js"

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="the hook reads payloads with jq")


@pytest.fixture
def layout(tmp_path: Path) -> dict[str, Path]:
    """An installed application tree (hooks copied in) and an engagement outside it."""
    app = tmp_path / "Acme Vigil app"
    hooks = app / "agent" / "scripts" / "hooks"
    hooks.mkdir(parents=True)
    for name in ("application-read-only.sh", "application-read-only.jq", "goose-hook-adapter.sh"):
        shutil.copy2(HOOKS_DIR / name, hooks / name)
    (app / "agent" / "scripts" / "lib").mkdir()
    shutil.copy2(REPO_ROOT / "agent" / "scripts" / "lib" / "engagement.sh", app / "agent" / "scripts" / "lib")
    (app / "agent" / ".claude" / "agents").mkdir(parents=True)
    (app / "agent" / ".claude" / "agents" / "general.md").write_text("role\n", encoding="utf-8")
    (app / "agent" / "scripts" / "assess" / "commands").mkdir(parents=True)
    (app / "agent" / "scripts" / "assess" / "commands" / "web_discovery.py").write_text("x = 1\n")
    engagement = tmp_path / "engagements" / "acme-example"
    (engagement / ".claude").mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"status": "in_progress"}), encoding="utf-8")
    (engagement / ".claude" / "agents").symlink_to(app / "agent" / ".claude" / "agents")
    return {"app": app, "hook": hooks / "application-read-only.sh", "engagement": engagement}


def _run(
    layout: dict[str, Path],
    tool_name: str,
    tool_input: dict[str, object],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    script: Path | None = None,
    extra: dict[str, object] | None = None,
) -> subprocess.CompletedProcess[str]:
    working_dir = cwd or layout["engagement"]
    environment = {k: v for k, v in os.environ.items() if k not in {
        "ENGAGEMENT_DIR", "VIGIL_APPLICATION_DIR", "VIGIL_AGENT_ROOT",
    }}
    environment.update(env or {})
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": str(working_dir),
        **(extra or {}),
    }
    command = ["bash", str(script or layout["hook"])]
    return subprocess.run(
        command, input=json.dumps(payload), capture_output=True, text=True,
        cwd=str(working_dir), env=environment, timeout=60,
    )


def _assert_refused(result: subprocess.CompletedProcess[str], layout: dict[str, Path]) -> None:
    assert result.returncode == 2, result.stderr
    # The refusal names the application directory and where the defect goes instead.
    assert str(layout["app"].resolve()) in result.stderr
    assert "ISSUES-AND-ENHANCEMENTS.md" in result.stderr
    assert "runtime_issues" in result.stderr


def _assert_allowed(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


@pytest.mark.parametrize("tool_name", ["Write", "Edit", "MultiEdit"])
def test_file_tools_aimed_at_the_application_are_refused(layout, tool_name) -> None:
    target = layout["app"] / "agent" / "scripts" / "assess" / "commands" / "web_discovery.py"
    _assert_refused(_run(layout, tool_name, {"file_path": str(target)}), layout)


def test_notebook_edit_and_dotdot_spellings_are_resolved(layout) -> None:
    sneaky = layout["engagement"] / ".." / ".." / layout["app"].name / "agent" / "new.ipynb"
    _assert_refused(_run(layout, "NotebookEdit", {"notebook_path": str(sneaky)}), layout)


def test_a_write_through_an_engagement_symlink_into_the_application_is_refused(layout) -> None:
    # `.claude/agents` in the engagement links into the application roster.
    _assert_refused(_run(layout, "Edit", {"file_path": ".claude/agents/general.md"}), layout)


def test_engagement_files_stay_writable(layout) -> None:
    _assert_allowed(_run(layout, "Write", {"file_path": str(layout["engagement"] / "notes" / "x.md")}))
    _assert_allowed(_run(layout, "Bash", {"command": "echo ok > notes/out.txt"}))


def test_an_engagement_nested_under_the_application_stays_writable(tmp_path: Path, layout) -> None:
    nested = layout["app"] / "engagements" / "acme-nested"
    nested.mkdir(parents=True)
    (nested / "scope.json").write_text("{}", encoding="utf-8")
    result = _run(layout, "Write", {"file_path": str(nested / "notes.md")}, cwd=nested)
    _assert_allowed(result)
    _assert_refused(
        _run(layout, "Write", {"file_path": str(layout["app"] / "agent" / "x.md")}, cwd=nested), layout
    )


def test_codex_apply_patch_headers_are_checked(layout) -> None:
    patch = (
        "*** Begin Patch\n"
        f"*** Update File: {layout['app'] / 'agent' / 'scripts' / 'assess' / 'commands' / 'web_discovery.py'}\n"
        "@@\n-x = 1\n+x = 2\n*** End Patch\n"
    )
    _assert_refused(_run(layout, "apply_patch", {"command": patch}), layout)
    local = "*** Begin Patch\n*** Add File: notes/a.md\n+ok\n*** End Patch\n"
    _assert_allowed(_run(layout, "apply_patch", {"command": local}))


@pytest.mark.parametrize(
    "command",
    [
        "git -C {app} checkout -- agent/scripts/assess/commands/web_discovery.py",
        "cd {app}/agent/scripts/assess/commands && git checkout -- web_discovery.py",
        "git -C {app} restore agent && echo done",
        "git -C {app} stash",
        "jj -R {app} restore",
        "sed -i.bak 's/1/2/' {app}/agent/scripts/assess/commands/web_discovery.py",
        "printf 'x' > {app}/agent/new.py",
        "cat notes/fix.py | tee -a {app}/agent/scripts/x.py",
        "cp notes/fix.py {app}/agent/scripts/assess/commands/",
        "rm -f {app}/agent/scripts/assess/commands/web_discovery.py",
        "patch -d {app} -p1 < notes/fix.diff",
        "find {app} -name '*.pyc' -delete",
        "bash -c \"echo x >> {app}/agent/x.py\"",
        "FOO=1 env BAR=2 mv {app}/agent/x.py notes/",
        "cat > {app}/agent/new.py <<'EOF'\nprint('x')\nEOF",
        "echo $(touch {app}/agent/flag)",
        "rm \"$VIGIL_APPLICATION_DIR/agent/x.py\"",
        "for f in a b; do rm -f {app}/agent/$f; done",
        "while true; do touch {app}/agent/flag; break; done",
        "if test -d notes; then touch {app}/agent/flag; else echo no; fi",
        "if true; then :; elif true; then mkdir {app}/agent/new; fi",
        "{{ echo start; mv notes/a.py {app}/agent/a.py; }}",
        "! rm {app}/agent/x.py",
        "case x in x) rm {app}/agent/x.py;; esac",
        "(cd {app}/agent && case x in (x) echo;; esac; rm x.py)",
        "ls notes | xargs -I{{}} cp {{}} {app}/agent/",
        "xargs -0 -n 1 rm -f {app}/agent/x.py < notes/list",
        "sudo -u acme rm {app}/agent/x.py",
        "sudo -u acme -- touch {app}/agent/flag",
        "nice -n 5 rm {app}/agent/x.py",
        "timeout -s KILL 5 rm {app}/agent/x.py",
        "env -u ACME rm {app}/agent/x.py",
        "(cd {app}/agent && rm x.py)",
        "pushd {app}/agent >/dev/null && rm x.py",
        "pushd {app} && pushd notes; popd; rm agent/x.py",
        "cd {app} && cd notes && cd - && rm agent/x.py",
    ],
)
def test_shell_writes_and_checkouts_aimed_at_the_application_are_refused(layout, command) -> None:
    rendered = command.format(app=shlex.quote(str(layout["app"])))
    result = _run(layout, "Bash", {"command": rendered}, env={"VIGIL_APPLICATION_DIR": str(layout["app"])})
    _assert_refused(result, layout)


@pytest.mark.parametrize(
    "command",
    [
        "cat {app}/agent/scripts/assess/commands/web_discovery.py",
        "sed -n 1,40p {app}/agent/scripts/assess/commands/web_discovery.py > notes/excerpt.txt",
        "grep -rn waf_tier {app}/agent 2>/dev/null | head",
        "git -C {app} status && git -C {app} log --oneline -3 && git -C {app} diff",
        "jj -R {app} log -r @",
        "cp {app}/agent/scripts/assess/commands/web_discovery.py notes/copy.py",
        "python3 {app}/agent/scripts/assess.py --help > notes/help.txt",
        "find {app} -name '*.md' -exec cat {{}} \\;",
        "git checkout -- notes/x.md",
        "cat > notes/plan.md <<'EOF'\nrm -rf {app}\nEOF",
        "(cd {app}/agent && git log -1) && rm -f notes/old.txt",
        "(cd {app}/agent; ls) > notes/listing.txt; touch notes/after",
        "pushd {app}/agent >/dev/null && git status && popd >/dev/null && rm -f notes/old.txt",
        "pushd {app} && pushd {app}/agent && popd && popd && touch notes/after",
        "bash -c \"cd {app}/agent\"; touch notes/after",
        "echo $(cd {app}/agent && pwd) > notes/where.txt; touch notes/after",
        "echo `cd {app}/agent` && touch notes/after",
        "cd {app} && cd - && rm -f notes/old.txt",
        "for f in a b; do cat {app}/agent/$f; done > notes/all.txt",
        "if test -d {app}; then echo present > notes/app.txt; fi",
        "ls notes | xargs -I{{}} cp {app}/agent/{{}} notes/",
        "sudo -u acme cat {app}/agent/x.py",
    ],
)
def test_reads_and_engagement_writes_are_allowed(layout, command) -> None:
    rendered = command.format(app=shlex.quote(str(layout["app"])))
    _assert_allowed(_run(layout, "Bash", {"command": rendered}))


def test_the_hook_is_silent_outside_an_engagement(tmp_path: Path, layout) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    target = layout["app"] / "agent" / "x.py"
    _assert_allowed(_run(layout, "Write", {"file_path": str(target)}, cwd=outside))


def test_goose_file_tools_reach_the_hook_through_the_adapter(layout) -> None:
    adapter = layout["hook"].parent / "goose-hook-adapter.sh"
    target = str(layout["app"] / "agent" / "x.py")

    def goose(tool: str, tool_input: dict[str, object]) -> subprocess.CompletedProcess[str]:
        payload = {"event": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
                   "working_dir": str(layout["engagement"])}
        env = {k: v for k, v in os.environ.items() if k != "ENGAGEMENT_DIR"}
        return subprocess.run(
            ["bash", str(adapter), str(layout["hook"])], input=json.dumps(payload),
            capture_output=True, text=True, cwd=str(layout["engagement"]), env=env, timeout=60,
        )

    _assert_refused(goose("write", {"path": target, "content": "x"}), layout)
    _assert_refused(goose("text_editor", {"command": "str_replace", "path": target}), layout)
    _assert_refused(goose("shell", {"command": f"rm {shlex.quote(target)}"}), layout)
    _assert_allowed(goose("text_editor", {"command": "view", "path": target}))
    _assert_allowed(goose("tree", {"path": str(layout["app"])}))


@pytest.mark.skipif(shutil.which("node") is None, reason="exercises the OpenCode plugin with node")
def test_opencode_plugin_refuses_through_tool_execute_before(tmp_path: Path, layout) -> None:
    plugin = tmp_path / "standard-hooks.mjs"
    shutil.copy2(OPENCODE_PLUGIN, plugin)
    target = str(layout["app"] / "agent" / "x.py")
    driver = tmp_path / "drive.mjs"
    driver.write_text(
        "import { VigilStandardHooks } from './standard-hooks.mjs'\n"
        "const hooks = await VigilStandardHooks()\n"
        "const results = []\n"
        f"for (const [tool, args] of [['write', {{filePath: {json.dumps(target)}}}],"
        " ['bash', {command: 'echo ok > notes/a.txt'}], ['read', {filePath: "
        f"{json.dumps(target)}}}]]) {{\n"
        "  try { await hooks['tool.execute.before']({tool}, {args}); results.push('allowed') }\n"
        "  catch (e) { results.push('refused: ' + e.message) }\n"
        "}\n"
        "console.log(JSON.stringify(results))\n",
        encoding="utf-8",
    )
    env = {**os.environ, "VIGIL_AGENT_ROOT": str(layout["app"] / "agent"),
           "ENGAGEMENT_DIR": str(layout["engagement"])}
    result = subprocess.run(["node", str(driver)], capture_output=True, text=True,
                            cwd=str(layout["engagement"]), env=env, timeout=60)
    assert result.returncode == 0, result.stderr
    write, bash, read = json.loads(result.stdout)
    assert write.startswith("refused: ") and str(layout["app"].resolve()) in write
    assert bash == "allowed"
    assert read == "allowed"


# --------------------------------------------------------------------------
# Registrations
# --------------------------------------------------------------------------


def _claude_commands(settings: dict, event: str) -> list[tuple[str | None, str]]:
    return [
        (entry.get("matcher"), hook["command"])
        for entry in settings["hooks"].get(event, [])
        for hook in entry["hooks"]
    ]


def test_claude_template_binds_the_read_only_and_post_compact_hooks() -> None:
    settings = json.loads(CLAUDE_SETTINGS.read_text(encoding="utf-8"))
    pre_tool = _claude_commands(settings, "PreToolUse")
    assert len(pre_tool) == 1
    matcher, command = pre_tool[0]
    assert set(matcher.split("|")) >= {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"}
    assert "application-read-only.sh" in command
    session_start = _claude_commands(settings, "SessionStart")
    assert session_start == [("compact", session_start[0][1])]
    assert "post-compact-resume.sh" in session_start[0][1]


def test_codex_template_binds_the_read_only_hook() -> None:
    hooks = tomllib.loads(CODEX_CONFIG.read_text(encoding="utf-8"))["hooks"]
    (entry,) = hooks["PreToolUse"]
    assert {"Bash", "Write", "Edit", "apply_patch"} <= set(entry["matcher"].strip("^$()").split("|"))
    assert "application-read-only.sh" in entry["hooks"][0]["command"]


def test_engagement_settings_bind_every_hook_to_the_rendered_agent_root(tmp_path: Path) -> None:
    agent_root = tmp_path / "application" / "agent"
    (agent_root / ".claude").mkdir(parents=True)
    shutil.copy2(CLAUDE_SETTINGS, agent_root / ".claude" / "settings.json")
    (agent_root / ".codex").mkdir()
    shutil.copy2(CODEX_CONFIG, agent_root / ".codex" / "config.toml")
    hooks = agent_root / "scripts" / "hooks"
    hooks.mkdir(parents=True)
    for script in HOOKS_DIR.glob("*.sh"):
        shutil.copy2(script, hooks / script.name)
    (agent_root / "scripts" / "lib").mkdir()
    shutil.copy2(REPO_ROOT / "agent" / "scripts" / "lib" / "engagement.sh", agent_root / "scripts" / "lib")
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    (engagement / "scope.json").write_text("{}", encoding="utf-8")

    client_rosters.ensure_claude_settings(agent_root, engagement / ".claude")
    settings = json.loads((engagement / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert _claude_commands(settings, "PreToolUse")[0][1] == shlex.join(
        ["bash", str(hooks / "application-read-only.sh")])
    assert _claude_commands(settings, "SessionStart") == [
        ("compact", shlex.join(["bash", str(hooks / "post-compact-resume.sh")]))]

    client_rosters.ensure_codex_config(agent_root, engagement / ".codex")
    codex = tomllib.loads((engagement / ".codex" / "config.toml").read_text(encoding="utf-8"))
    assert codex["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == shlex.join(
        ["bash", str(hooks / "application-read-only.sh")])

    client_rosters.ensure_goose_standard_hooks(agent_root, engagement)
    goose = json.loads(
        (engagement / ".agents" / "plugins" / "vigil-standard" / "hooks" / "hooks.json").read_text())
    (pre_tool,) = goose["hooks"]["PreToolUse"]
    assert "application-read-only.sh" in pre_tool["hooks"][0]["command"]
    assert {"shell", "write", "edit"} <= set(pre_tool["matcher"].split("|"))


def test_claude_refresh_keeps_operator_hooks_and_adds_the_new_bindings(tmp_path: Path) -> None:
    agent_root = tmp_path / "application" / "agent"
    (agent_root / ".claude").mkdir(parents=True)
    shutil.copy2(CLAUDE_SETTINGS, agent_root / ".claude" / "settings.json")
    claude_dir = tmp_path / "engagement" / ".claude"
    claude_dir.mkdir(parents=True)
    (claude_dir / "settings.json").write_text(json.dumps({
        "model": "acme-model",
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "acme-audit"}]}]},
    }), encoding="utf-8")

    client_rosters.ensure_claude_settings(agent_root, claude_dir, preserve_existing=True)
    settings = json.loads((claude_dir / "settings.json").read_text(encoding="utf-8"))
    commands = [command for _matcher, command in _claude_commands(settings, "PreToolUse")]
    assert "acme-audit" in commands
    assert any("application-read-only.sh" in command for command in commands)
    assert any("post-compact-resume.sh" in command for _m, command in _claude_commands(settings, "SessionStart"))
    assert settings["model"] == "acme-model"


def _codex_271_config(template: str, old_hooks: Path) -> str:
    """The template as a 2.7.1 engagement carried it: no PreToolUse table, bound to an old root."""
    lines = template.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.strip() == "[[hooks.PreToolUse]]")
    end = next(i for i, line in enumerate(lines) if line.strip() == "[[hooks.PostToolUse]]")
    kept = lines[:start] + lines[end:]
    rendered = []
    for line in kept:
        for script in ("post-tool-log.sh", "post-compact-resume.sh", "session-end.sh"):
            if line.startswith("command =") and script in line:
                line = f"command = {json.dumps(shlex.join(['bash', str(old_hooks / script)]))}\n"
        rendered.append(line)
    return "".join(rendered) + '\n[acme_operator]\nnote = "kept"\n'


def test_codex_refresh_adds_the_read_only_hook_to_an_existing_engagement(tmp_path: Path) -> None:
    agent_root = tmp_path / "application" / "agent"
    (agent_root / ".codex").mkdir(parents=True)
    shutil.copy2(CODEX_CONFIG, agent_root / ".codex" / "config.toml")
    hooks = agent_root / "scripts" / "hooks"
    hooks.mkdir(parents=True)
    for script in HOOKS_DIR.glob("*.sh"):
        shutil.copy2(script, hooks / script.name)
    (agent_root / "scripts" / "lib").mkdir()
    shutil.copy2(REPO_ROOT / "agent" / "scripts" / "lib" / "engagement.sh", agent_root / "scripts" / "lib")
    engagement = tmp_path / "engagement"
    (engagement / ".codex").mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    config_path = engagement / ".codex" / "config.toml"
    old_hooks = tmp_path / "old-application" / "agent" / "scripts" / "hooks"
    config_path.write_text(_codex_271_config(CODEX_CONFIG.read_text(encoding="utf-8"), old_hooks), encoding="utf-8")

    client_rosters.ensure_codex_config(agent_root, engagement / ".codex", preserve_existing=True)
    refreshed = config_path.read_text(encoding="utf-8")
    config = tomllib.loads(refreshed)
    (pre_tool,) = config["hooks"]["PreToolUse"]
    template_entry = tomllib.loads(CODEX_CONFIG.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]
    assert pre_tool["matcher"] == template_entry["matcher"]
    assert pre_tool["hooks"][0]["command"] == shlex.join(["bash", str(hooks / "application-read-only.sh")])
    assert pre_tool["hooks"][0]["timeout"] == template_entry["hooks"][0]["timeout"]
    for event, script in (("PostToolUse", "post-tool-log.sh"), ("SessionStart", "post-compact-resume.sh"),
                          ("SessionEnd", "session-end.sh")):
        (entry,) = config["hooks"][event]
        assert entry["hooks"][0]["command"] == shlex.join(["bash", str(hooks / script)])
    assert config["acme_operator"] == {"note": "kept"}

    client_rosters.ensure_codex_config(agent_root, engagement / ".codex", preserve_existing=True)
    assert config_path.read_text(encoding="utf-8") == refreshed


def test_post_compact_resume_answers_claude_session_start(tmp_path: Path) -> None:
    """Claude sends SessionStart with source=compact; the shared script must answer it."""
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    (engagement / "scope.json").write_text(json.dumps({"status": "in_progress"}), encoding="utf-8")
    payload = {"hook_event_name": "SessionStart", "source": "compact", "session_id": "acme",
               "transcript_path": str(tmp_path / "t.jsonl"), "cwd": str(engagement)}
    env = {k: v for k, v in os.environ.items() if k not in {"ENGAGEMENT_DIR", "VIGIL_AGENT_ROOT"}}
    env["VIGIL_OPERATOR_MODE"] = "web"
    result = subprocess.run(["bash", str(HOOKS_DIR / "post-compact-resume.sh")], input=json.dumps(payload),
                            capture_output=True, text=True, cwd=str(engagement), env=env, timeout=60)
    assert result.returncode == 0
    assert "agent/rules/resume.md" in result.stdout
    assert "vigil assess resume-brief" in result.stdout
