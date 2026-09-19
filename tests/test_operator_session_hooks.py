"""Executable contracts for the compaction and session-end operator hooks.

Both scripts run on a path where failure is expensive and invisible: one steers
every compaction of a live engagement, the other fires while a session is
already on its way out.  These tests exercise the real scripts as the clients
invoke them — hook JSON on stdin, exit status inspected — rather than asserting
on their text.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = REPO_ROOT / "agent" / "scripts" / "hooks"
PRE_COMPACT = HOOKS_DIR / "pre-compact.sh"
POST_COMPACT_RESUME = HOOKS_DIR / "post-compact-resume.sh"
SESSION_END = HOOKS_DIR / "session-end.sh"
POST_TOOL_LOG = HOOKS_DIR / "post-tool-log.sh"
CLAUDE_SETTINGS = REPO_ROOT / "agent" / ".claude" / "settings.json"
CODEX_CONFIG = REPO_ROOT / "agent" / ".codex" / "config.toml"


def _engagement(
    tmp_path: Path,
    *,
    status: str = "in_progress",
    engagement_type: str | None = None,
) -> Path:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    scope = {"status": status}
    if engagement_type is not None:
        scope["engagement_type"] = engagement_type
    (engagement_dir / "scope.json").write_text(
        json.dumps(scope), encoding="utf-8"
    )
    return engagement_dir


def _run_hook(
    script: Path,
    payload: object,
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.pop("ENGAGEMENT_DIR", None)
    environment.pop("VIGIL_AGENT_ROOT", None)
    environment.pop("VIGIL_CLIENT_NAME", None)
    if env:
        environment.update(env)
    return subprocess.run(
        ["bash", str(script)],
        input=json.dumps(payload) if stdin is None else stdin,
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=environment,
        timeout=60,
    )


# --------------------------------------------------------------------------
# pre-compact.sh
# --------------------------------------------------------------------------


@pytest.mark.parametrize("trigger", ["manual", "auto"])
def test_pre_compact_emits_the_contract_for_both_triggers(
    tmp_path: Path, trigger: str
) -> None:
    """Auto-compaction fires unannounced; a manual-only contract would be absent
    exactly when nobody is watching."""
    engagement_dir = _engagement(tmp_path)
    result = _run_hook(
        PRE_COMPACT,
        {"trigger": trigger, "cwd": str(engagement_dir), "hook_event_name": "PreCompact"},
        cwd=engagement_dir,
    )
    assert result.returncode == 0
    assert result.stdout.strip()
    assert "vigil assess resume-brief" in result.stdout
    assert "vigil assess operator-checkpoint show" in result.stdout


def test_pre_compact_appends_engagement_local_compact_md(tmp_path: Path) -> None:
    """An engagement adds rules without editing the shared hook."""
    engagement_dir = _engagement(tmp_path)
    addition = "- Keep the tenant id mapping verbatim.\n"
    (engagement_dir / "COMPACT.md").write_text(addition, encoding="utf-8")
    result = _run_hook(
        PRE_COMPACT,
        {"trigger": "manual", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
    )
    assert result.returncode == 0
    assert result.stdout.rstrip().endswith(addition.rstrip())
    assert len(result.stdout) > len(addition)


def test_pre_compact_can_render_a_stable_prompt_without_local_additions(
    tmp_path: Path,
) -> None:
    """Codex's saved compact_prompt must not freeze a mutable COMPACT.md."""
    engagement_dir = _engagement(tmp_path)
    (engagement_dir / "COMPACT.md").write_text("STALE-LOCAL-RULE\n", encoding="utf-8")

    result = _run_hook(
        PRE_COMPACT,
        {
            "trigger": "manual-or-auto",
            "cwd": str(engagement_dir),
            "include_engagement_additions": False,
        },
        cwd=engagement_dir,
    )

    assert result.returncode == 0
    assert "vigil assess resume-brief" in result.stdout
    assert "STALE-LOCAL-RULE" not in result.stdout


@pytest.mark.parametrize(
    ("engagement_type", "web_readiness", "code_readiness"),
    [
        ("web", True, False),
        ("code", False, True),
        ("both", True, True),
        ("android", False, False),
        ("blue", False, False),
    ],
    ids=("web", "code", "both", "android", "blue"),
)
def test_pre_compact_emits_mode_correct_operator_guidance(
    tmp_path: Path,
    engagement_type: str,
    web_readiness: bool,
    code_readiness: bool,
) -> None:
    engagement_dir = _engagement(tmp_path, engagement_type=engagement_type)

    result = _run_hook(
        PRE_COMPACT,
        {"trigger": "auto", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
    )

    assert result.returncode == 0
    assert "vigil assess resume-brief" in result.stdout
    assert "vigil assess operator-checkpoint show" in result.stdout
    assert (
        "vigil assess check-phase-readiness --phase report" in result.stdout
    ) is web_readiness
    assert ("vigil assess code-coverage" in result.stdout) is code_readiness


def test_pre_compact_uses_neutral_guidance_when_mode_is_unavailable(
    tmp_path: Path,
) -> None:
    engagement_dir = _engagement(tmp_path)

    result = _run_hook(
        PRE_COMPACT,
        {"trigger": "auto", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
    )

    assert result.returncode == 0
    assert result.stdout.strip()
    assert "vigil assess check-phase-readiness --phase report" not in result.stdout
    assert "vigil assess code-coverage" not in result.stdout


@pytest.mark.parametrize(
    "stdin_text",
    ["", "not json at all", "{", '{"trigger": null}', '{"unrelated": 1}'],
)
def test_pre_compact_never_blocks_compaction_on_a_malformed_payload(
    tmp_path: Path, stdin_text: str
) -> None:
    """Exit 2 from a PreCompact hook BLOCKS compaction outright, which would
    wedge a session at its context limit.  No input can produce it."""
    engagement_dir = _engagement(tmp_path)
    result = _run_hook(
        PRE_COMPACT, None, cwd=engagement_dir, stdin=stdin_text
    )
    assert result.returncode == 0
    assert result.returncode != 2
    assert result.stdout.strip()


def test_pre_compact_still_emits_the_contract_outside_any_engagement(
    tmp_path: Path,
) -> None:
    """The contract is standing doctrine; it does not depend on resolving an
    engagement.  Only the optional COMPACT.md section does."""
    elsewhere = tmp_path / "not-an-engagement"
    elsewhere.mkdir()
    result = _run_hook(PRE_COMPACT, {"trigger": "auto"}, cwd=elsewhere)
    assert result.returncode == 0
    assert result.stdout.strip()


# --------------------------------------------------------------------------
# post-compact-resume.sh
# --------------------------------------------------------------------------


def test_post_compact_resume_rehydrates_a_live_engagement(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path, engagement_type="web")
    (engagement_dir / "COMPACT.md").write_text(
        "Preserve the engagement-local sentinel: COBALT-ORCHID.\n",
        encoding="utf-8",
    )

    result = _run_hook(
        POST_COMPACT_RESUME,
        {
            "source": "compact",
            "cwd": str(engagement_dir),
            "hook_event_name": "SessionStart",
        },
        cwd=engagement_dir,
    )

    assert result.returncode == 0
    assert "Vigil post-compaction rehydration is mandatory" in result.stdout
    assert "vigil assess resume-brief" in result.stdout
    assert "agent/rules/resume.md" in result.stdout
    assert "AGENTS.md" in result.stdout
    assert "COMPACT.md" in result.stdout
    assert "COBALT-ORCHID" in result.stdout


@pytest.mark.parametrize(
    ("source", "status"),
    [("startup", "in_progress"), ("compact", "closed")],
    ids=("ordinary-start", "closed-engagement"),
)
def test_post_compact_resume_is_silent_outside_a_live_compaction(
    tmp_path: Path, source: str, status: str
) -> None:
    engagement_dir = _engagement(tmp_path, status=status)

    result = _run_hook(
        POST_COMPACT_RESUME,
        {"source": source, "cwd": str(engagement_dir)},
        cwd=engagement_dir,
    )

    assert result.returncode == 0
    assert result.stdout == ""


def test_pre_compact_degrades_when_the_engagement_lib_is_missing(
    tmp_path: Path,
) -> None:
    """A truncated install must not turn compaction into an error."""
    lone_hooks = tmp_path / "scripts" / "hooks"
    lone_hooks.mkdir(parents=True)
    script = lone_hooks / "pre-compact.sh"
    shutil.copy2(PRE_COMPACT, script)
    engagement_dir = _engagement(tmp_path)

    result = _run_hook(
        script, {"trigger": "manual", "cwd": str(engagement_dir)}, cwd=engagement_dir
    )
    assert result.returncode == 0
    assert result.stdout.strip()


def test_compaction_steering_is_registered_for_claude_and_codex() -> None:
    """Pin each client's distinct, documented compaction mechanism."""
    claude_settings = json.loads(CLAUDE_SETTINGS.read_text(encoding="utf-8"))
    assert claude_settings["env"]["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] == "510000"
    claude_hooks = claude_settings["hooks"]
    pre_compact = claude_hooks.get("PreCompact", [])
    assert pre_compact, (
        "agent/.claude/settings.json no longer registers PreCompact; Claude "
        "compaction now runs unsteered and the docs' 'run nothing afterwards' "
        "advice is wrong."
    )
    assert all("matcher" not in entry for entry in pre_compact), (
        "A matcher on PreCompact narrows it away from automatic compaction, "
        "which is the case the docs promise is covered."
    )
    assert any(
        "pre-compact.sh" in hook["command"]
        for entry in pre_compact
        for hook in entry["hooks"]
    )

    codex_config = tomllib.loads(CODEX_CONFIG.read_text(encoding="utf-8"))
    codex_hooks = codex_config.get("hooks", {})
    assert "PreCompact" not in codex_hooks, (
        "Codex ignores PreCompact stdout, so registering the canonical renderer "
        "there would look wired while leaving its summarizer unsteered."
    )
    assert codex_config["compact_prompt"] == "__VIGIL_RENDER_COMPACT_PROMPT__"
    assert codex_config["model_auto_compact_token_limit"] == 510_000
    session_start = codex_hooks["SessionStart"]
    assert len(session_start) == 1
    assert session_start[0]["matcher"] == "^compact$"
    assert "post-compact-resume.sh" in session_start[0]["hooks"][0]["command"]


# --------------------------------------------------------------------------
# session-end.sh
# --------------------------------------------------------------------------


def _fake_vigil(bin_dir: Path, capture: Path, *, exit_code: int = 0) -> None:
    """A `vigil` on PATH that appends its argv and environment to a capture file."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    executable = bin_dir / "vigil"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        f"capture = {str(capture)!r}\n"
        "with open(capture, 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps({\n"
        "        'argv': sys.argv[1:],\n"
        "        'engagement_dir_env': os.environ.get('ENGAGEMENT_DIR'),\n"
        "    }) + '\\n')\n"
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)


def _session_end_env(bin_dir: Path, **extra: str) -> dict[str, str]:
    env = {"PATH": f"{bin_dir}:{os.environ.get('PATH', '')}"}
    env.update(extra)
    return env


def _captured(capture: Path) -> list[dict]:
    if not capture.exists():
        return []
    return [json.loads(line) for line in capture.read_text().splitlines() if line]


def test_session_end_records_one_activity_receipt_with_an_explicit_engagement_selector(
    tmp_path: Path,
) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin", VIGIL_CLIENT_NAME="claude"),
    )

    assert result.returncode == 0
    calls = _captured(capture)
    assert len(calls) == 1
    argv = calls[0]["argv"]
    assert argv[:2] == ["assess", "--engagement-dir"]
    assert argv[2] == str(engagement_dir)
    assert argv[3:6] == ["--actor-kind", "hook", "log"]
    assert argv[6:8] == ["session-end-hook", "Client session ended"]
    assert "client=claude" in argv[8]
    assert "session=s-1" in argv[8]
    assert "reason=other" in argv[8]
    assert "current operator checkpoint" in argv[9]
    assert "operator-checkpoint" not in argv

    # ENGAGEMENT_DIR is an artifact-path variable that never selects assessment
    # state; setting it would risk a loud disagreement warning from a hook that
    # must stay silent.
    assert calls[0]["engagement_dir_env"] is None


def test_session_end_receipt_is_factual_and_does_not_replace_operator_intent(
    tmp_path: Path,
) -> None:
    """The hook records only the client lifecycle fact in normal activity.

    The operator checkpoint remains the current human-meaningful resume pointer.
    """
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "clear", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin"),
    )

    argv = _captured(capture)[0]["argv"]
    assert argv[3:6] == ["--actor-kind", "hook", "log"]
    assert "reason=clear" in argv[8]
    assert "operator-checkpoint" not in argv
    for guessed in ("--finding", "--agent-id", "--command-run", "--artifact"):
        assert guessed not in argv


def test_session_end_is_idempotent_for_a_repeated_event(tmp_path: Path) -> None:
    """A duplicate row in an immutable operator-facing record is worse than a
    missing one."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    payload = {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)}

    first = _run_hook(
        SESSION_END, payload, cwd=engagement_dir, env=_session_end_env(tmp_path / "bin")
    )
    second = _run_hook(
        SESSION_END, payload, cwd=engagement_dir, env=_session_end_env(tmp_path / "bin")
    )

    assert first.returncode == 0
    assert second.returncode == 0
    assert len(_captured(capture)) == 1
    assert (engagement_dir / ".hook_session_end_seen").is_file()


def test_session_end_missing_ids_are_idempotent_per_normalized_client(
    tmp_path: Path,
) -> None:
    """A missing client session id must not merge different client exits.

    Claude and Codex can both operate on one engagement. Their fallback
    ``unknown-session`` receipts remain distinct even when the exit reason is
    identical, while each client's own repeat is still bounded.
    """
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    payload = {"reason": "other", "cwd": str(engagement_dir)}

    for client in ("claude", "codex"):
        _run_hook(
            SESSION_END,
            payload,
            cwd=engagement_dir,
            env=_session_end_env(tmp_path / "bin", VIGIL_CLIENT_NAME=client),
        )

    calls = _captured(capture)
    assert len(calls) == 2
    assert {call["argv"][8].split()[0] for call in calls} == {
        "client=claude",
        "client=codex",
    }
    assert (engagement_dir / ".hook_session_end_seen").read_text().splitlines() == [
        "claude|unknown-session|other",
        "codex|unknown-session|other",
    ]


def test_session_end_distinguishes_clear_from_the_eventual_exit(tmp_path: Path) -> None:
    """`/clear` and the real exit are different events of one session; both are
    worth a marker, and neither is a duplicate of the other."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    for reason in ("clear", "other"):
        _run_hook(
            SESSION_END,
            {"session_id": "s-1", "reason": reason, "cwd": str(engagement_dir)},
            cwd=engagement_dir,
            env=_session_end_env(tmp_path / "bin"),
        )

    calls = _captured(capture)
    assert len(calls) == 2


def test_session_end_exits_zero_and_retries_later_when_the_backend_is_down(
    tmp_path: Path,
) -> None:
    """A failing checkpoint must neither error the exit nor consume the marker."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture, exit_code=1)

    result = _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin"),
    )

    assert result.returncode == 0
    seen = engagement_dir / ".hook_session_end_seen"
    assert not seen.exists() or "s-1|other" not in seen.read_text()

    # The claim was released, so a later event for the same session can record.
    _fake_vigil(tmp_path / "bin", capture, exit_code=0)
    _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin"),
    )
    assert len(_captured(capture)) == 2


def test_session_end_exits_zero_with_no_runner_available(tmp_path: Path) -> None:
    """No `vigil` on PATH and no assess.py beside the hook: still a clean exit."""
    engagement_dir = _engagement(tmp_path)
    scripts_dir = tmp_path / "scripts"
    lone_hooks = scripts_dir / "hooks"
    lone_hooks.mkdir(parents=True)
    script = lone_hooks / "session-end.sh"
    shutil.copy2(SESSION_END, script)
    # The engagement-resolution lib is present; only the runners are absent.
    shutil.copytree(HOOKS_DIR.parent / "lib", scripts_dir / "lib")
    jq = shutil.which("jq")
    assert jq is not None, "jq is required by every Vigil hook"
    path_without_vigil = f"{Path(jq).parent}:/usr/bin:/bin"
    assert shutil.which("vigil", path=path_without_vigil) is None

    result = _run_hook(
        script,
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"PATH": path_without_vigil},
    )
    assert result.returncode == 0
    # The claim was taken and then released, so nothing is left blocking a retry.
    assert not (engagement_dir / ".hook_session_end_seen").read_text().strip()


def test_session_end_is_a_silent_no_op_when_jq_is_unusable(tmp_path: Path) -> None:
    """Every Vigil hook degrades to a no-op without a working jq, never an error.

    Without jq the scope status cannot be read, and a checkpoint must not be
    written against an engagement whose state the hook could not confirm.
    """
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    broken = tmp_path / "broken-bin"
    broken.mkdir()
    (broken / "jq").write_text("#!/usr/bin/env bash\nexit 127\n", encoding="utf-8")
    (broken / "jq").chmod(0o755)

    result = _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"PATH": f"{broken}:{tmp_path / 'bin'}:{os.environ.get('PATH', '')}"},
    )
    assert result.returncode == 0
    assert _captured(capture) == []


@pytest.mark.parametrize("stdin_text", ["", "garbage", "{"])
def test_session_end_exits_zero_on_a_malformed_payload(
    tmp_path: Path, stdin_text: str
) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        SESSION_END,
        None,
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin"),
        stdin=stdin_text,
    )
    assert result.returncode == 0


def test_session_end_does_not_checkpoint_a_closed_engagement(tmp_path: Path) -> None:
    """Reopening a client in a finished engagement must not grow new rows."""
    engagement_dir = _engagement(tmp_path, status="completed")
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin"),
    )
    assert result.returncode == 0
    assert _captured(capture) == []


def test_session_end_outside_any_engagement_is_a_silent_no_op(tmp_path: Path) -> None:
    elsewhere = tmp_path / "not-an-engagement"
    elsewhere.mkdir()
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "other"},
        cwd=elsewhere,
        env=_session_end_env(tmp_path / "bin"),
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert _captured(capture) == []


def test_session_end_drops_an_unrecognized_client_name(tmp_path: Path) -> None:
    """`--client-name` is a closed set in the verb; an unknown label must not
    cost the whole checkpoint to an argparse rejection."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin", VIGIL_CLIENT_NAME="something-else"),
    )

    argv = _captured(capture)[0]["argv"]
    assert "--client-name" not in argv


@pytest.mark.parametrize("client", ["claude", "codex", "goose", "kimi", "opencode"])
def test_session_end_records_every_launcher_client_name(
    tmp_path: Path, client: str
) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    _run_hook(
        SESSION_END,
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin", VIGIL_CLIENT_NAME=client),
    )

    argv = _captured(capture)[0]["argv"]
    assert f"client={client}" in argv[8]


# --------------------------------------------------------------------------
# post-tool-log.sh
# --------------------------------------------------------------------------


def _isolated_hook(tmp_path: Path, script: Path) -> Path:
    """Copy one hook into a scripts tree of its own, with the shared libs beside it.

    ``$ASSESS_PY`` is resolved relative to the hook, so a copy is the only way a
    test can control which runner the fallback branch finds.
    """
    scripts_dir = tmp_path / "scripts"
    hooks_dir = scripts_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    shutil.copytree(HOOKS_DIR.parent / "lib", scripts_dir / "lib")
    copy = hooks_dir / script.name
    shutil.copy2(script, copy)
    return copy


def _fake_assess_py(scripts_dir: Path, capture: Path) -> Path:
    """An executable ``assess.py`` whose SHEBANG is what makes it work.

    The real one is a PEP 723 script — ``#!/usr/bin/env -S uv run --script`` —
    which provisions its inline dependency set before Python ever sees the file.
    This stand-in encodes the same property in the cheapest form a test can
    assert on: it is a shell script. Executed directly (correct), its shebang
    runs it and the call is recorded. Run as ``python3 assess.py`` (the bug), the
    interpreter chokes and nothing is recorded — exactly as the real script would
    fail once ``log`` needs anything outside the stdlib.
    """
    assess = scripts_dir / "assess.py"
    assess.write_text(
        "#!/bin/sh\n" f'printf "%s\\n" "$*" >> {str(capture)!r}\n' "exit 0\n",
        encoding="utf-8",
    )
    assess.chmod(0o755)
    return assess


def _path_without_vigil() -> str:
    jq = shutil.which("jq")
    assert jq is not None, "jq is required by every Vigil hook"
    path = f"{Path(jq).parent}:/usr/bin:/bin"
    assert shutil.which("vigil", path=path) is None
    return path


_BASH_PAYLOAD = {
    "tool_name": "Bash",
    "tool_input": {"command": "whoami"},
    "tool_response": {"stdout": "operator", "exitCode": 0},
    "tool_use_id": "tu-1",
}


def test_post_tool_log_records_through_the_vigil_launcher(tmp_path: Path) -> None:
    """The audit entry is written by `vigil assess log`, not a bare interpreter."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        POST_TOOL_LOG,
        {**_BASH_PAYLOAD, "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"PATH": f"{tmp_path / 'bin'}:{os.environ.get('PATH', '')}"},
    )

    assert result.returncode == 0
    calls = _captured(capture)
    assert len(calls) == 1
    argv = calls[0]["argv"]
    assert argv[:2] == ["assess", "--engagement-dir"]
    assert argv[2] == str(engagement_dir)
    assert argv[3] == "log"
    assert argv[argv.index("--actor-kind") + 1] == "hook"
    assert "bash: whoami" in argv


def test_post_tool_log_fallback_execs_assess_py_through_its_own_shebang(
    tmp_path: Path,
) -> None:
    """With no `vigil` on PATH, assess.py runs DIRECTLY — never under `python3`.

    This is the regression that matters. ``python3 assess.py`` skips the PEP 723
    dependency provisioning the shebang performs; it works today only because
    ``log`` reaches nothing outside the stdlib. This is the audit-logging hook, so
    the failure mode of getting it wrong is a silently missing audit trail.
    """
    engagement_dir = _engagement(tmp_path)
    hook = _isolated_hook(tmp_path, POST_TOOL_LOG)
    capture = tmp_path / "assess-calls.txt"
    _fake_assess_py(hook.parent.parent, capture)

    result = _run_hook(
        hook,
        {**_BASH_PAYLOAD, "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"PATH": _path_without_vigil()},
    )

    assert result.returncode == 0
    assert capture.exists(), (
        "assess.py was never executed through its own shebang — the hook is still "
        "invoking it under a bare interpreter, which skips PEP 723 dependency "
        "provisioning"
    )
    recorded = capture.read_text(encoding="utf-8")
    assert f"--engagement-dir {engagement_dir} log" in recorded
    assert "--actor-kind hook" in recorded


def test_post_tool_log_is_silent_and_clean_when_no_runner_is_available(
    tmp_path: Path,
) -> None:
    """No `vigil`, no assess.py: the tool call is neither blocked nor annotated."""
    engagement_dir = _engagement(tmp_path)
    hook = _isolated_hook(tmp_path, POST_TOOL_LOG)

    result = _run_hook(
        hook,
        {**_BASH_PAYLOAD, "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"PATH": _path_without_vigil()},
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_post_tool_log_stays_silent_when_the_backend_write_fails(
    tmp_path: Path,
) -> None:
    """A PostToolUse hook fires per tool call; a failed write must not become noise."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture, exit_code=1)

    result = _run_hook(
        POST_TOOL_LOG,
        {**_BASH_PAYLOAD, "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"PATH": f"{tmp_path / 'bin'}:{os.environ.get('PATH', '')}"},
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert len(_captured(capture)) == 1
