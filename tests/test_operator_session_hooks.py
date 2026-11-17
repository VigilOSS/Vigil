"""Executable contracts for the compaction and session-end operator hooks.

Both scripts run on a path where failure is expensive and invisible: one steers
every compaction of a live engagement, the other fires while a session is
already on its way out.  These tests exercise the real scripts as the clients
invoke them — hook JSON on stdin, exit status inspected — rather than asserting
on their text.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
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
    trace: bool = False,
    timeout: float = 60,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.pop("ENGAGEMENT_DIR", None)
    environment.pop("VIGIL_AGENT_ROOT", None)
    environment.pop("VIGIL_CLIENT_NAME", None)
    environment.pop("VIGIL_OPERATOR_MODE", None)
    if env:
        environment.update(env)
    return subprocess.run(
        ["bash", *(["-x"] if trace else []), str(script)],
        input=json.dumps(payload) if stdin is None else stdin,
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=environment,
        timeout=timeout,
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
        env={"VIGIL_OPERATOR_MODE": "web"},
    )

    assert result.returncode == 0
    assert "vigil assess resume-brief" in result.stdout
    assert "STALE-LOCAL-RULE" not in result.stdout
    assert "session-selected `web`" not in result.stdout
    assert "session-selected `code`" not in result.stdout
    assert "vigil assess check-phase-readiness --phase report" not in result.stdout
    assert "vigil assess code-coverage" not in result.stdout


@pytest.mark.parametrize(
    ("engagement_type", "web_readiness", "code_readiness"),
    [
        ("web", True, False),
        ("code", False, True),
        ("both", False, False),
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
    ("operator_mode", "web_readiness", "code_readiness"),
    [
        ("web", True, False),
        ("code", False, True),
        ("android", False, False),
        ("blue", False, False),
        ("remediation", False, False),
    ],
    ids=("web", "code", "android", "blue", "remediation"),
)
def test_pre_compact_uses_the_session_selected_operator_mode(
    tmp_path: Path,
    operator_mode: str,
    web_readiness: bool,
    code_readiness: bool,
) -> None:
    """A dual-capability engagement has no globally selected operator core."""
    engagement_dir = _engagement(tmp_path, engagement_type="offensive")
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "status": "in_progress",
                "engagement_type": "offensive",
                "tracks": {"web": True, "code": True},
            }
        ),
        encoding="utf-8",
    )

    result = _run_hook(
        PRE_COMPACT,
        {"trigger": "auto", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"VIGIL_OPERATOR_MODE": operator_mode},
    )

    assert result.returncode == 0
    assert f"session-selected `{operator_mode}` operator mode" in result.stdout
    assert (
        "vigil assess check-phase-readiness --phase report" in result.stdout
    ) is web_readiness
    assert ("vigil assess code-coverage" in result.stdout) is code_readiness


def test_pre_compact_does_not_choose_a_mode_for_a_dual_capability_engagement(
    tmp_path: Path,
) -> None:
    engagement_dir = _engagement(tmp_path, engagement_type="offensive")
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "status": "in_progress",
                "engagement_type": "offensive",
                "tracks": {"web": True, "code": True},
            }
        ),
        encoding="utf-8",
    )

    result = _run_hook(
        PRE_COMPACT,
        {"trigger": "auto", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
    )

    assert result.returncode == 0
    assert "vigil engagement mode" in result.stdout
    assert "vigil assess check-phase-readiness --phase report" not in result.stdout
    assert "vigil assess code-coverage" not in result.stdout


@pytest.mark.parametrize(
    ("operator_mode", "include_additions"),
    [
        ("web", True),
        ("code", True),
        ("blue", True),
        ("android", True),
        (None, True),
        ("web", False),
    ],
    ids=("web", "code", "blue", "android", "no-mode", "codex-stable-prompt"),
)
def test_pre_compact_names_the_trigger_loaded_resume_rule(
    tmp_path: Path, operator_mode: str | None, include_additions: bool
) -> None:
    """The resume rule loads only on resume/compaction, so every compaction
    contract outside remediation must name the file the next turn reads."""
    engagement_dir = _engagement(tmp_path)
    payload: dict[str, object] = {"trigger": "auto", "cwd": str(engagement_dir)}
    if not include_additions:
        payload["include_engagement_additions"] = False
    result = _run_hook(
        PRE_COMPACT,
        payload,
        cwd=engagement_dir,
        env={"VIGIL_OPERATOR_MODE": operator_mode} if operator_mode else None,
    )
    assert result.returncode == 0
    assert "agent/rules/resume.md" in result.stdout


def test_pre_compact_uses_remediation_case_state_in_remediation_mode(
    tmp_path: Path,
) -> None:
    engagement_dir = _engagement(tmp_path, engagement_type="remediation")
    result = _run_hook(
        PRE_COMPACT,
        {"trigger": "auto", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"VIGIL_OPERATOR_MODE": "remediation"},
    )
    assert result.returncode == 0
    assert "vigil remediation -k <key> list" in result.stdout
    assert "vigil assess resume-brief" not in result.stdout


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
        env={"VIGIL_OPERATOR_MODE": "web"},
    )

    assert result.returncode == 0
    assert "Vigil post-compaction rehydration is mandatory" in result.stdout
    assert "vigil assess resume-brief" in result.stdout
    assert "agent/rules/resume.md" in result.stdout
    assert "AGENTS.md" in result.stdout
    assert "COMPACT.md" in result.stdout
    assert "COBALT-ORCHID" in result.stdout


@pytest.mark.parametrize("operator_mode", ["web", "code", "blue", "remediation", "android"])
def test_post_compact_resume_restores_only_the_session_mode(
    tmp_path: Path, operator_mode: str
) -> None:
    engagement_dir = _engagement(tmp_path, engagement_type="offensive")
    result = _run_hook(
        POST_COMPACT_RESUME,
        {"source": "compact", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"VIGIL_OPERATOR_MODE": operator_mode},
    )
    assert result.returncode == 0
    assert f"session-selected `{operator_mode}` mode" in result.stdout
    assert "vigil engagement mode" in result.stdout
    assert "load only that prompt" in result.stdout


@pytest.mark.parametrize("operator_mode", ["web", "code", "blue", "android"])
def test_post_compact_resume_names_the_resume_rule_for_every_operator_mode(
    tmp_path: Path, operator_mode: str
) -> None:
    engagement_dir = _engagement(tmp_path)
    result = _run_hook(
        POST_COMPACT_RESUME,
        {"source": "compact", "cwd": str(engagement_dir), "hook_event_name": "SessionStart"},
        cwd=engagement_dir,
        env={"VIGIL_OPERATOR_MODE": operator_mode},
    )
    assert result.returncode == 0
    assert "agent/rules/resume.md" in result.stdout


def test_post_compact_resume_stops_without_a_session_mode(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path, engagement_type="offensive")
    result = _run_hook(
        POST_COMPACT_RESUME,
        {"source": "compact", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
    )
    assert result.returncode == 0
    assert "vigil engagement mode" in result.stdout
    assert "stop" in result.stdout.lower()


def test_post_compact_resume_uses_remediation_case_state(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path, engagement_type="remediation")
    result = _run_hook(
        POST_COMPACT_RESUME,
        {"source": "compact", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        env={"VIGIL_OPERATOR_MODE": "remediation"},
    )
    assert result.returncode == 0
    assert "vigil remediation -k <key> list" in result.stdout
    assert "vigil assess resume-brief" not in result.stdout


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


SessionEnd = Callable[..., tuple[subprocess.CompletedProcess[str], list[dict]]]


@pytest.fixture
def session_end(tmp_path: Path) -> SessionEnd:
    """Drive the real session-end hook against a fake `vigil` on PATH.

    ``run(payload, cwd=..., exit_code=..., stdin=..., **env)`` returns the
    hook's CompletedProcess and the receipts the launcher captured so far. The
    launcher's exit code stays a per-call parameter, so a test can still drive
    a failing backend and then a working one against the same capture file.
    """
    bin_dir = tmp_path / "bin"
    capture = tmp_path / "capture.jsonl"

    def run(
        payload: object, *, cwd: Path, exit_code: int = 0, stdin: str | None = None, **env: str
    ) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
        _fake_vigil(bin_dir, capture, exit_code=exit_code)
        result = _run_hook(
            SESSION_END, payload, cwd=cwd, env=_session_end_env(bin_dir, **env), stdin=stdin
        )
        return result, _captured(capture)

    return run


def test_session_end_records_one_activity_receipt_with_an_explicit_engagement_selector(
    tmp_path: Path, session_end: SessionEnd
) -> None:
    engagement_dir = _engagement(tmp_path)

    result, calls = session_end(
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        VIGIL_CLIENT_NAME="claude",
    )

    assert result.returncode == 0
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
    tmp_path: Path, session_end: SessionEnd
) -> None:
    """The hook records only the client lifecycle fact in normal activity.

    The operator checkpoint remains the current human-meaningful resume pointer.
    """
    engagement_dir = _engagement(tmp_path)

    _result, calls = session_end(
        {"session_id": "s-1", "reason": "clear", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
    )

    argv = calls[0]["argv"]
    assert argv[3:6] == ["--actor-kind", "hook", "log"]
    assert "reason=clear" in argv[8]
    assert "operator-checkpoint" not in argv
    for guessed in ("--finding", "--agent-id", "--command-run", "--artifact"):
        assert guessed not in argv


def test_session_end_is_idempotent_for_a_repeated_event(
    tmp_path: Path, session_end: SessionEnd
) -> None:
    """A duplicate row in an immutable operator-facing record is worse than a
    missing one."""
    engagement_dir = _engagement(tmp_path)
    payload = {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)}

    first, _first_calls = session_end(payload, cwd=engagement_dir)
    second, calls = session_end(payload, cwd=engagement_dir)

    assert first.returncode == 0
    assert second.returncode == 0
    assert len(calls) == 1
    assert (engagement_dir / ".hook_session_end_seen").is_file()


def test_session_end_missing_ids_are_idempotent_per_normalized_client(
    tmp_path: Path, session_end: SessionEnd
) -> None:
    """A missing client session id must not merge different client exits.

    Claude and Codex can both operate on one engagement. Their fallback
    ``unknown-session`` receipts remain distinct even when the exit reason is
    identical, while each client's own repeat is still bounded.
    """
    engagement_dir = _engagement(tmp_path)
    payload = {"reason": "other", "cwd": str(engagement_dir)}

    for client in ("claude", "codex"):
        _result, calls = session_end(payload, cwd=engagement_dir, VIGIL_CLIENT_NAME=client)

    assert len(calls) == 2
    assert {call["argv"][8].split()[0] for call in calls} == {
        "client=claude",
        "client=codex",
    }
    assert (engagement_dir / ".hook_session_end_seen").read_text().splitlines() == [
        "claude|unknown-session|other",
        "codex|unknown-session|other",
    ]


def test_session_end_distinguishes_clear_from_the_eventual_exit(
    tmp_path: Path, session_end: SessionEnd
) -> None:
    """`/clear` and the real exit are different events of one session; both are
    worth a marker, and neither is a duplicate of the other."""
    engagement_dir = _engagement(tmp_path)

    for reason in ("clear", "other"):
        _result, calls = session_end(
            {"session_id": "s-1", "reason": reason, "cwd": str(engagement_dir)},
            cwd=engagement_dir,
        )

    assert len(calls) == 2


def test_session_end_exits_zero_and_retries_later_when_the_backend_is_down(
    tmp_path: Path, session_end: SessionEnd
) -> None:
    """A failing checkpoint must neither error the exit nor consume the marker."""
    engagement_dir = _engagement(tmp_path)
    payload = {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)}

    result, _calls = session_end(payload, cwd=engagement_dir, exit_code=1)

    assert result.returncode == 0
    seen = engagement_dir / ".hook_session_end_seen"
    assert not seen.exists() or "s-1|other" not in seen.read_text()

    # The claim was released, so a later event for the same session can record.
    _retry, calls = session_end(payload, cwd=engagement_dir, exit_code=0)
    assert len(calls) == 2


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
    path_without_vigil = _path_without_vigil(tmp_path)

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
    tmp_path: Path, session_end: SessionEnd, stdin_text: str
) -> None:
    engagement_dir = _engagement(tmp_path)

    result, _calls = session_end(None, cwd=engagement_dir, stdin=stdin_text)
    assert result.returncode == 0


def test_session_end_does_not_checkpoint_a_closed_engagement(
    tmp_path: Path, session_end: SessionEnd
) -> None:
    """Reopening a client in a finished engagement must not grow new rows."""
    engagement_dir = _engagement(tmp_path, status="completed")

    result, calls = session_end(
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
    )
    assert result.returncode == 0
    assert calls == []


def test_session_end_outside_any_engagement_is_a_silent_no_op(
    tmp_path: Path, session_end: SessionEnd
) -> None:
    elsewhere = tmp_path / "not-an-engagement"
    elsewhere.mkdir()

    result, calls = session_end({"session_id": "s-1", "reason": "other"}, cwd=elsewhere)
    assert result.returncode == 0
    assert result.stderr == ""
    assert calls == []


def test_session_end_drops_an_unrecognized_client_name(
    tmp_path: Path, session_end: SessionEnd
) -> None:
    """`--client-name` is a closed set in the verb; an unknown label must not
    cost the whole checkpoint to an argparse rejection."""
    engagement_dir = _engagement(tmp_path)

    _result, calls = session_end(
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        VIGIL_CLIENT_NAME="something-else",
    )

    argv = calls[0]["argv"]
    assert "--client-name" not in argv


@pytest.mark.parametrize("client", ["claude", "codex", "goose", "kimi", "opencode", "pi"])
def test_session_end_records_every_launcher_client_name(
    tmp_path: Path, session_end: SessionEnd, client: str
) -> None:
    engagement_dir = _engagement(tmp_path)

    _result, calls = session_end(
        {"session_id": "s-1", "reason": "other", "cwd": str(engagement_dir)},
        cwd=engagement_dir,
        VIGIL_CLIENT_NAME=client,
    )

    argv = calls[0]["argv"]
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


def _path_without_vigil(tmp_path: Path) -> str:
    jq = shutil.which("jq")
    assert jq is not None, "jq is required by every Vigil hook"
    bin_dir = tmp_path / "hook-bin"
    bin_dir.mkdir()
    (bin_dir / "jq").symlink_to(jq)
    path = f"{bin_dir}:/usr/bin:/bin"
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
        env={"PATH": _path_without_vigil(tmp_path)},
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
        env={"PATH": _path_without_vigil(tmp_path)},
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


def test_post_tool_log_releases_failed_dedup_claim_for_retry(tmp_path: Path) -> None:
    """A transient backend failure must not make the event permanently invisible."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture, exit_code=1)
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ.get('PATH', '')}"}
    payload = {**_BASH_PAYLOAD, "cwd": str(engagement_dir)}

    first = _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=env)
    second = _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=env)

    assert first.returncode == second.returncode == 0
    assert first.stdout == first.stderr == second.stdout == second.stderr == ""
    assert len(_captured(capture)) == 2
    seen = engagement_dir / ".hook_seen_tool_uses"
    assert not seen.exists() or "tu-1" not in seen.read_text(encoding="utf-8").splitlines()


def _native_log_payload(engagement_dir: Path, **identity: str) -> dict:
    return {
        **_BASH_PAYLOAD,
        "cwd": str(engagement_dir),
        "client_name": "opencode",
        "session_id": "session-1",
        **identity,
    }


@pytest.mark.parametrize("changed", ["tool_use_id", "session_id", "client_name"])
def test_post_tool_log_distinguishes_native_calls(tmp_path: Path, changed: str) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    env = _session_end_env(tmp_path / "bin")
    payload = _native_log_payload(engagement_dir)

    first = _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=env)
    second = _run_hook(
        POST_TOOL_LOG, {**payload, changed: "distinct"}, cwd=engagement_dir, env=env
    )

    assert first.returncode == second.returncode == 0
    assert len(_captured(capture)) == 2


def test_post_tool_log_claims_one_concurrent_native_delivery(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    env = _session_end_env(tmp_path / "bin")
    payload = {
        **_native_log_payload(engagement_dir),
        "tool_name": "Agent",
        "tool_input": {"subagent_type": "reviewer", "description": "Review changes"},
    }

    def deliver(_: int) -> subprocess.CompletedProcess[str]:
        return _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=env)

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(deliver, range(24)))

    assert all(result.returncode == 0 for result in results)
    assert len(_captured(capture)) == 1


def test_post_tool_log_claim_is_atomic_during_delayed_seen_reads(tmp_path: Path) -> None:
    """Two already-completed empty reads must not both acquire one delivery."""
    engagement_dir = _engagement(tmp_path)
    (engagement_dir / ".hook_seen_tool_uses").write_text("", encoding="utf-8")
    capture = tmp_path / "capture.jsonl"
    bin_dir = tmp_path / "bin"
    _fake_vigil(bin_dir, capture)
    real_grep = shutil.which("grep")
    assert real_grep
    barrier = tmp_path / "read-barrier"
    barrier.mkdir()
    delayed_grep = bin_dir / "grep"
    delayed_grep.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, subprocess, sys, time\n"
        f"result = subprocess.run([{real_grep!r}, *sys.argv[1:]], check=False)\n"
        "if len(sys.argv) > 1 and sys.argv[1] == '-Fxq':\n"
        f"    barrier = pathlib.Path({str(barrier)!r})\n"
        "    (barrier / str(os.getpid())).touch()\n"
        "    deadline = time.monotonic() + 3\n"
        "    while len(list(barrier.iterdir())) < 2 and time.monotonic() < deadline:\n"
        "        pass\n"
        "sys.exit(result.returncode)\n",
        encoding="utf-8",
    )
    delayed_grep.chmod(0o755)
    payload = {
        **_native_log_payload(engagement_dir),
        "tool_name": "Agent",
        "tool_input": {"subagent_type": "reviewer", "description": "Review changes"},
    }

    env = _session_end_env(bin_dir)

    def deliver(_: int) -> subprocess.CompletedProcess[str]:
        # Preserve each actual delivery's trace: rerunning a race after failure
        # cannot explain which branch the original process took.
        return _run_hook(
            POST_TOOL_LOG, payload, cwd=engagement_dir, env=env, trace=True
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(deliver, range(2)))

    calls = _captured(capture)
    if any(result.returncode != 0 for result in results) or len(calls) != 1:
        pytest.fail(json.dumps({
            "captured_calls": calls,
            "deliveries": [
                {"returncode": result.returncode, "stdout": result.stdout,
                 "stderr": result.stderr}
                for result in results
            ],
            "native_claims": sorted(
                path.name for path in engagement_dir.glob(".hook_tool_use_*")
            ),
            "executables": {
                name: shutil.which(name, path=env["PATH"])
                for name in ("bash", "jq", "mkdir", "rmdir", "shasum", "sha256sum", "vigil")
            },
        }, indent=2))



def test_post_tool_log_claim_stays_exclusive_when_mkdir_masks_eexist(tmp_path: Path) -> None:
    """Model uutils <=0.10 turning a lost mkdir race into exit status zero."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    bin_dir = tmp_path / "bin"
    _fake_vigil(bin_dir, capture)
    barrier = tmp_path / "mkdir-barrier"
    barrier.mkdir()
    mkdir = bin_dir / "mkdir"
    mkdir.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys, time\n"
        "claim = pathlib.Path(sys.argv[-1])\n"
        "if claim.exists(): sys.exit(1)\n"
        f"barrier = pathlib.Path({str(barrier)!r})\n"
        "(barrier / str(os.getpid())).touch()\n"
        "deadline = time.monotonic() + 3\n"
        "while len(list(barrier.iterdir())) < 2 and time.monotonic() < deadline: pass\n"
        "try: claim.mkdir(mode=0o700)\n"
        "except FileExistsError: pass\n",
        encoding="utf-8",
    )
    mkdir.chmod(0o755)
    payload = _native_log_payload(engagement_dir)
    env = _session_end_env(bin_dir)

    def deliver(_: int) -> subprocess.CompletedProcess[str]:
        return _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=env)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(deliver, range(2)))
    assert all(result.returncode == 0 for result in results)
    assert len(_captured(capture)) == 1

    repeated = _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=env)
    assert repeated.returncode == 0
    assert len(_captured(capture)) == 1


@pytest.mark.parametrize("kind", ["file", "directory", "fifo", "dangling_symlink"])
def test_post_tool_log_existing_native_claim_is_a_nonblocking_noop(
    tmp_path: Path, kind: str
) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    identity = json.dumps(["opencode", "session-1", "tu-1"], separators=(",", ":"))
    digest = hashlib.sha256(identity.encode()).hexdigest()
    claim = engagement_dir / f".hook_tool_use_{digest}"
    if kind == "file":
        claim.write_text("successful prior delivery", encoding="utf-8")
    elif kind == "directory":
        claim.mkdir()
    elif kind == "fifo":
        os.mkfifo(claim)
    else:
        claim.symlink_to(tmp_path / "absent")

    result = _run_hook(
        POST_TOOL_LOG, _native_log_payload(engagement_dir), cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin"), timeout=3,
    )
    assert result.returncode == 0
    assert result.stdout == result.stderr == ""
    assert _captured(capture) == []

def test_post_tool_log_does_not_follow_native_claim_symlink(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    identity = json.dumps(["opencode", "session-1", "tu-1"], separators=(",", ":"))
    digest = hashlib.sha256(identity.encode()).hexdigest()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    claim = engagement_dir / f".hook_tool_use_{digest}"
    claim.symlink_to(outside, target_is_directory=True)

    result = _run_hook(
        POST_TOOL_LOG,
        _native_log_payload(engagement_dir),
        cwd=engagement_dir,
        env=_session_end_env(tmp_path / "bin"),
    )

    assert result.returncode == 0
    assert _captured(capture) == []
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert claim.is_symlink()


def test_post_tool_log_without_native_identity_retains_short_window_dedup(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    payload = {key: value for key, value in _BASH_PAYLOAD.items() if key != "tool_use_id"}
    env = _session_end_env(tmp_path / "bin")

    first = _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=env)
    second = _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=env)

    assert first.returncode == second.returncode == 0
    assert len(_captured(capture)) == 1


# Each case: the hook's stdin (a payload gets the engagement as ``cwd``; a string
# has ``<ENG>`` replaced) and the (agent, title, action, result) handed to
# `vigil assess log`, one tuple per expected call. Byte truncation, jq's raw and
# pretty printing, and its failure modes all reach the activity row, so the
# exact argv is pinned.
_LONG_UNICODE = "Z" * 281 + "é" * 30
_POST_TOOL_LOG_PIN_CASES: list[tuple[str, object, list[list[str]]]] = [
    ("bash_success", {
        "tool_name": "Bash", "agent_type": "code-vuln-hunter", "tool_use_id": "tu-ok",
        "tool_input": {"command": "rg -n 'parse' src/acme"},
        "tool_response": {"stdout": "src/acme/a.py:1:def parse():", "stderr": "", "exitCode": 0},
    }, [["code-vuln-hunter", "Bash", "bash: rg -n 'parse' src/acme", "src/acme/a.py:1:def parse():"]]),
    ("bash_nonzero_without_stdout", {
        "tool_name": "Bash", "tool_use_id": "tu-nz",
        "tool_input": {"command": "make test"},
        "tool_response": {"stdout": "", "stderr": "boom", "exitCode": 2},
    }, [["operator", "Bash", "bash: make test", "exit=2"]]),
    ("bash_nonzero_with_output", {
        "tool_name": "Bash", "agent_name": "codex-lane", "tool_use_id": "tu-nz2",
        "tool_input": {"command": "pytest -q"},
        "tool_response": {"stdout": "1 failed\n\n", "exit_code": 1},
    }, [["codex-lane", "Bash", "bash: pytest -q", "exit=1 | 1 failed"]]),
    ("bash_codex_string_response", {
        "tool_name": "Bash", "tool_use_id": "tu-cx", "client_name": "codex",
        "tool_input": {"command": "id -u\n\n"},
        "tool_response": "Exit code: 0\nWall time: 0.1 seconds\nOutput:\n501\n",
    }, [["operator", "Bash", "bash: id -u", "Exit code: 0\nWall time: 0.1 seconds\nOutput:\n501"]]),
    ("bash_object_exit_code_and_fallback_text", {
        "tool_name": "Bash", "tool_use_id": "tu-ob",
        "tool_input": {"command": "uname -a"},
        "tool_response": {"return_code": {"signal": 9}, "interrupted": False},
    }, [["operator", "Bash", "bash: uname -a", "exit={\n  \"signal\": 9\n} | {\"return_code\":{\"signal\":9},\"interrupted\":false}"]]),
    ("bash_long_unicode_output_is_byte_truncated", {
        "tool_name": "Bash", "tool_use_id": "tu-lu",
        "tool_input": {"command": "x" * 230},
        "tool_response": {"stdout": _LONG_UNICODE, "exitCode": "0"},
    }, [["operator", "Bash", "bash: " + "x" * 200, "Z" * 281 + "é" * 9 + "\udcc3"]]),
    ("bash_nul_inside_the_kept_output", {
        "tool_name": "Bash", "tool_use_id": "tu-nul",
        "tool_input": {"command": "xxd -r dump"},
        "tool_response": {"stdout": "a\u0000b", "exitCode": 0},
    }, [["operator", "Bash", "bash: xxd -r dump", "ab"]]),
    ("bash_nul_after_the_kept_output", {
        "tool_name": "Bash", "tool_use_id": "tu-nul2",
        "tool_input": {"command": "xxd -r dump"},
        "tool_response": {"stdout": "Q" * 400 + "\u0000", "exitCode": 0},
    }, [["operator", "Bash", "bash: xxd -r dump", "Q" * 300]]),
    ("bash_echo_option_command", {
        "tool_name": "Bash", "tool_use_id": "tu-dash",
        "tool_input": {"command": "-n"},
        "tool_response": {"stdout": "-e", "exitCode": 0},
    }, [["operator", "Bash", "bash: ", "-e"]]),
    ("bash_in_scope_raw_curl_is_flagged", {
        "tool_name": "Bash", "tool_use_id": "tu-curl",
        "tool_input": {"command": "cd x && /usr/bin/curl -sk https://EXAMPLE.com:8443/login"},
        "tool_response": {"stdout": "", "exitCode": 7},
    }, [["operator", "Bash", "bash: cd x && /usr/bin/curl -sk https://EXAMPLE.com:8443/login", "VIOLATION: host-side target traffic bypassed 'vigil assess kali'. exit=7"]]),
    ("bash_out_of_scope_curl_is_not_flagged", {
        "tool_name": "Bash", "tool_use_id": "tu-curl2",
        "tool_input": {"command": "curl -s https://api.example.org/x"},
        "tool_response": {"stdout": "{}", "exitCode": 0},
    }, [["operator", "Bash", "bash: curl -s https://api.example.org/x", "{}"]]),
    ("bash_noise_is_skipped", {
        "tool_name": "Bash", "tool_use_id": "tu-ls", "tool_input": {"command": "ls -la"},
    }, []),
    ("bash_non_string_input_is_skipped", {
        "tool_name": "Bash", "tool_use_id": "tu-str", "tool_input": "rg x",
    }, []),
    ("agent_dispatch", {
        "tool_name": "Agent", "agent_type": "operator", "tool_use_id": "tu-agent",
        "tool_input": {"subagent_type": "code-vuln-hunter", "description": "Hunt parsers",
                       "prompt": "P" * 140 + "ü" * 20},
    }, [["operator", "Dispatch: code-vuln-hunter", "Hunt parsers", "P" * 140 + "ü" * 5]]),
    ("agent_dispatch_description_only", {
        "tool_name": "Agent", "tool_use_id": "tu-agent2", "tool_input": {"description": "Map routes"},
    }, [["operator", "Dispatch: Map routes", "Map routes", ""]]),
    ("write_inside_engagements", {
        "tool_name": "Write", "tool_use_id": "tu-w",
        "tool_input": {"file_path": "/work/engagements/acme/notes.md", "content": "x"},
    }, [["operator", "Write", "file=engagements/acme/notes.md", ""]]),
    ("edit_outside_engagements_is_skipped", {
        "tool_name": "Edit", "tool_use_id": "tu-e", "tool_input": {"file_path": "/work/acme/app.py"},
    }, []),
    ("apply_patch", {
        "tool_name": "apply_patch", "tool_use_id": "tu-patch",
        "tool_input": {"command": "*** Begin Patch\n*** Update File: src/b.py\n*** Add File: src/a.py\n"
                                  "*** Update File: src/b.py\n*** Delete File: old.py\n*** End Patch"},
        "tool_response": {"output": "Success.\nM src/b.py"},
    }, [["operator", "apply_patch", "files=old.py, src/a.py, src/b.py", "Success.\nM src/b.py"]]),
    ("mcp_tool_with_object_result", {
        "tool_name": "mcp__acme__search", "tool_use_id": "tu-mcp",
        "tool_input": {"query": "parse", "limit": 5, "nested": {"a": [1, 2]}},
        "tool_response": {"result": {"hits": [{"path": "src/a.py", "line": 1}]}},
    }, [["operator", "mcp__acme__search", 'mcp args={"query":"parse","limit":5,"nested":{"a":[1,2]}}', "{\n  \"hits\": [\n    {\n      \"path\": \"src/a.py\",\n      \"line\": 1\n    }\n  ]\n}"]]),
    ("mcp_tool_with_long_args", {
        "tool_name": "mcp__acme__fetch", "tool_use_id": "tu-mcp2",
        "tool_input": {"blob": "q" * 290 + "ß" * 20}, "tool_response": [{"type": "text", "text": "ok"}],
    }, [["operator", "mcp__acme__fetch", 'mcp args={"blob":"' + "q" * 290 + "\udcc3",
      '[{"type":"text","text":"ok"}]']]),
    ("read_is_not_logged", {
        "tool_name": "Read", "tool_use_id": "tu-read", "tool_input": {"file_path": "/work/x"},
    }, []),
    ("two_json_documents", '{"tool_name":"Bash","cwd":"<ENG>","tool_input":{"command":"rg a"}}'
                           '{"tool_name":"Bash","cwd":"<ENG>","tool_input":{"command":"rg b"}}', []),
    # The ignored-tool shortcut reads tool_name before jq; these shapes must reach jq unchanged.
    ("nested_tool_name_key_does_not_hide_the_call", {
        "tool_input": {"command": "rg acme", "tool_name": "Read"}, "tool_name": "Bash", "tool_use_id": "tu-nest",
    }, [["operator", "Bash", "bash: rg acme", ""]]),
    ("tool_name_quoted_inside_a_command", {
        "tool_name": "Bash", "tool_use_id": "tu-quoted", "tool_input": {"command": 'rg \'"tool_name": "Read"\''},
    }, [["operator", "Bash", 'bash: rg \'"tool_name": "Read"\'', ""]]),
    ("escaped_ignored_tool_name", '{"tool_name":"Re\\u0061d","cwd":"<ENG>","tool_use_id":"tu-esc"}', []),
    ("escaped_logged_tool_name",
     '{"tool_name":"B\\u0061sh","cwd":"<ENG>","tool_use_id":"tu-esc2","tool_input":{"command":"rg q"}}',
     [["operator", "Bash", "bash: rg q", ""]]),
    ("spaced_ignored_tool_name", '{"tool_name" :\n "Grep","cwd":"<ENG>","tool_use_id":"tu-sp"}', []),
    ("spaced_logged_tool_name", '{"tool_name" : "Agent","cwd":"<ENG>","tool_use_id":"tu-sp2","tool_input":{"description":"d"}}',
     [["operator", "Dispatch: d", "d", ""]]),
    ("duplicate_tool_name_keys_take_the_last",
     '{"tool_name":"Read","tool_name":"Bash","cwd":"<ENG>","tool_use_id":"tu-dup","tool_input":{"command":"rg dup"}}',
     [["operator", "Bash", "bash: rg dup", ""]]),
    ("non_string_tool_name_is_skipped", {"tool_name": 5, "tool_use_id": "tu-num"}, []),
    ("trailing_garbage_after_the_payload",
     '{"tool_name":"Agent","cwd":"<ENG>","tool_use_id":"tu-tg","tool_input":{"description":"d"}} xx', [["operator\noperator", "Dispatch: d", "d", ""]]),
]


@pytest.mark.parametrize("jq_flavor", ["installed", "without_raw_output0"])
@pytest.mark.parametrize(
    ("stdin", "expected"),
    [pytest.param(stdin, expected, id=name) for name, stdin, expected in _POST_TOOL_LOG_PIN_CASES],
)
def test_post_tool_log_hands_the_logger_the_exact_activity_fields(
    tmp_path: Path, stdin: object, expected: list[list[str]], jq_flavor: str
) -> None:
    """The fields reaching `vigil assess log` are pinned for every tool shape.

    The second flavor models a jq without ``--raw-output0`` (jq 1.6), which must
    yield the same rows.
    """
    engagement_dir = _engagement(tmp_path)
    (engagement_dir / "scope.json").write_text(json.dumps({
        "status": "in_progress", "hostname": "example.com", "scope": ["example.com"],
    }), encoding="utf-8")
    capture = tmp_path / "capture.jsonl"
    bin_dir = tmp_path / "bin"
    _fake_vigil(bin_dir, capture)
    if jq_flavor == "without_raw_output0":
        real_jq = shutil.which("jq")
        assert real_jq
        jq = bin_dir / "jq"
        jq.write_text(
            "#!/bin/sh\n"
            'for arg in "$@"; do [ "$arg" = --raw-output0 ] && '
            '{ echo "jq: Unknown arguments: $arg" >&2; exit 2; }; done\n'
            f'exec {shlex.quote(real_jq)} "$@"\n',
            encoding="utf-8",
        )
        jq.chmod(0o755)
    text = (
        stdin.replace("<ENG>", str(engagement_dir)) if isinstance(stdin, str)
        else json.dumps({**stdin, "cwd": str(engagement_dir)})
    )

    result = _run_hook(
        POST_TOOL_LOG, None, stdin=text, cwd=engagement_dir, env=_session_end_env(bin_dir)
    )

    assert result.returncode == 0
    assert result.stdout == result.stderr == ""
    calls = _captured(capture)
    assert [call["argv"][:5] for call in calls] == [
        ["assess", "--engagement-dir", str(engagement_dir), "log", "--actor-kind"]
    ] * len(expected)
    assert [call["argv"][5:] for call in calls] == [["hook", "--", *fields] for fields in expected]


def test_post_tool_log_claims_non_ascii_native_identities_by_their_compact_json(
    tmp_path: Path,
) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)
    payload = {**_native_log_payload(engagement_dir), "tool_use_id": "tü-✓ \"q\"\t1"}
    identity = json.dumps(
        ["opencode", "session-1", payload["tool_use_id"]], separators=(",", ":"), ensure_ascii=False
    )
    claim = engagement_dir / f".hook_tool_use_{hashlib.sha256(identity.encode()).hexdigest()}"

    result = _run_hook(POST_TOOL_LOG, payload, cwd=engagement_dir, env=_session_end_env(tmp_path / "bin"))

    assert result.returncode == 0
    assert len(_captured(capture)) == 1
    assert claim.is_file()


def test_post_tool_log_reads_the_payload_with_one_jq_process(tmp_path: Path) -> None:
    """The hook runs after every tool call; its payload fields come from one jq read.

    The second jq process reads scope.json's status.
    """
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    bin_dir = tmp_path / "bin"
    _fake_vigil(bin_dir, capture)
    real_jq = shutil.which("jq")
    assert real_jq
    jq_calls = tmp_path / "jq-calls"
    jq = bin_dir / "jq"
    jq.write_text(
        f'#!/bin/sh\necho x >> {shlex.quote(str(jq_calls))}\nexec {shlex.quote(real_jq)} "$@"\n',
        encoding="utf-8",
    )
    jq.chmod(0o755)

    result = _run_hook(
        POST_TOOL_LOG, {**_BASH_PAYLOAD, "cwd": str(engagement_dir)},
        cwd=engagement_dir, env=_session_end_env(bin_dir),
    )

    assert result.returncode == 0
    assert len(_captured(capture)) == 1
    assert len(jq_calls.read_text(encoding="utf-8").splitlines()) == 2


def _counting_jq(bin_dir: Path, calls: Path) -> None:
    real_jq = shutil.which("jq")
    assert real_jq
    bin_dir.mkdir(parents=True, exist_ok=True)
    jq = bin_dir / "jq"
    jq.write_text(f'#!/bin/sh\necho x >> {shlex.quote(str(calls))}\nexec {shlex.quote(real_jq)} "$@"\n', encoding="utf-8")
    jq.chmod(0o755)


@pytest.mark.parametrize("tool", ["Read", "Grep", "Glob", "WebFetch", "WebSearch", "TodoWrite", "Skill"])
def test_post_tool_log_settles_an_ignored_tool_before_reading_the_payload(tmp_path: Path, tool: str) -> None:
    """An ignored tool never yields a row, so the hook neither runs jq nor claims the call."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    bin_dir = tmp_path / "bin"
    _fake_vigil(bin_dir, capture)
    jq_calls = tmp_path / "jq-calls"
    _counting_jq(bin_dir, jq_calls)

    result = _run_hook(
        POST_TOOL_LOG,
        {"tool_name": tool, "tool_use_id": "tu-ignored", "session_id": "s", "client_name": "opencode",
         "tool_input": {"file_path": "/work/engagements/acme/notes.md", "command": "nmap acme.example"},
         "cwd": str(engagement_dir)},
        cwd=engagement_dir, env=_session_end_env(bin_dir),
    )

    assert result.returncode == 0
    assert result.stdout == result.stderr == ""
    assert _captured(capture) == []
    assert not jq_calls.exists()
    assert not list(engagement_dir.glob(".hook_tool_use_*"))


@pytest.mark.parametrize(("occurred_at", "forwarded"), [
    *[(value, value) for value in ("2026-11-16T10:00:00.123Z", "2026-11-16T10:00:00+00:00", "yesterday",
                                   "2026-11-16T10:00:00.123Z --actor-kind operator", "-n", "Z" * 65, "Z" * 4096)],
    ("", ""), ("Z" * 4097, ""), (1794928482, ""), (None, ""),
])
def test_post_tool_log_dates_the_row_by_the_calls_finish(tmp_path: Path, occurred_at: object, forwarded: str) -> None:
    """A queued native logger names when the call finished; `vigil assess log` alone judges the value.

    It travels as one ``--occurred-at=`` word, so an option-shaped value stays that flag's value. Only a
    string is passed, and only one that keeps the logger's argv small."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _fake_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        POST_TOOL_LOG, {**_native_log_payload(engagement_dir), "occurred_at": occurred_at},
        cwd=engagement_dir, env=_session_end_env(tmp_path / "bin"),
    )

    assert result.returncode == 0
    (call,) = _captured(capture)
    assert call["argv"][5:] == ["hook", *([f"--occurred-at={forwarded}"] if forwarded else []),
                                "--", "operator", "Bash", "bash: whoami", "operator"]


def _recording_vigil(bin_dir: Path, capture: Path) -> None:
    """A `vigil` that runs the real `vigil assess log` and records the payload it posts.

    Only the backend is replaced, so a test sees the row `log` writes, or that it wrote none."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    executable = bin_dir / "vigil"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"sys.path[:0] = [{str(REPO_ROOT / 'agent' / 'scripts')!r}, {str(REPO_ROOT / 'src')!r}]\n"
        "from assess import cli\n"
        "from assess.commands import log_entry\n"
        "from assess.lib import config\n"
        "class Recorder:\n"
        "    def __init__(self, *_args): pass\n"
        "    def __enter__(self): return self\n"
        "    def __exit__(self, *_exc): return False\n"
        "    def post_engagement(self, endpoint, payload):\n"
        f"        with open({str(capture)!r}, 'a', encoding='utf-8') as handle:\n"
        "            handle.write(json.dumps(payload) + '\\n')\n"
        "        return {**payload, 'id': 1}\n"
        "    def post_event(self, _payload): return None\n"
        "log_entry.AssessmentClient = Recorder\n"
        "config._verify_backend = lambda _cfg: None\n"
        "cli.main(sys.argv[2:])\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)


@pytest.mark.parametrize("occurred_at", [
    "2026-13-45T25:61:61Z", "2026-11-16T10:00:00", "yesterday", "-n", "2999-01-01T00:00:00Z",
    "2026-04-17T12:00:00." + "1" * 40 + "+00:00",
])
def test_post_tool_log_records_the_row_when_its_finish_time_is_unusable(tmp_path: Path, occurred_at: str) -> None:
    """The row is still written, dated by the backend when it records it."""
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _recording_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        POST_TOOL_LOG, {**_native_log_payload(engagement_dir), "occurred_at": occurred_at},
        cwd=engagement_dir, env=_session_end_env(tmp_path / "bin", ORCHESTRATOR_BASE_URL="http://127.0.0.1:9"),
    )

    assert result.returncode == 0
    assert _captured(capture) == [{"actor_kind": "hook", "actor_name": "operator", "title": "Bash",
                                   "action": "bash: whoami", "result": "operator"}]
    assert list(engagement_dir.glob(".hook_tool_use_*"))


def test_post_tool_log_records_the_row_at_its_finish_time(tmp_path: Path) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _recording_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        POST_TOOL_LOG, {**_native_log_payload(engagement_dir), "occurred_at": "2026-11-16T10:00:00.123Z"},
        cwd=engagement_dir, env=_session_end_env(tmp_path / "bin", ORCHESTRATOR_BASE_URL="http://127.0.0.1:9"),
    )

    assert result.returncode == 0
    assert _captured(capture) == [{"actor_kind": "hook", "actor_name": "operator", "title": "Bash",
                                   "action": "bash: whoami", "result": "operator",
                                   "occurred_at": "2026-11-16T10:00:00.123Z"}]


def _parsing_vigil(bin_dir: Path, capture: Path) -> None:
    """A `vigil` that parses its argv with the real `vigil assess log` parser.

    It records the fields `log` would write, or the parser's refusal, so a test
    sees what reaches the activity row rather than the raw argv.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    executable = bin_dir / "vigil"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import contextlib, io, json, sys\n"
        f"sys.path[:0] = [{str(REPO_ROOT / 'agent' / 'scripts')!r}, {str(REPO_ROOT / 'src')!r}]\n"
        "from assess import cli\n"
        "argv = cli._hoist_root_flags(sys.argv[2:])\n"
        "row = {}\n"
        "try:\n"
        "    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):\n"
        "        args = cli._build_parser('log', argv).parse_args(argv)\n"
        "    row = {key: getattr(args, key, None) for key in\n"
        "           ('engagement_dir', 'eng_dir', 'actor_kind', 'agent', 'title', 'action', 'result')}\n"
        "except SystemExit as refusal:\n"
        "    row = {'refused': refusal.code}\n"
        f"with open({str(capture)!r}, 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(row) + '\\n')\n"
        "sys.exit(0 if 'refused' not in row else 2)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)


@pytest.mark.parametrize(
    ("payload", "fields"),
    [
        pytest.param(
            {"tool_name": "Bash", "tool_input": {"command": "rg -c x"},
             "tool_response": {"stdout": "-n", "exitCode": 0}},
            ("operator", "Bash", "bash: rg -c x", "-n"),
            id="bash_output_shaped_like_an_option",
        ),
        pytest.param(
            {"tool_name": "Bash", "tool_input": {"command": "printf -- --help"},
             "tool_response": {"stdout": "--help", "exitCode": 0}},
            ("operator", "Bash", "bash: printf -- --help", "--help"),
            id="bash_output_shaped_like_help",
        ),
        pytest.param(
            {"tool_name": "Agent", "agent_type": "-x",
             "tool_input": {"subagent_type": "recon-specialist", "description": "--engagement-dir",
                            "prompt": "--actor-kind"}},
            ("-x", "Dispatch: recon-specialist", "--engagement-dir", "--actor-kind"),
            id="agent_fields_shaped_like_root_flags",
        ),
    ],
)
def test_post_tool_log_rows_survive_option_shaped_values(
    tmp_path: Path, payload: dict, fields: tuple[str, str, str, str]
) -> None:
    engagement_dir = _engagement(tmp_path)
    capture = tmp_path / "capture.jsonl"
    _parsing_vigil(tmp_path / "bin", capture)

    result = _run_hook(
        POST_TOOL_LOG, {**payload, "tool_use_id": "tu-dash", "cwd": str(engagement_dir)},
        cwd=engagement_dir, env=_session_end_env(tmp_path / "bin"),
    )

    assert result.returncode == 0
    agent, title, action, outcome = fields
    assert _captured(capture) == [{
        "engagement_dir": str(engagement_dir), "eng_dir": None, "actor_kind": "hook",
        "agent": agent, "title": title, "action": action, "result": outcome,
    }]
