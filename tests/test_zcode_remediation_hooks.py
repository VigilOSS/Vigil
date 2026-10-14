"""Exercise the native ZCode subprocess protocol on defensive case context."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


REPO = Path(__file__).resolve().parents[1]
PLUGIN = REPO / "agent/.zcode"


def invoke(tmp_path: Path, payload, *, context_updates=None, malformed=False):
    registration = PLUGIN / "hooks/hooks.json"
    contract = json.loads(registration.read_text()) if registration.exists() else {}
    entries = contract.get("hooks", {}).get("SessionStart", [])
    assert entries, "The remediation plugin must register native session restoration"
    executor = entries[0]["hooks"][0]
    assert executor["type"] == "process"
    plugin = tmp_path / "plugin"
    shutil.copytree(PLUGIN, plugin)
    repository = tmp_path / "acme"
    repository.mkdir()
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    (engagement / "scope.json").write_text(json.dumps({
        "engagement_type": "remediation", "status": "in_progress",
    }))
    context = {
        "engagement_dir": str(engagement), "engagement_key": "acme",
        "install_root": str(tmp_path / "private workspace"),
        "repository": str(repository), "profile": str(repository / "PROJECT.md"),
        "agent_root": str(tmp_path / "release/agent"), "helper_path": None,
    }
    context.update(context_updates or {})
    (plugin / "vigil-context.json").write_text(json.dumps(context))
    if isinstance(payload, dict):
        payload = {"cwd": str(repository), **payload}
    stdin = "{" if malformed else json.dumps(payload)
    args = [arg.replace("${ZCODE_PLUGIN_ROOT}", str(plugin)) for arg in executor["args"]]
    result = subprocess.run(
        [executor["command"], *args], input=stdin, text=True, capture_output=True,
        env={**os.environ, "ZCODE_PLUGIN_ROOT": str(plugin)}, timeout=10,
    )
    return result, context


@pytest.mark.parametrize("source", ["startup", "resume", "clear", "compact"])
def test_native_session_hook_restores_only_bound_remediation_context(tmp_path, source):
    result, context = invoke(tmp_path, {"hook_event_name": "SessionStart", "source": source})
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)["hookSpecificOutput"]
    assert output["hookEventName"] == "SessionStart"
    text = output["additionalContext"]
    assert context["engagement_dir"] in text
    assert context["profile"] in text
    assert context["agent_root"] in text
    command = f"vigil --root '{context['install_root']}' remediation -k 'acme'"
    assert f"{command} list" in text
    assert f"{command} show <case-id>" in text


@pytest.mark.parametrize("payload", [
    {"hook_event_name": "Stop", "source": "compact"},
    {"hook_event_name": "SessionStart", "source": "unknown"},
    {"hook_event_name": "SessionStart", "source": "compact", "cwd": "/unrelated/acme"},
    [], None,
])
def test_hook_does_not_inject_into_unbound_or_unrelated_session(tmp_path, payload):
    result, _ = invoke(tmp_path, payload)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_malformed_native_hook_input_does_not_block_compaction(tmp_path):
    result, _ = invoke(tmp_path, None, malformed=True)
    assert result.returncode == 0
    assert result.stdout == ""


def test_invalid_context_does_not_become_an_authoritative_engagement(tmp_path):
    result, _ = invoke(tmp_path, {"hook_event_name": "SessionStart", "source": "compact"},
                       context_updates={"engagement_dir": "/unrelated/engagement"})
    assert result.returncode == 0
    assert result.stdout == ""


def test_engagement_key_is_quoted_as_one_command_argument(tmp_path):
    key = "acme'; printf unexpected; '"
    result, _ = invoke(tmp_path, {"hook_event_name": "SessionStart", "source": "compact"},
                       context_updates={"engagement_key": key})
    assert result.returncode == 0
    text = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "'acme'\"'\"'; printf unexpected; '\"'\"''" in text


def test_gui_context_explicitly_binds_private_root_despite_ambient_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_INSTALL_DIR", "/unrelated/old-workspace")
    result, context = invoke(tmp_path, {"hook_event_name": "SessionStart", "source": "compact"})
    assert result.returncode == 0
    text = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    assert f"--root '{context['install_root']}' remediation -k 'acme'" in text
    assert "/unrelated/old-workspace" not in text
