"""Native subprocess and activity contracts, without GUI or backend access."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
OPENCODE = ROOT / "agent/.opencode/plugin/assessment-hooks.js"
ZCODE = ROOT / "agent/.zcode/assessment/hooks/context.mjs"


def _binding(tmp_path: Path, *, client: str) -> tuple[Path, dict]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    (engagement / "scope.json").write_text(json.dumps({
        "status": "in_progress", "tracks": {"code": {"phase": "hunt"}},
    }))
    agent = tmp_path / "agent"
    hooks = agent / "scripts/hooks"
    hooks.mkdir(parents=True)
    capture = tmp_path / "capture.json"
    (hooks / "post-tool-log.sh").write_text(f"#!/bin/bash\n/bin/cat > {str(capture)!r}\n")
    context = {
        "schema_version": 1, "client": client, "mode": "code",
        "workspace": str(workspace), "engagement_dir": str(engagement),
        "agent_root": str(agent), "vigil_cli": "/bin/false",
        "install_root": str(tmp_path), "release_id": "test-release",
        "tools": {"bash": "/bin/bash"},
    }
    binding = workspace / ".vigil-client-context.json"
    binding.write_text(json.dumps(context))
    return binding, context


def _zcode_plugin(tmp_path: Path) -> Path:
    plugin = tmp_path / "plugin"
    hooks = plugin / "hooks"
    hooks.mkdir(parents=True)
    script = hooks / "context.mjs"
    shutil.copy2(ZCODE, script)
    (plugin / "vigil-release.json").write_text('{"release_id":"test-release"}')
    return script


def _zcode_run(script: Path, payload: dict, *, cwd: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("ZCODE_PLUGIN_DATA", None)
    return subprocess.run(["node", str(script)], input=json.dumps(payload), cwd=cwd,
                          env=env, text=True, capture_output=True, timeout=10, check=True)


@pytest.mark.parametrize("kind", ["code", "both"])
def test_zcode_legacy_scope_uses_canonical_mode_helper(tmp_path: Path, kind: str) -> None:
    binding, context = _binding(tmp_path, client="zcode")
    scope = {"status": "in_progress", "engagement_type": kind, "current_phase": "hunt", "code_phase": "hunt"}
    (Path(context["engagement_dir"]) / "scope.json").write_text(json.dumps(scope))
    helper = tmp_path / "vigil"
    helper.write_text("#!/bin/sh\nprintf '%s' '{\"mode\":\"code\",\"enabled_tracks\":[\"code\"]}'\n")
    helper.chmod(0o755)
    context["vigil_cli"] = str(helper)
    binding.write_text(json.dumps(context))
    result = _zcode_run(_zcode_plugin(tmp_path), {
        "hook_event_name": "SessionStart", "source": "startup", "session_id": "legacy-session",
        "cwd": context["workspace"],
    }, cwd=Path(context["workspace"]))
    output = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "Restore the session-selected code Vigil operator" in output
    assert list(Path(context["workspace"]).glob(".vigil-health-*.json"))


def test_zcode_specialist_receives_role_context_without_operator_hydration(tmp_path: Path) -> None:
    _, context = _binding(tmp_path, client="zcode")
    result = _zcode_run(_zcode_plugin(tmp_path), {
        "hook_event_name": "SessionStart", "source": "compact", "session_id": "child-session",
        "agent_type": "code-architect", "cwd": context["workspace"],
    }, cwd=Path(context["workspace"]))
    output = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "Restore only this specialist" in output
    assert context["vigil_cli"] in output


@pytest.mark.parametrize("event", ["PostToolUse", "PostToolUseFailure"])
def test_zcode_error_context_matches_native_event(tmp_path: Path, event: str) -> None:
    script = _zcode_plugin(tmp_path)
    # Missing session identity makes the adapter emit a recoverable diagnostic.
    result = _zcode_run(script, {"hook_event_name": event}, cwd=tmp_path)
    output = json.loads(result.stdout)
    assert output["hookSpecificOutput"]["hookEventName"] == event
    assert result.stderr


@pytest.mark.parametrize("tool", ["write", "edit"])
def test_opencode_normalizes_native_file_path_without_losing_input(tmp_path: Path, tool: str) -> None:
    binding, context = _binding(tmp_path, client="opencode")
    script = """
import {readFileSync} from 'node:fs';
const module = await import('data:text/javascript;base64,' + readFileSync(process.argv[1]).toString('base64'));
const adapter = await module.VigilAssessmentHooks({client:{}});
await adapter['tool.execute.after']({tool:process.argv[2],sessionID:'session-1',callID:'call-1',
  args:{filePath:'/workspace/engagements/acme/findings.md',content:'Acme content',oldString:'old',newString:'new'}},
  {output:'saved',metadata:{}});
"""
    result = subprocess.run(["node", "--input-type=module", "-e", script, str(OPENCODE), tool],
                            env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)},
                            capture_output=True, text=True, timeout=10, check=True)
    assert result.stdout == ""
    payload = json.loads((tmp_path / "capture.json").read_text())
    assert payload["tool_name"] == tool.title()
    assert payload["tool_input"]["file_path"] == payload["tool_input"]["filePath"]
    assert payload["tool_input"]["content"] == "Acme content"
    assert payload["tool_input"]["oldString"] == "old"
    assert payload["tool_input"]["newString"] == "new"
    assert payload["cwd"] == context["engagement_dir"]


def test_opencode_exit_normalization_preserves_native_payload(tmp_path: Path) -> None:
    binding, _ = _binding(tmp_path, client="opencode")
    script = """
import {readFileSync} from 'node:fs';
const module=await import('data:text/javascript;base64,'+readFileSync(process.argv[1]).toString('base64'));
const adapter=await module.VigilAssessmentHooks({client:{}});
await adapter['tool.execute.after']({tool:'bash',sessionID:'acme-session',callID:'acme-call',args:{command:'printf Acme'}},
 {title:'Acme',output:'Acme failure',metadata:{exit:7,description:'Acme task'},native_extra:{count:2}});
"""
    subprocess.run(["node", "--input-type=module", "-e", script, str(OPENCODE)],
                   env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)},
                   capture_output=True, text=True, timeout=10, check=True)
    payload = json.loads((tmp_path / "capture.json").read_text())
    assert payload["tool_response"]["exit_code"] == 7
    assert payload["tool_response"]["metadata"] == {"exit": 7, "description": "Acme task"}
    assert payload["tool_response"]["native_extra"] == {"count": 2}
    assert payload["native_tool_name"] == "bash"


def test_zcode_health_receipt_identifies_exact_binding(tmp_path: Path) -> None:
    binding, context = _binding(tmp_path, client="zcode")
    result = _zcode_run(_zcode_plugin(tmp_path), {
        "hook_event_name": "SessionStart", "source": "startup", "session_id": "session-1",
        "cwd": context["workspace"],
    }, cwd=Path(context["workspace"]))
    assert json.loads(result.stdout)["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    health = list(Path(context["workspace"]).glob(".vigil-health-*.json"))
    assert len(health) == 1
    receipt = json.loads(health[0].read_text())
    assert receipt["binding_sha256"] == hashlib.sha256(binding.read_bytes()).hexdigest()
    assert receipt["release_id"] == context["release_id"]


def test_opencode_health_receipt_identifies_exact_binding(tmp_path: Path) -> None:
    binding, context = _binding(tmp_path, client="opencode")
    script = """
import {readFileSync} from 'node:fs';
const module = await import('data:text/javascript;base64,' + readFileSync(process.argv[1]).toString('base64'));
const client = {session:{messages:async()=>({data:[{info:{role:'assistant',id:'a1',sessionID:'session-1',
  agent:'operator',time:{created:1},modelID:'model',providerID:'provider'}}]}),
  get:async()=>({data:{id:'session-1'}})}};
const adapter = await module.VigilAssessmentHooks({client});
await adapter['experimental.chat.system.transform']({sessionID:'session-1',model:{id:'model',providerID:'provider'}},{system:[]});
"""
    subprocess.run(["node", "--input-type=module", "-e", script, str(OPENCODE)],
                   env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)},
                   capture_output=True, text=True, timeout=10, check=True)
    health = list(Path(context["workspace"]).glob(".vigil-health-*.json"))
    assert len(health) == 1
    receipt = json.loads(health[0].read_text())
    assert receipt["binding_sha256"] == hashlib.sha256(binding.read_bytes()).hexdigest()
    assert receipt["release_id"] == context["release_id"]


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_health_write_can_retry_after_rename_failure(tmp_path: Path, client: str) -> None:
    binding, context = _binding(tmp_path, client=client)
    source = _zcode_plugin(tmp_path) if client == "zcode" else OPENCODE
    script = """
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
import {Readable} from 'node:stream';
import {pathToFileURL} from 'node:url';
const rename = fs.renameSync;
let failed = false;
fs.renameSync = (source, target) => {
  if (!failed && String(target).includes('.vigil-health-')) {failed=true; throw new Error('injected transient rename failure')}
  return rename(source,target);
};
syncBuiltinESMExports();
if (process.argv[2] === 'opencode') {
  const module = await import('data:text/javascript;base64,' + fs.readFileSync(process.argv[1]).toString('base64'));
  const client = {session:{messages:async()=>({data:[{info:{role:'assistant',id:'a1',sessionID:'session-1',
    agent:'operator',time:{created:1},modelID:'model',providerID:'provider'}}]}),get:async()=>({data:{id:'session-1'}})}};
  const adapter = await module.VigilAssessmentHooks({client});
  for (let attempt=0;attempt<2;attempt++) await adapter['experimental.chat.system.transform'](
    {sessionID:'session-1',model:{id:'model',providerID:'provider'}},{system:[]});
} else {
  for(let attempt=0;attempt<2;attempt++) {
    Object.defineProperty(process,'stdin',{value:Readable.from([JSON.stringify({hook_event_name:'SessionStart',
      source:'startup',session_id:'session-1',cwd:process.argv[3]})]),configurable:true});
    await import(pathToFileURL(process.argv[1]).href+'?attempt='+attempt);
  }
}
"""
    env = {**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)}
    env.pop("ZCODE_PLUGIN_DATA", None)
    subprocess.run(["node", "--input-type=module", "-e", script, str(source), client, context["workspace"]],
                   env=env, capture_output=True, text=True, timeout=10, check=True)
    health = list(Path(context["workspace"]).glob(".vigil-health-*.json"))
    assert len(health) == 1, "A recoverable receipt-write error must allow the next observation"
    receipt = json.loads(health[0].read_text())
    assert receipt["session_id"] == "session-1"


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_observations_from_other_binding_do_not_verify_current_binding(tmp_path: Path, client: str) -> None:
    binding, context = _binding(tmp_path, client=client)
    health = Path(context["workspace"]) / (
        ".vigil-health-" + hashlib.sha256(b"session-1").hexdigest() + ".json"
    )
    health.write_text(json.dumps({
        "schema_version": 1, "client": client, "session_id": "session-1",
        "release_id": context["release_id"], "binding_sha256": "other-binding",
        "compact_observed": True, "compacting_observed": True,
    }))
    if client == "zcode":
        _zcode_run(_zcode_plugin(tmp_path), {
            "hook_event_name": "SessionStart", "source": "startup", "session_id": "session-1",
            "cwd": context["workspace"],
        }, cwd=Path(context["workspace"]))
    else:
        script = """
import {readFileSync} from 'node:fs';
const module = await import('data:text/javascript;base64,' + readFileSync(process.argv[1]).toString('base64'));
const client = {session:{messages:async()=>({data:[{info:{role:'assistant',id:'a1',sessionID:'session-1',
  agent:'operator',time:{created:1},modelID:'model',providerID:'provider'}}]}),get:async()=>({data:{id:'session-1'}})}};
const adapter = await module.VigilAssessmentHooks({client});
await adapter['experimental.chat.system.transform']({sessionID:'session-1',model:{id:'model',providerID:'provider'}},{system:[]});
"""
        subprocess.run(["node", "--input-type=module", "-e", script, str(OPENCODE)],
                       env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)},
                       capture_output=True, text=True, timeout=10, check=True)
    receipt = json.loads(health.read_text())
    assert receipt["binding_sha256"] == hashlib.sha256(binding.read_bytes()).hexdigest()
    assert not receipt.get("compact_observed", False)
    assert not receipt.get("compacting_observed", False)


def test_opencode_in_memory_observations_are_scoped_to_exact_binding(tmp_path: Path) -> None:
    binding, context = _binding(tmp_path, client="opencode")
    (Path(context["agent_root"]) / "scripts/hooks/pre-compact.sh").write_text("printf 'Acme context'\n")
    script = """
import {readFileSync,writeFileSync} from 'node:fs';
const module = await import('data:text/javascript;base64,' + readFileSync(process.argv[1]).toString('base64'));
const client = {session:{messages:async()=>({data:[{info:{role:'assistant',id:'a1',sessionID:'session-1',
  agent:'operator',time:{created:1},modelID:'model',providerID:'provider'}}]}),get:async()=>({data:{id:'session-1'}})}};
const adapter = await module.VigilAssessmentHooks({client});
const request={sessionID:'session-1',model:{id:'model',providerID:'provider'}};
await adapter['experimental.chat.system.transform'](request,{system:[]});
await adapter['experimental.session.compacting']({sessionID:'session-1'},{context:[]});
const binding=JSON.parse(readFileSync(process.env.VIGIL_CLIENT_CONTEXT,'utf8'));
binding.backend_url='http://127.0.0.1:9';
writeFileSync(process.env.VIGIL_CLIENT_CONTEXT,JSON.stringify(binding));
await adapter['experimental.chat.system.transform'](request,{system:[]});
"""
    subprocess.run(["node", "--input-type=module", "-e", script, str(OPENCODE)],
                   env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)},
                   capture_output=True, text=True, timeout=10, check=True)
    health = list(Path(context["workspace"]).glob(".vigil-health-*.json"))
    assert len(health) == 1
    receipt = json.loads(health[0].read_text())
    assert receipt["binding_sha256"] == hashlib.sha256(binding.read_bytes()).hexdigest()
    assert not receipt.get("compacting_observed", False)


def test_zcode_activity_without_native_actor_is_unknown(tmp_path: Path) -> None:
    binding, context = _binding(tmp_path, client="zcode")
    result = _zcode_run(_zcode_plugin(tmp_path), {
        "hook_event_name": "PostToolUse", "session_id": "session-1", "tool_use_id": "call-1",
        "cwd": context["workspace"], "tool_name": "Bash", "tool_input": {"command": "whoami"},
        "tool_response": {"stdout": "Acme", "exit_code": 0},
    }, cwd=Path(context["workspace"]))
    assert result.stdout == ""
    payload = json.loads((tmp_path / "capture.json").read_text())
    assert payload["agent_type"] == "unknown"
