"""Exercise native protocol callbacks without contacting models or live state."""
import json
import os
from pathlib import Path
import subprocess
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_opencode_retained_runtime_supplies_its_own_shell_hook_environment(tmp_path):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"status":"in_progress","tracks":{"code":{}}}')
    application = tmp_path / "application-b"
    hooks = application / "agent/scripts/hooks"
    hooks.mkdir(parents=True)
    (hooks / "pre-compact.sh").write_text(
        '#!/bin/sh\nprintf "%s\\n" "$VIGIL_CLIENT_CONTEXT" "$VIGIL_APPLICATION_DIR" "$PATH"\n')
    binding = tmp_path / "context-b.json"
    tools = tmp_path / "tools-b"
    binding.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": "code",
        "workspace": str(tmp_path), "engagement_dir": str(engagement), "agent_root": str(application / "agent"),
        "vigil_cli": "/bin/false", "install_root": str(tmp_path), "release_id": "test",
        "tools": {"bash": shutil.which("bash"), "jq": str(tools / "jq")}}))
    script = """
import fs from 'node:fs';
const module=await import('data:text/javascript;base64,'+fs.readFileSync(process.argv[1]).toString('base64'));
const plugin=await module.VigilAssessmentHooks({client:{},bindingPath:process.argv[2]});
const out={context:[]}; await plugin['experimental.session.compacting']({sessionID:'session-b'},out);
process.stdout.write(JSON.stringify(out));
"""
    result = subprocess.run([shutil.which("node"), "--input-type=module", "-e", script,
        str(ROOT / "agent/.opencode/plugin/assessment-hooks.js"), str(binding)],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(tmp_path / "context-a.json"),
             "VIGIL_APPLICATION_DIR": str(tmp_path / "application-a"),
             "PATH": "/launch/tools-a:/usr/bin:/bin"},
        capture_output=True, text=True, timeout=10, check=True)
    context, app, path = json.loads(result.stdout)["context"][0].splitlines()
    assert context == str(binding)
    assert app == str(application)
    directories = path.split(os.pathsep)
    assert directories[0] == str(tmp_path / "bin")
    assert directories.index(str(tools)) < directories.index("/launch/tools-a")


def test_opencode_compaction_hook_extends_native_summary_context(tmp_path):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"status":"in_progress","engagement_type":"offensive","tracks":{"code":{"phase":"hunt"}}}')
    context = tmp_path / "context.json"
    context.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": "code",
        "workspace": str(tmp_path), "engagement_dir": str(engagement), "agent_root": str(ROOT / "agent"),
        "vigil_cli": "/bin/false", "install_root": str(tmp_path), "release_id": "test"}))
    source = ROOT / "agent/.opencode/plugin/assessment-hooks.js"
    if not source.exists():
        source = ROOT / "agent/.opencode/plugin/standard-hooks.js"
    script = """
import {readFileSync} from 'node:fs';
const module = await import('data:text/javascript;base64,' + readFileSync(process.argv[1]).toString('base64'));
const plugin = await Object.values(module)[0]({client:{}});
const out = {context:['native-default']};
if (plugin['experimental.session.compacting']) await plugin['experimental.session.compacting']({sessionID:'session-1'},out);
process.stdout.write(JSON.stringify(out));
"""
    result = subprocess.run(["node", "--input-type=module", "-e", script, str(source)],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(context)}, capture_output=True, text=True, check=True)
    contexts = json.loads(result.stdout)["context"]
    assert contexts[0] == "native-default"
    assert len(contexts) > 1


def test_pending_compaction_survives_summarizer_and_missing_summary(tmp_path):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"status":"in_progress","tracks":{"code":{"phase":"hunt"}}}')
    agent = tmp_path / "agent"
    scripts = agent / "scripts/hooks"
    scripts.mkdir(parents=True)
    for name in ("pre-compact.sh", "post-compact-resume.sh"):
        (scripts / name).write_text("#!/bin/sh\nprintf '%s' native-context\n")
    binding = tmp_path / "context.json"
    binding.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": "code",
        "workspace": str(tmp_path), "engagement_dir": str(engagement), "agent_root": str(agent),
        "vigil_cli": "/bin/false", "install_root": str(tmp_path), "release_id": "test"}))
    script = """
import fs from 'node:fs';
const module = await import('data:text/javascript;base64,' + fs.readFileSync(process.argv[1]).toString('base64'));
let agent = 'compaction';
const client = {session:{get:async()=>({data:{id:'s1'}}),messages:async()=>({data:[{info:{id:'a1',role:'assistant',
  agent,mode:agent,sessionID:'s1',time:{created:1},modelID:'m1',providerID:'p1'}}]})}};
const plugin = await module.VigilAssessmentHooks({client});
await plugin['experimental.session.compacting']({sessionID:'s1'},{context:[]});
const summarizer = {system:[]};
await plugin['experimental.chat.system.transform']({sessionID:'s1',model:{id:'m1',providerID:'p1'}},summarizer);
agent = 'operator';
await plugin['experimental.chat.system.transform']({sessionID:'s1',model:{id:'m1',providerID:'p1'}},{system:[]});
const receipt = JSON.parse(fs.readFileSync(process.argv[2]));
process.stdout.write(JSON.stringify({receipt,summarizer}));
"""
    import hashlib
    health = tmp_path / (".vigil-health-" + hashlib.sha256(b"s1").hexdigest() + ".json")
    result = subprocess.run(["node", "--input-type=module", "-e", script,
        str(ROOT / "agent/.opencode/plugin/assessment-hooks.js"), str(health)],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)}, capture_output=True, text=True, check=True)
    output = json.loads(result.stdout)
    assert output["summarizer"]["system"] == []
    assert output["receipt"]["recovery_pending"] is True


def test_ambiguous_native_requests_do_not_consume_context(tmp_path):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"status":"in_progress","tracks":{"web":{"phase":"recon"}}}')
    binding = tmp_path / "context.json"
    binding.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": "web",
        "workspace": str(tmp_path), "engagement_dir": str(engagement), "agent_root": str(ROOT / "agent"),
        "vigil_cli": "/bin/false", "install_root": str(tmp_path), "release_id": "test"}))
    script = """
import fs from 'node:fs';
const module=await import('data:text/javascript;base64,'+fs.readFileSync(process.argv[1]).toString('base64'));
const client={session:{get:async()=>({data:{id:'s'}}),messages:async()=>({data:[1,2].map(id=>({info:{id:String(id),
  role:'assistant',sessionID:'s',agent:'operator',time:{created:id},providerID:'p',modelID:'m'}}))})}};
const plugin=await module.VigilAssessmentHooks({client});
const out={system:[]}; await plugin['experimental.chat.system.transform']({sessionID:'s',model:{id:'m',providerID:'p'}},out);
process.stdout.write(JSON.stringify({out,receipts:fs.readdirSync(process.argv[2]).filter(n=>n.startsWith('.vigil-health-'))}));
"""
    result = subprocess.run(["node", "--input-type=module", "-e", script,
        str(ROOT / "agent/.opencode/plugin/assessment-hooks.js"), str(tmp_path)],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)}, capture_output=True, text=True, check=True)
    output = json.loads(result.stdout)
    assert output["out"]["system"]
    assert output["receipts"] == []


@pytest.mark.parametrize(("actor", "parent", "revert", "recover"), [
    ("operator", False, False, True),
    ("code-architect", False, False, False),
    ("operator", True, False, False),
    ("operator", False, True, False),
])
def test_summary_recovery_remains_available_for_operator_after_auxiliary_callback(
    tmp_path, actor, parent, revert, recover,
):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"status":"in_progress","tracks":{"code":{"phase":"hunt"}}}')
    agent = tmp_path / "agent"
    hooks = agent / "scripts/hooks"
    hooks.mkdir(parents=True)
    (hooks / "post-compact-resume.sh").write_text("#!/bin/sh\nprintf '%s' recovery-marker\n")
    binding = tmp_path / "context.json"
    binding.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": "code",
        "workspace": str(tmp_path), "engagement_dir": str(engagement), "agent_root": str(agent),
        "vigil_cli": "/bin/false", "install_root": str(tmp_path), "release_id": "test"}))
    script = """
import fs from 'node:fs';
const module=await import('data:text/javascript;base64,'+fs.readFileSync(process.argv[1]).toString('base64'));
const options=JSON.parse(process.argv[2]);
const client={session:{get:async()=>({data:{id:'s',...(options.parent?{parentID:'p'}:{}),
  ...(options.revert?{revert:{messageID:'summary'}}:{})}}),messages:async()=>({data:[
  {info:{id:'summary',role:'assistant',sessionID:'s',agent:'compaction',summary:true,finish:'stop',time:{created:1}}},
  {info:{id:'current',role:'assistant',sessionID:'s',agent:options.actor,time:{created:2},modelID:'m',providerID:'p'}}
]})}};
const plugin=await module.VigilAssessmentHooks({client});
// Title and ordinary requests expose the same session/model callback identity.
const auxiliary={system:[]},operator={system:[]};
for (const out of [auxiliary,operator])
  await plugin['experimental.chat.system.transform']({sessionID:'s',model:{id:'m',providerID:'p'}},out);
process.stdout.write(JSON.stringify({auxiliary,operator}));
"""
    result = subprocess.run(["node", "--input-type=module", "-e", script,
        str(ROOT / "agent/.opencode/plugin/assessment-hooks.js"),
        json.dumps({"actor": actor, "parent": parent, "revert": revert})],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)}, capture_output=True, text=True, check=True)
    output = json.loads(result.stdout)
    for callback in ("auxiliary", "operator"):
        assert any("recovery-marker" in value for value in output[callback]["system"]) is recover
