"""Exercise native protocol callbacks without contacting models or live state."""
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

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


_DISPATCH_SCRIPT = """
import fs from 'node:fs';
const module=await import('data:text/javascript;base64,'+fs.readFileSync(process.argv[1]).toString('base64'));
const options=JSON.parse(process.argv[2]);
const client={session:{
  get:async({path:{id}})=>({data:id==='child'?{id,parentID:'parent',directory:options.directory}:{id}}),
  messages:async()=>({data:[
    {info:{id:'u1',role:'user',sessionID:'child',time:{created:1}},parts:[{type:'text',text:options.prompt}]},
    {info:{id:'a1',role:'assistant',sessionID:'child',agent:options.agent,time:{created:2},
      providerID:'acme',modelID:'model-1',variant:'max'},parts:[]}]})}};
const plugin=await module.VigilAssessmentHooks({client});
const requests=[{system:[]},{system:[]}];
for (const out of requests)
  await plugin['experimental.chat.system.transform']({sessionID:'child',model:{id:'model-1',providerID:'acme'}},out);
const task={title:'lane',output:options.output ?? 'specialist result',metadata:{sessionId:'child'}};
await plugin['tool.execute.after']({tool:'task',sessionID:'parent',callID:'c1',args:{}},task);
process.stdout.write(JSON.stringify({requests,task}));
"""


def _dispatch_fixture(tmp_path, *, binding=None, status="in-progress", mode="web", handoff=None,
                      leases=(), reads_fail=False):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text(
        json.dumps({"status": "in_progress", "tracks": {mode: {"phase": "hunt"}}}))
    agent = tmp_path / "agent"
    (agent / "scripts/hooks").mkdir(parents=True)
    (agent / "scripts/hooks/post-tool-log.sh").write_text("#!/bin/sh\ncat >/dev/null\n")
    packet = ("## Runtime Identity\nagent_id: acme-recon-1\nagent_role: recon-specialist\n"
              f"assessment_mode: {mode}\n\n## Dispatch Context\nagent_id: acme-other\n").encode()
    digest = hashlib.sha256(packet).hexdigest()
    path = engagement / "tools/dispatch-packets/7" / f"{digest}.md"
    path.parent.mkdir(parents=True)
    path.write_bytes(packet)
    calls = tmp_path / "calls.jsonl"
    row = {"id": 7, "agent_id": "acme-recon-1", "agent_role": "recon-specialist", "status": status,
           "client_binding": binding}
    page = {"total": len(leases), "offset": 0, "count": len(leases), "has_more": False,
            "item_ids": [item["id"] for item in leases], "items": list(leases)}
    # The fake helper answers the read verbs the plugin uses: a missing handoff is
    # a failed point read plus `render-handoff` exit 2, as the real CLI reports it.
    helper = tmp_path / "vigil"
    helper.write_text(f"""#!{sys.executable}
import json, sys
with open({str(calls)!r}, "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
verb = sys.argv[2:4]
if {reads_fail!r} and verb != ["agent", "get"] and verb != ["agent", "bind-client-handle"]:
    print("ERROR: backend unreachable", file=sys.stderr)
    sys.exit(1)
if verb == ["agent", "get"]:
    print(json.dumps({row!r}))
elif verb == ["agent", "bind-client-handle"]:
    print(json.dumps({{"binding": {{"binding_version": 1}}, "superseded": None, "already_bound": False}}))
elif sys.argv[2] == "fetch" and sys.argv[3] == "dispatch-handoffs/acme-recon-1":
    if {handoff!r} is None:
        print("ERROR: HTTP 404", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({handoff!r}))
elif verb == ["agent", "render-handoff"]:
    sys.exit(2 if {handoff!r} is None else 0)
elif verb == ["code-dispatch", "list"]:
    print(json.dumps({page!r}, indent=2))
else:
    sys.exit(64)
""")
    helper.chmod(0o755)
    context = tmp_path / "context.json"
    context.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": mode,
        "workspace": str(tmp_path), "engagement_dir": str(engagement), "agent_root": str(agent),
        "vigil_cli": str(helper), "install_root": str(tmp_path), "release_id": "test"}))
    launch = (f"Read the captured dispatch packet {path}; verify SHA-256 {digest}. "
              "Use registered role recon-specialist; if it is not already loaded, read agent/agents/recon-specialist.md.")
    return context, calls, launch, path


def _run_dispatch(context, *, prompt, agent, directory="/acme/clients/opencode/web", output=None):
    result = subprocess.run(["node", "--input-type=module", "-e", _DISPATCH_SCRIPT,
        str(ROOT / "agent/.opencode/plugin/assessment-hooks.js"),
        json.dumps({"prompt": prompt, "agent": agent, "directory": directory,
                    **({} if output is None else {"output": output})})],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(context)}, capture_output=True, text=True,
        timeout=60, check=True)
    return json.loads(result.stdout)


def _calls(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _reported(task):
    lines = [line for line in task["output"].splitlines() if line.startswith("Vigil dispatch binding: ")]
    assert len(lines) == 1, task["output"]
    return json.loads(lines[0].split(": ", 1)[1])


def _advisories(request):
    return [json.loads(line.split("\n", 1)[0].split(": ", 1)[1])
            for line in request["system"] if line.startswith("Vigil advisory: ")]


@pytest.mark.parametrize("agent", ["recon-specialist", "general"])
def test_opencode_child_binds_its_dispatch_on_first_request(tmp_path, agent):
    context, calls, launch, _ = _dispatch_fixture(tmp_path)
    output = _run_dispatch(context, prompt=launch, agent=agent)
    recorded = [call for call in _calls(calls) if call[2] in {"get", "bind-client-handle"}]
    # Resolved once, on the first request, while the native task is still running.
    assert [call[:4] for call in recorded] == [["assess", "agent", "get", "acme-recon-1"],
                                                ["assess", "agent", "bind-client-handle", "acme-recon-1"]]
    bind = recorded[1]
    assert bind[bind.index("--client") + 1] == "opencode"
    assert bind[bind.index("--session-namespace") + 1] == "/acme/clients/opencode/web"
    assert bind[bind.index("--handle") + 1] == "child"
    note = bind[bind.index("--note") + 1]
    assert "acme/model-1" in note and "max" in note and agent in note
    report = _reported(output["task"])
    assert output["task"]["output"].startswith("specialist result")
    assert {key: report[key] for key in ("status", "agent_id", "dispatch_id", "handle", "native_agent",
                                         "registered_role", "model", "variant")} == {
        "status": "bound", "agent_id": "acme-recon-1", "dispatch_id": 7, "handle": "child",
        "native_agent": agent, "registered_role": "recon-specialist", "model": "acme/model-1", "variant": "max"}
    expected = [] if agent == "recon-specialist" else [{"advisory": "native_agent_role_mismatch",
        "agent_id": "acme-recon-1", "dispatch_id": 7, "registered_role": "recon-specialist",
        "native_agent": agent, "handle": "child"}]
    assert report.get("advisories", []) == expected
    # The system prompt is rebuilt per request, so the specialist keeps the advisory.
    for request in output["requests"]:
        assert _advisories(request) == expected


def test_opencode_child_does_not_supersede_another_sessions_binding(tmp_path):
    context, calls, launch, _ = _dispatch_fixture(tmp_path, binding={
        "asserted_client": "opencode", "asserted_session_namespace": "/acme", "asserted_client_handle": "other",
        "binding_version": 1})
    output = _run_dispatch(context, prompt=launch, agent="recon-specialist")
    assert [call[2] for call in _calls(calls)] == ["get"]
    report = _reported(output["task"])
    assert (report["status"], report["reason"]) == ("unresolved", "dispatch_bound_elsewhere")
    assert report["advisories"] == [{"advisory": "dispatch_already_bound", "agent_id": "acme-recon-1",
        "dispatch_id": 7, "handle": "child", "bound_client": "opencode", "bound_handle": "other"}]


def test_opencode_child_refuses_a_packet_that_differs_from_its_digest(tmp_path):
    context, calls, launch, path = _dispatch_fixture(tmp_path)
    path.write_bytes(path.read_bytes().replace(b"acme-recon-1", b"acme-recon-2"))
    output = _run_dispatch(context, prompt=launch, agent="recon-specialist")
    assert _calls(calls) == []
    report = _reported(output["task"])
    assert (report["status"], report["reason"]) == ("unresolved", "packet_unverified")


def test_opencode_child_without_a_dispatch_packet_is_left_unbound(tmp_path):
    context, calls, _, _ = _dispatch_fixture(tmp_path)
    output = _run_dispatch(context, prompt="Summarize the README.", agent="explore")
    assert _calls(calls) == []
    assert output["task"]["output"] == "specialist result"
    assert all(_advisories(request) == [] for request in output["requests"])


def _status(task):
    lines = [line for line in task["output"].splitlines() if line.startswith("Vigil dispatch status: ")]
    assert len(lines) <= 1, task["output"]
    return json.loads(lines[0].split(": ", 1)[1]) if lines else None


def _lease(item_id, receipts, *, file_path=None):
    return {"id": item_id, "status": "processing", "agent_name": "acme-recon-1", "repo_id": 3,
            "file_path": file_path or f"src/acme/module_{item_id}.py", "lease_token": f"lease-{item_id}",
            "heartbeat_age_seconds": 30, "current_result_count": receipts}


def _argv(command, helper):
    argv = shlex.split(command)
    assert argv[:2] == [helper, "assess"], command
    return argv[2:]


# OpenCode wraps a task result as `task_id: ...` plus a <task_result> block.
@pytest.mark.parametrize("output", ["", "  \n",
    "task_id: child (for resuming to continue this task if needed)\n\n<task_result>\n\n</task_result>"])
def test_opencode_reports_a_specialist_that_returns_empty_without_handoff_while_holding_leases(tmp_path, output):
    context, calls, launch, _ = _dispatch_fixture(tmp_path, mode="code",
                                                  leases=[_lease(11, 2), _lease(12, 0)])
    helper = json.loads(context.read_text())["vigil_cli"]
    task = _run_dispatch(context, prompt=launch, agent="recon-specialist", output=output)["task"]
    status = _status(task)
    assert {key: status[key] for key in ("agent_id", "dispatch_id", "empty_result", "handoff",
                                         "handoff_status", "held_leases")} == {
        "agent_id": "acme-recon-1", "dispatch_id": 7, "empty_result": True, "handoff": False,
        "handoff_status": None, "held_leases": 2}
    assert [(lease["item_id"], lease["receipts"], lease["lease_token"]) for lease in status["leases"]] == [
        (11, 2, "lease-11"), (12, 0, "lease-12")]
    commands = [_argv(command, helper) for command in status["next"]]
    verbs = [argv[:2] for argv in commands]
    # Durable work on incomplete scope closes blocked; the receipts move to the
    # replacement, and the attempt that recorded nothing is returned to pending.
    close = commands[verbs.index(["agent", "close"])]
    assert close[2] == "acme-recon-1" and close[close.index("--status") + 1] == "blocked"
    assert "--reason" in close
    assert ["agent", "continue"] in verbs
    adopt = commands[verbs.index(["code-dispatch", "adopt-lease"])]
    assert adopt[2] == "11"
    assert adopt[adopt.index("--from-agent") + 1] == "acme-recon-1"
    assert adopt[adopt.index("--from-lease") + 1] == "lease-11"
    reset = commands[verbs.index(["code-dispatch", "reset-stale"])]
    assert reset[reset.index("--repo-id") + 1] == "3"
    assert reset[reset.index("--path-prefix") + 1] == "src/acme/module_12.py"
    lease_reads = [call for call in _calls(calls) if call[1:3] == ["code-dispatch", "list"]]
    assert len(lease_reads) == 1
    read = lease_reads[0]
    assert read[read.index("--agent-id") + 1] == "acme-recon-1"
    assert read[read.index("--status") + 1] == "processing"


def test_opencode_reports_a_checkpointed_handoff_as_an_incomplete_return(tmp_path):
    context, _, launch, _ = _dispatch_fixture(tmp_path, mode="code",
                                              handoff={"agent_id": "acme-recon-1", "handoff_status": "checkpointed"})
    helper = json.loads(context.read_text())["vigil_cli"]
    task = _run_dispatch(context, prompt=launch, agent="recon-specialist")["task"]
    assert task["output"].startswith("specialist result")
    status = _status(task)
    assert (status["empty_result"], status["handoff"], status["handoff_status"], status["held_leases"]) == (
        False, True, "checkpointed", 0)
    commands = [_argv(command, helper) for command in status["next"]]
    close = next(argv for argv in commands if argv[:2] == ["agent", "close"])
    assert close[close.index("--status") + 1] == "blocked"
    assert not any(argv[0] == "code-dispatch" for argv in commands)


def test_opencode_web_dispatch_without_handoff_is_reported_without_a_lease_read(tmp_path):
    context, calls, launch, _ = _dispatch_fixture(tmp_path)
    helper = json.loads(context.read_text())["vigil_cli"]
    task = _run_dispatch(context, prompt=launch, agent="recon-specialist")["task"]
    status = _status(task)
    assert (status["handoff"], status["empty_result"]) == (False, False)
    assert "held_leases" not in status
    close = next(argv for argv in (_argv(command, helper) for command in status["next"]) if argv[:2] == ["agent", "close"])
    assert close[close.index("--status") + 1] == "failed"
    assert not any(call[1] == "code-dispatch" for call in _calls(calls))


def test_opencode_finished_dispatch_adds_no_status_line(tmp_path):
    context, _, launch, _ = _dispatch_fixture(tmp_path, mode="code",
                                              handoff={"agent_id": "acme-recon-1", "handoff_status": "ready"})
    task = _run_dispatch(context, prompt=launch, agent="recon-specialist")["task"]
    assert _status(task) is None
    _reported(task)


def test_opencode_reports_leases_left_behind_a_final_handoff(tmp_path):
    context, _, launch, _ = _dispatch_fixture(tmp_path, mode="code", leases=[_lease(21, 1)],
                                              handoff={"agent_id": "acme-recon-1", "handoff_status": "ready"})
    helper = json.loads(context.read_text())["vigil_cli"]
    status = _status(_run_dispatch(context, prompt=launch, agent="recon-specialist")["task"])
    assert (status["handoff_status"], status["held_leases"]) == ("ready", 1)
    commands = [_argv(command, helper) for command in status["next"]]
    assert ["code-dispatch", "adopt-lease", "21"] in [argv[:3] for argv in commands]
    close = next(argv for argv in commands if argv[:2] == ["agent", "close"])
    assert "--status" not in close


def test_opencode_empty_result_with_final_handoff_points_at_the_handoff(tmp_path):
    context, _, launch, _ = _dispatch_fixture(tmp_path, mode="code",
                                              handoff={"agent_id": "acme-recon-1", "handoff_status": "blocked"})
    helper = json.loads(context.read_text())["vigil_cli"]
    status = _status(_run_dispatch(context, prompt=launch, agent="recon-specialist", output="")["task"])
    assert (status["empty_result"], status["handoff_status"], status["held_leases"]) == (True, "blocked", 0)
    verbs = [_argv(command, helper)[:2] for command in status["next"]]
    assert ["agent", "render-handoff"] in verbs and ["agent", "close"] in verbs


def test_opencode_dispatch_status_fails_open_with_manual_checks(tmp_path):
    context, calls, launch, _ = _dispatch_fixture(tmp_path, mode="code", reads_fail=True)
    helper = json.loads(context.read_text())["vigil_cli"]
    task = _run_dispatch(context, prompt=launch, agent="recon-specialist", output="")["task"]
    status = _status(task)
    assert (status["agent_id"], status["verified"], status["empty_result"]) == ("acme-recon-1", False, True)
    assert status["detail"]
    verbs = [_argv(command, helper)[:2] for command in status["check"]]
    assert ["agent", "render-handoff"] in verbs and ["code-dispatch", "list"] in verbs
    _reported(task)
    # Bounded: one attempt per read, no polling.
    assert len([call for call in _calls(calls) if call[1:3] == ["code-dispatch", "list"]]) <= 1


_ACTIVITY_SCRIPT = """
import fs from 'node:fs';
const module=await import('data:text/javascript;base64,'+fs.readFileSync(process.argv[1]).toString('base64'));
const options=JSON.parse(process.argv[2]);
const client={session:{get:async({path:{id}})=>({data:{id}}),messages:async()=>({data:[
  {info:{id:'a1',role:'assistant',sessionID:'s1',agent:'operator',time:{created:1},providerID:'acme',modelID:'m'}}]})}};
const plugin=await module.VigilAssessmentHooks({client,activityTimeoutMs:options.timeout});
const started=Date.now();
await plugin['tool.execute.after']({tool:'bash',sessionID:'s1',callID:'call-1',args:{command:'id'}},
  {title:'id',output:'uid=0',metadata:{exit:0}});
process.stdout.write(JSON.stringify({returned_ms:Date.now()-started,marker:fs.existsSync(options.marker)}));
"""


def _activity_fixture(tmp_path, hook_body):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"status":"in_progress","tracks":{"code":{"phase":"hunt"}}}')
    hooks = tmp_path / "agent/scripts/hooks"
    hooks.mkdir(parents=True)
    (hooks / "post-tool-log.sh").write_text("#!/bin/bash\ncat >/dev/null\n" + hook_body)
    binding = tmp_path / "context.json"
    binding.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": "code",
        "workspace": str(tmp_path), "engagement_dir": str(engagement), "agent_root": str(tmp_path / "agent"),
        "vigil_cli": "/bin/false", "install_root": str(tmp_path), "release_id": "test"}))
    return binding


def _run_activity(binding, *, marker, timeout):
    result = subprocess.run(["node", "--input-type=module", "-e", _ACTIVITY_SCRIPT,
        str(ROOT / "agent/.opencode/plugin/assessment-hooks.js"),
        json.dumps({"marker": str(marker), "timeout": timeout})],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)}, capture_output=True, text=True,
        timeout=60, check=True)
    return json.loads(result.stdout), result.stderr


def test_opencode_activity_write_does_not_block_the_tool_result(tmp_path):
    marker = tmp_path / "logged"
    binding = _activity_fixture(tmp_path, f"sleep 1\ntouch {shlex.quote(str(marker))}\n")
    output, stderr = _run_activity(binding, marker=marker, timeout=30000)
    assert output["marker"] is False
    # The queued write still completes before the process exits.
    assert marker.exists(), stderr
    assert not list(tmp_path.glob(".vigil-activity-unrecorded*"))


def test_opencode_activity_timeout_keeps_the_unconfirmed_row(tmp_path):
    marker = tmp_path / "never"
    binding = _activity_fixture(tmp_path, "exec sleep 8\n")
    _, stderr = _run_activity(binding, marker=marker, timeout=300)
    spool = tmp_path / ".vigil-activity-unrecorded.jsonl"
    assert spool.exists(), stderr
    rows = [json.loads(line) for line in spool.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["unconfirmed_this_session"] == 1
    assert rows[0]["error"]
    assert (rows[0]["payload"]["tool_use_id"], rows[0]["payload"]["session_id"]) == ("call-1", "s1")
    assert str(spool) in stderr
