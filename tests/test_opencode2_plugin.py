"""OpenCode 2 plugin contracts, driven through a fake 2.x host without models or live state.

Every Vigil plugin entry is auto-discovered by whichever OpenCode major runs, so each one
default-exports ``{id, server, setup}``: 1.x selects ``server`` and 2.x calls ``setup``.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from vigil_cli import assessment_clients
from vigil_cli.assessment_clients import prepare_workspace
from vigil_cli.client_projects import prepare_project

ROOT = Path(__file__).resolve().parents[1]
PLUGINS = ROOT / "agent/.opencode/plugin"
RUNTIME = PLUGINS / "assessment-hooks.js"
DISPATCHER = PLUGINS / "project-dispatch.js"
STANDARD = PLUGINS / "standard-hooks.js"

# OpenCode 2.3.0 registers any hook name silently, so a misspelt name would never fire.
# These are the names its plugin API defines: packages/plugin/src/promise/tool.ts:44-70
# (ToolHooks) and packages/plugin/src/promise/session.ts:201-217 (SessionHooks).
OPENCODE_2_HOOKS = {
    "tool": ["execute.before", "execute.after"],
    "session": ["fork", "prompt", "context", "compaction", "generate", "title",
                "experimental.model.resolve", "model.request", "http.request", "http.response",
                "experimental.ws.handshake", "experimental.ws.send", "experimental.ws.receive",
                "retry", "experimental.idle"],
}
# packages/schema/src/session-event.ts:651-662 (RevertEvent.Committed).
OPENCODE_2_EVENTS = ["session.revert.committed"]

# The fake host rejects unknown hook names and lets a rejected callback fail the run,
# as OpenCode 2 does (packages/core/src/plugin/hooks.ts:88-95: callbacks run serially
# and a rejection fails the operation).
_HOST = r"""
import {pathToFileURL} from 'node:url';
const options = JSON.parse(process.argv[2]);
const state = {sessions: options.sessions || {}, contexts: options.contexts || {}, tools: options.tools || [],
  servers: options.servers || []};
const log = {registered: [], subscribed: [], synthetic: [], results: [], errors: [], cleanup: false};
console.error = (...values) => { log.errors.push(values.map(String).join(' ')) };
const callbacks = new Map();
const hook = domain => async (name, callback) => {
  if (!options.names[domain]?.includes(name)) throw new Error(`OpenCode 2.3.0 has no ${domain} hook ${name}`);
  log.registered.push(`${domain}.${name}`);
  callbacks.set(`${domain}.${name}`, [...(callbacks.get(`${domain}.${name}`) || []), callback]);
  return {dispose: async () => {}};
};
const fail = name => { if ((options.fail || []).includes(name)) throw new Error(`${name} unavailable`) };
const queue = [], waiting = [];
const emit = event => { const next = waiting.shift(); if (next) next({value: event, done: false}); else queue.push(event) };
const ctx = {
  app: {name: 'cli', version: '2.3.0', channel: 'latest'}, options: {},
  location: {directory: options.directory || process.cwd(), project: {id: 'acme'}},
  tool: {hook: hook('tool'), list: async () => { fail('tool.list'); return state.tools }},
  session: {
    hook: hook('session'),
    get: async ({sessionID}) => {
      fail('session.get');
      const session = state.sessions[sessionID];
      if (!session) throw Object.assign(new Error(''), {name: 'Session.NotFoundError', _tag: 'Session.NotFoundError'});
      return structuredClone(session);
    },
    context: async ({sessionID}) => { fail('session.context'); return structuredClone(state.contexts[sessionID] || []) },
    synthetic: async input => { fail('session.synthetic'); log.synthetic.push(input); return {id: 'msg_' + log.synthetic.length} },
  },
  mcp: {list: async () => { fail('mcp.list'); return {location: {}, data: state.servers} }},
  event: {subscribe: (subscription = {}) => {
    log.subscribed.push(subscription.types || null);
    return {[Symbol.asyncIterator]: () => ({
      next: () => queue.length ? Promise.resolve({value: queue.shift(), done: false})
        : new Promise(resolve => { waiting.push(resolve); subscription.signal?.addEventListener('abort',
            () => resolve({value: undefined, done: true})) }),
      return: async () => ({value: undefined, done: true}),
    })};
  }},
};
const module = await import(pathToFileURL(process.argv[1]).href);
log.shape = {id: module.default?.id, server: typeof module.default?.server, setup: typeof module.default?.setup,
  serverIsNamed: Object.entries(module).some(([name, value]) => name !== 'default' && value === module.default?.server)};
const cleanup = await module.default.setup(ctx);
for (const step of options.steps || []) {
  if (step.contexts) Object.assign(state.contexts, step.contexts);
  if (step.emit) { emit(step.emit); await new Promise(resolve => setTimeout(resolve, 50)) }
  if (step.hook) {
    for (const callback of callbacks.get(step.hook) || []) await callback(step.event);
    log.results.push({hook: step.hook, event: step.event});
  }
}
if (typeof cleanup === 'function') { await cleanup(); log.cleanup = true }
process.stdout.write(JSON.stringify(log));
"""


def _host(source: Path, *, env: dict | None = None, **options) -> dict:
    result = subprocess.run(["node", "--input-type=module", "-e", _HOST, str(source),
        json.dumps({"names": OPENCODE_2_HOOKS, **options})],
        env={**os.environ, **(env or {})}, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _texts(event: dict) -> list[str]:
    assert all(part["type"] == "text" for part in event["system"])
    return [part["text"] for part in event["system"]]


def _context_event(session: str, agent: str = "operator") -> dict:
    return {"sessionID": session, "agent": agent, "model": {"id": "model-1", "providerID": "acme", "variant": "max"},
            "system": [{"type": "text", "text": "native-default"}], "messages": [], "options": {}, "tools": {}}


def _binding(tmp_path: Path, *, mode: str = "code", agent: Path | None = None, vigil_cli: str = "/bin/false"):
    engagement = tmp_path / "acme"
    engagement.mkdir(exist_ok=True)
    (engagement / "scope.json").write_text(json.dumps({"status": "in_progress", "tracks": {mode: {"phase": "hunt"}}}))
    if agent is None:
        agent = tmp_path / "agent"
        (agent / "scripts/hooks").mkdir(parents=True, exist_ok=True)
    binding = tmp_path / "context.json"
    binding.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": mode,
        "workspace": str(tmp_path), "engagement_dir": str(engagement), "agent_root": str(agent),
        "vigil_cli": vigil_cli, "install_root": str(tmp_path), "release_id": "test"}))
    return binding, engagement, agent


@pytest.mark.parametrize("source", [RUNTIME, DISPATCHER, STANDARD], ids=lambda path: path.name)
def test_every_discovered_entry_loads_on_both_majors(tmp_path, source):
    # 1.18.10 selects a default export carrying id/server and calls server(); 2.x calls setup().
    # The 1.x factory stays the named export each entry already had.
    host = subprocess.run(["node", "--input-type=module", "-e",
        "import {pathToFileURL} from 'node:url';"
        "const m=await import(pathToFileURL(process.argv[1]).href);"
        "process.stdout.write(JSON.stringify({id:m.default?.id,server:typeof m.default?.server,"
        "setup:typeof m.default?.setup,named:Object.entries(m).filter(([k,v])=>k!=='default'&&v===m.default?.server)"
        ".map(([k])=>k),other:Object.entries(m).filter(([k,v])=>k!=='default'&&typeof v!=='function').map(([k])=>k)}))",
        str(source)], capture_output=True, text=True, timeout=20, check=True)
    shape = json.loads(host.stdout)
    assert (shape["server"], shape["setup"]) == ("function", "function")
    assert shape["named"] and not shape["other"]
    assert shape["id"].startswith("vigil-")


def test_entry_ids_are_distinct():
    ids = []
    for source in (RUNTIME, DISPATCHER, STANDARD):
        result = subprocess.run(["node", "--input-type=module", "-e",
            "import {pathToFileURL} from 'node:url';"
            "process.stdout.write((await import(pathToFileURL(process.argv[1]).href)).default.id)", str(source)],
            capture_output=True, text=True, timeout=20, check=True)
        ids.append(result.stdout)
    # OpenCode 2 keeps the first plugin with an ID and reports later ones as failed.
    assert len(set(ids)) == 3


def test_runtime_registers_only_opencode_2_hook_names(tmp_path):
    binding, _, _ = _binding(tmp_path)
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding), "OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS": ""})
    assert sorted(log["registered"]) == ["session.compaction", "session.context", "session.experimental.idle",
                                         "session.prompt", "tool.execute.after"]
    assert log["subscribed"] == [OPENCODE_2_EVENTS]
    assert log["cleanup"] is True


@pytest.mark.parametrize("agent", ["operator", "recon-specialist"])
def test_standard_hooks_log_each_sessions_shell_commands_as_its_agent(tmp_path, agent):
    """OpenCode 2 runs execute.after for child sessions too."""
    capture = tmp_path / "capture.json"
    hooks = tmp_path / "scripts/hooks"
    hooks.mkdir(parents=True)
    (hooks / "post-tool-log.sh").write_text(f"#!/bin/bash\n/bin/cat > {shlex.quote(str(capture))}\n")
    log = _host(STANDARD, env={"VIGIL_AGENT_ROOT": str(tmp_path), "ENGAGEMENT_DIR": str(tmp_path)}, steps=[
        {"hook": "tool.execute.after", "event": {"tool": "read", "sessionID": "s", "agent": "operator",
         "messageID": "m", "id": "c0", "input": {"path": "/acme"}, "status": "completed", "result": {"content": []}}},
        {"hook": "tool.execute.after", "event": {"tool": "shell", "sessionID": "s", "agent": agent,
         "messageID": "m", "id": "c1", "input": {"command": "id"}, "status": "completed",
         "result": {"output": {"output": "uid=0", "exitCode": 0}, "content": []}}}])
    assert log["registered"] == ["tool.execute.after"]
    payload = json.loads(capture.read_text())
    assert (payload["tool_name"], payload["tool_input"], payload["cwd"], payload["agent_type"]) == (
        "Bash", {"command": "id"}, str(tmp_path), agent)


def test_standard_hooks_fail_open_without_a_hook_script(tmp_path):
    log = _host(STANDARD, env={"VIGIL_AGENT_ROOT": str(tmp_path / "missing")}, steps=[
        {"hook": "tool.execute.after", "event": {"tool": "shell", "sessionID": "s", "agent": "operator",
         "messageID": "m", "id": "c1", "input": {"command": "id"}, "status": "error", "error": {"message": "x"}}}])
    assert log["results"]


def test_compaction_contract_and_post_compaction_recovery(tmp_path):
    binding, _, agent = _binding(tmp_path)
    (agent / "scripts/hooks/pre-compact.sh").write_text("#!/bin/sh\nprintf '%s' preserve-marker\n")
    (agent / "scripts/hooks/post-compact-resume.sh").write_text("#!/bin/sh\nprintf '%s' recovery-marker\n")
    summary = {"id": "msg_summary", "type": "compaction", "status": "completed", "reason": "auto", "summary": "Acme"}
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)},
        sessions={"ses_root": {"id": "ses_root", "agent": "operator", "location": {"directory": str(tmp_path)}}},
        steps=[
            {"hook": "session.context", "event": _context_event("ses_root")},
            {"hook": "session.compaction", "event": _context_event("ses_root")},
            # The summary has not been swapped in yet: dependent work must stop.
            {"hook": "session.context", "event": _context_event("ses_root")},
            {"contexts": {"ses_root": [summary, {"id": "msg_u", "type": "user", "text": "continue"}]}},
            {"hook": "session.context", "event": _context_event("ses_root")},
            {"hook": "session.context", "event": _context_event("ses_root")},
        ])
    first, compaction, pending, recovered, again = (_texts(result["event"]) for result in log["results"])
    assert first[0] == "native-default" and str(binding) in first[1] and len(first) == 2
    assert compaction == ["native-default", "preserve-marker"]
    assert any(text.startswith("Vigil context could not be verified: Compaction is pending") for text in pending)
    for texts in (recovered, again):
        contract = [text for text in texts if "recovery-marker" in text]
        assert len(contract) == 1 and "msg_summary" in contract[0]
    health = json.loads((tmp_path / (".vigil-health-" + hashlib.sha256(b"ses_root").hexdigest() + ".json")).read_text())
    assert (health["last_summary_id"], health["recovery_pending"]) == ("msg_summary", False)


def test_committed_revert_clears_a_pending_compaction(tmp_path):
    binding, _, agent = _binding(tmp_path)
    (agent / "scripts/hooks/pre-compact.sh").write_text("#!/bin/sh\nprintf '%s' preserve-marker\n")
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)},
        sessions={"ses_root": {"id": "ses_root", "agent": "operator"}},
        steps=[
            {"hook": "session.compaction", "event": _context_event("ses_root")},
            {"emit": {"id": "evt_1", "type": "session.revert.committed", "data": {"sessionID": "ses_root", "to": "msg_7"}}},
            {"hook": "session.context", "event": _context_event("ses_root")},
        ])
    texts = _texts(log["results"][-1]["event"])
    assert not any(text.startswith("Vigil context could not be verified") for text in texts), texts


def test_specialist_context_restores_only_its_role(tmp_path):
    binding, _, _ = _binding(tmp_path)
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)},
        sessions={"ses_root": {"id": "ses_root", "agent": "operator"},
                  "ses_child": {"id": "ses_child", "parentID": "ses_root", "agent": "explore"}},
        steps=[{"hook": "session.context", "event": _context_event("ses_child", "explore")}])
    texts = _texts(log["results"][0]["event"])
    assert any(text.startswith("Restore only this specialist") for text in texts)
    assert log["synthetic"] == []


@pytest.mark.parametrize("failure", ["session.get", "session.context"])
def test_every_hook_fails_open(tmp_path, failure):
    binding, _, _ = _binding(tmp_path)
    shell = {"tool": "shell", "sessionID": "ses_child", "agent": "explore", "messageID": "m", "id": "c1",
             "input": {"command": "id"}}
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)}, fail=[failure],
        sessions={"ses_child": {"id": "ses_child", "parentID": "ses_root", "agent": "explore"}},
        steps=[
            {"hook": "session.prompt", "event": {"sessionID": "ses_child", "messageID": "m",
             "prompt": {"text": "Read tools/dispatch-packets/7/" + "a" * 64 + ".md"}, "delivery": "steer"}},
            {"hook": "session.context", "event": _context_event("ses_child", "explore")},
            {"hook": "session.compaction", "event": _context_event("ses_child", "explore")},
            {"hook": "tool.execute.after", "event": {**shell, "status": "completed", "result": {"content": []}}},
            {"hook": "tool.execute.after", "event": {**shell, "status": "error", "error": {"message": "denied"}}},
            {"hook": "session.experimental.idle", "event": {"sessionID": "ses_child", "background": []}},
        ])
    assert any(text.startswith("Vigil context could not be verified")
               for text in _texts(log["results"][1]["event"]))
    assert any(text.startswith("Vigil preservation unavailable")
               for text in _texts(log["results"][2]["event"]))


def test_runtime_without_binding_fails_open(tmp_path):
    env = {key: value for key, value in os.environ.items() if key != "VIGIL_CLIENT_CONTEXT"}
    result = subprocess.run(["node", "--input-type=module", "-e", _HOST, str(RUNTIME), json.dumps({
        "names": OPENCODE_2_HOOKS, "steps": [{"hook": "session.context", "event": _context_event("ses_root")}]})],
        env=env, capture_output=True, text=True, timeout=30, check=True)
    texts = _texts(json.loads(result.stdout)["results"][0]["event"])
    assert any("No native Vigil context binding" in text for text in texts)


# --- activity -----------------------------------------------------------------------------

def _activity(tmp_path, events, **options):
    capture = tmp_path / "captures"
    capture.mkdir()
    agent = tmp_path / "agent"
    (agent / "scripts/hooks").mkdir(parents=True)
    (agent / "scripts/hooks/post-tool-log.sh").write_text(
        f"#!/bin/bash\n/bin/cat > {shlex.quote(str(capture))}/$(date +%s%N)-$$.json\n")
    binding, _, _ = _binding(tmp_path, agent=agent)
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)},
                steps=[{"hook": "tool.execute.after", "event": event} for event in events], **options)
    rows = [json.loads(path.read_text()) for path in sorted(capture.iterdir())]
    return rows, log


def _call(tool, input, **result):
    return {"tool": tool, "sessionID": "ses_root", "agent": "operator", "messageID": "msg_1", "id": "call-1",
            "input": input, **result}


def test_shell_activity_keeps_native_result_and_exit(tmp_path):
    rows, _ = _activity(tmp_path, [_call("shell", {"command": "printf Acme"}, status="completed", result={
        "output": {"output": "Acme", "exitCode": 7, "wallTimeSeconds": 0.1},
        "content": [{"type": "text", "text": "Acme"}], "metadata": {"status": "completed", "exit": 7}})])
    assert len(rows) == 1
    row = rows[0]
    assert (row["tool_name"], row["native_tool_name"], row["agent_type"]) == ("Bash", "shell", "operator")
    assert (row["session_id"], row["tool_use_id"], row["client_name"]) == ("ses_root", "call-1", "opencode")
    assert row["tool_input"] == {"command": "printf Acme"}
    assert (row["tool_response"]["output"], row["tool_response"]["exit_code"]) == ("Acme", 7)
    assert row["tool_response"]["wallTimeSeconds"] == 0.1


def test_failed_tool_activity_records_the_native_error(tmp_path):
    rows, _ = _activity(tmp_path, [_call("shell", {"command": "id"}, status="error",
                                         error={"_tag": "Tool.Error", "message": "Acme denied"})])
    response = rows[0]["tool_response"]
    assert (response["stderr"], response["exit_code"]) == ("Acme denied", 1)
    assert response["error"]["message"] == "Acme denied"


@pytest.mark.parametrize("tool", ["write", "edit"])
def test_file_activity_names_the_native_path(tmp_path, tool):
    rows, _ = _activity(tmp_path, [_call(tool, {"path": "/acme/engagements/acme/findings.md", "content": "Acme"},
                                         status="completed", result={"output": "saved", "content": []})])
    assert rows[0]["tool_name"] == tool.title()
    assert rows[0]["tool_input"]["file_path"] == rows[0]["tool_input"]["path"]
    assert rows[0]["tool_input"]["content"] == "Acme"


def test_subagent_activity_is_a_dispatch(tmp_path):
    rows, _ = _activity(tmp_path, [_call("subagent", {"agent": "recon-specialist", "description": "Acme recon",
        "prompt": "Read the packet"}, status="completed", result={"output": {"sessionID": "ses_child",
        "status": "running", "output": "working"}, "content": [], "metadata": {"sessionID": "ses_child"}})])
    assert rows[0]["tool_name"] == "Agent"
    assert rows[0]["tool_input"]["subagent_type"] == "recon-specialist"
    assert rows[0]["tool_input"]["agent"] == "recon-specialist"


def test_patch_activity_names_the_patched_files(tmp_path):
    patch = "*** Begin Patch\n*** Update File: src/acme.py\n@@\n-a\n+b\n*** End Patch"
    rows, _ = _activity(tmp_path, [_call("patch", {"patchText": patch}, status="completed",
                                         result={"output": {}, "content": [{"type": "text", "text": "Applied"}]})])
    assert rows[0]["tool_name"] == "apply_patch"
    assert rows[0]["tool_input"]["command"] == patch


_MCP = {"tools": [{"id": "acme-server_lookup", "options": {"namespace": "acme-server"}},
                  {"id": "acme_example_lookup", "options": {"namespace": "acme_example"}},
                  {"id": "offline_lookup", "options": {"namespace": "offline"}},
                  {"id": "opencode_session_rename", "options": {"namespace": "opencode"}},
                  {"id": "local_custom"}],
        "servers": [{"name": "acme-server", "status": {"status": "connected"}},
                    {"name": "acme.example", "status": {"status": "connected"}},
                    {"name": "offline", "status": {"status": "failed", "error": "down"}}]}


@pytest.mark.parametrize(("tool", "expected"), [("acme-server_lookup", "mcp__acme-server_lookup"),
    ("acme_example_lookup", "mcp__acme_example_lookup"), ("offline_lookup", "offline_lookup"),
    ("opencode_session_rename", "opencode_session_rename"), ("local_custom", "local_custom")])
def test_mcp_identity_comes_from_the_connected_server_namespace(tmp_path, tool, expected):
    rows, _ = _activity(tmp_path, [_call(tool, {"query": "Acme"}, status="completed",
        result={"output": {"count": 2}, "content": [{"type": "text", "text": "Acme answer"}]})], **_MCP)
    assert rows[0]["tool_name"] == expected
    if expected.startswith("mcp__"):
        assert '"count":2' in rows[0]["tool_response"]["output"]


def test_unverifiable_mcp_catalog_keeps_the_native_name(tmp_path):
    rows, log = _activity(tmp_path, [_call("acme-server_lookup", {}, status="completed",
        result={"content": [{"type": "text", "text": "Acme"}]})], fail=["mcp.list"], **_MCP)
    assert rows[0]["tool_name"] == "acme-server_lookup"
    assert any("MCP identity could not be verified" in line for line in log["errors"])


# --- dispatch binding and the end-of-task report ------------------------------------------

def _dispatch_fixture(tmp_path, *, binding=None, mode="web", handoff=None, leases=(), reads_fail=False):
    agent = tmp_path / "agent"
    (agent / "scripts/hooks").mkdir(parents=True)
    (agent / "scripts/hooks/post-tool-log.sh").write_text("#!/bin/sh\ncat >/dev/null\n")
    helper = tmp_path / "vigil"
    context, engagement, _ = _binding(tmp_path, mode=mode, agent=agent, vigil_cli=str(helper))
    packet = ("## Runtime Identity\nagent_id: acme-recon-1\nagent_role: recon-specialist\n"
              f"assessment_mode: {mode}\n\n## Dispatch Context\nagent_id: acme-other\n").encode()
    digest = hashlib.sha256(packet).hexdigest()
    path = engagement / "tools/dispatch-packets/7" / f"{digest}.md"
    path.parent.mkdir(parents=True)
    path.write_bytes(packet)
    calls = tmp_path / "calls.jsonl"
    row = {"id": 7, "agent_id": "acme-recon-1", "agent_role": "recon-specialist", "status": "in-progress",
           "client_binding": binding}
    page = {"total": len(leases), "offset": 0, "count": len(leases), "has_more": False,
            "item_ids": [item["id"] for item in leases], "items": list(leases)}
    helper.write_text(f"""#!{sys.executable}
import json, sys
with open({str(calls)!r}, "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
verb = sys.argv[2:4]
if {reads_fail!r} and verb not in (["agent", "get"], ["agent", "bind-client-handle"]):
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
    launch = (f"You are a subagent spawned by another session.\nRead the captured dispatch packet {path}; "
              f"verify SHA-256 {digest}. Use registered role recon-specialist.")
    return context, calls, launch, helper


def _run_child(context, *, launch, agent="recon-specialist", final_text="specialist result", background=()):
    sessions = {
        "ses_root": {"id": "ses_root", "agent": "operator", "location": {"directory": "/acme/clients/opencode/web"}},
        "ses_child": {"id": "ses_child", "parentID": "ses_root", "agent": agent,
                      "model": {"id": "model-1", "providerID": "acme", "variant": "max"},
                      "location": {"directory": "/acme/clients/opencode/web"}},
    }
    finished = [{"id": "msg_u", "type": "user", "text": launch},
                {"id": "msg_a", "type": "assistant", "agent": agent, "model": sessions["ses_child"]["model"],
                 "content": [{"type": "text", "text": final_text}] if final_text else [], "finish": "stop"}]
    return _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(context)}, sessions=sessions, steps=[
        {"hook": "session.prompt", "event": {"sessionID": "ses_child", "messageID": "msg_u",
                                            "prompt": {"text": launch}, "delivery": "steer"}},
        {"contexts": {"ses_child": finished[:1]}},
        {"hook": "session.context", "event": _context_event("ses_child", agent)},
        {"hook": "session.context", "event": _context_event("ses_child", agent)},
        {"contexts": {"ses_child": finished}},
        {"hook": "session.experimental.idle", "event": {"sessionID": "ses_child", "background": list(background)}},
    ])


def _calls(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _report(log):
    assert len(log["synthetic"]) <= 1, log["synthetic"]
    if not log["synthetic"]:
        return None, None, None
    note = log["synthetic"][0]
    assert (note["sessionID"], note["resume"]) == ("ses_root", False)
    assert note["metadata"]["source"] == "vigil" and note["metadata"]["childID"] == "ses_child"
    lines = note["text"].splitlines()
    binding = [json.loads(line.split(": ", 1)[1]) for line in lines if line.startswith("Vigil dispatch binding: ")]
    status = [json.loads(line.split(": ", 1)[1]) for line in lines if line.startswith("Vigil dispatch status: ")]
    assert len(binding) <= 1 and len(status) <= 1
    return note, binding[0] if binding else None, status[0] if status else None


def _advisories(event):
    return [json.loads(text.split("\n", 1)[0].split(": ", 1)[1])
            for text in _texts(event) if text.startswith("Vigil advisory: ")]


@pytest.mark.parametrize("agent", ["recon-specialist", "general"])
def test_child_launch_prompt_binds_its_dispatch(tmp_path, agent):
    context, calls, launch, _ = _dispatch_fixture(tmp_path)
    log = _run_child(context, launch=launch, agent=agent)
    recorded = [call for call in _calls(calls) if call[2] in {"get", "bind-client-handle"}]
    assert [call[:4] for call in recorded] == [["assess", "agent", "get", "acme-recon-1"],
                                                ["assess", "agent", "bind-client-handle", "acme-recon-1"]]
    bind = recorded[1]
    assert bind[bind.index("--client") + 1] == "opencode"
    assert bind[bind.index("--session-namespace") + 1] == "/acme/clients/opencode/web"
    assert bind[bind.index("--handle") + 1] == "ses_child"
    note = bind[bind.index("--note") + 1]
    assert "launch prompt" in note and "acme/model-1" in note and "max" in note and agent in note
    _, report, _ = _report(log)
    assert {key: report[key] for key in ("status", "agent_id", "dispatch_id", "handle", "native_agent",
                                         "registered_role", "model", "variant")} == {
        "status": "bound", "agent_id": "acme-recon-1", "dispatch_id": 7, "handle": "ses_child",
        "native_agent": agent, "registered_role": "recon-specialist", "model": "acme/model-1", "variant": "max"}
    expected = [] if agent == "recon-specialist" else [{"advisory": "native_agent_role_mismatch",
        "agent_id": "acme-recon-1", "dispatch_id": 7, "registered_role": "recon-specialist",
        "native_agent": agent, "handle": "ses_child"}]
    assert report.get("advisories", []) == expected
    for result in log["results"]:
        if result["hook"] == "session.context":
            assert _advisories(result["event"]) == expected


def test_child_report_waits_for_its_own_background_work(tmp_path):
    context, _, launch, _ = _dispatch_fixture(tmp_path)
    log = _run_child(context, launch=launch, background=[
        {"kind": "shell", "sessionID": "ses_child", "shellID": "sh_1", "command": "sleep 60"}])
    assert log["synthetic"] == []


def test_child_without_a_dispatch_packet_is_left_unbound(tmp_path):
    context, calls, _, _ = _dispatch_fixture(tmp_path)
    log = _run_child(context, launch="You are a subagent spawned by another session.\nSummarize the README.",
                     agent="explore")
    assert _calls(calls) == []
    assert log["synthetic"] == []


def test_child_does_not_supersede_another_sessions_binding(tmp_path):
    context, calls, launch, _ = _dispatch_fixture(tmp_path, binding={
        "asserted_client": "opencode", "asserted_session_namespace": "/acme", "asserted_client_handle": "other",
        "binding_version": 1})
    _, report, _ = _report(_run_child(context, launch=launch))
    assert [call[2] for call in _calls(calls)] == ["get"]
    assert (report["status"], report["reason"]) == ("unresolved", "dispatch_bound_elsewhere")


def _lease(item_id, receipts):
    return {"id": item_id, "status": "processing", "agent_name": "acme-recon-1", "repo_id": 3,
            "file_path": f"src/acme/module_{item_id}.py", "lease_token": f"lease-{item_id}",
            "heartbeat_age_seconds": 30, "current_result_count": receipts}


def _argv(command, helper):
    argv = shlex.split(command)
    assert argv[:2] == [str(helper), "assess"], command
    return argv[2:]


def test_empty_return_without_handoff_while_holding_leases_is_reported_to_the_operator(tmp_path):
    context, _, launch, helper = _dispatch_fixture(tmp_path, mode="code", leases=[_lease(11, 2), _lease(12, 0)])
    _, report, status = _report(_run_child(context, launch=launch, final_text=""))
    assert report["status"] == "bound"
    assert {key: status[key] for key in ("agent_id", "dispatch_id", "empty_result", "handoff", "held_leases")} == {
        "agent_id": "acme-recon-1", "dispatch_id": 7, "empty_result": True, "handoff": False, "held_leases": 2}
    verbs = [_argv(command, helper)[:2] for command in status["next"]]
    assert ["agent", "close"] in verbs and ["code-dispatch", "adopt-lease"] in verbs
    assert ["code-dispatch", "reset-stale"] in verbs


def test_finished_dispatch_reports_only_its_binding(tmp_path):
    context, _, launch, _ = _dispatch_fixture(tmp_path, mode="code",
                                              handoff={"agent_id": "acme-recon-1", "handoff_status": "ready"})
    note, report, status = _report(_run_child(context, launch=launch))
    assert report["status"] == "bound" and status is None
    assert "This handle is recorded" in note["text"]


def test_dispatch_status_fails_open_with_manual_checks(tmp_path):
    context, _, launch, helper = _dispatch_fixture(tmp_path, mode="code", reads_fail=True)
    _, _, status = _report(_run_child(context, launch=launch, final_text=""))
    assert (status["verified"], status["empty_result"]) == (False, True)
    verbs = [_argv(command, helper)[:2] for command in status["check"]]
    assert ["agent", "render-handoff"] in verbs and ["code-dispatch", "list"] in verbs


def test_report_delivery_failure_is_contained(tmp_path):
    context, _, launch, _ = _dispatch_fixture(tmp_path)
    sessions = {"ses_root": {"id": "ses_root", "agent": "operator"},
                "ses_child": {"id": "ses_child", "parentID": "ses_root", "agent": "recon-specialist"}}
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(context)}, sessions=sessions, fail=["session.synthetic"],
        steps=[{"hook": "session.prompt", "event": {"sessionID": "ses_child", "messageID": "m",
                                                   "prompt": {"text": launch}, "delivery": "steer"}},
               {"hook": "session.experimental.idle", "event": {"sessionID": "ses_child", "background": []}}])
    assert any("Vigil dispatch report" in line for line in log["errors"])


# --- the staged project dispatcher --------------------------------------------------------

@pytest.fixture
def staged(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(ROOT))
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(tmp_path / "cache"))
    root = tmp_path / "private"
    engagement = root / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"status": "in_progress", "tracks": {"web": {"phase": "recon"}}}))
    snapshot, binding = prepare_workspace(root, engagement, "opencode", "web", native_version="2.3.0")
    project = prepare_project(snapshot, binding)
    env = {"VIGIL_CLIENT_CONTEXT": str(snapshot / ".vigil-client-context.json"),
           "VIGIL_INSTALL_DIR": binding["install_root"], "OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS": "660000"}
    return snapshot, binding, project, env


def _dispatch(snapshot, env, **options):
    return _host(snapshot / ".opencode/plugins/vigil-assessment.js", env=env, **options)


def test_dispatcher_registers_only_opencode_2_hook_names(staged):
    snapshot, _, _, env = staged
    log = _dispatch(snapshot, env)
    assert sorted(log["registered"]) == ["session.compaction", "session.context", "session.experimental.idle",
                                         "session.prompt", "tool.execute.after", "tool.execute.before"]
    assert log["subscribed"] == [OPENCODE_2_EVENTS]
    assert log["shape"]["id"] == "vigil-assessment"


@pytest.mark.parametrize(("tool", "given", "expected"), [
    ("shell", {"command": "vigil assess kali"}, 660000),
    ("shell", {"command": "sleep 1", "timeout": 5000}, 5000),
    ("shell", {"command": "sleep 1", "timeout": 0}, 0),
    ("shell", {"command": "serve", "background": True}, None),
    ("read", {"path": "/acme"}, None),
])
def test_dispatcher_gives_shell_calls_the_launch_budget(staged, tool, given, expected):
    snapshot, _, _, env = staged
    event = {"tool": tool, "sessionID": "ses_root", "agent": "operator", "messageID": "m", "id": "c", "input": given}
    log = _dispatch(snapshot, env, steps=[{"hook": "tool.execute.before", "event": event}])
    assert log["results"][0]["event"]["input"].get("timeout") == expected
    assert {key: value for key, value in log["results"][0]["event"]["input"].items() if key != "timeout"} == {
        key: value for key, value in given.items() if key != "timeout"}


def test_dispatcher_without_a_launch_budget_leaves_the_native_default(staged):
    snapshot, _, _, env = staged
    env = {**env, "OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS": ""}
    event = {"tool": "shell", "sessionID": "s", "agent": "operator", "messageID": "m", "id": "c", "input": {"command": "id"}}
    log = _dispatch(snapshot, env, steps=[{"hook": "tool.execute.before", "event": event}])
    assert "timeout" not in log["results"][0]["event"]["input"]


def test_dispatcher_binds_root_and_child_sessions_to_the_task(staged):
    snapshot, binding, project, env = staged
    log = _dispatch(snapshot, env,
        sessions={"ses_root": {"id": "ses_root", "agent": "operator"},
                  "ses_child": {"id": "ses_child", "parentID": "ses_root", "agent": "recon-specialist"}},
        steps=[{"hook": "session.context", "event": _context_event("ses_root")},
               {"hook": "session.prompt", "event": {"sessionID": "ses_child", "messageID": "m",
                "prompt": {"text": "You are a subagent spawned by another session.\nSummarize."}, "delivery": "steer"}},
               {"hook": "session.context", "event": _context_event("ses_child", "recon-specialist")}])
    root, child = (_texts(result["event"]) for result in log["results"] if result["hook"] == "session.context")
    assert any(binding["vigil_cli"] in text for text in root)
    assert any(text.startswith("Restore only this specialist") for text in child)
    for session in ("ses_root", "ses_child"):
        receipt = project / ".vigil-sessions/opencode" / (hashlib.sha256(session.encode()).hexdigest() + ".json")
        assert json.loads(receipt.read_text())["binding_path"] == str(snapshot / ".vigil-client-context.json")


def test_dispatcher_refuses_to_rebind_an_old_conversation(staged):
    snapshot, binding, _, env = staged
    old = [{"id": "msg_a", "type": "assistant", "agent": "operator", "content": [], "finish": "stop"}]
    log = _dispatch(snapshot, env, sessions={"ses_old": {"id": "ses_old", "agent": "operator"}},
                    contexts={"ses_old": old}, steps=[{"hook": "session.context", "event": _context_event("ses_old")}])
    texts = _texts(log["results"][0]["event"])
    assert any(text.startswith("Vigil task binding unavailable: Existing conversation") for text in texts)
    assert not any(binding["vigil_cli"] in text for text in texts)


def test_dispatcher_reports_a_retained_runtime_without_an_opencode_2_adapter(staged, tmp_path, monkeypatch):
    old, binding, project, _ = staged
    runtime = old / ".opencode/vigil-assessment-runtime.mjs"
    runtime.write_text("export const VigilAssessmentHooks = async () => ({})\n")
    manifest_path = old / ".vigil-managed-files.json"
    manifest = json.loads(manifest_path.read_text())
    manifest[".opencode/vigil-assessment-runtime.mjs"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    # A task bound to the earlier release, continued from a launch of the current one.
    subprocess.run(["node", "--input-type=module", "-e",
        "import {pathToFileURL} from 'node:url';"
        "const p=await import(pathToFileURL(process.argv[1]).href);"
        "p.bindSession(process.argv[2],'opencode','ses_old',p.bindingInfo(process.argv[3],process.argv[2]))",
        str(old / ".opencode/vigil-project.mjs"), str(project), str(old / ".vigil-client-context.json")],
        capture_output=True, text=True, timeout=20, check=True)
    root = tmp_path / "private"
    original = assessment_clients.application_provenance(ROOT)
    monkeypatch.setattr(assessment_clients, "application_provenance", lambda _: {
        **original, "content_sha256": hashlib.sha256(b"acme-next-release").hexdigest()})
    current, launch = prepare_workspace(root, root / "engagements/acme", "opencode", "web", native_version="2.3.0")
    assert current != old
    prepare_project(current, launch)
    env = {"VIGIL_CLIENT_CONTEXT": str(current / ".vigil-client-context.json"), "VIGIL_INSTALL_DIR": launch["install_root"]}
    log = _dispatch(current, env, sessions={"ses_old": {"id": "ses_old", "agent": "operator"}},
        steps=[{"hook": "session.context", "event": _context_event("ses_old")},
               {"hook": "session.compaction", "event": _context_event("ses_old")}])
    for result in log["results"]:
        assert any(text.startswith("Vigil task binding unavailable") and "OpenCode 2" in text
                   for text in _texts(result["event"]))


def test_dispatcher_without_a_launch_context_does_not_load(staged):
    snapshot, _, _, env = staged
    env = {key: value for key, value in {**os.environ, **env}.items() if key != "VIGIL_CLIENT_CONTEXT"}
    result = subprocess.run(["node", "--input-type=module", "-e", _HOST, str(snapshot / ".opencode/plugins/vigil-assessment.js"),
                             json.dumps({"names": OPENCODE_2_HOOKS})], env=env, capture_output=True, text=True,
                            timeout=30)
    # The same refusal the 1.x factory raises: OpenCode reports the plugin as failed to load.
    assert result.returncode != 0
    assert "No native Vigil launch context" in result.stderr

