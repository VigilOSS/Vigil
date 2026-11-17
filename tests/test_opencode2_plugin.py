"""OpenCode plugin contracts, driven through a fake OpenCode 2 host without models or live state.

OpenCode auto-discovers every Vigil plugin entry and loads its default export ``{id, setup}``,
calling ``setup`` with the plugin context.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

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
import {existsSync, writeFileSync} from 'node:fs';
const options = JSON.parse(process.argv[2]);
// `gate` holds the MCP catalog read until that file exists (at most 3 s).
const gate = async () => { for (let i = 0; options.gate && i < 300 && !existsSync(options.gate); i++) await new Promise(r => setTimeout(r, 10)) };
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
  mcp: {list: async () => { fail('mcp.list'); await gate(); return {location: {}, data: state.servers} }},
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
log.shape = {id: module.default?.id, setup: typeof module.default?.setup};
const cleanup = await module.default.setup(ctx);
for (const step of options.steps || []) {
  if (step.contexts) Object.assign(state.contexts, step.contexts);
  if (step.touch) writeFileSync(step.touch, '');
  if (step.write) writeFileSync(step.write.path, step.write.text);
  // Creates the file once the event loop is free for `after` ms; the next step does not wait for it.
  if (step.later) setTimeout(() => writeFileSync(step.later.touch, ''), step.later.after);
  if (step.emit) { emit(step.emit); await new Promise(resolve => setTimeout(resolve, 50)) }
  if (step.hook) {
    for (const callback of callbacks.get(step.hook) || []) await callback(step.event);
    log.results.push({hook: step.hook, event: step.event});
  }
}
if (typeof cleanup === 'function') { await cleanup(); log.cleanup = true }
// The log is read once the callbacks' pending promise work has run.
await new Promise(resolve => setTimeout(resolve, 0));
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
def test_every_discovered_entry_exports_an_id_and_setup(source):
    # OpenCode 2.3.0 loads a default export {id: string, setup: function}
    # (packages/core/src/plugin/module.ts:80-93) and reports any other module as failed to load.
    host = subprocess.run(["node", "--input-type=module", "-e",
        "import {pathToFileURL} from 'node:url';"
        "const m=await import(pathToFileURL(process.argv[1]).href);"
        "process.stdout.write(JSON.stringify({id:m.default?.id,setup:typeof m.default?.setup,"
        "other:Object.entries(m).filter(([k,v])=>k!=='default'&&typeof v!=='function').map(([k])=>k)}))",
        str(source)], capture_output=True, text=True, timeout=20, check=True)
    shape = json.loads(host.stdout)
    assert shape["setup"] == "function"
    assert isinstance(shape["id"], str) and shape["id"].startswith("vigil-")
    assert not shape["other"]


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


def _shell_event(session: str, agent: str, command: str) -> dict:
    return {"tool": "shell", "sessionID": session, "agent": agent, "messageID": "m", "id": "c-" + command,
            "input": {"command": command}, "status": "completed", "result": {"content": []}}


def _row_logger(tmp_path: Path, body: str = "") -> Path:
    """A post-tool-log.sh stand-in that appends each payload to rows.jsonl and flags overlapping runs."""
    hooks = tmp_path / "scripts/hooks"
    hooks.mkdir(parents=True)
    quoted = shlex.quote(str(tmp_path))
    (hooks / "post-tool-log.sh").write_text(
        f"#!/bin/bash\nIN=$(cat)\nmkdir {quoted}/running 2>/dev/null || echo overlap >> {quoted}/overlap\n"
        f"{body}\nprintf '%s\\n' \"$IN\" >> {quoted}/rows.jsonl\nrmdir {quoted}/running\n")
    return tmp_path / "rows.jsonl"


def _timed_logger(tmp_path: Path, body: str = "") -> Path:
    """A post-tool-log.sh stand-in that appends {start, end, payload} to rows.jsonl."""
    hooks = tmp_path / "scripts/hooks"
    hooks.mkdir(parents=True)
    rows = shlex.quote(str(tmp_path / "rows.jsonl"))
    now = "perl -MTime::HiRes=time -e 'printf q(%.6f), time'"
    (hooks / "post-tool-log.sh").write_text(
        f"#!/bin/bash\nIN=$(cat)\nstart=$({now})\n{body}\nend=$({now})\n"
        f"printf '{{\"start\":%s,\"end\":%s,\"payload\":%s}}\\n' \"$start\" \"$end\" \"$IN\" >> {rows}\n")
    return tmp_path / "rows.jsonl"


def _overlaps(timed: list[dict]) -> int:
    """The most loggers that ran at one moment."""
    edges = sorted([(row["start"], 1) for row in timed] + [(row["end"], -1) for row in timed])
    running = peak = 0
    for _, step in edges:
        running += step
        peak = max(peak, running)
    return peak


def _rows(path: Path, count: int) -> list[dict]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        rows = path.read_text().splitlines() if path.exists() else []
        if len(rows) >= count:
            break
        time.sleep(0.05)
    return [json.loads(row) for row in rows]


def test_standard_hooks_return_before_the_logger_finishes(tmp_path):
    """A shell call's result is not held while its activity row is written."""
    release = tmp_path / "release"
    rows = _row_logger(tmp_path, f"for i in $(seq 100); do [ -e {shlex.quote(str(release))} ] && break; sleep 0.05; done\n"
                                 f"[ -e {shlex.quote(str(release))} ] || echo held >> {shlex.quote(str(tmp_path))}/held")
    _host(STANDARD, env={"VIGIL_AGENT_ROOT": str(tmp_path), "ENGAGEMENT_DIR": str(tmp_path)}, steps=[
        {"hook": "tool.execute.after", "event": _shell_event("s", "operator", "id")},
        # Runs only once the call's hook has returned.
        {"touch": str(release)}])
    assert [row["tool_input"] for row in _rows(rows, 1)] == [{"command": "id"}]
    assert not (tmp_path / "held").exists()


_STANDARD_CALLS = [("ses_root", "operator", "nmap acme.example"), ("ses_a", "recon-specialist", "curl -sI https://acme.example"),
                   ("ses_b", "fuzzer", "ffuf -u https://acme.example/FUZZ"), ("ses_root", "operator", "whoami"),
                   ("ses_a", "recon-specialist", "dig acme.example"), ("ses_c", "fuzzer", "nikto -h acme.example"),
                   ("ses_d", "recon-specialist", "dnsx -d acme.example"), ("ses_e", "fuzzer", "httpx -u acme.example"),
                   ("ses_b", "fuzzer", "ffuf -u https://acme.example/api/FUZZ")]


def test_standard_hooks_log_sessions_side_by_side_keeping_each_sessions_order(tmp_path):
    """Loggers for different sessions run together, at most four at once; one session's rows stay in call order."""
    rows = _timed_logger(tmp_path, "sleep 0.4")
    _host(STANDARD, env={"VIGIL_AGENT_ROOT": str(tmp_path), "ENGAGEMENT_DIR": str(tmp_path)},
          steps=[{"hook": "tool.execute.after", "event": _shell_event(*call)} for call in _STANDARD_CALLS])
    timed = _rows(rows, len(_STANDARD_CALLS))
    written = [row["payload"] for row in timed]
    assert sorted((row["session_id"], row["agent_type"], row["tool_input"]["command"]) for row in written) == sorted(
        _STANDARD_CALLS)
    for session in {call[0] for call in _STANDARD_CALLS}:
        own = [row for row in timed if row["payload"]["session_id"] == session]
        assert [row["payload"]["tool_input"]["command"] for row in own] == [
            command for call_session, _, command in _STANDARD_CALLS if call_session == session]
        assert all(earlier["end"] <= later["start"] for earlier, later in zip(own, own[1:]))
    assert 2 <= _overlaps(timed) <= 4


def test_standard_hooks_name_each_call_and_when_it_finished(tmp_path):
    """The logger claims the native call, not its command text, and dates the row by the call's finish."""
    rows = _timed_logger(tmp_path, "sleep 0.3")
    before = time.time()
    _host(STANDARD, env={"VIGIL_AGENT_ROOT": str(tmp_path), "ENGAGEMENT_DIR": str(tmp_path)},
          steps=[{"hook": "tool.execute.after", "event": {**_shell_event("ses_a", "fuzzer", "id"), "messageID": "msg_7",
                                                           "id": "call_1"}}])
    (timed,) = _rows(rows, 1)
    payload = timed["payload"]
    finished = datetime.fromisoformat(payload.pop("occurred_at")).timestamp()
    assert payload == {"hook_event_name": "PostToolUse", "client_name": "opencode", "session_id": "ses_a",
                       "tool_use_id": "msg_7/call_1", "tool_name": "Bash", "tool_input": {"command": "id"},
                       "tool_response": {}, "agent_type": "fuzzer", "cwd": str(tmp_path)}
    assert before <= finished <= timed["start"]


def test_standard_hooks_log_a_repeated_command_once_per_call(tmp_path):
    """The real logger: the same command run twice is two rows; one call is one row."""
    agent_root = tmp_path / "agent"
    shutil.copytree(ROOT / "agent/scripts/hooks", agent_root / "scripts/hooks")
    shutil.copytree(ROOT / "agent/scripts/lib", agent_root / "scripts/lib")
    engagement = tmp_path / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"status": "in_progress"}))
    capture = tmp_path / "logged.jsonl"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "vigil").write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {shlex.quote(str(capture))}\n")
    (bin_dir / "vigil").chmod(0o755)
    first = {**_shell_event("ses_a", "fuzzer", "nmap -sV acme.example"), "messageID": "msg_1", "id": "call_1"}
    _host(STANDARD, env={"VIGIL_AGENT_ROOT": str(agent_root), "ENGAGEMENT_DIR": str(engagement),
                         "PATH": f"{bin_dir}:{os.environ['PATH']}"},
          steps=[{"hook": "tool.execute.after", "event": first},
                 {"hook": "tool.execute.after", "event": {**first, "messageID": "msg_2"}},
                 {"hook": "tool.execute.after", "event": {**first, "id": "call_2"}},
                 {"hook": "tool.execute.after", "event": first}])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and len(capture.read_text().splitlines() if capture.exists() else []) < 3:
        time.sleep(0.05)
    time.sleep(1)
    assert [line.count("bash: nmap -sV acme.example") for line in capture.read_text().splitlines()] == [1, 1, 1]


_EXIT_HOST = r"""
import {pathToFileURL} from 'node:url';
const callbacks = [];
const ctx = {tool: {hook: async (name, callback) => { if (name === 'execute.after') callbacks.push(callback) }}};
await (await import(pathToFileURL(process.argv[2]).href)).default.setup(ctx);
for (const [index, command] of ['nmap acme.example', 'dig acme.example', 'whoami'].entries())
  for (const callback of callbacks) await callback({tool: 'shell', sessionID: 's', agent: index ? 'recon-specialist' : 'operator',
    messageID: 'm', id: 'c' + index, input: {command}, status: 'completed', result: {content: []}});
process.exit(0);
"""


def test_standard_hooks_leave_a_call_without_native_identity_to_the_duplicate_window(tmp_path):
    """A call the host does not name keeps the logger's command-text duplicate window."""
    rows = _timed_logger(tmp_path)
    anonymous = {key: value for key, value in _shell_event("ses_a", "fuzzer", "whoami").items() if key != "id"}
    _host(STANDARD, env={"VIGIL_AGENT_ROOT": str(tmp_path), "ENGAGEMENT_DIR": str(tmp_path)},
          steps=[{"hook": "tool.execute.after", "event": anonymous}])
    (timed,) = _rows(rows, 1)
    assert timed["payload"]["tool_input"] == {"command": "whoami"}
    assert not {"client_name", "session_id", "tool_use_id"} & set(timed["payload"])


@pytest.mark.parametrize("runtime", ["node", "bun"])
def test_standard_hooks_keep_rows_queued_when_opencode_exits(tmp_path, runtime):
    """OpenCode may exit right after a call; every row it already returned still reaches the logger, in order.

    OpenCode runs on Bun, whose pipes drop unflushed input at exit."""
    if shutil.which(runtime) is None:
        pytest.skip(f"{runtime} is not installed")
    rows = _row_logger(tmp_path, "sleep 0.3")
    spool = tmp_path / "tmp"
    spool.mkdir()
    script = tmp_path / "exit-host.mjs"
    script.write_text(_EXIT_HOST)
    subprocess.run([runtime, str(script), str(STANDARD)], env={**os.environ, "VIGIL_AGENT_ROOT": str(tmp_path),
        "ENGAGEMENT_DIR": str(tmp_path), "TMPDIR": str(spool)}, capture_output=True, text=True, timeout=30, check=True)
    written = _rows(rows, 3)
    assert [(row["agent_type"], row["tool_input"]["command"]) for row in written] == [
        ("operator", "nmap acme.example"), ("recon-specialist", "dig acme.example"), ("recon-specialist", "whoami")]
    assert not (tmp_path / "overlap").exists()
    deadline = time.monotonic() + 5
    while list(spool.iterdir()) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert list(spool.iterdir()) == []


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


def test_compaction_extends_the_native_summary_with_the_real_preservation_contract(tmp_path):
    binding, _, _ = _binding(tmp_path, agent=ROOT / "agent")
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)},
                steps=[{"hook": "session.compaction", "event": _context_event("ses_root")}])
    texts = _texts(log["results"][0]["event"])
    assert texts[0] == "native-default" and len(texts) == 2
    assert not texts[1].startswith("Vigil preservation unavailable"), texts[1]


@pytest.mark.parametrize(("agent", "parent", "revert", "recover"), [
    ("operator", False, False, True),
    ("code-architect", False, False, False),
    ("operator", True, False, False),
    ("operator", False, True, False),
])
def test_summary_recovery_is_standing_for_the_operator_at_a_visible_summary(tmp_path, agent, parent, revert, recover):
    """Every operator request after a visible summary carries the recovery contract; a specialist, a child, or a
    revert that hides the summary gets none."""
    binding, _, agent_root = _binding(tmp_path)
    (agent_root / "scripts/hooks/post-compact-resume.sh").write_text("#!/bin/sh\nprintf '%s' recovery-marker\n")
    session = {"id": "ses_root", "agent": agent, **({"parentID": "ses_parent"} if parent else {}),
               **({"revert": {"messageID": "msg_summary"}} if revert else {})}
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)},
        sessions={"ses_root": session, "ses_parent": {"id": "ses_parent", "agent": "operator"}},
        contexts={"ses_root": [{"id": "msg_summary", "type": "compaction", "status": "completed", "summary": "Acme"},
                               {"id": "msg_u", "type": "user", "text": "continue"}]},
        steps=[{"hook": "session.context", "event": _context_event("ses_root", agent)} for _ in range(2)])
    for result in log["results"]:
        assert any("recovery-marker" in text for text in _texts(result["event"])) is recover


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


_RETAINED_HOST = r"""
import {pathToFileURL} from 'node:url';
const {VigilAssessmentHooksV2} = await import(pathToFileURL(process.argv[1]).href);
const adapter = await VigilAssessmentHooksV2({ctx: {}, bindingPath: process.argv[2]});
const event = {sessionID: 'ses_b', system: []};
await adapter['session.compaction'](event);
process.stdout.write(JSON.stringify(event));
"""


def test_retained_runtime_supplies_its_own_shell_hook_environment(tmp_path):
    """The dispatcher hands a retained task its own binding; its hooks see that binding, not the launch's."""
    application = tmp_path / "application-b"
    (application / "agent/scripts/hooks").mkdir(parents=True)
    (application / "agent/scripts/hooks/pre-compact.sh").write_text(
        '#!/bin/sh\nprintf "%s\\n" "$VIGIL_CLIENT_CONTEXT" "$VIGIL_APPLICATION_DIR" "$PATH"\n')
    binding, _, _ = _binding(tmp_path, agent=application / "agent")
    tools = tmp_path / "tools-b"
    binding.write_text(json.dumps({**json.loads(binding.read_text()),
                                   "tools": {"bash": shutil.which("bash"), "jq": str(tools / "jq")}}))
    result = subprocess.run([shutil.which("node"), "--input-type=module", "-e", _RETAINED_HOST, str(RUNTIME), str(binding)],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(tmp_path / "context-a.json"),
             "VIGIL_APPLICATION_DIR": str(tmp_path / "application-a"), "PATH": "/launch/tools-a:/usr/bin:/bin"},
        capture_output=True, text=True, timeout=20, check=True)
    context, app, path = _texts(json.loads(result.stdout))[0].splitlines()
    assert context == str(binding)
    assert app == str(application)
    directories = path.split(os.pathsep)
    assert directories[0] == str(tmp_path / "bin")
    assert directories.index(str(tools)) < directories.index("/launch/tools-a")


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
        "content": [{"type": "text", "text": "Acme"}], "metadata": {"status": "completed", "exit": 7},
        "native_extra": {"count": 2}})])
    assert len(rows) == 1
    row = rows[0]
    assert (row["tool_name"], row["native_tool_name"], row["agent_type"]) == ("Bash", "shell", "operator")
    # A call id is unique within its message, so the message names the call too.
    assert (row["session_id"], row["tool_use_id"], row["client_name"]) == ("ses_root", "msg_1/call-1", "opencode")
    assert datetime.fromisoformat(row["occurred_at"]).tzinfo is not None
    assert row["tool_input"] == {"command": "printf Acme"}
    assert (row["tool_response"]["output"], row["tool_response"]["exit_code"]) == ("Acme", 7)
    assert row["tool_response"]["wallTimeSeconds"] == 0.1
    assert row["tool_response"]["metadata"] == {"status": "completed", "exit": 7}
    assert row["tool_response"]["native_extra"] == {"count": 2}


def test_failed_tool_activity_records_the_native_error(tmp_path):
    rows, _ = _activity(tmp_path, [_call("shell", {"command": "id"}, status="error",
                                         error={"_tag": "Tool.Error", "message": "Acme denied"})])
    response = rows[0]["tool_response"]
    assert (response["stderr"], response["exit_code"]) == ("Acme denied", 1)
    assert response["error"]["message"] == "Acme denied"


@pytest.mark.parametrize("tool", ["write", "edit"])
def test_file_activity_names_the_native_path(tmp_path, tool):
    given = {"path": "/acme/engagements/acme/findings.md", "content": "Acme", "oldString": "old", "newString": "new"}
    rows, _ = _activity(tmp_path, [_call(tool, given, status="completed", result={"output": "saved", "content": []})])
    assert rows[0]["tool_name"] == tool.title()
    assert rows[0]["tool_input"] == {**given, "file_path": given["path"]}
    assert rows[0]["cwd"] == str(tmp_path / "acme")


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


def test_catalog_lookup_does_not_hold_the_tool_result_or_reorder_rows(tmp_path):
    """An MCP name is resolved after the call returns, and its row keeps its place before later rows."""
    agent = tmp_path / "agent"
    rows = _row_logger(agent)
    binding, _, _ = _binding(tmp_path, agent=agent)
    release = tmp_path / "release"
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)}, gate=str(release), steps=[
        {"hook": "tool.execute.after", "event": {**_call("acme-server_lookup", {"query": "Acme"}, status="completed",
         result={"output": {"count": 2}, "content": [{"type": "text", "text": "Acme answer"}]}), "id": "call-mcp"}},
        # Runs only once the MCP call's hook has returned.
        {"touch": str(release)},
        {"hook": "tool.execute.after", "event": {**_call("shell", {"command": "id"}, status="completed",
         result={"output": {"output": "uid=0", "exitCode": 0}, "content": []}), "id": "call-shell"}}], **_MCP)
    written = _rows(rows, 2)
    assert [(row["tool_use_id"], row["tool_name"]) for row in written] == [
        ("msg_1/call-mcp", "mcp__acme-server_lookup"), ("msg_1/call-shell", "Bash")]
    assert '"count":2' in written[0]["tool_response"]["output"]
    assert not any("MCP identity could not be verified" in line for line in log["errors"]), log["errors"]
    assert not (agent / "overlap").exists()


def test_activity_sessions_are_written_side_by_side_in_each_sessions_order(tmp_path):
    """At most four hooks at once; a session's rows in call order; rows without a call identity never together."""
    agent = tmp_path / "agent"
    rows = _timed_logger(agent, "sleep 0.4")
    binding, _, _ = _binding(tmp_path, agent=agent)
    calls = [(session, f"echo {session}-{index}") for index in range(2) for session in ("ses_a", "ses_b", "ses_c", "ses_d", "ses_e")]
    anonymous = [("ses_x", "echo anonymous-1"), ("ses_y", "echo anonymous-2")]
    events = [{**_call("shell", {"command": command}, status="completed", result={"content": []}),
               "sessionID": session, "id": f"call-{index}"} for index, (session, command) in enumerate(calls)]
    events += [{key: value for key, value in _call("shell", {"command": command}, status="completed",
                result={"content": []}).items() if key != "id"} | {"sessionID": session} for session, command in anonymous]
    _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)}, steps=[{"hook": "tool.execute.after", "event": event} for event in events])
    timed = _rows(rows, len(events))
    assert sorted(row["payload"]["tool_input"]["command"] for row in timed) == sorted(command for _, command in calls + anonymous)
    for session in {session for session, _ in calls}:
        own = [row for row in timed if row["payload"]["session_id"] == session]
        assert [row["payload"]["tool_input"]["command"] for row in own] == [c for s, c in calls if s == session]
        assert all(earlier["end"] <= later["start"] for earlier, later in zip(own, own[1:]))
    assert 2 <= _overlaps(timed) <= 4
    assert _overlaps([row for row in timed if "tool_use_id" not in row["payload"]]) == 1


def test_activity_write_does_not_hold_the_tool_result(tmp_path):
    """A call's result is not held while its row is written; a normal end waits for the write and keeps nothing."""
    agent = tmp_path / "agent"
    release = shlex.quote(str(tmp_path / "release"))
    rows = _row_logger(agent, f"for i in $(seq 100); do [ -e {release} ] && break; sleep 0.05; done\n"
                              f"[ -e {release} ] || echo held >> {shlex.quote(str(tmp_path))}/held")
    binding, _, _ = _binding(tmp_path, agent=agent)
    _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)}, steps=[
        {"hook": "tool.execute.after", "event": _call("shell", {"command": "id"}, status="completed",
                                                      result={"output": {"output": "uid=0", "exitCode": 0}, "content": []})},
        # Runs only once the call's hook has returned.
        {"touch": str(tmp_path / "release")}])
    assert [row["tool_use_id"] for row in _rows(rows, 1)] == ["msg_1/call-1"]
    assert not (tmp_path / "held").exists()
    assert not list(tmp_path.glob(".vigil-activity-unrecorded*"))


_TIMEOUT_HOST = r"""
import {pathToFileURL} from 'node:url';
const {VigilAssessmentHooksV2} = await import(pathToFileURL(process.argv[1]).href);
const ctx = {tool: {list: async () => []}, mcp: {list: async () => ({data: []})}};
const adapter = await VigilAssessmentHooksV2({ctx, activityTimeoutMs: 300});
await adapter['tool.execute.after']({tool: 'shell', sessionID: 'ses_1', agent: 'operator', messageID: 'msg_1', id: 'call-1',
  input: {command: 'id'}, status: 'completed', result: {output: {output: 'uid=0', exitCode: 0}, content: []}});
"""


def test_activity_timeout_keeps_the_unconfirmed_row(tmp_path):
    agent = tmp_path / "agent"
    (agent / "scripts/hooks").mkdir(parents=True)
    (agent / "scripts/hooks/post-tool-log.sh").write_text("#!/bin/bash\ncat >/dev/null\nexec sleep 8\n")
    binding, _, _ = _binding(tmp_path, agent=agent)
    result = subprocess.run(["node", "--input-type=module", "-e", _TIMEOUT_HOST, str(RUNTIME)],
                            env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)}, capture_output=True, text=True,
                            timeout=60, check=True)
    spool = tmp_path / ".vigil-activity-unrecorded.jsonl"
    assert spool.exists(), result.stderr
    rows = [json.loads(line) for line in spool.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["unconfirmed_this_session"] == 1
    assert rows[0]["error"]
    assert (rows[0]["payload"]["tool_use_id"], rows[0]["payload"]["session_id"]) == ("msg_1/call-1", "ses_1")
    assert str(spool) in result.stderr


def test_compaction_contract_does_not_stall_other_sessions(tmp_path):
    """The preservation hook runs while the host keeps serving other work."""
    binding, _, agent = _binding(tmp_path)
    release = shlex.quote(str(tmp_path / "release"))
    (agent / "scripts/hooks/pre-compact.sh").write_text(
        f"#!/bin/sh\nfor i in $(seq 60); do [ -e {release} ] && break; sleep 0.05; done\n"
        f"[ -e {release} ] && printf '%s' preserve-marker || printf '%s' held\n")
    log = _host(RUNTIME, env={"VIGIL_CLIENT_CONTEXT": str(binding)},
        sessions={"ses_root": {"id": "ses_root", "agent": "operator"}},
        steps=[{"later": {"touch": str(tmp_path / "release"), "after": 50}},
               {"hook": "session.compaction", "event": _context_event("ses_root")}])
    assert _texts(log["results"][0]["event"]) == ["native-default", "preserve-marker"]


_RUNTIME_EXIT_HOST = r"""
import {pathToFileURL} from 'node:url';
const callbacks = [];
const hook = domain => async (name, callback) => { callbacks.push([`${domain}.${name}`, callback]) };
const ctx = {tool: {hook: hook('tool'), list: async () => []}, session: {hook: hook('session')},
  mcp: {list: async () => ({data: []})}, event: {subscribe: () => ({[Symbol.asyncIterator]: () => ({next: () => new Promise(() => {})})})}};
await (await import(pathToFileURL(process.argv[2]).href)).default.setup(ctx);
for (const [index, command] of ['nmap acme.example', 'dig acme.example', 'whoami'].entries())
  for (const [name, callback] of callbacks) if (name === 'tool.execute.after') await callback({tool: 'shell',
    sessionID: 'ses_root', agent: 'operator', messageID: 'm', id: 'call-' + index, input: {command}, status: 'completed',
    result: {output: {output: '', exitCode: 0}, content: []}});
process.exit(0);
"""


@pytest.mark.parametrize("runtime", ["node", "bun"])
def test_activity_queued_at_exit_is_still_written_in_order(tmp_path, runtime):
    """Rows queued when OpenCode exits reach the logger once each, in call order, and stay kept as unconfirmed."""
    if shutil.which(runtime) is None:
        pytest.skip(f"{runtime} is not installed")
    agent = tmp_path / "agent"
    claims = shlex.quote(str(tmp_path / "claims"))
    # Like post-tool-log.sh, a call identity is claimed once; unreadable input writes nothing.
    rows = _row_logger(agent, f"mkdir -p {claims}\n"
        "id=$(printf '%s' \"$IN\" | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"tool_use_id\"])' 2>/dev/null)"
        f" || {{ rmdir {shlex.quote(str(agent))}/running; exit 0; }}\n"
        f"mkdir {claims}/\"${{id//\\//_}}\" 2>/dev/null || {{ rmdir {shlex.quote(str(agent))}/running; exit 0; }}\nsleep 0.3")
    binding, _, _ = _binding(tmp_path, agent=agent)
    spool = tmp_path / "tmp"
    spool.mkdir()
    script = tmp_path / "exit-host.mjs"
    script.write_text(_RUNTIME_EXIT_HOST)
    subprocess.run([runtime, str(script), str(RUNTIME)], env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding),
        "TMPDIR": str(spool)}, capture_output=True, text=True, timeout=30, check=True)
    written = _rows(rows, 3)
    time.sleep(0.5)
    assert [row["tool_use_id"] for row in _rows(rows, 3)] == ["m/call-0", "m/call-1", "m/call-2"]
    assert [row["tool_input"]["command"] for row in written] == ["nmap acme.example", "dig acme.example", "whoami"]
    kept = [json.loads(line) for line in (tmp_path / ".vigil-activity-unrecorded.jsonl").read_text().splitlines()]
    assert [row["payload"]["tool_use_id"] for row in kept] == ["m/call-0", "m/call-1", "m/call-2"]
    deadline = time.monotonic() + 5
    while list(spool.iterdir()) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert list(spool.iterdir()) == []


# An OpenCode process can end without its `exit` event: `opencode serve` run without a terminal
# leaves SIGHUP to its default action, and SIGKILL ends any process at once. The host below
# loads a plugin through `setup`, fires the calls, and ends as `ending` says: `exit`
# (process.exit), a signal name (that signal's default action), or `worker` (the plugin runs in
# a worker thread whose exit event never fires; the main thread exits). The MCP catalog answers
# its first `answered` reads and never answers later ones; `removeSpoolsAfter` deletes the
# plugins' spool folders mid-run.
_ENDING_HOST = r"""
import {pathToFileURL} from 'node:url';
import {Worker, isMainThread, parentPort, workerData} from 'node:worker_threads';
import {readdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const [plugin, ending, options] = isMainThread ? [process.argv[2], process.argv[3], JSON.parse(process.argv[4])] : workerData;
if (isMainThread && ending === 'worker') {
  const worker = new Worker(new URL(import.meta.url), {workerData: [plugin, ending, options]});
  worker.on('message', () => process.exit(0));
} else {
  const callbacks = [];
  const hook = domain => async (name, callback) => { callbacks.push([`${domain}.${name}`, callback]) };
  let reads = 0;
  const ctx = {tool: {hook: hook('tool'), list: async () => options.tools || []}, session: {hook: hook('session')},
    mcp: {list: () => ++reads <= (options.answered ?? Infinity) ? Promise.resolve({data: options.servers || []}) : new Promise(() => {})},
    event: {subscribe: () => ({[Symbol.asyncIterator]: () => ({next: () => new Promise(() => {})})})}};
  await (await import(pathToFileURL(plugin).href)).default.setup(ctx);
  for (const [index, event] of options.events.entries()) {
    // Something else removes the plugin's private spool folders after this many calls.
    if (index === options.removeSpoolsAfter) for (const name of readdirSync(tmpdir()))
      if (name.startsWith('vigil-activity-')) rmSync(join(tmpdir(), name), {recursive: true, force: true});
    for (const [name, callback] of callbacks) if (name === 'tool.execute.after') await callback(event);
  }
  await new Promise(resolve => setTimeout(resolve, options.settle ?? 0));
  if (ending === 'worker') { parentPort.postMessage('queued'); await new Promise(() => {}) }
  else if (ending === 'exit') process.exit(0);
  else process.kill(process.pid, ending);
}
"""
_ENDINGS = ["exit", "SIGTERM", "SIGHUP", "SIGKILL", "worker"]


def _end_host(tmp_path: Path, runtime: str, plugin: Path, ending: str, env: dict, **options) -> Path:
    """Runs the ending host; returns its TMPDIR, where a plugin keeps private payload files."""
    if shutil.which(runtime) is None:
        pytest.skip(f"{runtime} is not installed")
    spool = tmp_path / "tmp"
    spool.mkdir(exist_ok=True)
    script = tmp_path / "ending-host.mjs"
    script.write_text(_ENDING_HOST)
    subprocess.run([runtime, str(script), str(plugin), ending, json.dumps(options)],
                   env={**os.environ, **env, "TMPDIR": str(spool)}, capture_output=True, timeout=30)
    return spool


def _drained(spool: Path) -> list[Path]:
    deadline = time.monotonic() + 10
    while list(spool.iterdir()) and time.monotonic() < deadline:
        time.sleep(0.05)
    return list(spool.iterdir())


@pytest.mark.parametrize("ending", _ENDINGS)
@pytest.mark.parametrize("runtime", ["node", "bun"])
def test_standard_hooks_write_every_row_however_opencode_ends(tmp_path, runtime, ending):
    """Closing the terminal or a signal ends OpenCode without its exit event; every row it returned is still written once, in order."""
    rows = _row_logger(tmp_path, "sleep 0.3")
    commands = ["nmap acme.example", "dig acme.example", "whoami", "id"]
    spool = _end_host(tmp_path, runtime, STANDARD, ending, {"VIGIL_AGENT_ROOT": str(tmp_path), "ENGAGEMENT_DIR": str(tmp_path)},
                      events=[_shell_event("s", "operator", command) for command in commands], settle=100)
    written = _rows(rows, len(commands))
    time.sleep(0.6)
    assert [row["tool_input"]["command"] for row in _rows(rows, len(commands))] == commands
    assert [row["tool_input"]["command"] for row in written] == commands
    assert not (tmp_path / "overlap").exists()
    assert _drained(spool) == []


@pytest.mark.parametrize("ending", ["exit", "SIGTERM"])
def test_standard_hooks_keep_logging_after_their_spool_folder_is_removed(tmp_path, ending):
    """A removed spool starts over: rows already queued and every later row are still written once each."""
    rows = _row_logger(tmp_path, "sleep 0.3")
    commands = [f"nmap acme-{index}.example" for index in range(6)]
    spool = _end_host(tmp_path, "node", STANDARD, ending, {"VIGIL_AGENT_ROOT": str(tmp_path), "ENGAGEMENT_DIR": str(tmp_path)},
                      events=[_shell_event("s", "operator", command) for command in commands], removeSpoolsAfter=3, settle=100)
    written = _rows(rows, len(commands))
    time.sleep(0.6)
    assert [row["tool_input"]["command"] for row in _rows(rows, len(commands))] == commands
    assert [row["tool_input"]["command"] for row in written] == commands
    assert _drained(spool) == []


_SPOOL_PROGRAMS = r"""
import {readFileSync} from 'node:fs';
const out = {};
for (const path of process.argv.slice(1)) {
  const source = readFileSync(path, 'utf8');
  out[path] = Object.fromEntries(['CLAIM', 'DRAIN', 'UNSPOOLED'].map(name => {
    const match = new RegExp(`const ${name} = ((?:'[^']*'|\\d+)(?:\\s*\\+\\s*'[^']*')*)`).exec(source);
    return [name, match ? eval(match[1]) : null];
  }));
}
process.stdout.write(JSON.stringify(out));
"""


def test_both_plugins_spool_rows_with_the_same_shell_programs():
    """Each plugin carries its own copy (a plugin folder loads every file in it); the copies must not drift."""
    result = subprocess.run(["node", "--input-type=module", "-e", _SPOOL_PROGRAMS, str(STANDARD), str(RUNTIME)],
                            capture_output=True, text=True, timeout=30, check=True)
    standard, runtime = json.loads(result.stdout).values()
    assert standard == runtime
    assert isinstance(standard["UNSPOOLED"], int) and f"exit {standard['UNSPOOLED']};" in standard["CLAIM"]
    for name in ("CLAIM", "DRAIN"):
        assert isinstance(standard[name], str) and standard[name]
        subprocess.run(["bash", "-n", "-c", standard[name]], check=True)


def _claiming_logger(agent: Path, claims: Path, body: str = "sleep 0.3") -> Path:
    """Like post-tool-log.sh: a call identity is claimed once; a row without one is always written."""
    return _row_logger(agent, f"mkdir -p {shlex.quote(str(claims))}\n"
        "id=$(printf '%s' \"$IN\" | python3 -c 'import json,sys; print(json.load(sys.stdin).get(\"tool_use_id\") or \"\")' 2>/dev/null)"
        f" || {{ rmdir {shlex.quote(str(agent))}/running; exit 0; }}\n"
        f"[ -z \"$id\" ] || mkdir {shlex.quote(str(claims))}/\"${{id//\\//_}}\" 2>/dev/null"
        f" || {{ rmdir {shlex.quote(str(agent))}/running; exit 0; }}\n{body}")


@pytest.mark.parametrize("ending", _ENDINGS)
@pytest.mark.parametrize("runtime", ["node", "bun"])
def test_activity_is_written_however_opencode_ends(tmp_path, runtime, ending):
    agent = tmp_path / "agent"
    rows = _claiming_logger(agent, tmp_path / "claims")
    binding, _, _ = _binding(tmp_path, agent=agent)
    commands = ["nmap acme.example", "dig acme.example", "whoami", "id"]
    events = [{**_call("shell", {"command": command}, status="completed", result={"content": []}), "id": f"call-{index}"}
              for index, command in enumerate(commands)]
    spool = _end_host(tmp_path, runtime, RUNTIME, ending, {"VIGIL_CLIENT_CONTEXT": str(binding)}, events=events, settle=100)
    written = _rows(rows, len(commands))
    time.sleep(0.6)
    assert [row["tool_input"]["command"] for row in _rows(rows, len(commands))] == commands
    assert [row["tool_input"]["command"] for row in written] == commands
    assert _drained(spool) == []


@pytest.mark.parametrize("ending", ["exit", "SIGTERM"])
def test_activity_keeps_logging_after_its_spool_folder_is_removed(tmp_path, ending):
    agent = tmp_path / "agent"
    rows = _claiming_logger(agent, tmp_path / "claims")
    binding, _, _ = _binding(tmp_path, agent=agent)
    commands = [f"nmap acme-{index}.example" for index in range(6)]
    events = [{**_call("shell", {"command": command}, status="completed", result={"content": []}), "id": f"call-{index}"}
              for index, command in enumerate(commands)]
    spool = _end_host(tmp_path, "node", RUNTIME, ending, {"VIGIL_CLIENT_CONTEXT": str(binding)}, events=events,
                      removeSpoolsAfter=3, settle=100)
    written = _rows(rows, len(commands))
    time.sleep(0.6)
    assert [row["tool_input"]["command"] for row in _rows(rows, len(commands))] == commands
    assert [row["tool_input"]["command"] for row in written] == commands
    assert _drained(spool) == []


@pytest.mark.parametrize("ending", ["exit", "SIGTERM"])
def test_a_row_being_written_when_opencode_ends_is_written_once(tmp_path, ending):
    """A row without a call identity has no claim to make a second write a no-op."""
    agent = tmp_path / "agent"
    rows = _claiming_logger(agent, tmp_path / "claims", "sleep 0.6")
    binding, engagement, _ = _binding(tmp_path, agent=agent)
    event = {key: value for key, value in _call("write", {"path": str(engagement / "notes.md"), "content": "Acme"},
             status="completed", result={"content": []}).items() if key not in ("id", "messageID")}
    spool = _end_host(tmp_path, "node", RUNTIME, ending, {"VIGIL_CLIENT_CONTEXT": str(binding)}, events=[event], settle=200)
    time.sleep(2)
    assert [row["tool_name"] for row in _rows(rows, 1)] == ["Write"]
    assert _drained(spool) == []


@pytest.mark.parametrize("ending", ["exit", "SIGTERM", "worker"])
def test_an_mcp_row_still_resolving_when_opencode_ends_keeps_its_mcp_name(tmp_path, ending):
    """The catalog this process already read names a row whose own lookup had not answered."""
    agent = tmp_path / "agent"
    rows = _claiming_logger(agent, tmp_path / "claims", "")
    binding, _, _ = _binding(tmp_path, agent=agent)
    events = [{**_call("acme-server_lookup", {"query": "Acme"}, status="completed",
                       result={"content": [{"type": "text", "text": f"Acme answer {index}"}]}), "id": f"call-{index}"}
              for index in range(2)]
    spool = _end_host(tmp_path, "node", RUNTIME, ending, {"VIGIL_CLIENT_CONTEXT": str(binding)}, events=events,
                      answered=1, settle=100, **_MCP)
    written = _rows(rows, 2)
    assert [(row["tool_use_id"], row["tool_name"]) for row in written] == [
        ("msg_1/call-0", "mcp__acme-server_lookup"), ("msg_1/call-1", "mcp__acme-server_lookup")]
    assert "Acme answer 1" in written[1]["tool_response"]["output"]
    assert _drained(spool) == []


def test_the_first_call_reads_the_catalog_for_a_later_mcp_row(tmp_path):
    """A row whose lookup has not answered when OpenCode ends falls back on the catalog an earlier call read."""
    agent = tmp_path / "agent"
    rows = _claiming_logger(agent, tmp_path / "claims", "")
    binding, _, _ = _binding(tmp_path, agent=agent)
    events = [{**_call("shell", {"command": "id"}, status="completed", result={"content": []}), "id": "call-shell"},
              {**_call("acme-server_lookup", {"query": "Acme"}, status="completed",
                       result={"content": [{"type": "text", "text": "Acme answer"}]}), "id": "call-mcp"}]
    spool = _end_host(tmp_path, "node", RUNTIME, "SIGTERM", {"VIGIL_CLIENT_CONTEXT": str(binding)}, events=events,
                      answered=1, settle=100, **_MCP)
    assert [(row["tool_use_id"], row["tool_name"]) for row in _rows(rows, 2)] == [
        ("msg_1/call-shell", "Bash"), ("msg_1/call-mcp", "mcp__acme-server_lookup")]
    assert _drained(spool) == []


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
    assert report["advisories"] == [{"advisory": "dispatch_already_bound", "agent_id": "acme-recon-1",
        "dispatch_id": 7, "handle": "ses_child", "bound_client": "opencode", "bound_handle": "other"}]


def test_child_refuses_a_packet_that_differs_from_its_digest(tmp_path):
    context, calls, launch, _ = _dispatch_fixture(tmp_path)
    (packet,) = (tmp_path / "acme/tools/dispatch-packets/7").iterdir()
    packet.write_bytes(packet.read_bytes().replace(b"acme-recon-1", b"acme-recon-2"))
    _, report, status = _report(_run_child(context, launch=launch))
    assert _calls(calls) == []
    assert (report["status"], report["reason"]) == ("unresolved", "packet_unverified")
    assert status is None


def _lease(item_id, receipts):
    return {"id": item_id, "status": "processing", "agent_name": "acme-recon-1", "repo_id": 3,
            "file_path": f"src/acme/module_{item_id}.py", "lease_token": f"lease-{item_id}",
            "heartbeat_age_seconds": 30, "current_result_count": receipts}


def _argv(command, helper):
    argv = shlex.split(command)
    assert argv[:2] == [str(helper), "assess"], command
    return argv[2:]


@pytest.mark.parametrize("final_text", ["", "  \n"])
def test_empty_return_without_handoff_while_holding_leases_is_reported_to_the_operator(tmp_path, final_text):
    context, calls, launch, helper = _dispatch_fixture(tmp_path, mode="code", leases=[_lease(11, 2), _lease(12, 0)])
    _, report, status = _report(_run_child(context, launch=launch, final_text=final_text))
    assert report["status"] == "bound"
    assert {key: status[key] for key in ("agent_id", "dispatch_id", "empty_result", "handoff", "handoff_status",
                                         "held_leases")} == {
        "agent_id": "acme-recon-1", "dispatch_id": 7, "empty_result": True, "handoff": False, "handoff_status": None,
        "held_leases": 2}
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
    (read,) = [call for call in _calls(calls) if call[1:3] == ["code-dispatch", "list"]]
    assert read[read.index("--agent-id") + 1] == "acme-recon-1"
    assert read[read.index("--status") + 1] == "processing"


def test_checkpointed_handoff_is_reported_as_an_incomplete_return(tmp_path):
    context, _, launch, helper = _dispatch_fixture(tmp_path, mode="code",
                                                   handoff={"agent_id": "acme-recon-1", "handoff_status": "checkpointed"})
    _, _, status = _report(_run_child(context, launch=launch))
    assert (status["empty_result"], status["handoff"], status["handoff_status"], status["held_leases"]) == (
        False, True, "checkpointed", 0)
    commands = [_argv(command, helper) for command in status["next"]]
    close = next(argv for argv in commands if argv[:2] == ["agent", "close"])
    assert close[close.index("--status") + 1] == "blocked"
    assert not any(argv[0] == "code-dispatch" for argv in commands)


def test_web_dispatch_without_handoff_is_reported_without_a_lease_read(tmp_path):
    context, calls, launch, helper = _dispatch_fixture(tmp_path)
    _, _, status = _report(_run_child(context, launch=launch))
    assert (status["handoff"], status["empty_result"]) == (False, False)
    assert "held_leases" not in status
    close = next(argv for argv in (_argv(command, helper) for command in status["next"]) if argv[:2] == ["agent", "close"])
    assert close[close.index("--status") + 1] == "failed"
    assert not any(call[1] == "code-dispatch" for call in _calls(calls))


def test_leases_left_behind_a_final_handoff_are_reported(tmp_path):
    context, _, launch, helper = _dispatch_fixture(tmp_path, mode="code", leases=[_lease(21, 1)],
                                                   handoff={"agent_id": "acme-recon-1", "handoff_status": "ready"})
    _, _, status = _report(_run_child(context, launch=launch))
    assert (status["handoff_status"], status["held_leases"]) == ("ready", 1)
    commands = [_argv(command, helper) for command in status["next"]]
    assert ["code-dispatch", "adopt-lease", "21"] in [argv[:3] for argv in commands]
    close = next(argv for argv in commands if argv[:2] == ["agent", "close"])
    assert "--status" not in close


def test_empty_return_with_a_final_handoff_points_at_the_handoff(tmp_path):
    context, _, launch, helper = _dispatch_fixture(tmp_path, mode="code",
                                                   handoff={"agent_id": "acme-recon-1", "handoff_status": "blocked"})
    _, _, status = _report(_run_child(context, launch=launch, final_text=""))
    assert (status["empty_result"], status["handoff_status"], status["held_leases"]) == (True, "blocked", 0)
    verbs = [_argv(command, helper)[:2] for command in status["next"]]
    assert ["agent", "render-handoff"] in verbs and ["agent", "close"] in verbs


def test_finished_dispatch_reports_only_its_binding(tmp_path):
    context, _, launch, _ = _dispatch_fixture(tmp_path, mode="code",
                                              handoff={"agent_id": "acme-recon-1", "handoff_status": "ready"})
    note, report, status = _report(_run_child(context, launch=launch))
    assert report["status"] == "bound" and status is None
    assert "This handle is recorded" in note["text"]


def test_dispatch_status_fails_open_with_manual_checks(tmp_path):
    context, calls, launch, helper = _dispatch_fixture(tmp_path, mode="code", reads_fail=True)
    _, report, status = _report(_run_child(context, launch=launch, final_text=""))
    assert report["status"] == "bound"
    assert (status["agent_id"], status["verified"], status["empty_result"]) == ("acme-recon-1", False, True)
    assert status["detail"]
    verbs = [_argv(command, helper)[:2] for command in status["check"]]
    assert ["agent", "render-handoff"] in verbs and ["code-dispatch", "list"] in verbs
    # Bounded: one attempt per read, no polling.
    assert len([call for call in _calls(calls) if call[1:3] == ["code-dispatch", "list"]]) <= 1


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
    # OpenCode reports the plugin as failed to load.
    assert result.returncode != 0
    assert "No native Vigil launch context" in result.stderr

