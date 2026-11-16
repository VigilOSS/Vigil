"""Native payloads cross the real shared logger into an isolated activity sink."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from threading import Thread

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def activity_runtime(tmp_path):
    received = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(201)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    # The default 0.5s polling interval becomes an idle teardown wait per case.
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    engagement = tmp_path / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"status": "in_progress", "tracks": {"code": {"phase": "hunt"}}}))
    agent = tmp_path / "agent"
    shutil.copytree(ROOT / "agent/scripts/hooks", agent / "scripts/hooks")
    shutil.copytree(ROOT / "agent/scripts/lib", agent / "scripts/lib")
    (workspace / "bin").mkdir()
    helper = workspace / "bin/vigil"
    endpoint = f"http://127.0.0.1:{server.server_port}/activity"
    helper.write_text(f"#!{sys.executable}\nimport json,sys,urllib.request\n"
                      f"urllib.request.urlopen(urllib.request.Request({endpoint!r},"
                      "data=json.dumps(sys.argv[1:]).encode(),headers={'Content-Type':'application/json'})).read()\n")
    helper.chmod(0o755)
    binding = workspace / ".vigil-client-context.json"
    binding.write_text(json.dumps({"schema_version": 1, "client": "opencode", "mode": "code",
        "workspace": str(workspace), "engagement_dir": str(engagement), "agent_root": str(agent),
        "install_root": str(tmp_path), "vigil_cli": str(helper), "release_id": "acme-release"}))

    def run(tool, output, *, error=False, catalog="available"):
        script = """
import {readFileSync} from 'node:fs';
const module=await import('data:text/javascript;base64,'+readFileSync(process.argv[1]).toString('base64'));
const adapter=await module.VigilAssessmentHooks({client:{
 mcp:{status:async()=>process.argv[5]==='unavailable'?{error:'offline'}:
   process.argv[5]==='timeout'?await new Promise(()=>{}):
   ({data:{'acme-server':{status:'connected'},'acme.example':{status:'connected'},'offline':{status:'disconnected'}}})},
 tool:{ids:async()=>({data:['bash','local_custom','acme-server_local']})}}});
const input={tool:process.argv[2],sessionID:'native-session',callID:'native-call',args:{command:'printf Acme',query:'Acme'}};
const output=JSON.parse(process.argv[3]);
for(let i=0;i<2;i++) {
 if(process.argv[4]==='true') await adapter.event({event:{type:'message.part.updated',properties:{part:{
  type:'tool',...input,state:{status:'error',input:input.args,error:output.error}}}}});
 else await adapter['tool.execute.after'](input,output);
}
"""
        result = subprocess.run(["node", "--input-type=module", "-e", script,
            str(ROOT / "agent/.opencode/plugin/assessment-hooks.js"), tool, json.dumps(output), str(error).lower(), catalog],
            env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)}, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        return received

    def run_v2(tool, event, *, catalog="available"):
        # The OpenCode 2 host: one execute.after event per call, the MCP namespace on the tool entry.
        script = """
import {readFileSync} from 'node:fs';
const module=await import('data:text/javascript;base64,'+readFileSync(process.argv[1]).toString('base64'));
const catalog=process.argv[4];
const ctx={
 mcp:{list:async()=>catalog==='unavailable'?Promise.reject(new Error('offline')):
   catalog==='timeout'?await new Promise(()=>{}):
   ({location:{},data:[{name:'acme-server',status:{status:'connected'}},{name:'acme.example',status:{status:'connected'}},
     {name:'offline',status:{status:'failed',error:'down'}}]})},
 tool:{list:async()=>[{id:'shell',options:{codemode:false}},{id:'local_custom'},
   {id:'acme-server_lookup',options:{namespace:'acme-server'}},{id:'acme_example_lookup',options:{namespace:'acme_example'}},
   {id:'offline_lookup',options:{namespace:'offline'}}]}};
const adapter=await module.VigilAssessmentHooksV2({ctx});
const event={tool:process.argv[2],sessionID:'native-session',agent:'operator',messageID:'msg_1',id:'native-call',
 input:{command:'printf Acme',query:'Acme'},...JSON.parse(process.argv[3])};
for(let i=0;i<2;i++) await adapter['tool.execute.after'](structuredClone(event));
"""
        result = subprocess.run(["node", "--input-type=module", "-e", script,
            str(ROOT / "agent/.opencode/plugin/assessment-hooks.js"), tool, json.dumps(event), catalog],
            env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(binding)}, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        return received

    run.v2 = run_v2
    try:
        yield run
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("exit_code", [0, 7])
def test_native_shell_exit_reaches_activity_once(activity_runtime, exit_code):
    rows = activity_runtime("bash", {"output": "Acme output", "metadata": {"exit": exit_code}})
    assert len(rows) == 1
    assert rows[0][-1] == ("exit=7 | " if exit_code else "") + "Acme output"


@pytest.mark.parametrize("output,error,expected", [
    ({"content": [{"type": "text", "text": "Acme answer"}, {"type": "image", "mimeType": "image/png", "data": "YQ=="}],
      "structuredContent": {"count": 2}}, False, '"structuredContent":{"count":2}'),
    ({"structuredContent": {"count": 3}}, False, '"structuredContent":{"count":3}'),
    ({"content": [{"type": "text", "text": "Acme denied"}], "isError": True}, False, '"isError":true'),
    ({"error": "Acme cancelled"}, True, "Acme cancelled"),
])
def test_native_mcp_response_reaches_activity_once(activity_runtime, output, error, expected):
    rows = activity_runtime("acme-server_lookup", output, error=error)
    assert len(rows) == 1
    assert rows[0][-3] == "mcp__acme-server_lookup"
    assert expected in rows[0][-1]
    assert "Acme" in rows[0][-2]


@pytest.mark.parametrize("tool", ["unknown_lookup", "acme-server_local", "local_custom", "offline_lookup"])
def test_non_mcp_native_tools_keep_existing_noise_policy(activity_runtime, tool):
    assert activity_runtime(tool, {"output": "Acme", "metadata": {}}) == []


@pytest.mark.parametrize("catalog", ["unavailable", "timeout"])
def test_unverifiable_mcp_catalog_does_not_fabricate_identity(activity_runtime, catalog):
    assert activity_runtime("acme-server_lookup", {"content": [{"type": "text", "text": "Acme"}]}, catalog=catalog) == []


def test_mcp_server_identity_uses_native_sanitization(activity_runtime):
    rows = activity_runtime("acme_example_lookup", {"structuredContent": {"count": 2}})
    assert len(rows) == 1
    assert rows[0][-3] == "mcp__acme_example_lookup"


@pytest.mark.parametrize("exit_code", [0, 7])
def test_opencode_2_shell_exit_reaches_activity_once(activity_runtime, exit_code):
    rows = activity_runtime.v2("shell", {"status": "completed", "result": {
        "output": {"output": "Acme output", "exitCode": exit_code, "wallTimeSeconds": 0.1},
        "content": [{"type": "text", "text": "Acme output"}], "metadata": {"status": "completed", "exit": exit_code}}})
    assert len(rows) == 1
    assert rows[0][-1] == ("exit=7 | " if exit_code else "") + "Acme output"


def test_opencode_2_failed_shell_reaches_activity_once(activity_runtime):
    rows = activity_runtime.v2("shell", {"status": "error", "error": {"message": "Acme denied"}})
    assert len(rows) == 1
    assert rows[0][-1].startswith("exit=1")


@pytest.mark.parametrize("tool,result,expected", [
    ("acme-server_lookup", {"output": {"count": 2}, "content": [{"type": "text", "text": "Acme answer"}]},
     '"count":2'),
    ("acme_example_lookup", {"content": [{"type": "text", "text": "Acme answer"}]}, "Acme answer"),
])
def test_opencode_2_mcp_response_reaches_activity_once(activity_runtime, tool, result, expected):
    rows = activity_runtime.v2(tool, {"status": "completed", "result": result})
    assert len(rows) == 1
    assert rows[0][-3] == "mcp__" + tool
    assert expected in rows[0][-1]


@pytest.mark.parametrize("tool", ["offline_lookup", "local_custom", "unknown_lookup"])
def test_opencode_2_non_mcp_tools_keep_existing_noise_policy(activity_runtime, tool):
    assert activity_runtime.v2(tool, {"status": "completed", "result": {"output": "Acme", "content": []}}) == []


@pytest.mark.parametrize("catalog", ["unavailable", "timeout"])
def test_opencode_2_unverifiable_mcp_catalog_does_not_fabricate_identity(activity_runtime, catalog):
    assert activity_runtime.v2("acme-server_lookup", {"status": "completed", "result": {
        "content": [{"type": "text", "text": "Acme"}]}}, catalog=catalog) == []
