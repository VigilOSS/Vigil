"""Task bindings survive new project selections without native services."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil

import pytest

from vigil_cli.assessment_clients import prepare_workspace
from vigil_cli.client_projects import prepare_project

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(ROOT))
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(tmp_path / "cache"))
    root = tmp_path / "private"
    engagement = root / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"status": "in_progress",
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}}}))

    def prepare(client, version="1", mode="code", release=None, layout=None):
        from vigil_cli import assessment_clients
        target = engagement
        if layout == "legacy":
            target = root / "agent/engagements/acme"
            target.mkdir(parents=True, exist_ok=True)
            (target / "scope.json").write_text((engagement / "scope.json").read_text())
        original = assessment_clients.application_provenance(ROOT)
        with monkeypatch.context() as patch:
            if release:
                patch.setattr(assessment_clients, "application_provenance", lambda _: {
                    **original, "content_sha256": hashlib.sha256(release.encode()).hexdigest()})
            snapshot, binding = prepare_workspace(root, target, client, mode, native_version=version)
        return prepare_project(snapshot, binding), snapshot, binding

    return prepare


def _opencode(snapshot, session, *, parent=None):
    binding = json.loads((snapshot / ".vigil-client-context.json").read_text())
    script = """
import {pathToFileURL} from 'node:url';
const module=await import(pathToFileURL(process.argv[1]).href);
const session=process.argv[2];
const client={session:{get:async({path})=>({data:{id:path.id,parentID:process.argv[3]||undefined}}),
 messages:async()=>({data:[{info:{role:'assistant',id:'a1',sessionID:session,
 agent:'operator',time:{created:1},modelID:'model',providerID:'provider'}}]})}};
const adapter=await module.VigilAssessmentHooks({client});
const output={system:[]};
await adapter['experimental.chat.system.transform']({sessionID:session,model:{id:'model',providerID:'provider'}},output);
process.stdout.write(JSON.stringify(output));
"""
    return subprocess.run(["node", "--input-type=module", "-e", script,
        str(snapshot / ".opencode/plugins/vigil-assessment.js"), session, parent or ""],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(snapshot / ".vigil-client-context.json"),
             "VIGIL_INSTALL_DIR": binding["install_root"]},
        capture_output=True, text=True, timeout=15, check=True)


def test_opencode_existing_native_task_retains_binding_across_processes(prepared):
    project, first, a = prepared("opencode", "1")
    assert a["vigil_cli"] in _opencode(first, "old-session").stdout
    _, second, b = prepared("opencode", "2")
    result = _opencode(second, "old-session")
    assert a["vigil_cli"] in result.stdout
    assert b["vigil_cli"] in _opencode(second, "new-session").stdout
    receipt = project / ".vigil-sessions/opencode" / (hashlib.sha256(b"old-session").hexdigest() + ".json")
    assert json.loads(receipt.read_text())["binding_path"] == str(first / ".vigil-client-context.json")


def test_opencode_child_inherits_native_parent_binding(prepared):
    _, first, a = prepared("opencode", "1")
    _opencode(first, "parent-session")
    _, second, _ = prepared("opencode", "2")
    assert a["vigil_cli"] in _opencode(second, "child-session", parent="parent-session").stdout


def _zcode(project, session, source="startup", registry=None, actor=None, script=None):
    env = dict(os.environ)
    env.pop("VIGIL_NATIVE_DISPATCH_CONTEXT", None)
    env.pop("ZCODE_PLUGIN_DATA", None)
    if registry:
        env["ZCODE_PLUGIN_DATA"] = str(registry)
    return subprocess.run(["node", str(script or project / "plugin/hooks/dispatch.mjs")], input=json.dumps({
        "hook_event_name": "SessionStart", "session_id": session, "cwd": str(project), "source": source,
        "agent_type": actor}),
        env=env, capture_output=True, text=True, timeout=15, check=True)


def test_zcode_existing_native_task_keeps_binding_after_selection_and_compaction(prepared):
    project, first, a = prepared("zcode", "1")
    result = _zcode(project, "old-session")
    assert a["vigil_cli"] in result.stdout, result.stderr
    _, second, b = prepared("zcode", "2")
    result = _zcode(project, "old-session", "compact")
    assert a["vigil_cli"] in result.stdout, result.stderr
    assert b["vigil_cli"] in _zcode(project, "new-session").stdout
    receipt = project / ".vigil-sessions/zcode" / (hashlib.sha256(b"old-session").hexdigest() + ".json")
    assert json.loads(receipt.read_text())["binding_path"] == str(first / ".vigil-client-context.json")


def test_zcode_missing_compaction_binding_requires_new_task(prepared):
    project, _, binding = prepared("zcode")
    result = _zcode(project, "unknown-session", "compact")
    assert "No retained binding" in result.stderr
    assert binding["vigil_cli"] not in result.stdout


def test_project_bootstrap_restricts_unbound_workflow_commands(prepared):
    project, _, _ = prepared("zcode")
    result = subprocess.run([str(project / "bin/vigil"), "assess", "resume-brief"],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert "NEW-task setup only" in result.stderr


@pytest.mark.parametrize("client", ["zcode", "opencode"])
def test_native_receipt_without_binding_digest_is_not_adopted(prepared, client):
    project, snapshot, binding = prepared(client)
    run = (lambda: _zcode(project, "session")) if client == "zcode" else (lambda: _opencode(snapshot, "session"))
    run()
    receipt = project / ".vigil-sessions" / client / (hashlib.sha256(b"session").hexdigest() + ".json")
    data = json.loads(receipt.read_text())
    data.pop("binding_sha256")
    receipt.write_text(json.dumps(data))
    result = run()
    assert "Native session" in result.stderr or "Native session" in result.stdout
    assert binding["vigil_cli"] not in result.stdout


def test_unbound_zcode_specialist_requires_explicit_parent_identity(prepared):
    project, _, _ = prepared("zcode", "1")
    _zcode(project, "parent")
    _, _, latest = prepared("zcode", "2")
    result = _zcode(project, "specialist", actor="code-architect")
    assert "specialist" in result.stderr
    assert latest["vigil_cli"] not in result.stdout


def test_selection_owner_manifest_failure_preserves_project_selection(prepared):
    project, snapshot, _ = prepared("zcode", "1")
    selection = (project / ".vigil-current-context.json").read_bytes()
    (snapshot / ".vigil-managed-files.json").unlink()
    with pytest.raises(SystemExit, match="selection|manifest|context"):
        prepared("zcode", "2")
    assert (project / ".vigil-current-context.json").read_bytes() == selection


@pytest.mark.parametrize("payload", [b"[]", b"{invalid", b" " * (1024 * 1024 + 1)],
                         ids=["non-object", "malformed-json", "oversized"])
def test_invalid_project_selection_reports_recovery_without_replacing_it(prepared, payload):
    project, _, _ = prepared("zcode", "1")
    selection = project / ".vigil-current-context.json"
    selection.write_bytes(payload)
    with pytest.raises(SystemExit, match="selection.*preserve.*inspect"):
        prepared("zcode", "2")
    assert selection.read_bytes() == payload


@pytest.mark.parametrize("client", ["zcode", "opencode"])
def test_retained_task_uses_its_exact_application_release(prepared, client):
    project, first, a = prepared(client, release="application-a")
    before = (project / "AGENTS.md").read_bytes()
    run = (lambda snapshot, session: _zcode(project, session)) if client == "zcode" else _opencode
    assert a["vigil_cli"] in run(first, "old-session").stdout
    _, second, b = prepared(client, release="application-b")
    assert a["release_id"] != b["release_id"]
    assert a["vigil_cli"] in run(second, "old-session").stdout
    assert b["vigil_cli"] in run(second, "new-session").stdout
    assert (project / "AGENTS.md").read_bytes() == before


def test_zcode_bootstrap_finds_known_node_without_terminal_path(prepared):
    project, _, _ = prepared("zcode")
    result = subprocess.run([str(project / "bin/vigil"), "assess", "resume-brief"],
                            env={**os.environ, "PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert "NEW-task setup only" in result.stderr


def test_opencode_new_task_in_running_process_uses_current_project_selection(prepared):
    project, first, a = prepared("opencode", "1")
    old_selection = (project / ".vigil-current-context.json").read_bytes()
    _, _, b = prepared("opencode", "2")
    new_selection = (project / ".vigil-current-context.json").read_text()
    (project / ".vigil-current-context.json").write_bytes(old_selection)
    script = """
import {pathToFileURL} from 'node:url';
import {writeFileSync} from 'node:fs';
const module=await import(pathToFileURL(process.argv[1]).href);
let active;
const client={session:{get:async({path})=>({data:{id:path.id}}),messages:async()=>({data:[{info:{
 role:'assistant',id:'a1',sessionID:active,agent:'operator',time:{created:1},modelID:'model',providerID:'provider'}}]})}};
const adapter=await module.VigilAssessmentHooks({client});
const outputs=[];
for(const session of ['old-session','new-session','old-session']){
 active=session;
 const output={system:[]};
 await adapter['experimental.chat.system.transform']({sessionID:session,model:{id:'model',providerID:'provider'}},output);
 outputs.push(output.system.join('\\n'));
 writeFileSync(process.argv[2],process.argv[3]);
}
process.stdout.write(JSON.stringify(outputs));
"""
    result = subprocess.run(["node", "--input-type=module", "-e", script,
        str(first / ".opencode/plugins/vigil-assessment.js"), str(project / ".vigil-current-context.json"), new_selection],
        env={**os.environ, "VIGIL_CLIENT_CONTEXT": str(first / ".vigil-client-context.json"),
             "VIGIL_INSTALL_DIR": a["install_root"]},
        capture_output=True, text=True, timeout=15, check=True)
    outputs = json.loads(result.stdout)
    assert a["vigil_cli"] in outputs[0]
    assert b["vigil_cli"] in outputs[1]
    assert a["vigil_cli"] in outputs[2]


def test_zcode_dispatcher_keeps_approved_owner_when_native_app_copies_plugin(prepared, tmp_path):
    project, _, binding = prepared("zcode")
    copied = tmp_path / "native-plugin-cache"
    shutil.copytree(project / "plugin", copied)
    result = _zcode(project, "session", script=copied / "hooks/dispatch.mjs")
    assert binding["vigil_cli"] in result.stdout, result.stderr


@pytest.mark.parametrize("client", ["zcode", "opencode"])
def test_native_dispatch_supports_adopted_engagement_layout(prepared, client):
    project, snapshot, adopted = prepared(client, layout="legacy")
    result = _zcode(project, "adopted") if client == "zcode" else _opencode(snapshot, "adopted")
    assert adopted["vigil_cli"] in result.stdout, result.stderr


def _rewrite_managed(path, value):
    path.write_text(json.dumps(value))
    manifest_path = path.parent / ".vigil-managed-files.json"
    manifest = json.loads(manifest_path.read_text())
    manifest[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))


@pytest.mark.parametrize("forgery", ["nested-key", "foreign-engagement-root"])
def test_global_zcode_dispatcher_rejects_counterfeit_project_in_target_source(prepared, tmp_path, forgery):
    project, _, binding = prepared("zcode")
    root = Path(binding["install_root"])
    nested = Path(binding["engagement_dir"]) / "source/counterfeit"
    nested.mkdir(parents=True)
    (nested / "scope.json").write_text('{"status":"in_progress","tracks":{"code":{}}}')
    snapshot, fake = prepare_workspace(root, nested, "zcode", "code")
    counterfeit = prepare_project(snapshot, fake)
    descriptor_path = counterfeit / ".vigil-client-project.json"
    descriptor = json.loads(descriptor_path.read_text())
    if forgery == "nested-key":
        descriptor["engagement_key"] = "acme/source/counterfeit"
    else:
        descriptor["engagements_root"] = str(nested.parent)
    _rewrite_managed(descriptor_path, descriptor)
    marker = tmp_path / "executed"
    executable = tmp_path / "target-controlled-node"
    executable.write_text(f"#!/bin/sh\nprintf executed > '{marker}'\n")
    executable.chmod(0o755)
    fake["engagement_key"] = descriptor["engagement_key"]
    fake["tools"]["node"] = str(executable)
    context_path = snapshot / ".vigil-client-context.json"
    _rewrite_managed(context_path, fake)
    selection = {"schema_version": 1, "binding_path": str(context_path),
                 "binding_sha256": hashlib.sha256(context_path.read_bytes()).hexdigest()}
    (counterfeit / ".vigil-current-context.json").write_text(json.dumps(selection))
    result = _zcode(counterfeit, "counterfeit", script=project / "plugin/hooks/dispatch.mjs")
    expected = "Project identity mismatch" if forgery == "nested-key" else "user-approved dispatcher installation"
    assert expected in result.stderr
    assert not marker.exists()
