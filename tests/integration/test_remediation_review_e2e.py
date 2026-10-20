"""Real CLI, HTTP backend and browser remediation review in disposable workspaces.

Run explicitly with ``-m integration`` after building the frontend. Requires
Node 22+ and Chrome/Chromium; no Docker, native agent or external account is used.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from test_report_browser_runtime import _chrome

pytestmark = pytest.mark.integration
REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("vcs", ["git", "jj"])
def test_regression_review_rewrite_and_backend_drift(tmp_path, vcs):
    chrome = _chrome()
    if not chrome or not shutil.which("node") or not (REPO / "orchestrator/frontend/dist/index.html").is_file():
        pytest.skip("requires Chrome/Chromium, Node 22+, and built frontend assets")
    if vcs == "jj" and not shutil.which("jj"):
        pytest.skip("requires jj for the JJ workspace scenario")

    application = tmp_path / "vigil-application"
    for relative in ("src/vigil_cli", "agent/scripts/assess", "agent/schemas", "agent/.claude/commands",
                     "orchestrator/backend/app", "orchestrator/frontend/dist"):
        shutil.copytree(REPO / relative, application / relative,
                        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    for relative in ("pyproject.toml", "orchestrator/backend/pyproject.toml", "orchestrator/backend/uv.lock"):
        shutil.copyfile(REPO / relative, application / relative)
    workspace = tmp_path / "workspace"
    engagement = workspace / "engagements/acme-remediation"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"engagement_type": "remediation", "hostname": "Acme"}))
    repository = tmp_path / "acme-app"
    repository.mkdir()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("VIGIL_", "ENGAGEMENT_", "KALI_MCP_", "ORCHESTRATOR_", "REDTEAM_"))}
    environment.update(
        VIGIL_INSTALL_DIR=str(workspace), VIGIL_APPLICATION_DIR=str(application),
        VIGIL_DATA_DIR=str(workspace / "state"), VIGIL_ENGAGEMENTS_DIR=str(workspace / "engagements"),
        VIGIL_CONFIG=str(tmp_path / "config.json"), VIGIL_BACKUP_DISABLED="1",
        VIGIL_APPLICATION_CACHE=str(tmp_path / "application-cache"),
        PYTHONDONTWRITEBYTECODE="1", ORCHESTRATOR_BASE_URL=base_url,
        PYTHONPATH=os.pathsep.join(str(application / relative) for relative in
                                  ("src", "agent/scripts", "orchestrator/backend")),
    )

    def run(*argv, cwd=repository):
        result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout.strip()

    def cli(*arguments):
        return json.loads(run(sys.executable, "-c", "from vigil_cli.main import main; main()",
                              "--root", str(workspace), "remediation", "-k", engagement.name, *arguments))

    def api(method, path, payload=None):
        request = urllib.request.Request(base_url + path, method=method,
                                         data=json.dumps(payload).encode() if payload is not None else None,
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    run(sys.executable, "-c", "from pathlib import Path; from vigil_cli.workspace import initialize_workspace; "
        f"initialize_workspace(Path({str(workspace)!r}), Path({str(application)!r}))")
    run("git", "init", "-b", "main")
    run("git", "config", "user.name", "Acme Test")
    run("git", "config", "user.email", "test@example.com")
    (repository / ".gitignore").write_text("worktrees/\n__pycache__/\n")
    (repository / "accounts.py").write_text("def allowed(actor, owner):\n    return True\n")
    command = shlex.join([sys.executable, "-B", "test_accounts.py"])
    (repository / "PROJECT.md").write_text(
        '+++\nrepository = "."\nbase_branch = "main"\nworkspace_directory = "worktrees"\n'
        '[remediation]\ncheck_commands = [{name = "account-controls", command = ' + json.dumps(command) + '}]\n+++\n')
    (engagement / "PROJECT.md").symlink_to(repository / "PROJECT.md")
    run("git", "add", ".")
    run("git", "commit", "-qm", "Acme baseline")
    if vcs == "jj":
        run("jj", "git", "init", "--colocate")
        run("jj", "config", "set", "--repo", "user.name", "Acme Test")
        run("jj", "config", "set", "--repo", "user.email", "test@example.com")

    processes = []
    backend_log = (tmp_path / "backend.log").open("wb")

    def start_backend():
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
                                   cwd=application / "orchestrator/backend", env=environment,
                                   stdout=backend_log, stderr=subprocess.STDOUT)
        processes.append(process)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert process.poll() is None, (tmp_path / "backend.log").read_text()
            try:
                if api("GET", "/readyz")["status"] == "ready":
                    return process
            except OSError:
                pass
            time.sleep(0.1)
        pytest.fail("isolated backend did not become ready")

    browser_runs = 0

    def browser(case_id, mode):
        nonlocal browser_runs
        browser_runs += 1
        profile = tmp_path / f"chrome-{mode}-{browser_runs}"
        process = subprocess.Popen([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-background-networking",
                                    "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)
        deadline = time.monotonic() + 15
        receipt = profile / "DevToolsActivePort"
        endpoint_lines = []
        while time.monotonic() < deadline:
            assert process.poll() is None
            endpoint_lines = receipt.read_text().splitlines() if receipt.exists() else []
            if len(endpoint_lines) >= 2 and endpoint_lines[0].isdigit():
                break
            time.sleep(0.1)
        assert len(endpoint_lines) >= 2, "Chrome did not publish its isolated debugging endpoint"
        debug_url = "http://127.0.0.1:" + endpoint_lines[0]
        request = urllib.request.Request(debug_url + "/json/new?about:blank", method="PUT")
        with urllib.request.urlopen(request, timeout=10) as response:
            target = json.load(response)
        try:
            run("node", str(Path(__file__).with_name("remediation_browser.mjs")), target["webSocketDebuggerUrl"],
                f"{base_url}/#/remediation/{engagement.name}?case={case_id}", mode,
                str(api("GET", f"/engagements/{engagement.name}/remediation/cases/{case_id}")["evidence_total"]))
        finally:
            process.terminate()
            process.wait(timeout=10)

    def terminal_join(case_id, source):
        # Exercise both real terminal pickers and the complete binding/attachment
        # path, with a local native-client fixture instead of a model session.
        binary_dir = tmp_path / "native-client-bin"
        binary_dir.mkdir()
        for executable in ("git", "jj", "python3"):
            target = sys.executable if executable == "python3" else shutil.which(executable)
            if target:
                (binary_dir / executable).symlink_to(target)
        native_id = "11111111-1111-4111-8111-111111111111"
        job_id = "acme-remediation-job"
        binding = {"case_id": case_id, "engagement_key": engagement.name, "workspace": str(source),
                   "session_cwd": str(repository), "session_id": native_id, "job_id": job_id, "settings": {}}
        (engagement / "remediation/cases" / case_id / "session.json").write_text(json.dumps(binding))
        inventory = [{"id": job_id, "sessionId": native_id, "cwd": str(repository),
                      "kind": "background", "state": "blocked"}]
        receipt = tmp_path / "attached.json"
        inventory_file = tmp_path / "native-inventory.json"
        inventory_file.write_text(json.dumps(inventory))
        launch_receipt = tmp_path / "native-launch.json"
        native = binary_dir / "claude"
        native.write_text(
            '#!/usr/bin/env python3\nimport json, sys, time\nfrom pathlib import Path\n'
            f'inventory = Path({str(inventory_file)!r})\n'
            f'receipt = Path({str(receipt)!r})\n'
            'args = sys.argv[1:]\n'
            'if args == ["--version"]: print("2.1.296 (Claude Code)")\n'
            'elif args == ["--help"]: time.sleep(0.15); print("--bg\\n  agents [options]\\n  attach <id>")\n'
            'elif args == ["agents", "--json", "--all"]: time.sleep(0.2); print(inventory.read_text())\n'
            'elif args[0] == "stop":\n'
            '    rows = json.loads(inventory.read_text())\n'
            '    row = next(row for row in rows if row["id"] == args[1])\n'
            '    row["state"] = "stopped"\n'
            '    inventory.write_text(json.dumps(rows))\n'
            'elif "--bg" in args:\n'
            '    rows = json.loads(inventory.read_text())\n'
            '    identity = args[args.index("--session-id") + 1]\n'
            '    rows.append({"id": "acme-fresh-job", "sessionId": identity, '
            f'"cwd": {str(repository)!r}, "name": args[args.index("--name") + 1], '
            '"kind": "background", "state": "blocked"})\n'
            '    inventory.write_text(json.dumps(rows))\n'
            f'    Path({str(launch_receipt)!r}).write_text(json.dumps(args))\n'
            'elif args[0] == "attach":\n'
            '    receipt.write_text(json.dumps(args))\n'
            '    print("ATTACH_READY", flush=True); time.sleep(0.2)\n'
            'else: raise SystemExit("Unexpected native client command: " + repr(args))\n'
        )
        native.chmod(0o700)

        def attach(arguments, answers):
            master, slave = pty.openpty()
            process = subprocess.Popen(
                [sys.executable, "-c", "from vigil_cli.main import main; main()", "--root", str(workspace),
                 "remediation", *arguments],
                cwd=repository, env={**environment, "PATH": str(binary_dir), "TERM": "xterm-256color",
                                     "COLUMNS": "80", "NO_COLOR": "1"},
                stdin=slave, stdout=slave, stderr=slave,
            )
            processes.append(process)
            os.close(slave)
            output = bytearray()
            try:
                if answers:
                    os.write(master, answers)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    readable, _, _ = select.select([master], [], [], 0.1)
                    if readable:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output.extend(chunk)
                    elif process.poll() is not None:
                        break
                assert process.wait(timeout=5) == 0, output.decode(errors="replace")
            finally:
                os.close(master)
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
            assert b"Checking Claude" in output and b"Finding the recorded conversation" in output
            assert output.index(b"Opening Claude") < output.index(b"ATTACH_READY")
            assert output.split(b"ATTACH_READY", 1)[1].strip() == b""
            return output

        output = attach(["join"], b"1\n1\n1\n")
        assert json.loads(receipt.read_text()) == ["attach", job_id]
        assert f"#{case_id}" in output.decode()
        before = api("GET", f"/engagements/{engagement.name}/remediation/cases/{case_id}")
        attach(["join"], b"1\n1\n2\ny\n")
        assert json.loads(receipt.read_text()) == ["attach", "acme-fresh-job"]
        updated = json.loads((engagement / "remediation/cases" / case_id / "session.json").read_text())
        assert updated["session_id"] != native_id
        assert updated["replaced_session_id"] == native_id
        launch = json.loads(launch_receipt.read_text())
        assert str(engagement / "remediation/cases" / case_id / "handoff.md") in launch[-1]
        assert str(source) in launch[-1]
        after = api("GET", f"/engagements/{engagement.name}/remediation/cases/{case_id}")
        assert before == after
        attach(["-k", engagement.name, "join", case_id], b"")
        assert json.loads(receipt.read_text()) == ["attach", "acme-fresh-job"]
        assert len(json.loads(inventory_file.read_text())) == 2

    try:
        backend = start_backend()
        earlier = tmp_path / "earlier-report.json"
        earlier.write_text(json.dumps({"original_report": "Acme independent earlier report"}))
        cli("import", "--source", "manual", "--source-key", "ACME-0", "--title", "Acme earlier case",
            "--snapshot-file", str(earlier))
        snapshot = tmp_path / "report.json"
        snapshot.write_text(json.dumps({"original_report": "Acme cross-account write", "suggested_remediation": "Check the owner"}))
        identifier = str(cli("import", "--source", "manual", "--title", "Acme account boundary",
                             "--snapshot-file", str(snapshot))["id"])
        case = cli("worktree", identifier)
        source = Path(case["worktree_path"])
        assert source == repository / "worktrees" / f"case-{identifier}"
        original_snapshot = case["snapshot"]
        listed = cli("list", "--json")
        assert int(identifier) > 1  # Case identity differs from the picker's row number.
        assert listed[0]["case_id"] == int(identifier)
        assert shlex.split(listed[0]["join_command"])[-2:] == ["join", identifier]
        terminal_join(identifier, source)
        binding_path = engagement / "remediation/cases" / identifier / "session.json"
        original_binding = binding_path.read_bytes()
        (source / "accounts.py").write_text("def allowed(actor, owner):\n    return actor == owner\n")
        (source / "test_accounts.py").write_text(
            'from accounts import allowed\nassert not allowed("guest", "owner"), "cross-account write"\n'
            'assert allowed("owner", "owner"), "owner control"\nprint("Acme account controls passed")\n')

        def commit(message):
            if vcs == "jj":
                run("jj", "describe", "-m", message, cwd=source)
            else:
                run("git", "add", ".", cwd=source)
                run("git", "commit", "-qm", message, cwd=source)
        commit("Enforce account ownership with regression")
        cli("sync-revision", identifier)
        brief = tmp_path / "plan.txt"
        brief.write_text("Run account regression and legitimate owner control, then review the outputs.")
        requirements = tmp_path / "requirements.json"
        requirements.write_text(json.dumps([
            {"kind": "red-test", "methods": ["python"], "outcome": "failed_as_expected", "fix_paths": ["accounts.py"]},
            {"kind": "green-test", "methods": ["python"]},
        ]))
        cli("plan", identifier, "--file", str(brief), "--requirements-file", str(requirements),
            "--alternatives-reason", "Local account and legitimate-use controls exercise the boundary")
        cli("baseline", identifier, "--outcome", "code_test_confirmed", "--method", "python", "--proved", "Cross-account write",
            "--owner-decision", "proceed", "--owner-actor", "Acme owner", "--owner-reason", "Local fixture needs no deployment")
        endpoint = f"/engagements/{engagement.name}/remediation/cases/{identifier}"
        for index in range(21):
            artifact = engagement / "remediation/cases" / identifier / f"note-{index}.txt"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text("<script>window.acmeInjected = true</script>\nAcme literal evidence\n")
            api("POST", endpoint + "/evidence", {"kind": "intake-note", "method": "manual", "environment": "not_applicable",
                "observed": "Acme source context", "proved": "Intake only", "artifact_path": str(artifact.relative_to(engagement))})
        current_revision = cli("show", identifier)["worktree_revision"]
        for index, (revision, outcome, method, observation) in enumerate([
            (case["base_revision"], "passed", "python", "Earlier source permits cross-account access"),
            (current_revision, "failed", "python", "Earlier current-source attempt failed"),
            (current_revision, "passed", "unselected", "Unselected verification method passed"),
        ]):
            artifact = engagement / "remediation/cases" / identifier / f"earlier-check-{index}.txt"
            artifact.write_text(observation + "\n")
            api("POST", endpoint + "/evidence", {"kind": "green-test", "method": method, "environment": "local",
                "observed": observation, "proved": "Earlier verification history", "outcome": outcome,
                "command": command, "revision": revision, "executed_revision": revision,
                "executed_directory": str(source), "execution": "executed", "artifact_path": str(artifact.relative_to(engagement))})
        cli("test", identifier, "--method", "python", "--command", command, "--expected-failure", "cross-account write")
        cli("checks", identifier, "--actor", "Acme developer", "--stage", "publication")
        cli("release-plan", identifier, "--production-canary", "not_required", "--rationale", "Isolated Acme fixture",
            "--monitoring", "Account authorization failures")
        cli("transition", identifier, "review", "--actor", "Acme developer", "--reason", "Verification complete")
        ready = cli("show", identifier)
        assert ready["review_evidence_ready"] and ready["evidence_total"] == 28
        assert all(match["evidence_ids"][0] > 20 for match in ready["verification_matches"])
        browser(identifier, "approve")
        approved = cli("show", identifier)
        assert approved["approval_current"]
        lease = cli("environment", "acquire", identifier, "--name", "acme-local", "--actor", "Acme developer")
        identified = cli("identity", identifier, "--provider", "tracker", "--key", "ACME-1")
        assert not identified["approval_current"]
        assert identified["snapshot"] == original_snapshot
        finalized = cli("finalize-branch", identifier, "--branch", "fix/ACME-1")
        assert finalized["worktree_path"] == str(source)
        assert finalized["worktree_revision"] == approved["worktree_revision"]
        assert finalized["worktree_branch"] == "fix/ACME-1"
        assert finalized["review_evidence_ready"] and not finalized["approval_current"]
        assert binding_path.read_bytes() == original_binding
        assert any(item["token"] == lease["token"] and not item["released_at"]
                   for item in finalized["environment_leases"])
        assert cli("finalize-branch", identifier, "--branch", "fix/ACME-1")["worktree_revision"] == approved["worktree_revision"]
        assert cli("list", "--json")[0]["external_key"] == "ACME-1"
        cli("environment", "release", identifier, "--name", "acme-local", "--actor", "Acme developer", "--token", lease["token"])
        cli("transition", identifier, "review", "--actor", "Acme developer", "--reason", "Review finalized external identity")
        browser(identifier, "approve-finalized")
        final_review = cli("show", identifier)
        assert final_review["approval_current"]
        body_file = tmp_path / "prepared-pr.md"
        root_cause = "The account permission check accepted every actor without comparing the owner."
        fix_summary = "Compare actor and owner before allowing the account operation."
        cli("prepare-pr", identifier, "--output", str(body_file), "--root-cause", root_cause,
            "--fix-summary", fix_summary)
        prepared_body = body_file.read_text()
        assert root_cause in prepared_body and fix_summary in prepared_body
        assert "ACME-1" in prepared_body
        assert [line for line in prepared_body.splitlines() if line.startswith("- ")] == [
            "- python [environment: local] (failed as expected): exit 1; source changed: False",
            "- python [environment: local] (passed): exit 0; source changed: False",
        ]
        intended = api("POST", endpoint + "/publication-intent", {
            "review_digest": final_review["approvals"][-1]["review_digest"],
            "revision": final_review["worktree_revision"], "branch": final_review["worktree_branch"],
        })
        assert intended["approval_current"]
        marker = engagement / "remediation/cases" / identifier / "pr/publication-intent.json"
        assert json.loads(marker.read_text())["branch"] == "fix/ACME-1"
        with pytest.raises(urllib.error.HTTPError) as refused:
            api("POST", endpoint + "/finalize-branch", {
                "old_branch": "fix/ACME-1", "new_branch": "fix/another-reference",
                "revision": final_review["worktree_revision"],
            })
        assert refused.value.code == 409

        if vcs == "jj":
            run("jj", "describe", "-m", "Enforce account ownership", cwd=source)
        else:
            run("git", "commit", "--amend", "-qm", "Enforce account ownership", cwd=source)
        rewritten = cli("sync-revision", identifier)
        assert rewritten["worktree_revision"] != ready["worktree_revision"]
        assert rewritten["review_evidence_ready"] and not rewritten["approval_current"]
        assert len(rewritten["evidence_carries"]) == 3
        browser(identifier, "carried")
        (source / "accounts.py").write_text("def allowed(actor, owner):\n    return actor == owner and bool(owner)\n")
        commit("Reject empty account owners")
        assert not cli("sync-revision", identifier)["review_evidence_ready"]

        changed_module = application / "orchestrator/backend/app/services/remediation.py"
        changed_module.write_text(changed_module.read_text() + "\n# Acme E2E input change.\n")
        assert api("GET", "/readyz")["backend_runtime"]["restart_required"]
        warning = subprocess.run([sys.executable, "-c", "from vigil_cli.main import main; main()", "--root", str(workspace),
                                  "remediation", "-k", engagement.name, "list", "--json"], env=environment,
                                 capture_output=True, text=True, timeout=30)
        assert warning.returncode == 0 and json.loads(warning.stdout)
        assert "backend restart required" in warning.stderr and base_url in warning.stderr
        browser(identifier, "drift")
        backend.terminate()
        backend.wait(timeout=10)
        start_backend()
        assert not api("GET", "/readyz")["backend_runtime"]["restart_required"]
        browser(identifier, "fresh")
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        backend_log.close()
