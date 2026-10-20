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
    for relative in ("src/vigil_cli", "agent/scripts/assess", "agent/schemas",
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

    def browser(case_id, mode):
        profile = tmp_path / f"chrome-{mode}"
        process = subprocess.Popen([chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-background-networking",
                                    "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)
        deadline = time.monotonic() + 15
        receipt = profile / "DevToolsActivePort"
        while not receipt.exists() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(0.1)
        assert receipt.exists(), "Chrome did not publish its isolated debugging endpoint"
        debug_url = "http://127.0.0.1:" + receipt.read_text().splitlines()[0]
        request = urllib.request.Request(debug_url + "/json/new?about:blank", method="PUT")
        with urllib.request.urlopen(request, timeout=10) as response:
            target = json.load(response)
        try:
            run("node", str(Path(__file__).with_name("remediation_browser.mjs")), target["webSocketDebuggerUrl"],
                f"{base_url}/#/remediation/{engagement.name}?case={case_id}", mode)
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
        native = binary_dir / "claude"
        native.write_text(
            '#!/usr/bin/env python3\nimport json, sys\nfrom pathlib import Path\n'
            'args = sys.argv[1:]\n'
            'if args == ["--version"]: print("2.1.296 (Claude Code)")\n'
            'elif args == ["--help"]: print("--bg\\n  agents [options]\\n  attach <id>")\n'
            f'elif args == ["agents", "--json", "--all"]: print({json.dumps(inventory)!r})\n'
            f'elif args == ["attach", {job_id!r}]: Path({str(receipt)!r}).write_text(json.dumps(args))\n'
            'else: raise SystemExit("Unexpected native client command: " + repr(args))\n'
        )
        native.chmod(0o700)
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [sys.executable, "-c", "from vigil_cli.main import main; main()", "--root", str(workspace), "remediation", "join"],
            cwd=repository, env={**environment, "PATH": str(binary_dir)}, stdin=slave, stdout=slave, stderr=slave,
        )
        processes.append(process)
        os.close(slave)
        output = bytearray()
        try:
            os.write(master, b"1\n1\n")
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
        assert json.loads(receipt.read_text()) == ["attach", job_id]
        assert f"case_id={case_id}" in output.decode()

    try:
        backend = start_backend()
        earlier = tmp_path / "earlier-report.json"
        earlier.write_text(json.dumps({"original_report": "Acme independent earlier report"}))
        cli("import", "--source", "manual", "--source-key", "ACME-0", "--title", "Acme earlier case",
            "--snapshot-file", str(earlier))
        snapshot = tmp_path / "report.json"
        snapshot.write_text(json.dumps({"original_report": "Acme cross-account write", "suggested_remediation": "Check the owner"}))
        identifier = str(cli("import", "--source", "manual", "--source-key", "ACME-1", "--title", "Acme account boundary",
                             "--snapshot-file", str(snapshot))["id"])
        case = cli("worktree", identifier, "--branch", "fix/ACME-1")
        source = Path(case["worktree_path"])
        listed = cli("list", "--json")
        assert int(identifier) > 1  # Case identity differs from the picker's row number.
        assert listed[0]["case_id"] == int(identifier)
        assert shlex.split(listed[0]["join_command"])[-2:] == ["join", identifier]
        terminal_join(identifier, source)
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
        cli("test", identifier, "--method", "python", "--command", command, "--expected-failure", "cross-account write")
        cli("checks", identifier, "--actor", "Acme developer")
        cli("release-plan", identifier, "--production-canary", "not_required", "--rationale", "Isolated Acme fixture",
            "--monitoring", "Account authorization failures")
        cli("transition", identifier, "review", "--actor", "Acme developer", "--reason", "Verification complete")
        ready = cli("show", identifier)
        assert ready["review_evidence_ready"] and ready["evidence_total"] == 25
        assert all(match["evidence_ids"][0] > 20 for match in ready["verification_matches"])
        browser(identifier, "approve")
        assert cli("show", identifier)["approval_current"]

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
