"""End-to-end code finding -> owed runtime proof -> audited Kali proof -> confirmed.

Drives the real ``vigil`` CLI, the real orchestrator backend, ``vigil assess`` and
a real Kali runtime container against the Acme fixture library in
``fixtures/acme_reports`` (a supported ``read_report(name)`` API with a CWE-22
path traversal).

Opt-in (``-m integration``). Prerequisites: a responsive Docker daemon, a
``vigil:latest`` runtime image that is current for this checkout (``vigil runtime
build``; the test skips instead of rebuilding the shared tag), ``uv`` with the
CLI and backend dependencies already cached, and built frontend/report assets or
npm to build them. ``UV_OFFLINE=1`` is enforced so nothing is downloaded.
``vigil assess`` resolves its script dependencies through the workspace's own
``cache/uv``, which a fresh workspace lacks: point ``VIGIL_E2E_UV_CACHE_SEED`` at
a populated one (for example ``<workspace>/cache/uv`` of an existing install) to
seed it; without a seed the first ``vigil assess`` call fails offline.

Everything the test writes is isolated: a private workspace, config and
application cache under one work directory (``VIGIL_E2E_WORKDIR`` keeps it for
inspection; default is a pytest temp dir), a backend on a free localhost port,
and a uniquely named runtime container that the teardown removes. No other
container, workspace or backend is touched, and no traffic leaves localhost.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "acme_reports"
CANARY = "ACME-E2E-CANARY-7f3a"
BASELINE = "Acme Corp Q3 summary"

AUTHOR = "HUNT-E2E-1"
VERIFIER = "VERIFY-E2E-1"
PROVER = "PROOF-E2E-1"

NEXT_TEST = {
    "hypothesis": (
        "acme_reports.read_report('../private/canary.txt') returns private/canary.txt "
        "from outside the report store."
    ),
    "confirm_if": f"The call prints the {CANARY} line from private/canary.txt.",
    "falsify_if": "The call raises or returns only report-store content, never the canary line.",
    "route_hint": "local",
    "prerequisites": "Python 3 in the Kali runtime and a copy of the sealed source.",
}

FINDING = {
    "title": "Path traversal in acme_reports.read_report",
    "severity": "medium",
    "defect_family": "path-traversal",
    "root_cause_key": "read-report-unconstrained-join",
    "canonical_location": "file:acme_reports.py:16",
    "summary": (
        "`read_report(name)` joins the caller-supplied report name onto `REPORT_ROOT` "
        "without containment, so `../private/canary.txt` reads a file outside the report store."
    ),
    "details": {
        "cwe_id": "CWE-22",
        "function": "read_report",
        "entry_point": "acme_reports.read_report(name)",
        "sink": "(REPORT_ROOT / name).read_text() at acme_reports.py:16",
        "taint_path": "read_report(name) -> REPORT_ROOT / name -> Path.read_text()",
        "guards_evaluated": "No resolve()/is_relative_to() containment and no rejection of '..' segments.",
        "evidence": (
            "`return (REPORT_ROOT / name).read_text(encoding=\"utf-8\")` at acme_reports.py:16 "
            "uses the caller-supplied name verbatim."
        ),
        "impact": (
            "A caller that forwards an untrusted report name can read any file the process "
            "can read, such as `private/canary.txt`."
        ),
        "remediation": "Resolve the joined path and reject it unless it is relative to REPORT_ROOT.",
    },
}

PROOF_CONTEXT = {
    "authorized_phase": "code-verify",
    "target": "acme-reports sealed source; local supported-API reproduction only",
    "hunt_scope": "read_report path traversal",
    "mindset_lens": "falsify the candidate claim before confirming it",
    "depth_expectation": "one decisive local reproduction through audited Kali",
    "oob": "not applicable",
    "auth_context": "not applicable",
    "credential_id": "none",
    "prior_state": "Parked pending_runtime_proof by the verifier; proof-work get carries next_test.",
    "coverage": "not applicable",
    "cleanup": "remove the /tmp copy of the sealed source after the run",
    "human_reach_decision": "not applicable",
    "role_specific_additions": "Record proof-run start, a command receipt and finish before finding verify.",
}

_SCRUBBED_ENV_PREFIXES = ("VIGIL_", "ENGAGEMENT_", "KALI_MCP_", "ORCHESTRATOR_")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _docker_names() -> set[str]:
    result = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=30, check=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


class Vigil:
    """Run the checkout's CLI the way Vigil's own session launcher does."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.root = workdir / "root"
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.container = f"vigil-e2e-{uuid.uuid4().hex[:10]}"
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(_SCRUBBED_ENV_PREFIXES)
        }
        self.env.update(
            VIGIL_CONFIG=str(workdir / "vigil-config.json"),
            VIGIL_INSTALL_DIR=str(self.root),
            VIGIL_APPLICATION_CACHE=str(workdir / "app-cache"),
            ORCHESTRATOR_BASE_URL=self.base_url,
            VIGIL_RUNTIME_CONTAINER=self.container,
            PYTHONPATH=str(REPO_ROOT / "src"),
            PYTHONDONTWRITEBYTECODE="1",
            UV_OFFLINE="1",
        )
        self.log = workdir / "commands.log"
        self.engagement: Path | None = None

    def _python(self, code: str) -> list[str]:
        return [
            "uv", "run", "--no-project", "--python", ">=3.11",
            "--with", "questionary>=2.1.1,<3", "--quiet", "python", "-c", code,
        ]

    def run(self, *args: str, cwd: Path | None = None, timeout: float = 300,
            expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
        argv = self._python("from vigil_cli.main import main; main()") + list(args)
        workdir = cwd or self.engagement or self.workdir
        result = subprocess.run(
            argv, cwd=workdir, env=self.env, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        with self.log.open("a", encoding="utf-8") as log:
            log.write(f"$ vigil {' '.join(args)}\n[rc={result.returncode}]\n")
            log.write(result.stdout[-4000:] + "\n--- stderr ---\n" + result.stderr[-4000:] + "\n\n")
        if expect_ok:
            assert result.returncode == 0, (
                f"vigil {' '.join(args)} failed rc={result.returncode}\n"
                f"stdout:\n{result.stdout[-3000:]}\nstderr:\n{result.stderr[-3000:]}"
            )
        return result

    def json(self, *args: str, **kwargs) -> object:
        return json.loads(self.run(*args, **kwargs).stdout)

    def assess(self, *args: str, **kwargs) -> subprocess.CompletedProcess[str]:
        return self.run("assess", *args, **kwargs)

    def assess_json(self, *args: str, **kwargs) -> object:
        return json.loads(self.assess(*args, **kwargs).stdout)

    def backend(self, action: str) -> None:
        code = (
            "import sys; from pathlib import Path; from vigil_cli import orchestrator as o; "
            f"root = Path({str(self.root)!r}); "
            f"o.start_orchestrator(o.OrchestratorOptions(install_root=root, port={self.port})) "
            f"if sys.argv[1] == 'start' else o.stop_orchestrator(root, port={self.port})"
        )
        result = subprocess.run(
            self._python(code) + [action], cwd=self.workdir, env=self.env,
            capture_output=True, text=True, timeout=900, check=False,
        )
        assert result.returncode == 0, f"backend {action} failed:\n{result.stdout}\n{result.stderr}"

    def api(self, method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
        assert self.engagement is not None
        url = f"{self.base_url}/engagements/{self.engagement.name}/assessment/{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            url, data=data, method=method, headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"null")

    def write(self, name: str, value: object) -> Path:
        path = self.workdir / "inputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2), encoding="utf-8")
        return path


@pytest.fixture(scope="module")
def vigil(tmp_path_factory: pytest.TempPathFactory):
    for tool in ("docker", "uv"):
        if shutil.which(tool) is None:
            pytest.skip(f"requires {tool} on PATH")
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=30, check=True)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pytest.skip("requires a responsive Docker daemon")
    from vigil_cli.runtime import runtime_image_build_state

    image_state = runtime_image_build_state(REPO_ROOT)
    if image_state != "current":
        pytest.skip(f"vigil:latest is {image_state} for this checkout; run `vigil runtime build` first")

    configured = os.environ.get("VIGIL_E2E_WORKDIR")
    if configured:
        workdir = Path(configured) / f"run-{uuid.uuid4().hex[:8]}"
        workdir.mkdir(parents=True)
    else:
        workdir = tmp_path_factory.mktemp("vigil-e2e")
    workdir = workdir.resolve()
    harness = Vigil(workdir)
    containers_before = _docker_names()
    assert harness.container not in containers_before
    try:
        yield harness
    finally:
        try:
            harness.backend("stop")
        finally:
            if harness.container in _docker_names():
                subprocess.run(["docker", "rm", "-f", harness.container],
                               capture_output=True, timeout=120, check=False)
            remaining = _docker_names()
            assert harness.container not in remaining
            assert containers_before <= remaining, (
                f"pre-existing containers disappeared: {sorted(containers_before - remaining)}"
            )


def _finding(vigil: Vigil, slug: str) -> dict:
    status, finding = vigil.api("GET", f"findings/{slug}")
    assert status == 200, finding
    assert isinstance(finding, dict)
    return finding


def _history_length(vigil: Vigil, slug: str) -> int:
    history = vigil.assess_json("finding", "history", slug)
    assert isinstance(history, list)
    return len(history)


def _dispatch_ids(vigil: Vigil) -> set[str]:
    status, dispatches = vigil.api("GET", "dispatches")
    assert status == 200, dispatches
    items = dispatches if isinstance(dispatches, list) else dispatches.get("items", [])
    return {item["agent_id"] for item in items}


def _start_dispatch(vigil: Vigil, agent_id: str, role: str, task: str, *extra: str) -> None:
    vigil.assess(
        "agent", "start", "--agent-id", agent_id, "--role", role, "--task", task,
        "--model", "claude-opus-5", "--reasoning", "high", "--dispatch-mode", "deep-manual",
        "--skills", "code-vulnerability-analysis", "--no-target-traffic", *extra,
    )


def test_code_finding_runtime_proof_end_to_end(vigil: Vigil) -> None:
    # 1. Isolated install, backend and code engagement over a copy of the fixture
    #    that sits outside any VCS worktree.
    source = vigil.workdir / "source" / "acme-reports"
    shutil.copytree(FIXTURE, source, ignore=shutil.ignore_patterns("__pycache__"))
    vigil.run("--root", str(vigil.root), "install")
    seed = os.environ.get("VIGIL_E2E_UV_CACHE_SEED")
    if seed:
        shutil.copytree(seed, vigil.root / "cache" / "uv", symlinks=True, dirs_exist_ok=True)
    workspace = json.loads((vigil.root / "workspace.json").read_text(encoding="utf-8"))
    assert Path(workspace["application"]["root"]).resolve() == REPO_ROOT
    vigil.backend("start")

    created = vigil.json(
        "engagement", "create", "--type", "code", "--name", "acme-e2e",
        "--source-dir", str(source), "--no-prompt", "--json",
    )
    assert isinstance(created, dict)
    vigil.engagement = Path(created["path"])
    assert vigil.engagement.parent == vigil.root / "engagements"
    assert created["scope"]["tracks"] == {"code": {"phase": "ingest"}}

    # Source confirmation: the CLI reports the registered original and its
    # inventory; this test is the human who confirms it before first ingest.
    mode = vigil.json("engagement", "mode", "--json")
    assert isinstance(mode, dict)
    assert mode["mode"] == "code"
    assert Path(mode["source"]["path"]) == source
    assert mode["source"]["state"] == "present"
    assert {"acme_reports.py", "private", "reports"} <= set(mode["source"]["entries"])

    ingest = vigil.assess("code-ingest", str(source), "--name", "acme-reports", "--language", "python")
    repo_id = re.search(r"^Repository: acme-reports \(id: (\d+)\)$", ingest.stdout, re.M)
    sealed = re.search(r"^Sealed source: (.+)$", ingest.stdout, re.M)
    assert repo_id and sealed, ingest.stdout
    sealed_source = Path(sealed.group(1))
    assert (sealed_source / "acme_reports.py").read_bytes() == (FIXTURE / "acme_reports.py").read_bytes()
    assert (sealed_source / "private" / "canary.txt").is_file()
    vigil.assess("code-index", "build", "--repo-id", repo_id.group(1), str(sealed_source))
    sync = vigil.assess("code-index", "sync")
    assert "3 files updated" in sync.stderr

    # 2. Finder dispatch records the code finding.
    _start_dispatch(vigil, AUTHOR, "code-vuln-hunter", "Hunt path traversal in read_report")
    record = vigil.assess(
        "finding", "record", "code-vuln-hunter", str(vigil.write("finding.json", FINDING)),
        "--agent-id", AUTHOR, "--evidence-type", "code-inferred", "--allow-unindexed-evidence",
    )
    slug = record.stdout.strip().splitlines()[-1]
    finding = _finding(vigil, slug)
    assert finding["verification_status"] == "unreviewed"
    assert finding["provenance"]["agent_id"] == AUTHOR
    assert finding["code_snapshot_status"] == "current"

    # 3. A separate verifier parks it; first prove a park without a plan writes nothing.
    _start_dispatch(vigil, VERIFIER, "code-vuln-verifier", "Verify source evidence", "--finding-slugs", slug)
    before = (finding["row_version"], _history_length(vigil, slug))
    refused = vigil.assess(
        "finding", "verify", slug, "--status", "pending_runtime_proof",
        "--reason", "Source evidence accepted; runtime proof owed", "--agent-id", VERIFIER,
        expect_ok=False,
    )
    assert refused.returncode != 0
    assert "--next-test-file" in refused.stderr
    status, body = vigil.api("POST", f"findings/{slug}/verify", {
        "verification_status": "pending_runtime_proof",
        "reason_text": "Source evidence accepted; runtime proof owed",
        "provenance": {"agent_id": VERIFIER},
    })
    assert status == 400 and "next_test" in json.dumps(body)
    unpark = vigil.assess(
        "finding", "record", "code-vuln-hunter",
        str(vigil.write("finding-variant.json", FINDING | {"root_cause_key": "read-report-variant"})),
        "--agent-id", AUTHOR, "--pending-runtime-proof", "owed", expect_ok=False,
    )
    assert unpark.returncode != 0
    status, findings = vigil.api("GET", "findings")
    assert status == 200 and [item["slug"] for item in findings] == [slug]
    after_refusals = _finding(vigil, slug)
    assert (after_refusals["row_version"], _history_length(vigil, slug)) == before
    assert after_refusals["verification_status"] == "unreviewed"

    vigil.assess(
        "finding", "verify", slug, "--status", "pending_runtime_proof",
        "--reason", "Source evidence accepted; runtime proof owed", "--agent-id", VERIFIER,
        "--next-test-file", str(vigil.write("next-test.json", NEXT_TEST)),
    )
    parked = _finding(vigil, slug)
    assert parked["verification_status"] == "pending_runtime_proof"
    assert parked["next_test"] == NEXT_TEST

    queue = vigil.assess_json("proof-work", "list")
    assert isinstance(queue, dict)
    assert queue["items"] == []
    assert queue["queue_state_counts"] == {"unprepared": 1}
    [owed] = queue["owed"]
    assert owed["finding_slug"] == slug
    assert owed["queue_state"] == "unprepared"
    assert owed["next_test"] == NEXT_TEST
    assert owed["work_ids"] == []

    # 4. Prepare the local code route, refuse ineligible claimants, then claim.
    work = vigil.assess_json(
        "proof-work", "prepare", slug, "--route", "code", "--objective", f"Challenge: {NEXT_TEST['hypothesis']}",
    )
    assert isinstance(work, dict)
    work_id = work["id"]
    assert (work["status"], work["queue_state"], work["route"]) == ("prepared", "ready", "code")
    assert work["authorized_phase"] == "code-verify"
    assert work["approval_required"] is False
    assert work["target_hosts"] == []
    assert work["next_test"] == NEXT_TEST

    context = vigil.write("proof-context.json", PROOF_CONTEXT)
    claim_args = ("--prompt-context-json", f"@{context}", "--no-target-traffic")
    by_author = vigil.assess(
        "proof-work", "claim", str(work_id), "--agent-id", AUTHOR,
        "--agent-role", "code-vuln-verifier", *claim_args, expect_ok=False,
    )
    assert by_author.returncode != 0
    assert "Finding author cannot own its independent proof work" in by_author.stderr
    wrong_role = vigil.assess(
        "proof-work", "claim", str(work_id), "--agent-id", "PROOF-E2E-HUNTER",
        "--agent-role", "code-vuln-hunter", *claim_args, expect_ok=False,
    )
    assert wrong_role.returncode != 0
    dispatch_ids = _dispatch_ids(vigil)
    assert {AUTHOR, VERIFIER} <= dispatch_ids
    assert "PROOF-E2E-HUNTER" not in dispatch_ids
    still_ready = vigil.assess_json("proof-work", "get", str(work_id))
    assert isinstance(still_ready, dict)
    assert (still_ready["queue_state"], still_ready["owner_dispatch_id"]) == ("ready", None)

    claim = vigil.assess_json(
        "proof-work", "claim", str(work_id), "--agent-id", PROVER,
        "--agent-role", "code-vuln-verifier", *claim_args,
    )
    assert isinstance(claim, dict)
    assert claim["launch_required"] is True
    assert (claim["status"], claim["queue_state"]) == ("claimed", "in_progress")
    assert claim["owner_agent_id"] == PROVER
    prover_dispatch_id = claim["owner_dispatch_id"]
    prompt = claim["prompt_packet"]["rendered_prompt"]
    for expected in (
        "proof_route: code",
        f"proof_work_id: {work_id}",
        f"finding_slug: {slug}",
        "target_hosts: none — local execution only",
        f"--agent-name {PROVER}",
        f"vigil assess proof-work get {work_id}",
        f"agent_id: {PROVER}",
        "agent_role: code-vuln-verifier",
        "assessment_mode: code",
        "authorized_phase: code-verify",
        f"snapshot_path: {sealed_source}",
        "rate_limit_budget: not applicable — no target traffic",
        *(f"  {field}: {value}" for field, value in NEXT_TEST.items()),
    ):
        assert expected in prompt, expected
    assert prompt.count("proof_route:") == 1
    # The prompt carries the current next_test; proof-work get carries the same plan.
    pointed = vigil.assess_json("proof-work", "get", str(work_id))
    assert isinstance(pointed, dict)
    assert pointed["next_test"] == NEXT_TEST
    stored_packet = vigil.assess_json("fetch", f"dispatches/{PROVER}/prompt-packet")
    assert isinstance(stored_packet, dict)
    assert stored_packet["rendered_prompt"] == prompt
    assert stored_packet["sha256"] == claim["prompt_packet"]["sha256"]

    replay = vigil.assess_json(
        "proof-work", "claim", str(work_id), "--agent-id", PROVER,
        "--agent-role", "code-vuln-verifier", *claim_args,
    )
    assert isinstance(replay, dict)
    assert replay["launch_required"] is False
    assert "prompt_packet" not in replay

    # 5. Audited proof inside the runtime, attributed to the claiming dispatch.
    author_run = vigil.assess(
        "proof-run", "start", "proof-by-author", "--kind", "code", "--agent-id", AUTHOR,
        "--for-finding", slug, expect_ok=False,
    )
    assert author_run.returncode != 0
    assert "cannot be its own verifier" in author_run.stderr

    run = vigil.assess_json(
        "proof-run", "start", f"proof-{slug.lower()}-{uuid.uuid4().hex[:6]}", "--kind", "code",
        "--agent-id", PROVER, "--for-finding", slug,
    )
    assert isinstance(run, dict)
    run_id = run["id"]
    assert (run["status"], run["run_purpose"]) == ("running", "proof")
    assert run["producer_dispatch_id"] == prover_dispatch_id

    container_source = f"/engagements/{vigil.engagement.name}/{sealed_source.relative_to(vigil.engagement)}"
    script = (
        f"rm -rf /tmp/acme-proof && cp -r {container_source} /tmp/acme-proof && cd /tmp/acme-proof && "
        "python3 -B -c 'import acme_reports as a; "
        "print(\"baseline:\", a.read_report(\"q3-summary.txt\").strip()); "
        "print(\"traversal:\", a.read_report(\"../private/canary.txt\").strip())'; "
        "status=$?; rm -rf /tmp/acme-proof; exit $status"
    )
    executed = vigil.assess_json(
        "kali", "exec", "--technique", "PATH-TRAVERSAL",
        "--intent", "reproduce read_report traversal on a copy of the sealed source",
        "--probe-kind", "exploit", "--phase", "code-verify", "--timeout", "120",
        "--agent-name", PROVER, "--", "sh", "-c", script, timeout=900,
    )
    assert isinstance(executed, dict)
    assert (executed["status"], executed["return_code"]) == ("completed", 0)
    assert f"baseline: {BASELINE}" in executed["stdout_preview"]
    assert f"traversal: {CANARY}" in executed["stdout_preview"]
    command_run_id = executed["run_id"]
    command_run = vigil.assess_json("command-run", "get", str(command_run_id))
    assert isinstance(command_run, dict)
    command_run = command_run.get("command_run", command_run)
    assert command_run["agent_name"] == PROVER
    assert command_run["phase"] == "code-verify"

    receipt = vigil.assess_json(
        "proof-receipt", "create", "--run-id", str(run_id), "--kind", "command",
        "--command-run-id", str(command_run_id),
        "--expected-result", NEXT_TEST["confirm_if"],
        "--observed-result", f"stdout: traversal: {CANARY}: this file lives outside the report store.",
        "--evidence-health", "healthy",
    )
    assert isinstance(receipt, dict)
    receipt_id = receipt["id"]
    assert receipt["evidence_health"] == "healthy"
    assert receipt["producer_dispatch_id"] == prover_dispatch_id
    linked = vigil.assess_json(
        "proof-work", "update", str(work_id), "--agent-id", PROVER, "--status", "claimed",
        "--run-id", str(run_id),
    )
    assert isinstance(linked, dict)
    assert linked["run_ids"] == [run_id]

    confirm_check = vigil.write("confirm-check.json", {
        "method": "Ran read_report('../private/canary.txt') on a copy of the sealed source through audited Kali exec.",
        "attempted_falsification": "Checked whether read_report contains the joined path or raises for names escaping reports/.",
        "expected_result": NEXT_TEST["confirm_if"],
        "observed_result": f"stdout: traversal: {CANARY}: this file lives outside the report store.",
        "completed": True,
        "proof_receipt_ids": [receipt_id],
    })
    confirm_args = (
        "finding", "verify", slug, "--status", "confirmed",
        "--reason", "Reproduced the read_report traversal locally", "--agent-id", PROVER,
        "--proof-receipt-id", str(receipt_id), "--confirm-check-file", str(confirm_check),
    )
    early = vigil.assess(*confirm_args, expect_ok=False)
    assert early.returncode != 0
    assert "not completed" in early.stderr + early.stdout
    assert _finding(vigil, slug)["verification_status"] == "pending_runtime_proof"

    finished = vigil.assess_json("proof-run", "finish", str(run_id), "--status", "completed")
    assert isinstance(finished, dict)
    assert finished["status"] == "completed"
    vigil.assess(*confirm_args)
    done = vigil.assess_json(
        "proof-work", "update", str(work_id), "--agent-id", PROVER, "--status", "finished",
    )
    assert isinstance(done, dict)
    assert (done["status"], done["queue_state"], done["owed"]) == ("finished", "done", False)
    for agent_id in (PROVER, VERIFIER, AUTHOR):
        vigil.assess("agent", "done", agent_id, "--status", "completed", "--finding-slugs", slug)

    # 6. Final durable state.
    confirmed = _finding(vigil, slug)
    assert confirmed["verification_status"] == "confirmed"
    assert confirmed["next_test"] is None
    assert confirmed["provenance"]["agent_id"] == AUTHOR
    attestation = confirmed["provenance"]["code_snapshot_attestation"]
    assert (attestation["agent_id"], attestation["dispatch_id"]) == (PROVER, prover_dispatch_id)
    assert confirmed["code_snapshot_attestation_status"] == "attested"
    assert [r["id"] for r in confirmed["proof_receipts"]] == [receipt_id]
    assert confirmed["proof_receipts"][0]["producer_dispatch_id"] == prover_dispatch_id
    assert confirmed["proof_receipts"][0]["command_run_id"] == command_run_id
    assert confirmed["verification_audit"]["proof_receipt_ids"] == [receipt_id]

    final_queue = vigil.assess_json("proof-work", "list")
    assert isinstance(final_queue, dict)
    assert final_queue["owed"] == []
    assert final_queue["queue_state_counts"] == {"done": 1}
    [final_work] = final_queue["items"]
    assert (final_work["id"], final_work["queue_state"], final_work["owner_agent_id"]) == (
        work_id, "done", PROVER,
    )
    assert final_work["run_ids"] == [run_id]

    # 7. An exploit-developer dispatch must declare its assessment mode.
    no_mode = vigil.assess(
        "agent", "start", "--agent-id", "XDEV-E2E-1", "--role", "exploit-developer",
        "--task", "Exploit without a declared mode", "--model", "claude-opus-5",
        "--reasoning", "high", "--dispatch-mode", "deep-manual", "--no-target-traffic",
        expect_ok=False,
    )
    assert no_mode.returncode != 0
    assert "--assessment-mode" in no_mode.stderr
    dispatch_ids = _dispatch_ids(vigil)
    assert {AUTHOR, VERIFIER, PROVER} <= dispatch_ids
    assert "XDEV-E2E-1" not in dispatch_ids
