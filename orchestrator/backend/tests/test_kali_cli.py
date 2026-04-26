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
                "--target", "10.0.0.1",
                "--ports", "top-100",
                "--service-detection",
                "--technique", "RECON",
                "--intent", "phase-1 baseline",
                "--probe-kind", "fingerprint",
                "--phase", "recon",
                "--timeout", "600",
            ],
            ["nmap", "-sV", "--top-ports", "100", "10.0.0.1"],
        ),
        (
            "nuclei",
            [
                "-l", "hosts.txt",
                "-t", "http/cves/",
                "--technique", "RECON",
                "--intent", "reactive sweep",
                "--probe-kind", "fingerprint",
                "--phase", "recon",
                "--timeout", "1800",
            ],
            ["nuclei", "-l", "hosts.txt", "-t", "http/cves/"],
        ),
        (
            "httpx",
            [
                "-u", "https://x.example.com",
                "-tech-detect",
                "-tls-grab",
                "--technique", "RECON",
                "--intent", "fingerprint stack",
                "--probe-kind", "fingerprint",
                "--phase", "recon",
                "--timeout", "300",
            ],
            ["httpx", "-u", "https://x.example.com", "-tech-detect", "-tls-grab"],
        ),
        (
            "sqlmap",
            [
                "-u", "https://x.example.com/?id=1",
                "--batch",
                "--sql-technique", "BEUSTQ",
                "--technique", "SQLI",
                "--intent", "verify SQLi",
                "--probe-kind", "payload",
                "--phase", "consume-test",
                "--timeout", "1800",
            ],
            ["sqlmap", "-u", "https://x.example.com/?id=1", "--batch", "--technique=BEUSTQ"],
        ),
    ],
)
def test_verb_translates_argv_into_underlying_command(monkeypatch, verb, argv, expected_substrings):
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
                "-u", "https://x.example.com",
                "-tech-detect",
                "--technique", "DISCOVERY",
                "--intent", "tech detect with custom headers",
                "--probe-kind", "fingerprint",
                "--phase", "recon",
                "--timeout", "60",
                "--extra-args", "-H 'X-Forwarded-For: 127.0.0.1' -mc 200",
            ],
            ["-H", "X-Forwarded-For: 127.0.0.1", "-mc", "200"],
        ),
        (
            "ffuf",
            [
                "-u", "https://x/FUZZ",
                "-w", "/lists/common.txt",
                "--technique", "FUZZ",
                "--intent", "fuzz with extra header",
                "--probe-kind", "payload",
                "--phase", "consume-test",
                "--timeout", "1800",
                "--extra-args", "-H 'X-Real-IP: 127.0.0.1' -t 50",
            ],
            ["-H", "X-Real-IP: 127.0.0.1", "-t", "50"],
        ),
        (
            "sqlmap",
            [
                "-u", "https://x/?id=1",
                "--batch",
                "--technique", "SQLI",
                "--intent", "sqli with os-shell",
                "--probe-kind", "exploit",
                "--phase", "exploit",
                "--timeout", "3600",
                "--destructive",
                "--extra-args", "--os-shell --tamper=space2comment",
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
        (["--engagement-dir", "/tmp/x", "fetch", "surfaces"],
         ["--engagement-dir", "/tmp/x", "fetch", "surfaces"]),
        # hoist after kali verb
        (["kali", "subfinder", "-d", "fema.gov", "--engagement-dir", "/tmp/x", "--technique", "RECON"],
         ["--engagement-dir", "/tmp/x", "kali", "subfinder", "-d", "fema.gov", "--technique", "RECON"]),
        # hoist `--flag=value` form
        (["kali", "subfinder", "--engagement-dir=/tmp/x", "-d", "fema.gov"],
         ["--engagement-dir=/tmp/x", "kali", "subfinder", "-d", "fema.gov"]),
        # hoist actor-kind too
        (["log", "operator", "msg", "--actor-kind", "agent"],
         ["--actor-kind", "agent", "log", "operator", "msg"]),
        # do NOT hoist anything after `--` (would corrupt kali exec user argv)
        (["kali", "exec", "--", "echo", "--engagement-dir", "foo"],
         ["kali", "exec", "--", "echo", "--engagement-dir", "foo"]),
        # hoist legitimately before --, leave inner alone
        (["kali", "exec", "--engagement-dir", "/tmp/x", "--", "echo", "--engagement-dir", "inner"],
         ["--engagement-dir", "/tmp/x", "kali", "exec", "--", "echo", "--engagement-dir", "inner"]),
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
        cli.main([
            "kali", "exec",
            "--technique", "RECON",
            "--intent", "extra args probe",
            "--probe-kind", "baseline",
            "--phase", "recon",
            "--timeout", "60",
            "--extra-args", "-foo",
            "--",
            "curl", "https://x",
        ])
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

    cli.main([
        "kali", "exec",
        "--technique", "RECON",
        "--intent", "raw curl probe",
        "--probe-kind", "baseline",
        "--phase", "recon",
        "--timeout", "60",
        "--",
        "curl",
        "-sS",
        "https://example.com/health",
    ])
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
    (eng_dir / "auth.json").write_text(json.dumps({"kind": "cookies", "state": "present"}))
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

    def patch(self, endpoint, payload):
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
    assert payload["working_dir"]
    assert payload["scope_version"]
    assert payload["auth_context"] == "cookies"

    # Finalize PATCH followed.
    assert len(fake_client.patches) == 1
    patch_endpoint, patch_payload = fake_client.patches[0]
    assert patch_endpoint == "command-runs/7"
    assert patch_payload["status"] == "completed"
    assert patch_payload["return_code"] == 0
    assert patch_payload["timed_out"] is False


def test_kali_exec_timeout_kills_process_group_and_marks_timed_out(monkeypatch, fake_engagement):
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
    # Shape: docker exec <container> sh -c '<wrapper>' sh <user-cmd...>
    assert argv[:3] == ["docker", "exec", "security-research"]
    assert argv[3:5] == ["sh", "-c"]
    wrapper = argv[5]
    assert wrapper.startswith("echo $$ > /tmp/aith-pid-"), wrapper
    assert wrapper.endswith('exec "$@"')
    # ``sh`` placeholder makes ``$@`` skip the script-name positional.
    assert argv[6] == "sh"
    assert argv[7:] == ["nmap", "-sV", "10.0.0.1"]


def test_b1_docker_exec_wrapper_with_strace_keeps_pid_capture(monkeypatch, fake_engagement):
    """B1 + L18: when ``--strace`` is set, the wrapper still records the
    container-side PID before exec-ing strace. The strace artifact path and
    the pid file must share the same ``run_uuid`` so audit ↔ pid file ↔
    strace artifact key on a single identifier."""
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
        ["curl", "-sS", "https://example.com/"],
        technique="RECON",
        intent="b1 wrapper shape with strace",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        strace=True,
        tool_name="curl",
    )
    wrapper = captured["argv"][5]
    assert "echo $$ > /tmp/aith-pid-" in wrapper
    assert "strace -f -e trace=network,write,unlink" in wrapper
    assert 'exec strace ' in wrapper
    assert wrapper.endswith('"$@"')
    # Same UUID body in both file paths so the operator can correlate them.
    import re

    pid_match = re.search(r"/tmp/aith-pid-([0-9a-f]+)\.pid", wrapper)
    strace_match = re.search(r"/tmp/aith-strace-([0-9a-f]+)\.log", wrapper)
    assert pid_match is not None and strace_match is not None
    assert pid_match.group(1) == strace_match.group(1)


def test_b1_timeout_cascade_kills_in_container_pid_then_host_pgid(monkeypatch, fake_engagement):
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


def test_b1_timeout_without_pid_file_falls_back_to_host_kill(monkeypatch, fake_engagement, capsys):
    """B1 edge: when the wrapper hadn't written the pid file yet (race) or
    the container is gone (read fails), the helper must log a warning and
    still issue the host-side process-group kill cascade rather than crash."""
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
    assert docker_kills == []  # no in-container kill possible
    assert signal.SIGTERM in host_signals  # but host-side cascade still fired


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
            aith, "assess", "kali", "exec",
            "--technique", "RECON",
            "--intent", "B1 orphan-cleanup acceptance test",
            "--probe-kind", "fingerprint",
            "--phase", "recon",
            "--timeout", "2",
            "--",
            "nmap", "-p", "1-65535", "127.0.0.1",
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


def test_kali_exec_dedup_warns_and_returns_early_without_force(monkeypatch, fake_engagement, capsys):
    kali = _setup_fake_config(monkeypatch, fake_engagement)

    class _DedupClient(_FakeClient):
        def post(self, endpoint, payload):
            self.posts.append((endpoint, payload))
            return {"id": 9, "superseded_by_id": 8}

    fake_client = _DedupClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    popen_called = []
    monkeypatch.setattr(
        kali.subprocess,
        "Popen",
        lambda *a, **k: popen_called.append(True) or _FakePopen(returncode=0),
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
        tool_name="nmap",
    )
    assert result.status == "superseded"
    assert "dedup hit" in capsys.readouterr().err
    assert popen_called == [], "subprocess must not run when dedup blocked"


def test_kali_exec_dedup_force_bypasses_check(monkeypatch, fake_engagement):
    kali = _setup_fake_config(monkeypatch, fake_engagement)

    class _DedupClient(_FakeClient):
        def post(self, endpoint, payload):
            self.posts.append((endpoint, payload))
            return {"id": 11, "superseded_by_id": 10 if not payload.get("force") else None}

    fake_client = _DedupClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(kali.subprocess, "Popen", lambda *a, **k: _FakePopen(returncode=0))

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


def test_kali_exec_rejects_unknown_technique(monkeypatch, fake_engagement):
    kali = _setup_fake_config(monkeypatch, fake_engagement)
    monkeypatch.setattr(kali, "AssessmentClient", _FakeClient)
    with pytest.raises(Exception) as exc:
        kali.kali_exec(
            ["nmap", "10.0.0.1"],
            technique="MADE-UP-NOT-IN-ENUM",
            intent="probe",
            probe_kind="fingerprint",
            phase="recon",
            timeout=60,
            agent_name="recon-specialist",
            engagement_dir=fake_engagement,
            engagement_key=fake_engagement.name,
        )
    assert "TECHNIQUE_ENUM" in str(exc.value) or "technique" in str(exc.value).lower()


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


def test_kali_exec_audit_post_failure_writes_marker_and_continues(monkeypatch, fake_engagement, capsys):
    kali = _setup_fake_config(monkeypatch, fake_engagement)

    class _BrokenClient(_FakeClient):
        def post(self, endpoint, payload):
            from assess.lib.client import AssessError
            raise AssessError("backend down")

    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: _BrokenClient("u", "k"))
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(kali.subprocess, "Popen", lambda *a, **k: _FakePopen(returncode=0))

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
            return {"id": 14, "status": "queued"}

        def patch(self, endpoint, payload):
            self.patches.append((endpoint, payload))
            return {
                "id": 14,
                "status": payload.get("status"),
                "dtach_socket_path": payload.get("dtach_socket_path"),
                "stdout_path": payload.get("stdout_path"),
            }

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
    # PATCH /jobs/14 transitioned to running.
    assert fake_client.patches and fake_client.patches[0][0] == "jobs/14"
    assert fake_client.patches[0][1]["status"] == "running"
    # docker exec -d dtach ... was invoked.
    assert any("dtach" in arg for argv in seen_argv for arg in argv)


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

        def patch(self, endpoint, payload):
            self.patches.append((endpoint, payload))
            return {"id": 22, "status": payload["status"]}

    fake_client = _StopClient("http://127.0.0.1:18000", fake_engagement.name)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake_client)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda name: True)
    monkeypatch.setattr(
        kali_jobs.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    record = kali_jobs.job_stop(22, container_name="security-research")
    assert record["status"] == "killed"
    assert fake_client.patches[0] == ("jobs/22", {"status": "killed"})


# ──────────────────────────────────────────────────────────────────────────
# Contract command + smoke tests
# ──────────────────────────────────────────────────────────────────────────


def test_contract_kali_root_lists_verbs():
    contracts = _import("assess.lib.contracts")
    rendered = contracts.render_contract("kali")
    assert "nmap-scan" in rendered
    assert "nuclei" in rendered
    assert "--phase" in rendered


def test_contract_kali_per_verb_renders_examples():
    contracts = _import("assess.lib.contracts")
    rendered = contracts.render_contract("kali nmap-scan")
    assert "nmap-scan" in rendered
    assert "Examples" in rendered
    assert "--technique" in rendered


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
