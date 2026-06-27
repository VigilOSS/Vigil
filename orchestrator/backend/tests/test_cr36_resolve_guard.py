"""CR-36 — host-resolve ``--resolve`` IP-pin + the http=000 false-negative guard.

Covers the two halves of the kali-path fix in isolation (no docker, no backend):

1. ``kali_resolve`` — host resolution + ``--resolve host:port:ip`` injection:
   eligibility (Docker-Desktop-only, env opt-out), idempotency (operator pin /
   double-add), tool allowlist (sqlmap excluded), IP-literal/list-mode skips,
   multi-A first-IP pin, port/scheme defaults.

2. ``kali_output.detect_transport_error`` — the http=000 / connection-failed /
   DNS-failure signature that MUST NOT be read as a target verdict, plus the
   ``KaliResult`` flag.

3. ``kali.kali_exec`` end-to-end (mocked subprocess + AssessmentClient) — the
   pre-flight pin is injected on Docker Desktop, the guard auto-retries ONCE with
   a host-resolved pin, the backend status stays in the enum while the
   ``KaliResult.status`` surfaces ``transport_error``, and native Linux is a
   transparent no-op (no over-flagging).

This is a NEW, distinctly-named test file (does not touch the existing
``test_kali_cli.py``); it reuses that module's sys.path + reload conventions.
"""

from __future__ import annotations

import importlib
import json
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
    """Force-reload assess modules so monkeypatching/caches reset per test."""
    for mod in list(sys.modules):
        if mod == "assess" or mod.startswith("assess."):
            sys.modules.pop(mod, None)
    yield


def _import(name: str) -> ModuleType:
    return importlib.import_module(name)


def _runtimes():
    rr = _import("assess.lib.runtime_route")
    dd = rr.RuntimeInfo(platform="darwin", is_docker_desktop=True, recommended="host")
    linux = rr.RuntimeInfo(platform="linux", is_docker_desktop=False, recommended="container")
    return rr, dd, linux


# ──────────────────────────────────────────────────────────────────────────
# 1. kali_resolve — pin injection
# ──────────────────────────────────────────────────────────────────────────


def test_pin_injects_resolve_for_curl_on_docker_desktop():
    kr = _import("assess.lib.kali_resolve")
    _rr, dd, _lx = _runtimes()
    cmd = ["curl", "-sS", "https://api.example.com/v1/users"]
    ip = kr.apply_resolve_pin(cmd, "curl", runtime=dd, ips=["203.0.113.7", "203.0.113.8"])
    assert ip == "203.0.113.7"  # multi-A pins the FIRST address (documented)
    assert cmd[-2:] == ["--resolve", "api.example.com:443:203.0.113.7"]


def test_pin_is_idempotent_on_repeat_call():
    kr = _import("assess.lib.kali_resolve")
    _rr, dd, _lx = _runtimes()
    cmd = ["httpx", "-u", "https://api.example.com/"]
    assert kr.apply_resolve_pin(cmd, "httpx", runtime=dd, ips=["203.0.113.7"]) == "203.0.113.7"
    # A second pass must NOT add a second --resolve for the same host:port.
    assert kr.apply_resolve_pin(cmd, "httpx", runtime=dd, ips=["203.0.113.9"]) is None
    assert cmd.count("--resolve") == 1


def test_pin_respects_operator_supplied_resolve():
    kr = _import("assess.lib.kali_resolve")
    _rr, dd, _lx = _runtimes()
    cmd = ["curl", "--resolve", "api.example.com:443:9.9.9.9", "https://api.example.com/"]
    assert kr.apply_resolve_pin(cmd, "curl", runtime=dd, ips=["203.0.113.7"]) is None
    assert cmd.count("--resolve") == 1  # operator's pin untouched


def test_pin_respects_operator_wildcard_port_resolve():
    kr = _import("assess.lib.kali_resolve")
    _rr, dd, _lx = _runtimes()
    cmd = ["curl", "--resolve", "api.example.com:*:9.9.9.9", "https://api.example.com/"]
    assert kr.apply_resolve_pin(cmd, "curl", runtime=dd, ips=["203.0.113.7"]) is None


def test_pin_excludes_sqlmap():
    kr = _import("assess.lib.kali_resolve")
    _rr, dd, _lx = _runtimes()
    # sqlmap is in _IDENTITY_INJECTABLE_TOOLS but does NOT accept --resolve.
    cmd = ["sqlmap", "-u", "https://api.example.com/?id=1"]
    assert kr.apply_resolve_pin(cmd, "sqlmap", runtime=dd, ips=["203.0.113.7"]) is None
    assert "--resolve" not in cmd


def test_pin_is_noop_on_native_linux():
    kr = _import("assess.lib.kali_resolve")
    _rr, _dd, lx = _runtimes()
    cmd = ["curl", "https://api.example.com/"]
    assert kr.apply_resolve_pin(cmd, "curl", runtime=lx, ips=["203.0.113.7"]) is None
    assert "--resolve" not in cmd


def test_pin_disabled_by_env(monkeypatch):
    kr = _import("assess.lib.kali_resolve")
    _rr, dd, _lx = _runtimes()
    monkeypatch.setenv("VIGIL_NO_RESOLVE_PIN", "1")
    cmd = ["curl", "https://api.example.com/"]
    assert kr.apply_resolve_pin(cmd, "curl", runtime=dd, ips=["203.0.113.7"]) is None
    assert "--resolve" not in cmd


def test_pin_skips_ip_literal_target():
    kr = _import("assess.lib.kali_resolve")
    _rr, dd, _lx = _runtimes()
    cmd = ["curl", "https://203.0.113.50/health"]
    assert kr.target_host_port("curl", cmd) == ("", 0)
    assert kr.apply_resolve_pin(cmd, "curl", runtime=dd, ips=["203.0.113.7"]) is None


def test_pin_skips_when_resolution_empty():
    kr = _import("assess.lib.kali_resolve")
    _rr, dd, _lx = _runtimes()
    cmd = ["curl", "https://api.example.com/"]
    # Empty resolution list (host did not resolve) → no pin, no crash.
    assert kr.apply_resolve_pin(cmd, "curl", runtime=dd, ips=[]) is None
    assert "--resolve" not in cmd


def test_target_host_port_http_scheme_defaults_80():
    kr = _import("assess.lib.kali_resolve")
    assert kr.target_host_port("curl", ["curl", "http://plain.example.com/x"]) == (
        "plain.example.com",
        80,
    )


def test_target_host_port_https_default_443_and_explicit_port():
    kr = _import("assess.lib.kali_resolve")
    assert kr.target_host_port("httpx", ["httpx", "-u", "https://api.example.com/"]) == (
        "api.example.com",
        443,
    )
    assert kr.target_host_port("httpx", ["httpx", "-u", "https://api.example.com:8443/"]) == (
        "api.example.com",
        8443,
    )


def test_resolve_host_ips_ip_literal_is_empty():
    kr = _import("assess.lib.kali_resolve")
    assert kr.resolve_host_ips("203.0.113.50") == []
    assert kr.resolve_host_ips("") == []


def test_pin_tools_excludes_sqlmap_and_ffuf_includes_http_set():
    kr = _import("assess.lib.kali_resolve")
    # ffuf is excluded (I-10): the image ffuf (v2.x) has no --resolve flag — its
    # Go flag parser rejects it and aborts with exit 2, so a pin would turn a
    # recoverable resolver flap into a hard failure. sqlmap likewise has no
    # host-pin flag. Both stay OUT of the pin set; the http=000 guard handles them.
    assert kr.RESOLVE_PIN_TOOLS == frozenset({"curl", "httpx", "nuclei", "katana"})
    assert "ffuf" not in kr.RESOLVE_PIN_TOOLS
    assert "sqlmap" not in kr.RESOLVE_PIN_TOOLS


# ──────────────────────────────────────────────────────────────────────────
# 2. kali_output.detect_transport_error — http=000 signature
# ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "rc,stderr",
    [
        (6, "curl: (6) Could not resolve host: api.example.com"),
        (7, "curl: (7) Failed to connect to api.example.com port 443: Connection refused"),
        (28, "curl: (28) Connection timed out after 10000 ms"),
        (35, "curl: (35) OpenSSL SSL_connect: error"),
        (1, "lookup api.example.com: no such host"),  # Go/httpx style
        (1, "dial tcp: i/o timeout"),
    ],
)
def test_detect_transport_error_positive_signatures(rc, stderr):
    ko = _import("assess.lib.kali_output")
    is_te, detail = ko.detect_transport_error(
        tool_name="curl", return_code=rc, stdout_preview="", stderr_preview=stderr, timed_out=False
    )
    assert is_te is True
    assert "http=000" in detail


def test_detect_transport_error_real_answer_with_body_is_not_flagged():
    ko = _import("assess.lib.kali_output")
    # A 4xx/5xx wall that returned a BODY is a real verdict (LIVE), never a TE.
    is_te, _ = ko.detect_transport_error(
        tool_name="curl",
        return_code=22,  # curl --fail on 404
        stdout_preview='{"error":"not found"}',
        stderr_preview="curl: (22) The requested URL returned error: 404",
        timed_out=False,
    )
    assert is_te is False


def test_detect_transport_error_curl_w_writeout_000_is_flagged():
    """REGRESSION (the gap that masked the original defect): the canonical probe
    `curl -o /dev/null -w "%{http_code} %{time_connect} %{remote_ip}"` writes a
    `000 0.000000 ` write-out line to stdout EVEN on a transport failure. A naive
    "non-empty stdout = real answer" shortcut would let this through as a clean
    verdict — exactly the false negative CR-36 exists to prevent. It MUST flag."""
    ko = _import("assess.lib.kali_output")
    is_te, detail = ko.detect_transport_error(
        tool_name="curl",
        return_code=7,  # couldn't connect
        stdout_preview="000 0.000000 \n",
        stderr_preview="curl: (7) Failed to connect to api.example.com port 443: Connection refused",
        timed_out=False,
    )
    assert is_te is True
    assert "http=000" in detail


def test_detect_transport_error_curl_w_writeout_real_status_not_flagged():
    """A write-out line carrying a real (>0) HTTP status is a genuine verdict,
    never a transport error — the parser must read the status, not the byte count."""
    ko = _import("assess.lib.kali_output")
    is_te, _ = ko.detect_transport_error(
        tool_name="curl",
        return_code=7,
        stdout_preview="403 0.183000 93.184.216.34\n",
        stderr_preview="curl: (7) transient noise on stderr",
        timed_out=False,
    )
    assert is_te is False


def test_detect_transport_error_clean_exit_zero_is_not_flagged():
    ko = _import("assess.lib.kali_output")
    is_te, _ = ko.detect_transport_error(
        tool_name="httpx",
        return_code=0,
        stdout_preview="https://api.example.com [200]",
        stderr_preview="",
        timed_out=False,
    )
    assert is_te is False


def test_detect_transport_error_non_http_tool_never_flagged():
    ko = _import("assess.lib.kali_output")
    is_te, _ = ko.detect_transport_error(
        tool_name="nmap",
        return_code=1,
        stdout_preview="",
        stderr_preview="connection refused",
        timed_out=False,
    )
    assert is_te is False


def test_detect_transport_error_timeout_is_not_flagged():
    ko = _import("assess.lib.kali_output")
    # A wall-clock timeout is its own terminal status (partial-but-real), kept
    # distinct from the transport-failure signature.
    is_te, _ = ko.detect_transport_error(
        tool_name="httpx",
        return_code=None,
        stdout_preview="",
        stderr_preview="",
        timed_out=True,
    )
    assert is_te is False


def test_detect_transport_error_nonzero_exit_no_signature_not_flagged():
    ko = _import("assess.lib.kali_output")
    # Non-transport error exit (e.g. nuclei bad-template) with no telltale
    # stderr and no body → not a transport error (UNKNOWN, not flagged).
    is_te, _ = ko.detect_transport_error(
        tool_name="nuclei",
        return_code=2,
        stdout_preview="",
        stderr_preview="could not load templates: invalid syntax",
        timed_out=False,
    )
    assert is_te is False


def test_kali_result_transport_error_defaults_false():
    ko = _import("assess.lib.kali_output")
    r = ko.KaliResult(
        run_id=1,
        status="completed",
        return_code=0,
        stdout_path="o",
        stderr_path="e",
        duration_ms=1,
        peak_rss_bytes=None,
        stdout_preview="",
        stderr_preview="",
        timed_out=False,
        partial_results=False,
    )
    assert r.transport_error is False
    assert r.transport_error_detail == ""


# ──────────────────────────────────────────────────────────────────────────
# 3. kali_exec end-to-end (mocked subprocess + AssessmentClient)
# ──────────────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_engagement(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "2026-06-13-test"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(json.dumps({"hostname": "example.com"}))
    # Credentials are centralized in the backend store; no auth.json file. The
    # runtime creds_client fails closed (auth_context "none") with no backend.
    monkeypatch.setenv("ENGAGEMENT_DIR", str(eng_dir))
    monkeypatch.setenv("AGENT_NAME", "vulnerability-analyst")
    monkeypatch.delenv("VIGIL_NO_RESOLVE_PIN", raising=False)
    return eng_dir


class _FakeClient:
    def __init__(self, base_url, engagement_key):
        self.posts: list = []
        self.patches: list = []

    def post(self, endpoint, payload):
        self.posts.append((endpoint, payload))
        return {"id": 7, "superseded_by_id": None}

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        return {"id": 7, "status": payload.get("status")}

    def close(self):
        return None


class _Proc:
    def __init__(self, returncode):
        self.pid = 4242
        self._rc = returncode

    def wait(self, timeout=None):
        return self._rc


def _setup(monkeypatch, eng_dir, *, runtime):
    """Wire kali_exec for a container-free run pinned to a chosen runtime."""
    kali = _import("assess.lib.kali")
    kr = _import("assess.lib.kali_resolve")
    rr = _import("assess.lib.runtime_route")

    monkeypatch.setattr(
        kali,
        "load_config",
        lambda _flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(eng_dir),
            engagement_key=eng_dir.name,
            agent_root=str(eng_dir.parent.parent),
        ),
    )
    client = _FakeClient("http://127.0.0.1:18000", eng_dir.name)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: client)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(kali, "_read_container_pid", lambda *a, **k: None)
    monkeypatch.setattr(kali, "_kill_in_container", lambda *a, **k: None)
    monkeypatch.setattr(kali, "_cleanup_container_pid_file", lambda *a, **k: None)
    # Force the runtime (no docker probe) — kali_resolve reads it through the
    # runtime_route module reference, so patch detect_runtime there + reset the
    # per-process cache. Deterministic host resolution avoids real DNS.
    rr.reset_runtime_cache()
    monkeypatch.setattr(rr, "detect_runtime", lambda *a, **k: runtime)
    monkeypatch.setattr(kr, "resolve_host_ips", lambda host: ["203.0.113.7"] if host else [])
    return kali, kr, client


def test_kali_exec_pins_resolve_on_docker_desktop(monkeypatch, fake_engagement):
    _rr, dd, _lx = _runtimes()
    kali, _kr, client = _setup(monkeypatch, fake_engagement, runtime=dd)

    seen = {}

    def fake_popen(argv, **kwargs):
        seen["argv"] = list(argv)
        kwargs["stdout"].write(b"https://api.example.com [200]\n")
        return _Proc(0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    result = kali.kali_exec(
        ["httpx", "-u", "https://api.example.com/"],
        technique="RECON",
        intent="liveness probe",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="httpx",
    )
    # --resolve was injected into the argv that actually ran in-container.
    joined = " ".join(seen["argv"])
    assert "--resolve api.example.com:443:203.0.113.7" in joined
    assert result.status == "completed"
    assert result.transport_error is False


def test_kali_exec_no_pin_on_native_linux(monkeypatch, fake_engagement):
    _rr, _dd, lx = _runtimes()
    kali, _kr, _client = _setup(monkeypatch, fake_engagement, runtime=lx)

    seen = {}

    def fake_popen(argv, **kwargs):
        seen["argv"] = list(argv)
        kwargs["stdout"].write(b"ok\n")
        return _Proc(0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    kali.kali_exec(
        ["httpx", "-u", "https://api.example.com/"],
        technique="RECON",
        intent="liveness probe",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="httpx",
    )
    assert "--resolve" not in seen["argv"]


def test_kali_exec_http000_retries_then_succeeds(monkeypatch, fake_engagement):
    """First attempt is http=000 (no pin available pre-flight); the guard
    retries ONCE with a host-resolved pin and the retry returns a real answer."""
    _rr, dd, _lx = _runtimes()
    kali, kr, client = _setup(monkeypatch, fake_engagement, runtime=dd)

    # Pre-flight resolution FAILS (empty), so no pin is injected and the first
    # attempt hits the broken container resolver → http=000. The post-run guard
    # then re-resolves (success) and retries with the pin.
    state = {"calls": 0}

    def flaky_resolve(host):
        state["calls"] += 1
        # 1st call = pre-flight (fails); subsequent = retry (succeeds).
        return [] if state["calls"] == 1 else ["203.0.113.7"]

    monkeypatch.setattr(kr, "resolve_host_ips", flaky_resolve)

    attempts = {"n": 0}

    def fake_popen(argv, **kwargs):
        attempts["n"] += 1
        if attempts["n"] == 1:
            kwargs["stderr"].write(b"curl: (6) Could not resolve host: api.example.com\n")
            return _Proc(6)
        # Retry attempt carries the pin and gets a real answer.
        assert "--resolve" in argv, "retry must carry the host-resolved pin"
        kwargs["stdout"].write(b'{"status":"ok"}\n')
        return _Proc(0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    result = kali.kali_exec(
        ["curl", "-sS", "https://api.example.com/v1/health"],
        technique="RECON",
        intent="health probe",
        probe_kind="baseline",
        phase="recon",
        timeout=30,
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="curl",
    )
    assert attempts["n"] == 2, "guard must auto-retry exactly once"
    assert result.status == "completed"
    assert result.transport_error is False
    assert result.return_code == 0
    # Backend status PATCH stayed in the enum.
    assert client.patches[-1][1]["status"] == "completed"


def test_kali_exec_http000_persists_flags_transport_error(monkeypatch, fake_engagement, capsys):
    """When http=000 persists after the retry, the run is flagged transport_error
    (KaliResult.status) while the backend PATCH stays 'failed' (enum-safe)."""
    _rr, dd, _lx = _runtimes()
    kali, _kr, client = _setup(monkeypatch, fake_engagement, runtime=dd)

    attempts = {"n": 0}

    def fake_popen(argv, **kwargs):
        attempts["n"] += 1
        # Pre-flight resolution succeeds (default stub) so attempt 1 carries a
        # pin; both attempts still fail → real transport error, not a flap.
        kwargs["stderr"].write(b"curl: (7) Failed to connect to api.example.com port 443: Connection refused\n")
        return _Proc(7)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    result = kali.kali_exec(
        ["curl", "-sS", "https://api.example.com/v1/health"],
        technique="RECON",
        intent="health probe",
        probe_kind="baseline",
        phase="recon",
        timeout=30,
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="curl",
    )
    # Pre-flight already pinned, so the guard does NOT retry (same pin would fail).
    assert attempts["n"] == 1
    assert result.transport_error is True
    assert result.status == "transport_error"
    assert "http=000" in result.transport_error_detail
    # Backend status PATCH stayed inside the enum (failed, NOT transport_error).
    assert client.patches[-1][1]["status"] == "failed"
    # Loud stderr runtime-error line was printed.
    err = capsys.readouterr().err
    assert "RUNTIME ERROR" in err
    assert "NOT a target verdict" in err


def test_kali_exec_http000_native_linux_not_overflagged(monkeypatch, fake_engagement):
    """A clean connection-refused on native Linux is a LEGITIMATE verdict; the
    guard must NOT arm there (no over-flagging, no retry)."""
    _rr, _dd, lx = _runtimes()
    kali, _kr, client = _setup(monkeypatch, fake_engagement, runtime=lx)

    attempts = {"n": 0}

    def fake_popen(argv, **kwargs):
        attempts["n"] += 1
        kwargs["stderr"].write(b"curl: (7) Failed to connect: Connection refused\n")
        return _Proc(7)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    result = kali.kali_exec(
        ["curl", "-sS", "https://api.example.com/"],
        technique="RECON",
        intent="health probe",
        probe_kind="baseline",
        phase="recon",
        timeout=30,
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="curl",
    )
    assert attempts["n"] == 1, "no retry on native Linux"
    assert result.transport_error is False
    assert result.status == "failed"  # legitimate connect-refused verdict


def test_kali_exec_pin_opt_out_env_disables_pin(monkeypatch, fake_engagement):
    _rr, dd, _lx = _runtimes()
    kali, _kr, _client = _setup(monkeypatch, fake_engagement, runtime=dd)
    monkeypatch.setenv("VIGIL_NO_RESOLVE_PIN", "1")

    seen = {}

    def fake_popen(argv, **kwargs):
        seen["argv"] = list(argv)
        kwargs["stdout"].write(b"ok\n")
        return _Proc(0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    kali.kali_exec(
        ["curl", "https://api.example.com/"],
        technique="RECON",
        intent="probe",
        probe_kind="baseline",
        phase="recon",
        timeout=30,
        engagement_dir=fake_engagement,
        engagement_key=fake_engagement.name,
        tool_name="curl",
    )
    assert "--resolve" not in seen["argv"]
