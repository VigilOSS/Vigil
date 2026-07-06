"""Layer-2 fail-closed required-header attribution backstop (ADR 0010).

Layer 1 (``_apply_required_headers``) injects the program attribution header into
the curated set of HTTP-to-target tools. Layer 2 is the dynamic, per-tool-knowledge-
free safety net: AFTER the final argv (and any shell-script text) is assembled, a
command that REACHES an in-scope host WITHOUT the configured marker is REFUSED
rather than sent un-attributed (a federal/managed-program ban-risk). This catches
the cases Layer 1 misses — a ``bash -c "curl <in-scope>"`` whose script could not
be injected, an unknown/future tool, or a tool whose header flag can't carry an
inline value (wafw00f).

The detector is purely lexical (no DNS/HTTP) so it is safe inside the exec gate.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from assess.lib import kali, kali_output, scope


HDR = {"X-Bug-Bounty": "vigiloss"}


def _allow(*hosts: str) -> list[dict[str, str]]:
    return scope.scope_entries({"hosts": list(hosts)})


# --------------------------------------------------------------------------- #
# Detector: required_header_attribution_gap
# --------------------------------------------------------------------------- #

def test_in_scope_curl_without_marker_is_refused() -> None:
    gap = kali_output.required_header_attribution_gap(
        ["curl", "-s", "https://app.example.com/x"], "curl", dict(HDR),
        _allow("app.example.com"),
    )
    assert gap
    assert "app.example.com" in gap
    assert "X-Bug-Bounty: vigiloss" in gap


def test_in_scope_curl_with_marker_passes() -> None:
    gap = kali_output.required_header_attribution_gap(
        ["curl", "-H", "X-Bug-Bounty: vigiloss", "https://app.example.com/x"],
        "curl", dict(HDR), _allow("app.example.com"),
    )
    assert gap == ""


def test_bash_c_curl_in_scope_without_marker_is_refused() -> None:
    # The I-8 catch: the marker literal must be found in the SCRIPT TEXT (an argv
    # element), and the in-scope host token lives inside that same script.
    gap = kali_output.required_header_attribution_gap(
        ["bash", "-c", "curl https://app.example.com/x"], "curl", dict(HDR),
        _allow("app.example.com"),
    )
    assert gap
    assert "app.example.com" in gap


def test_bash_c_curl_in_scope_with_marker_in_script_passes() -> None:
    gap = kali_output.required_header_attribution_gap(
        ["bash", "-c", "curl -H 'X-Bug-Bounty: vigiloss' https://app.example.com/x"],
        "curl", dict(HDR), _allow("app.example.com"),
    )
    assert gap == ""


def test_in_scope_marker_without_space_after_colon_passes() -> None:
    # F2: an operator hand-writing "-H X-Bug-Bounty:vigiloss" (no space after the
    # colon — valid curl) genuinely carries the marker, so the backstop must NOT
    # refuse it. Layer-1 idempotency is name-only (it does not re-canonicalize the
    # operator's spacing), and Layer-2 now matches name:value spacing-tolerantly.
    gap = kali_output.required_header_attribution_gap(
        ["curl", "-H", "X-Bug-Bounty:vigiloss", "https://app.example.com/x"],
        "curl", dict(HDR), _allow("app.example.com"),
    )
    assert gap == ""


def test_wildcard_scope_subdomain_reached_without_marker_is_refused() -> None:
    gap = kali_output.required_header_attribution_gap(
        ["whatweb", "https://deep.api.example.com"], "whatweb", dict(HDR),
        _allow("*.example.com"),
    )
    assert gap


def test_out_of_scope_host_is_not_refused() -> None:
    # A host that is NOT in the allowlist needs no attribution from us.
    gap = kali_output.required_header_attribution_gap(
        ["curl", "https://other.test/x"], "curl", dict(HDR),
        _allow("app.example.com"),
    )
    assert gap == ""


def test_local_command_is_not_refused() -> None:
    gap = kali_output.required_header_attribution_gap(
        ["curl", "http://127.0.0.1:8000/health"], "curl", dict(HDR),
        _allow("app.example.com"),
    )
    assert gap == ""


def test_passive_skip_set_tool_is_not_refused() -> None:
    # gau queries the public archive, not the in-scope host, so it must never be
    # refused for lacking attribution even though the in-scope host is its query
    # subject (and the handle must never leak to web.archive.org).
    gap = kali_output.required_header_attribution_gap(
        ["gau", "app.example.com"], "gau", dict(HDR), _allow("app.example.com"),
    )
    assert gap == ""


def test_no_required_headers_is_never_refused() -> None:
    gap = kali_output.required_header_attribution_gap(
        ["curl", "https://app.example.com"], "curl", {}, _allow("app.example.com"),
    )
    assert gap == ""


def test_empty_allowlist_is_never_refused() -> None:
    gap = kali_output.required_header_attribution_gap(
        ["curl", "https://app.example.com"], "curl", dict(HDR), [],
    )
    assert gap == ""


def test_multi_header_partial_attribution_is_refused_naming_missing() -> None:
    headers = {"X-Bug-Bounty": "vigiloss", "X-HackerOne": "h1user"}
    gap = kali_output.required_header_attribution_gap(
        ["curl", "-H", "X-Bug-Bounty: vigiloss", "https://app.example.com"],
        "curl", dict(headers), _allow("app.example.com"),
    )
    assert gap
    assert "X-HackerOne: h1user" in gap
    assert "X-Bug-Bounty" not in gap.replace("X-Bug-Bounty: vigiloss", "")  # only the missing one named


def test_unknown_future_tool_reaching_in_scope_is_refused() -> None:
    gap = kali_output.required_header_attribution_gap(
        ["futurescan", "https://app.example.com"], "futurescan", dict(HDR),
        _allow("app.example.com"),
    )
    assert gap


# --------------------------------------------------------------------------- #
# JSON-threaded attribution (the ``browser`` verb): the marker rides argv as a
# JSON headers blob ``{"X-Bug-Bounty": "handle"}`` the driver sets over CDP
# (``Network.setExtraHTTPHeaders``), NOT as a ``-H`` flag. The ``name": "value``
# quoting must be recognized as PRESENT — otherwise a render of an in-scope host
# is falsely refused even though it carries the attribution header.
# --------------------------------------------------------------------------- #

def _browser_cmd(url: str, headers_json: str) -> list[str]:
    # Mirrors commands/kali_browser.py's argv layout: python3 -c <driver> url
    # screenshot dom page_timeout settle wait_selector headers_json.
    return [
        "python3", "-c", "<selenium driver body>", url,
        "scans/browser/x.png", "scans/browser/x.html", "30.0", "2.0", "",
        headers_json,
    ]


def test_browser_json_threaded_marker_present_passes() -> None:
    gap = kali_output.required_header_attribution_gap(
        _browser_cmd("https://app.example.com/x", '{"X-Bug-Bounty": "vigiloss"}'),
        "browser", dict(HDR), _allow("app.example.com"),
    )
    assert gap == ""


def test_browser_json_threaded_marker_sorted_keys_present_passes() -> None:
    # json.dumps(..., sort_keys=True) is exactly what the verb emits.
    headers = {"X-Bug-Bounty": "vigiloss", "X-HackerOne": "h1user"}
    blob = json.dumps(headers, sort_keys=True)
    gap = kali_output.required_header_attribution_gap(
        _browser_cmd("https://app.example.com/x", blob),
        "browser", dict(headers), _allow("app.example.com"),
    )
    assert gap == ""


def test_browser_json_threaded_no_space_variant_present_passes() -> None:
    # A compact separator emitter ``{"x-bug-bounty":"vigiloss"}`` (no space after
    # the colon) must also be recognized.
    gap = kali_output.required_header_attribution_gap(
        _browser_cmd("https://app.example.com/x", '{"x-bug-bounty":"vigiloss"}'),
        "browser", dict(HDR), _allow("app.example.com"),
    )
    assert gap == ""


def test_browser_reaching_in_scope_without_marker_is_refused() -> None:
    # Empty headers blob "{}" — the marker is genuinely absent, so a render of an
    # in-scope host must STILL be refused. The JSON-tolerant matcher must not
    # defeat the backstop's fail-closed guarantee.
    gap = kali_output.required_header_attribution_gap(
        _browser_cmd("https://app.example.com/x", "{}"),
        "browser", dict(HDR), _allow("app.example.com"),
    )
    assert gap
    assert "X-Bug-Bounty: vigiloss" in gap


def test_browser_json_threaded_partial_attribution_is_refused_naming_missing() -> None:
    # Only one of two required markers present in the JSON blob → refuse, naming
    # the missing one (parity with the -H multi-header test).
    headers = {"X-Bug-Bounty": "vigiloss", "X-HackerOne": "h1user"}
    gap = kali_output.required_header_attribution_gap(
        _browser_cmd("https://app.example.com/x", '{"X-Bug-Bounty": "vigiloss"}'),
        "browser", dict(headers), _allow("app.example.com"),
    )
    assert gap
    assert "X-HackerOne: h1user" in gap


# --------------------------------------------------------------------------- #
# Wiring: kali_exec REFUSES (no exec) when the backstop trips
# --------------------------------------------------------------------------- #

class _NoPopen:
    def __init__(self, *a, **k):
        raise AssertionError("subprocess.Popen must NOT run for a refused command")


def _fake_config(monkeypatch, eng_dir):
    def fake_load_config(_flag):
        return SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(eng_dir),
            engagement_key=eng_dir.name,
            agent_root=str(eng_dir.parent.parent),
        )

    monkeypatch.setattr(kali, "load_config", fake_load_config)


def test_kali_exec_refuses_unattributed_in_scope_run(tmp_path, monkeypatch, capsys):
    eng_dir = tmp_path / "engagements" / "eng"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        json.dumps({
            "engagement_type": "web",
            "hosts": ["app.example.com"],
            "required_headers": {"X-Bug-Bounty": "vigiloss"},
        })
    )
    _fake_config(monkeypatch, eng_dir)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)
    monkeypatch.setattr(kali.subprocess, "Popen", _NoPopen)
    # A client must never be constructed — refusal happens before the audit POST.
    monkeypatch.setattr(
        kali, "AssessmentClient",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no client on refusal")),
    )

    # whatweb in a shell wrapper: W5 cannot inject (whatweb is not a -H sub-command
    # head) so the marker is genuinely absent and the backstop must fire.
    result = kali.kali_exec(
        ["bash", "-c", "whatweb https://app.example.com"],
        technique="DISCOVERY",
        intent="fingerprint app",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=eng_dir,
        engagement_key=eng_dir.name,
        tool_name="whatweb",
    )

    assert result.status == "refused"
    assert result.return_code is None
    err = capsys.readouterr().err
    assert "refusing to run" in err
    assert "X-Bug-Bounty" in err


def test_kali_exec_runs_when_marker_present(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "eng"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        json.dumps({
            "engagement_type": "web",
            "hosts": ["app.example.com"],
            "required_headers": {"X-Bug-Bounty": "vigiloss"},
        })
    )
    _fake_config(monkeypatch, eng_dir)
    monkeypatch.setattr(kali, "_check_container_running", lambda name: None)

    popen_seen = {}

    class _OkPopen:
        def __init__(self, argv, **kw):
            popen_seen["argv"] = argv
            self.pid = 4321

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(kali.subprocess, "Popen", _OkPopen)

    class _Client:
        def __init__(self, *a, **k):
            pass

        def post(self, ep, payload):
            return {"id": 1, "superseded_by_id": None}

        def patch(self, ep, payload, *, accept_409=False):
            return {"id": 1, "status": payload.get("status")}

        def close(self):
            pass

    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: _Client())
    monkeypatch.setattr(kali, "_read_container_pid", lambda *a, **k: None)
    monkeypatch.setattr(kali, "_kill_in_container", lambda *a, **k: None)
    monkeypatch.setattr(kali, "_cleanup_container_pid_file", lambda *a, **k: None)

    # curl: Layer 1 injects the marker, so the backstop sees it and lets the run
    # proceed to exec.
    result = kali.kali_exec(
        ["curl", "-s", "https://app.example.com/x"],
        technique="DISCOVERY",
        intent="probe app",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=eng_dir,
        engagement_key=eng_dir.name,
        tool_name="curl",
    )

    assert result.status != "refused"
    assert "argv" in popen_seen  # exec actually happened
