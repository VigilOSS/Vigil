"""`vigil auth keepalive` — pure-logic unit tests (network-free).

The verb keeps long-lived (enterprise SSO / reverse-proxy) sessions live by
probing an authed endpoint each cycle. Vigil bakes in NO target-specific cookie
names: the operator MUST declare this engagement's session-anchor cookie name(s)
via `--anchor-cookie` (repeatable), and every helper below keys on THOSE provided
names rather than any built-in set. The two pieces that are testable without a
live target are factored into pure helpers, exercised here:

  * `_resolve_caps`  — freshest full-anchor capture per distinct login, dedup by
    anchor value (newest `updated_at` first), skipping captured logouts
    (`<anchor>=deleted`) and rows lacking any declared anchor cookie.
  * `_parse_probe_blob` / `_classify_probe` — the lenient regex parse of the raw
    `kali exec` output blob (status / userId / `<anchor>=deleted`), and the
    LIVE/DEAD/UNKNOWN decision (deleted-override → material.liveness → unknown).

Plus a guard that the probe argv routes through `vigil assess kali exec` with
`--identity` and NEVER `bash -c`, that keepalive ERRORS clearly when no
`--anchor-cookie` is given, and a foreground-loop integration check that tees
LIVE/DEAD to the log — all with the subprocess/network boundary stubbed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import pytest  # noqa: E402

from vigil_cli import auth  # noqa: E402  (src must be on sys.path first)


# The engagement's operator-declared session-anchor cookie names. These are
# arbitrary here — Vigil assumes NONE — and every helper is keyed on them.
_ANCHORS = ("MRHSession", "IDMSession")


# --------------------------------------------------------------------------- #
# _resolve_caps — freshest-per-anchor dedup, skip deleted / anchor-less
# --------------------------------------------------------------------------- #
def _identities() -> dict:
    return {
        # cap-old and cap-new are the SAME login (same MRHSession/IDMSession
        # values); only the newest updated_at should survive the dedup.
        "cap-old": {
            "updated_at": "2026-07-06T10:00:00Z",
            "cookies": {"MRHSession": "AAA", "IDMSession": "iAAA"},
        },
        "cap-new": {
            "updated_at": "2026-07-06T12:00:00Z",
            "cookies": {"MRHSession": "AAA", "IDMSession": "iAAA"},
        },
        # A DISTINCT login (different anchor values) — kept alongside cap-new.
        "cap-other": {
            "updated_at": "2026-07-06T11:00:00Z",
            "cookies": {"MRHSession": "BBB", "IDMSession": "iBBB"},
        },
        # A captured logout: anchor value literally "deleted" -> skipped.
        "cap-logout": {
            "updated_at": "2026-07-06T13:00:00Z",
            "cookies": {"MRHSession": "deleted", "IDMSession": "iCCC"},
        },
        # No declared-anchor cookie (junk row) -> skipped.
        "cap-junk": {
            "updated_at": "2026-07-06T14:00:00Z",
            "cookies": {"JSESSIONID": "whatever"},
        },
    }


def test_resolve_caps_dedups_freshest_per_anchor_newest_first():
    resolved = auth._resolve_caps(_identities(), 10, anchor_cookies=_ANCHORS)
    # cap-new (12:00) beats its duplicate cap-old (10:00); cap-other (11:00) is a
    # distinct login. logout + junk are dropped. Newest updated_at first.
    assert resolved == ["cap-new", "cap-other"]


def test_resolve_caps_caps_to_n():
    assert auth._resolve_caps(_identities(), 1, anchor_cookies=_ANCHORS) == ["cap-new"]
    assert auth._resolve_caps(_identities(), 0, anchor_cookies=_ANCHORS) == []


def test_resolve_caps_skips_deleted_anchor_value():
    ids = {
        "cap-live": {"updated_at": "2026-07-06T09:00:00Z", "cookies": {"MRHSession": "X"}},
        "cap-dead": {"updated_at": "2026-07-06T10:00:00Z", "cookies": {"MRHSession": "deleted"}},
        # Case/whitespace variants of the logout marker are still skipped.
        "cap-dead2": {"updated_at": "2026-07-06T11:00:00Z", "cookies": {"MRHSession": " Deleted "}},
    }
    assert auth._resolve_caps(ids, 10, anchor_cookies=("MRHSession",)) == ["cap-live"]


@pytest.mark.parametrize(
    "anchor",
    ["SMSESSION", "SESSIONID", "MRHSession", "totally-made-up-anchor"],
)
def test_resolve_caps_keys_on_operator_provided_anchor_name(anchor):
    # No baked-in set: resolution keys PURELY on whatever anchor name the operator
    # declares. The same identities resolve under any provided anchor name.
    ids = {
        "one": {"updated_at": "2026-07-06T10:00:00Z", "cookies": {anchor: "S1"}},
        "one-dup": {"updated_at": "2026-07-06T09:00:00Z", "cookies": {anchor: "S1"}},
        "two": {"updated_at": "2026-07-06T11:00:00Z", "cookies": {anchor: "S2"}},
    }
    assert auth._resolve_caps(ids, 10, anchor_cookies=(anchor,)) == ["two", "one"]


def test_resolve_caps_ignores_cookies_not_named_as_anchors():
    # Proof the old F5/SiteMinder defaults are gone: an MRHSession capture does NOT
    # resolve when the operator named a DIFFERENT anchor — no fallback to a built-in
    # set. Only the cookie the operator declared as the anchor counts.
    ids = {
        "f5": {"updated_at": "2026-07-06T10:00:00Z", "cookies": {"MRHSession": "X"}},
    }
    assert auth._resolve_caps(ids, 10, anchor_cookies=("SESSIONID",)) == []
    assert auth._resolve_caps(ids, 10, anchor_cookies=("MRHSession",)) == ["f5"]


def test_resolve_caps_tolerates_malformed_rows():
    ids = {
        "ok": {"updated_at": "2026-07-06T10:00:00Z", "cookies": {"MRHSession": "V"}},
        "not-a-dict": "garbage",
        "no-cookies": {"updated_at": "2026-07-06T11:00:00Z"},
        "bad-cookies": {"updated_at": "2026-07-06T11:00:00Z", "cookies": "nope"},
    }
    assert auth._resolve_caps(ids, 10, anchor_cookies=("MRHSession",)) == ["ok"]


# --------------------------------------------------------------------------- #
# _parse_probe_blob — regex on the raw blob, NEVER json.loads
# --------------------------------------------------------------------------- #
def test_parse_status_and_status_line_http2_and_http11():
    p1 = auth._parse_probe_blob("HTTP/2 200 OK\r\n...", anchor_cookies=_ANCHORS)
    assert p1["status"] == 200
    p = auth._parse_probe_blob(
        "...\nHTTP/1.1 302 Found\nlocation: /login", anchor_cookies=_ANCHORS
    )
    assert p["status"] == 302
    assert p["status_line"] == "HTTP/1.1 302"


def test_parse_status_unparseable_is_none():
    p = auth._parse_probe_blob(
        "__keepalive_probe_error__ kali exec timed out", anchor_cookies=_ANCHORS
    )
    assert p["status"] is None
    assert p["status_line"] == "?"


def test_parse_user_id_escaped_and_unescaped():
    # As it appears inside the JSON-escaped stdout_preview: quotes backslash-escaped.
    escaped = 'HTTP/2 200\\r\\n\\r\\n{\\"userId\\":\\"u-123\\",\\"role\\":\\"a\\"}'
    assert auth._parse_probe_blob(escaped, anchor_cookies=_ANCHORS)["user_id"] == "u-123"
    # Plain unescaped body.
    assert auth._parse_probe_blob('{"userId":"plain"}', anchor_cookies=_ANCHORS)["user_id"] == "plain"
    # Missing -> sentinel.
    assert auth._parse_probe_blob("HTTP/2 200\nno body here", anchor_cookies=_ANCHORS)["user_id"] == "-"


@pytest.mark.parametrize("anchor", ["MRHSession", "SMSESSION", "SESSIONID"])
def test_parse_deleted_detection_keys_on_provided_anchor(anchor):
    # A Set-Cookie tearing down the OPERATOR-DECLARED anchor is a server logout.
    assert auth._parse_probe_blob(
        f"set-cookie: {anchor}=deleted; path=/", anchor_cookies=(anchor,)
    )["deleted"] is True
    # A live value for the same anchor is NOT a teardown.
    assert auth._parse_probe_blob(
        f"set-cookie: {anchor}=livevalue", anchor_cookies=(anchor,)
    )["deleted"] is False


def test_parse_deleted_detection_ignores_undeclared_anchor():
    # No baked-in set: a `MRHSession=deleted` teardown is NOT detected when the
    # operator declared a different anchor — detection keys only on provided names.
    assert auth._parse_probe_blob(
        "set-cookie: MRHSession=deleted", anchor_cookies=("SESSIONID",)
    )["deleted"] is False
    assert auth._parse_probe_blob(
        "set-cookie: MRHSession=deleted", anchor_cookies=("MRHSession",)
    )["deleted"] is True


def test_parse_never_calls_json_loads(monkeypatch):
    # Hard rule: the parser must not json.loads the (often-truncated) envelope.
    import json as _json

    def _boom(*_a, **_k):  # pragma: no cover - only fires on a violation
        raise AssertionError("_parse_probe_blob must not call json.loads")

    monkeypatch.setattr(_json, "loads", _boom)
    # A truncated envelope that WOULD raise 'Unterminated string' under json.loads.
    truncated = '{"run_id":"r","stdout_preview":"HTTP/2 200\\r\\nset-cookie: MRHSession=v'
    p = auth._parse_probe_blob(truncated, anchor_cookies=_ANCHORS)
    assert p["status"] == 200 and p["deleted"] is False


# --------------------------------------------------------------------------- #
# _classify_probe — deleted override -> material.liveness -> reference default
# --------------------------------------------------------------------------- #
def test_classify_deleted_is_hard_dead_override_even_on_200():
    parsed = {"status": 200, "status_line": "HTTP/2 200", "user_id": "u", "deleted": True}
    verdict, reason = auth._classify_probe(parsed, "HTTP/2 200 ...", None)
    assert verdict == "dead"
    assert "deleted" in reason


def test_classify_without_typed_signature_is_unknown():
    live_parsed = {"status": 200, "status_line": "HTTP/2 200", "user_id": "u", "deleted": False}
    assert auth._classify_probe(live_parsed, "HTTP/2 200 body", None)[0] == "unknown"
    dead_parsed = {"status": 302, "status_line": "HTTP/1.1 302", "user_id": "-", "deleted": False}
    assert auth._classify_probe(dead_parsed, "HTTP/1.1 302 Found", None)[0] == "unknown"


def test_classify_transport_failure_is_unknown_not_dead():
    parsed = {"status": None, "status_line": "?", "user_id": "-", "deleted": False}
    verdict, reason = auth._classify_probe(
        parsed, "__keepalive_probe_error__ timeout", {"expect_status": 200}
    )
    assert verdict == "unknown"
    assert "transport" in reason


def test_classify_defers_to_material_liveness_when_present():
    parsed = {"status": 200, "status_line": "HTTP/2 200", "user_id": "u", "deleted": False}
    raw_live = 'HTTP/2 200\n{"userId":"u"}'
    cfg = {"expect_status": 200, "authed_marker": "userId", "dead_marker": "sessionExpired"}
    verdict, reason = auth._classify_probe(parsed, raw_live, cfg)
    assert verdict == "live" and reason.startswith("live:")
    # dead_marker present -> dead, even at HTTP 200.
    verdict2, reason2 = auth._classify_probe(parsed, "HTTP/2 200 sessionExpired", cfg)
    assert verdict2 == "dead" and reason2.startswith("dead:")


# --------------------------------------------------------------------------- #
# _vigil_assess_argv — routes through kali exec, argv list, NEVER bash -c
# --------------------------------------------------------------------------- #
def test_probe_argv_uses_kali_exec_with_identity_and_no_shell(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth.shutil, "which", lambda _name: "/usr/local/bin/vigil")
    argv = auth._vigil_assess_argv(eng, "cap-x", "https://portal.example/profile")
    assert argv[0] == "/usr/local/bin/vigil"
    assert argv[1] == "assess"
    for token in ("kali", "exec", "--identity", "cap-x", "--", "curl", "-i",
                  "https://portal.example/profile", "--engagement-dir"):
        assert token in argv, token
    # The identity must ride the flag directly (a shell wrapper would strip it).
    assert "bash" not in argv and "-c" not in argv
    # `--` precedes the curl invocation so nothing is parsed as a kali flag.
    assert argv.index("--") < argv.index("curl")


def test_probe_argv_falls_back_to_assess_script_off_path(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth.shutil, "which", lambda _name: None)
    argv = auth._vigil_assess_argv(eng, "cap-x", "https://x/y")
    assert argv[0].endswith("agent/scripts/assess.py")
    assert "bash" not in argv and "-c" not in argv


# --------------------------------------------------------------------------- #
# keepalive() — arg validation + foreground loop tees LIVE/DEAD to the log
# --------------------------------------------------------------------------- #
def test_keepalive_requires_probe_url(tmp_path):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    # Anchor is supplied so the ONLY missing input under test is --probe-url.
    with pytest.raises(SystemExit) as exc:
        auth.keepalive(eng, probe_url="", anchor_cookies=["MRHSession"], iters=1)
    assert "probe-url" in str(exc.value)


def test_keepalive_requires_anchor_cookie(tmp_path):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    # A valid probe URL but NO --anchor-cookie must error clearly. Vigil bakes in no
    # default anchor set, so the operator must name the engagement's anchor cookie(s).
    with pytest.raises(SystemExit) as exc:
        auth.keepalive(
            eng, probe_url="https://portal.example/profile", anchor_cookies=None, iters=1
        )
    msg = str(exc.value)
    assert "anchor-cookie" in msg
    # An empty / whitespace-only list is treated as "not provided".
    with pytest.raises(SystemExit):
        auth.keepalive(
            eng, probe_url="https://portal.example/profile", anchor_cookies=["  "], iters=1
        )


def test_keepalive_foreground_loop_tees_verdict_to_log(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    log = tmp_path / "keepalive.log"

    monkeypatch.setattr(
        auth, "read_auth",
        lambda _eng: {"identities": {"cap-x": {
            "cookies": {"MRHSession": "V"},
            "liveness": {"expect_status": 200, "authed_marker": "userId"},
        }}},
    )
    monkeypatch.setattr(
        auth, "_keepalive_probe",
        lambda _eng, _cap, _url: 'HTTP/2 200 OK\r\n\r\n{"userId":"u-9"}',
    )
    monkeypatch.setattr(auth.time, "sleep", lambda _s: None)

    auth.keepalive(
        eng, identities=["cap-x"], anchor_cookies=["MRHSession"], iters=1, caps=1,
        probe_url="https://portal.example/profile", log_path=log, detach=False,
    )
    text = log.read_text(encoding="utf-8")
    assert "KEEPALIVE START" in text
    assert "KEEPALIVE EXITED" in text
    assert "cap-x  LIVE" in text
    assert "userId=u-9" in text


def test_keepalive_cycle_persists_typed_scoped_liveness(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth,
        "read_auth",
        lambda _eng: {"identities": {"cap-x": {
            "cookies": {"MRHSession": "V"},
            "liveness": {"expect_status": 200, "authed_marker": "userId"},
        }}},
    )
    monkeypatch.setattr(
        auth, "_keepalive_probe",
        lambda *_: 'HTTP/2 200 OK\r\n\r\n{"userId":"u-9"}',
    )
    persisted = []
    monkeypatch.setattr(
        auth,
        "persist_liveness",
        lambda engagement_dir, identity, verdict, **kwargs: persisted.append(
            (identity, verdict, kwargs)
        ) or {},
    )
    monkeypatch.setattr(auth.time, "sleep", lambda _s: None)
    auth._keepalive_cycle(
        eng, ["cap-x"], 1, ("MRHSession",),
        "https://portal.example/account", lambda _line: None, 1,
        scope_key="portal-account", ttl_seconds=600,
    )
    assert persisted == [(
        "cap-x",
        "live",
        {
            "scope_key": "portal-account",
            "ttl_seconds": 600,
            "source": "auth-keepalive",
            "reason": "live: authed_marker present, status 200",
        },
    )]
def test_env_preflight_reports_presence_and_source_per_key(monkeypatch):
    monkeypatch.setenv("VIGIL_USER", "super-secret-user")
    rows = auth.env_preflight(["VIGIL_USER", "VIGIL_PASS"])
    assert rows == [
        {"name": "VIGIL_USER", "present": True, "source": "environment"},
        {"name": "VIGIL_PASS", "present": False, "source": "missing"},
    ]


def test_packaged_cli_loads_single_classifier_from_matched_application(tmp_path):
    package_root = tmp_path / "package"
    shutil.copytree(Path(auth.__file__).resolve().parent, package_root / "vigil_cli")
    install_root = tmp_path / "install"
    application_root = tmp_path / "application"
    (application_root / "orchestrator").mkdir(parents=True)
    classifier = application_root / "agent" / "scripts" / "assess" / "lib" / "auth_liveness.py"
    classifier.parent.mkdir(parents=True)
    shutil.copy2(
        REPO_ROOT / "agent" / "scripts" / "assess" / "lib" / "auth_liveness.py",
        classifier,
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from vigil_cli.auth import _classify_liveness; "
                "print(_classify_liveness(200, 'member-home', "
                "{'expect_status': 200, 'authed_marker': 'member-home'})[0])"
            ),
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(package_root),
            "VIGIL_INSTALL_DIR": str(install_root),
            "VIGIL_APPLICATION_DIR": str(application_root),
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "live"
