"""CLI tests for `vigil assess auth list` (WS3) + `auth-status --probe --identity`
per-session verdict persistence (WS4).

Backend + runtime are stubbed the same way the other assess CLI suites do
(``load_config`` + a fake non-context-managed client closed in a ``finally``; see
test_http_cmd.py). These pin: the list view renders EVERY stored identity with
metadata, the host/include-dead filters map to the exact backend query params,
raw cookie VALUES never leak into the list view (names only), and a
``--probe --identity`` run persists the classified verdict (while an
active-identity probe stays read-only).
"""
from __future__ import annotations

import argparse
import json
from urllib.parse import parse_qs, urlparse

from assess.commands import auth_cmd, auth_status


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Records get_engagement calls and serves a canned identities listing."""

    def __init__(self, *, listing=None) -> None:
        self.gets: list[str] = []
        self._listing = listing if listing is not None else {"identities": {}, "active_identity": ""}
        self.closed = False

    def get_engagement(self, endpoint: str):
        self.gets.append(endpoint)
        return self._listing

    def close(self) -> None:
        self.closed = True


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    auth_cmd.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(auth_cmd, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(auth_cmd, "AssessmentClient", lambda *a, **k: fake)


def _query_of(endpoint: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(endpoint).query)


_LISTING = {
    "active_identity": "cap-aaaa",
    "identities": {
        "cap-aaaa": {
            "identity_name": "cap-aaaa",
            "auth_context": "user_a",
            "state": "available",
            "liveness_verdict": "live",
            "last_seen_at": "2026-07-03T11:00:00Z",
            "last_probed_at": "2026-07-03T11:30:00Z",
            "is_active": True,
            "cookies": {"MRHSession": "SECRET-VALUE-AAA"},
            "host_cookies": [
                {"host": "portal.example.com", "cookies": {"MRHSession": "SECRET-VALUE-AAA"}},
            ],
        },
        "cap-bbbb": {
            "identity_name": "cap-bbbb",
            "auth_context": "user_b",
            "state": "stale",
            "liveness_verdict": "unknown",
            "last_seen_at": "2026-07-01T00:00:00Z",
            "last_probed_at": None,
            "is_active": False,
            "cookies": {"MRHSession": "SECRET-VALUE-BBB", "csrf": "x"},
            "host_cookies": [
                {"host": "portal.example.com", "cookies": {"MRHSession": "SECRET-VALUE-BBB", "csrf": "x"}},
            ],
        },
    },
}


def test_list_renders_every_identity_with_metadata(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list"], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    # Both identities listed with their metadata columns.
    assert "cap-aaaa*" in out  # active identity flagged
    assert "cap-bbbb" in out
    assert "user_a" in out and "user_b" in out
    assert "available" in out and "stale" in out
    assert "live" in out and "unknown" in out
    # cookie NAMES surface; hosts surface.
    assert "MRHSession" in out
    assert "portal.example.com" in out
    # No filters -> bare endpoint.
    assert fake.gets == ["credentials"]
    assert fake.closed is True


def test_list_does_not_leak_raw_cookie_values(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list"], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    assert "SECRET-VALUE-AAA" not in out
    assert "SECRET-VALUE-BBB" not in out


def test_list_host_filter_maps_to_query_param(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list", "--host", "portal.example.com"], str(tmp_path))
    args.func(args)
    capsys.readouterr()
    assert len(fake.gets) == 1
    endpoint = fake.gets[0]
    assert endpoint.startswith("credentials?")
    assert _query_of(endpoint)["host"] == ["portal.example.com"]
    assert "include_dead" not in _query_of(endpoint)


def test_list_include_dead_maps_to_query_param(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list", "--include-dead"], str(tmp_path))
    args.func(args)
    capsys.readouterr()
    assert _query_of(fake.gets[0])["include_dead"] == ["true"]


def test_list_json_emits_redacted_listing(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing=_LISTING)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list", "--json"], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    parsed = json.loads(out)
    # Every identity is still enumerated with its metadata + cookie NAMES.
    assert set(parsed["identities"]) == {"cap-aaaa", "cap-bbbb"}
    assert parsed["identities"]["cap-aaaa"]["cookie_names"] == ["MRHSession"]
    assert sorted(parsed["identities"]["cap-bbbb"]["cookie_names"]) == ["MRHSession", "csrf"]
    assert parsed["identities"]["cap-aaaa"]["host_cookies"][0]["cookie_names"] == ["MRHSession"]
    # But no live cookie VALUE anywhere in the JSON — the safe list view must not
    # leak session material into stdout/logs/LLM context.
    assert "SECRET-VALUE-AAA" not in out
    assert "SECRET-VALUE-BBB" not in out


def test_list_json_redacts_header_and_token_values(tmp_path, monkeypatch, capsys):
    listing = {
        "active_identity": "cap-jwt",
        "identities": {
            "cap-jwt": {
                "identity_name": "cap-jwt",
                "headers": {"Authorization": "Bearer SECRET-BEARER-XYZ"},
                "tokens": {"access_token": "SECRET-BEARER-XYZ"},
                "cookies": {},
            }
        },
    }
    fake = _FakeClient(listing=listing)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list", "--json"], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["identities"]["cap-jwt"]["header_names"] == ["Authorization"]
    assert parsed["identities"]["cap-jwt"]["token_names"] == ["access_token"]
    assert "SECRET-BEARER-XYZ" not in out


def test_list_empty_store_renders_placeholder(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(listing={"identities": {}, "active_identity": ""})
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["auth", "list"], str(tmp_path))
    args.func(args)
    assert "no identities stored" in capsys.readouterr().out


def test_humanize_age_buckets():
    assert auth_cmd._humanize_age(None) == "-"
    assert auth_cmd._humanize_age("not-a-date") == "-"
    # A far-past timestamp reads in days.
    assert auth_cmd._humanize_age("2000-01-01T00:00:00Z").endswith("d")


# --------------------------------------------------------------------------- #
# auth-status --probe --identity: per-session verdict persistence (WS4)
# --------------------------------------------------------------------------- #

class _StatusCfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


def _status_parser():
    # auth-status folded into `auth status` (2026-07 CLI consolidation); the
    # module now registers a `status` subparser via register_status.
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    auth_status.register_status(sub)
    return parser


def _parse_status(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _status_parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install_status(monkeypatch, tmp_path, *, verdict, material=None):
    """Stub the status command's collaborators so run() is network-free."""
    monkeypatch.setattr(auth_status, "load_config", lambda *a, **k: _StatusCfg(str(tmp_path)))
    monkeypatch.setattr(auth_status, "_last_auth_probe", lambda *_a, **_k: None)
    monkeypatch.setattr(auth_status, "AssessmentClient", lambda *a, **k: None)
    resolved_material = material if material is not None else {
        "identity_name": "cap-target",
        "auth_context": "user_b",
        "liveness": {"authed_marker": "Sign out"},
        "cookies": {"S": "1"},
    }
    calls: dict[str, object] = {}

    def fake_resolve(_dir, requested, *, scope_key="", record_use=True):
        calls["resolved"] = requested
        calls["resolved_scope"] = scope_key
        # The status VIEW is inspection, never a use — see auth_status.run.
        calls["resolve_record_use"] = record_use
        return (requested, dict(resolved_material))

    def fake_active(_dir, *, record_use=True):
        calls["active_used"] = True
        calls["active_record_use"] = record_use
        return dict(resolved_material)

    def fake_probe(
        _dir, identity, url, *, liveness_cfg, scope_key="", timeout=15
    ):
        calls["probed_identity"] = identity
        calls["probed_scope"] = scope_key
        return {"liveness": verdict, "reason": "stubbed", "http_status": 200, "error": None}

    def fake_persist(_dir, identity, v, probed_at, **kwargs):
        calls.setdefault("persisted", []).append((identity, v, probed_at, kwargs))
        state = "available" if v == "live" else resolved_material.get("state", "available")
        return {
            **resolved_material,
            "identity_name": identity,
            "liveness_verdict": v,
            "state": state,
            "last_probed_at": probed_at,
        }

    monkeypatch.setattr(auth_status, "resolve_identity", fake_resolve)
    monkeypatch.setattr(auth_status, "active_material", fake_active)
    monkeypatch.setattr(auth_status, "_run_identity_probe", fake_probe)
    monkeypatch.setattr(auth_status, "persist_liveness", fake_persist)
    return calls


def test_probe_identity_persists_live_verdict(tmp_path, monkeypatch, capsys):
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    args = _parse_status(
        ["status", "--json", "--probe", "--identity", "cap-target", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    out = json.loads(capsys.readouterr().out)
    assert calls["resolved"] == "cap-target"      # targeted the requested identity
    assert calls["probed_identity"] == "cap-target"
    assert calls["persisted"][0][0] == "cap-target"
    assert calls["persisted"][0][1] == "live"     # verdict persisted
    assert out["liveness"] == "live"
    assert out["liveness_probe"]["persisted"] is True


def test_probe_identity_persists_dead_verdict(tmp_path, monkeypatch, capsys):
    calls = _install_status(monkeypatch, tmp_path, verdict="dead")
    args = _parse_status(
        ["status", "--probe", "--identity", "cap-target", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    capsys.readouterr()
    assert calls["persisted"][0][1] == "dead"


def test_probe_no_signature_persists_unknown_not_dead(tmp_path, monkeypatch, capsys):
    # A no-signature / transport-error verdict is `unknown`: it IS persisted
    # (records last_probed_at) but the backend leaves state untouched — nothing is
    # persisted as dead. Assert the verdict sent is `unknown`, never `dead`.
    calls = _install_status(monkeypatch, tmp_path, verdict="unknown")
    args = _parse_status(
        ["status", "--probe", "--identity", "cap-target", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    capsys.readouterr()
    assert calls["persisted"][0][1] == "unknown"
    assert calls["persisted"][0][1] != "dead"


def test_probe_defaults_observation_scope_to_probe_origin(
    tmp_path, monkeypatch, capsys
):
    calls = _install_status(monkeypatch, tmp_path, verdict="dead")
    args = _parse_status(
        [
            "status",
            "--json",
            "--probe",
            "--identity",
            "cap-target",
            "--probe-url",
            "https://publishing.example.test/account?tab=profile",
        ],
        str(tmp_path),
    )

    args.func(args)
    out = json.loads(capsys.readouterr().out)

    assert calls["resolved_scope"] == "https://publishing.example.test"
    assert calls["probed_scope"] == "https://publishing.example.test"
    assert calls["persisted"][0][3]["scope_key"] == (
        "https://publishing.example.test"
    )
    assert out["identity_name"] == "cap-target"
    assert out["liveness_probe"]["scope_key"] == (
        "https://publishing.example.test"
    )


def test_probe_requested_identity_is_the_reported_and_audited_subject(
    tmp_path, monkeypatch, capsys
):
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    monkeypatch.setattr(
        auth_status,
        "active_material",
        lambda _dir: {
            "identity_name": "other-active",
            "auth_context": "other-active",
        },
    )
    args = _parse_status(
        [
            "status",
            "--json",
            "--probe",
            "--identity",
            "cap-target",
            "--probe-url",
            "https://chat.example.test/me",
        ],
        str(tmp_path),
    )

    args.func(args)
    out = json.loads(capsys.readouterr().out)

    assert calls["probed_identity"] == "cap-target"
    assert calls["persisted"][0][0] == "cap-target"
    assert out["identity_name"] == "cap-target"
    assert out["liveness_probe"]["identity_name"] == "cap-target"


def test_active_identity_probe_does_not_persist(tmp_path, monkeypatch, capsys):
    # No --identity: the active-identity probe stays READ-ONLY (no persistence).
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    args = _parse_status(
        ["status", "--probe", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    capsys.readouterr()
    assert "persisted" not in calls          # never wrote a verdict
    assert calls.get("active_used") is True  # used the active identity


def test_status_view_is_inspection_not_a_use(tmp_path, monkeypatch, capsys):
    """Reading the record must not reset the clock the stale flag keys off.

    ``resolve_identity`` refreshes ``last_seen_at`` because it is normally the
    resolve-for-replay path. ``auth status`` only DISPLAYS the record, so a status
    loop that resolved the same way kept an unused, unprobed session out of the
    8h stale flag and the 5d purge — and printed a misleading age doing it.
    """
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    args = _parse_status(["status", "--identity", "cap-target"], str(tmp_path))
    args.func(args)
    capsys.readouterr()

    assert calls["resolved"] == "cap-target"
    assert calls["resolve_record_use"] is False
    assert "probed_identity" not in calls  # no --probe: nothing went on the wire


def test_scoped_status_view_is_inspection_not_a_use(tmp_path, monkeypatch, capsys):
    # --scope takes the other resolve branch; both are inspection.
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    args = _parse_status(
        ["status", "--identity", "member", "--scope", "billing"], str(tmp_path)
    )
    args.func(args)
    capsys.readouterr()

    assert calls["resolved_scope"] == "billing"
    assert calls["resolve_record_use"] is False


def test_active_status_view_is_inspection_not_a_use(tmp_path, monkeypatch, capsys):
    # No --identity: the ACTIVE row is read for display and must not be touched.
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    args = _parse_status(["status"], str(tmp_path))
    args.func(args)
    capsys.readouterr()

    assert calls.get("active_used") is True
    assert calls["active_record_use"] is False


def test_probe_still_puts_the_identity_on_the_wire(tmp_path, monkeypatch, capsys):
    # The status VIEW stays read-only even under --probe; the USE is recorded
    # where the credential is actually replayed — _run_identity_probe hands the
    # identity to kali_exec, whose injection path resolves for replay.
    calls = _install_status(monkeypatch, tmp_path, verdict="live")
    args = _parse_status(
        ["status", "--probe", "--identity", "cap-target", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    capsys.readouterr()

    assert calls["resolve_record_use"] is False
    assert calls["probed_identity"] == "cap-target"


def test_probe_missing_identity_reports_and_does_not_persist(tmp_path, monkeypatch, capsys):
    # A requested identity that resolves to empty material must not probe/persist.
    calls = _install_status(monkeypatch, tmp_path, verdict="live", material={})
    args = _parse_status(
        ["status", "--json", "--probe", "--identity", "ghost", "--probe-url", "https://x/y"],
        str(tmp_path),
    )
    args.func(args)
    out = json.loads(capsys.readouterr().out)
    assert "persisted" not in calls
    assert out["liveness"] == "unknown"
    assert "ghost" in out["liveness_probe"]["error"]


def test_scoped_alias_probes_and_persists_resolved_identity(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(
        auth_status, "load_config", lambda *a, **k: _StatusCfg(str(tmp_path))
    )
    monkeypatch.setattr(auth_status, "_last_auth_probe", lambda *_a, **_k: None)
    monkeypatch.setattr(auth_status, "AssessmentClient", lambda *a, **k: None)
    calls: dict[str, object] = {}

    def resolve(_dir, requested, *, scope_key="", record_use=True):
        calls["resolved"] = (requested, scope_key)
        calls["resolve_record_use"] = record_use
        return "cap-billing-42", {
            "identity_name": "cap-billing-42",
            "auth_context": "member",
            "state": "available",
            "use_for_requests": True,
            "headers": {"Authorization": "Bearer scoped"},
            "liveness": {"authed_marker": "Sign out"},
        }

    def probe(_dir, identity, url, *, liveness_cfg, scope_key="", timeout=15):
        calls["probed"] = (identity, scope_key, url)
        return {
            "liveness": "live",
            "reason": "stubbed",
            "http_status": 200,
            "error": None,
        }

    def persist(_dir, identity, verdict, probed_at, **kwargs):
        calls["persisted"] = (identity, verdict, kwargs)
        return {"identity_name": identity, "liveness_verdict": verdict}

    monkeypatch.setattr(auth_status, "resolve_identity", resolve)
    monkeypatch.setattr(auth_status, "_run_identity_probe", probe)
    monkeypatch.setattr(auth_status, "persist_liveness", persist)

    args = _parse_status(
        [
            "status",
            "--json",
            "--probe",
            "--identity",
            "member",
            "--scope",
            "billing",
            "--probe-url",
            "https://app.example.com/account",
        ],
        str(tmp_path),
    )
    args.func(args)
    out = json.loads(capsys.readouterr().out)

    assert calls["resolved"] == ("member", "billing")
    assert calls["probed"] == (
        "cap-billing-42",
        "billing",
        "https://app.example.com/account",
    )
    assert calls["persisted"] == (
        "cap-billing-42",
        "live",
        {
            "scope_key": "billing",
            "source": "auth-status",
            "reason": "stubbed",
        },
    )
    assert out["liveness_probe"]["persisted"] is True


# --------------------------------------------------------------------------- #
# One classifier, one signature: `vigil assess auth status --probe` and
# `vigil auth status --probe` / `vigil auth keepalive` must never be able to
# reach different verdicts for the same identity and the same response.
# --------------------------------------------------------------------------- #

def test_both_cli_surfaces_call_the_classifier_with_the_same_arguments() -> None:
    """Arity parity is the guard, not just value parity.

    The two surfaces have drifted before by ARGUMENT: the assess command passed
    a probe scope the ``vigil_cli.auth`` mirror had no way to supply, so the
    same identity could resolve on one surface and read ``unknown`` on the
    other. Pinning the classifier's parameter list — and both wrappers against
    it — makes that drift a test failure rather than a field surprise.
    """
    import inspect
    import sys
    from pathlib import Path

    repo_src = Path(__file__).resolve().parents[4] / "src"
    if str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))

    from assess.lib.auth_liveness import classify_liveness

    from vigil_cli import auth as cli_auth

    expected = ["status", "haystack", "liveness"]
    assert list(inspect.signature(classify_liveness).parameters) == expected
    assert list(inspect.signature(cli_auth._classify_liveness).parameters) == expected
    # The assess command consumes the same canonical function, not a copy.
    assert auth_status._classify_liveness is classify_liveness


def test_an_authentication_challenge_is_positive_evidence_without_expect_status() -> None:
    """``dead`` needs positive evidence — and a 401 IS that evidence on its own.

    ``expect_status`` is optional, so the challenge check must not be gated on
    the operator having configured one. It is skipped in exactly one case: the
    operator's signature names this status as the expected authed response, and
    their declaration beats the generic rule.
    """
    from assess.lib.auth_liveness import classify_liveness

    # A signature with no expect_status still classifies a 401 as death.
    verdict, reason = classify_liveness(401, "nope", {"authed_marker": "Sign out"})
    assert verdict == "dead"
    assert "authentication challenge" in reason
    # ...but with NO signature at all there is nothing to be dead against: the
    # probe proved only that this URL is not characterised for this identity.
    verdict, reason = classify_liveness(401, "nope", None)
    assert verdict == "unknown"
    assert "material.liveness" in reason
    assert classify_liveness(401, "nope", {})[0] == "unknown"
    # An operator who declares 401 as the authed response is believed.
    assert classify_liveness(
        401, "Sign out", {"expect_status": 401, "authed_marker": "Sign out"}
    )[0] == "live"


# --------------------------------------------------------------------------- #
# probe argv: an egress proxy's CONNECT block is another hop's text and must not
# reach this identity's marker haystack.
# --------------------------------------------------------------------------- #

def test_identity_probe_argv_suppresses_the_proxy_connect_block(tmp_path, monkeypatch):
    """The numeric status here comes from curl's %{http_code}, which is already
    the ORIGIN's — but the haystack the authed_marker / dead_marker / Location
    rules run over is the raw ``-i`` output, and behind an HTTP egress proxy that
    output starts with the tunnel's own headers.
    """
    from assess.lib import kali as kali_lib

    seen: dict[str, object] = {}

    def fake_kali_exec(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        seen["identity"] = kwargs.get("identity")

        class _Result:
            stdout_preview = "HTTP/1.1 200 OK\nSign out\nVIGIL_HTTP_CODE=200\n"
            stdout_path = ""
            transport_error = False

        return _Result()

    monkeypatch.setattr(kali_lib, "kali_exec", fake_kali_exec)

    result = auth_status._run_identity_probe(
        str(tmp_path),
        "cap-target",
        "https://app.example.com/me",
        liveness_cfg={"expect_status": 200, "authed_marker": "Sign out"},
    )

    assert result["liveness"] == "live"
    assert "--suppress-connect-headers" in seen["cmd"]
    # The identity still goes to kali_exec, which resolves it for replay — the
    # probe is where the USE gets recorded.
    assert seen["identity"] == "cap-target"
