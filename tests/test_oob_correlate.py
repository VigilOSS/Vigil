"""Unit tests for the OAST nonce minting + log-parse + match pure functions
and the ``vigil oob mint`` CLI smoke (docker + backend mocked).

The interactsh log parser and the nonce↔callback matcher are PURE functions
(no network, no filesystem, no container), so they are exercised directly by
feeding raw interactsh-client output. The CLI mint smoke drives
``main._oob_mint`` with a seeded deterministic nonce, a stub docker runner,
and a fake AssessmentClient so it asserts the wiring (nonce → URL → recorded
probe) without a live runtime.

The live frp + container round-trip is covered by an ``integration``-marked
test that is deselected by default — it cannot run in this environment.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vigil_cli import oob  # noqa: E402


# ── nonce minting ────────────────────────────────────────────────────────


def test_mint_nonce_is_seedable_and_deterministic():
    nonce = oob.mint_nonce(token_factory=lambda n: "f" * n, length=12)
    # No prefix → pure token.
    assert nonce == "f" * 12


def test_mint_nonce_prepends_sanitized_prefix():
    nonce = oob.mint_nonce(
        prefix="2026-05-30-Shop_Test",
        token_factory=lambda n: "abcdef0123456789"[:n],
        length=16,
    )
    label, token = nonce.split("-", 1)
    assert label == "20260530shoptest"
    assert token == "abcdef0123456789"


def test_mint_nonce_default_is_lowercase_alnum_and_unique():
    a = oob.mint_nonce()
    b = oob.mint_nonce()
    assert a != b
    assert a.isalnum() and a.islower()
    assert len(a) == oob._DEFAULT_NONCE_LENGTH


def test_mint_nonce_rejects_empty_token_factory():
    with pytest.raises(ValueError):
        oob.mint_nonce(token_factory=lambda n: "!!!")


# ── client-bound callback URLs (nonce under a running client's id) ──────────
#
# interactsh delivers a callback to a client's poll ONLY when the host carries
# that client's registered correlation id, and it reads the id from the
# RIGHTMOST subdomain label. So a pollable minted host must be
# `<nonce>.<clientid>.<oob_domain>` — nonce leftmost (the matcher's label),
# client id to its right. A bare `<nonce>.<oob_domain>` lands in server.log but
# never in the per-client log `vigil oob poll` reads, so `callback_urls`
# REQUIRES the client's payload host (no bare form).


def test_callback_urls_binds_nonce_under_client_payload_host():
    payload_host = "researcher.example"
    urls = oob.callback_urls("shop-deadbeef", payload_host)
    assert urls["host"] == f"shop-deadbeef.{payload_host}"
    assert urls["http"] == f"http://shop-deadbeef.{payload_host}/"
    assert urls["https"] == f"https://shop-deadbeef.{payload_host}/"
    assert urls["dns"] == f"shop-deadbeef.{payload_host}"


def test_callback_urls_ordering_invariant_nonce_left_clientid_right():
    # The delivery-critical invariant: nonce is the LEFTMOST label and the
    # client payload host (carrying the correlation id) is to its right, so
    # interactsh attributes the hit to that client AND the matcher keys on the
    # nonce. Guards against an accidental `<clientid>.<nonce>` flip.
    payload_host = "researcher.example"
    host = oob.callback_urls("eng-tok123", payload_host)["host"]
    assert host.startswith("eng-tok123.")
    assert host.endswith("." + payload_host)
    # And it round-trips through the real parser+matcher as the client would log it.
    line = f"[{host}] Received DNS interaction (A) from 203.0.113.9 at 2026-06-17 12:00:00\n"
    matched, unmatched = oob.match_interactions_to_nonces(oob.parse_interactsh_log(line), ["eng-tok123"])
    assert not unmatched
    assert matched and matched[0].nonce == "eng-tok123"


# ── parse_client_payload_host: discover a client's registered interactsh id ──

_REGISTRATION_LOG = (
    "\n"
    "    _       __\n"
    "\t\tprojectdiscovery.io\n"
    "\n"
    "[\x1b[34mINF\x1b[0m] Current interactsh version 1.3.1 (\x1b[92mlatest\x1b[0m)\n"
    "[\x1b[34mINF\x1b[0m] Listing 1 payload for OOB Testing\n"
    "[\x1b[34mINF\x1b[0m] researcher.example\n"
)


def test_parse_client_payload_host_extracts_registered_id():
    host = oob.parse_client_payload_host(_REGISTRATION_LOG, "researcher.example")
    assert host == "researcher.example"


def test_parse_client_payload_host_ignores_callback_lines():
    # A real callback line `[<nonce>.<id>.oob...] Received ... interaction` must
    # NOT be mistaken for the registration line (its bracket holds an FQDN, and
    # it has trailing "Received ..." text).
    log = _REGISTRATION_LOG + (
        "[researcher.example] Received DNS interaction (A) from 1.2.3.4\n"
    )
    assert oob.parse_client_payload_host(log, "researcher.example") == (
        "researcher.example"
    )


def test_parse_client_payload_host_returns_latest_registration():
    # Client restarts re-register (possibly a new id); the most recent wins.
    log = _REGISTRATION_LOG + (
        "[\x1b[34mINF\x1b[0m] Listing 1 payload for OOB Testing\n"
        "[\x1b[34mINF\x1b[0m] researcher.example\n"
    )
    assert oob.parse_client_payload_host(log, "researcher.example") == (
        "researcher.example"
    )


def test_parse_client_payload_host_unregistered_returns_empty():
    log = (
        "[\x1b[34mVER\x1b[0m] Could not register to http://researcher.example: "
        'cause="no address found for host"\n'
        "[\x1b[1;31mFTL\x1b[0m] Could not create client\n"
    )
    assert oob.parse_client_payload_host(log, "researcher.example") == ""


# ── verbose-log parsing ───────────────────────────────────────────────────


def test_parse_verbose_dns_and_http_lines():
    log = (
        "[researcher.example] Received DNS interaction (A) from 203.0.113.9 at 2026-05-30 12:00:00\n"
        "[researcher.example] Received HTTP interaction from 198.51.100.4 at 2026-05-30 12:00:05\n"
    )
    interactions = oob.parse_interactsh_log(log)
    assert len(interactions) == 2
    dns, http = interactions
    assert dns.protocol == "dns"
    assert dns.query_type == "A"
    assert dns.remote_address == "203.0.113.9"
    assert dns.observed_at == "2026-05-30 12:00:00"
    assert dns.label == "abc123def456"
    assert dns.full_host == "researcher.example"
    assert http.protocol == "http"
    assert http.remote_address == "198.51.100.4"


def test_parse_ignores_runtime_marker_and_blank_lines():
    log = (
        "\n"
        "[oob-client] exited, retrying in 10s...\n"
        "[researcher.example] Received DNS interaction from 192.0.2.1\n"
        "some unrelated log noise without a bracket\n"
    )
    interactions = oob.parse_interactsh_log(log)
    assert len(interactions) == 1
    assert interactions[0].label == "xyz789"
    assert interactions[0].protocol == "dns"


def test_parse_handles_smtp_and_missing_timestamp():
    log = "[researcher.example] Received SMTP interaction from 192.0.2.55\n"
    (interaction,) = oob.parse_interactsh_log(log)
    assert interaction.protocol == "smtp"
    assert interaction.remote_address == "192.0.2.55"
    assert interaction.observed_at == ""


def test_parse_json_lines():
    log = (
        '{"protocol":"dns","unique-id":"jsonnonce01","full-id":"researcher.example",'
        '"remote-address":"203.0.113.77","q-type":"AAAA","timestamp":"2026-05-30T12:00:00Z"}\n'
        'not json, ignore me\n'
    )
    interactions = oob.parse_interactsh_log(log)
    assert len(interactions) == 1
    item = interactions[0]
    assert item.protocol == "dns"
    assert item.label == "jsonnonce01"
    assert item.remote_address == "203.0.113.77"
    assert item.query_type == "AAAA"
    assert item.observed_at == "2026-05-30T12:00:00Z"


def test_parse_empty_log_is_empty_list():
    assert oob.parse_interactsh_log("") == []


# ── nonce ↔ callback matching ──────────────────────────────────────────────


def test_match_exact_label():
    log = "[researcher.example] Received DNS interaction from 203.0.113.1\n"
    interactions = oob.parse_interactsh_log(log)
    matched, unmatched = oob.match_interactions_to_nonces(interactions, ["probe1abc"])
    assert len(matched) == 1
    assert not unmatched
    assert matched[0].nonce == "probe1abc"


def test_match_substring_with_tool_appended_clientid():
    # nuclei/dalfox prepend their own 33-char client id to the label; the
    # recorded nonce is a substring of the leftmost label.
    log = "[c" + "0" * 32 + "researcher.example] Received HTTP interaction from 203.0.113.2\n"
    interactions = oob.parse_interactsh_log(log)
    matched, unmatched = oob.match_interactions_to_nonces(interactions, ["probe1abc"])
    assert len(matched) == 1
    assert matched[0].nonce == "probe1abc"


def test_match_unknown_nonce_is_unmatched():
    log = "[researcher.example] Received DNS interaction from 203.0.113.3\n"
    interactions = oob.parse_interactsh_log(log)
    matched, unmatched = oob.match_interactions_to_nonces(interactions, ["probe1abc", "probe2def"])
    assert not matched
    assert len(unmatched) == 1
    assert unmatched[0].full_host == "researcher.example"


def test_match_prefers_longer_nonce_on_overlap():
    log = "[researcher.example] Received DNS interaction from 203.0.113.4\n"
    interactions = oob.parse_interactsh_log(log)
    # Both "alpha" and "alphabeta123" are substrings; the longer specific
    # token must win so a short accidental substring can't steal the match.
    matched, unmatched = oob.match_interactions_to_nonces(interactions, ["alpha", "alphabeta123"])
    assert len(matched) == 1
    assert matched[0].nonce == "alphabeta123"


def test_match_is_case_insensitive_on_recorded_nonce():
    log = "[researcher.example] Received DNS interaction from 203.0.113.5\n"
    interactions = oob.parse_interactsh_log(log)
    matched, _ = oob.match_interactions_to_nonces(interactions, ["LowerCaseTok"])
    assert matched and matched[0].nonce == "lowercasetok"


def test_short_nonce_does_not_match_domain_suffix():
    # Regression: a nonce must match only the leftmost label, never the OOB
    # domain suffix. "eng" is a substring of "example" — matching the full
    # FQDN would mis-correlate every callback to this probe.
    log = "[researcher.example] Received DNS interaction from 203.0.113.9\n"
    interactions = oob.parse_interactsh_log(log)
    matched, unmatched = oob.match_interactions_to_nonces(interactions, ["eng"])
    assert not matched
    assert len(unmatched) == 1


def test_match_tiebreak_is_deterministic_on_equal_length():
    # Two equal-length nonces both substring-matching one label must resolve
    # deterministically (by name ascending), independent of set iteration order.
    log = "[researcher.example] Received DNS interaction from 203.0.113.7\n"
    interactions = oob.parse_interactsh_log(log)
    matched, _ = oob.match_interactions_to_nonces(interactions, ["bbb", "aaa"])
    assert len(matched) == 1
    assert matched[0].nonce == "aaa"


def test_parse_ignores_empty_host_line():
    # A "[.]" bracket collapses to an empty host after normalization; it must
    # not yield a degenerate empty-host interaction.
    assert oob.parse_interactsh_log("[.] Received DNS interaction from 203.0.113.5\n") == []


# ── read_client_log reuses the client-log source via the docker runner ─────


def test_read_client_log_reverse_scans_bounded_interaction_records():
    from vigil_cli.docker import DockerResult

    seen = {}

    def runner(argv, **_):
        seen["argv"] = argv
        return DockerResult(0, "[researcher.example] Received DNS interaction from 203.0.113.6\n", "")

    text = oob.read_client_log("agent-1", runner=runner, lines=500)
    assert "Received DNS interaction" in text
    # Read the SAME file as `oob client logs`, but count parser candidates
    # rather than raw verbose lines (one callback expands to ~37 lines).
    joined = " ".join(seen["argv"])
    assert "/data/oob/clients/agent-1.log" in joined
    assert "tac" in joined
    assert "grep" in joined
    assert "-m 500" in joined
    assert "Received" in joined
    assert '"protocol"' in joined


def test_read_client_log_rejects_unbounded_interaction_windows():
    from vigil_cli.docker import DockerResult

    def runner(argv, **_):
        return DockerResult(0, "", "")

    with pytest.raises(ValueError, match="between 1 and 10000"):
        oob.read_client_log("agent-1", runner=runner, lines=0)
    with pytest.raises(ValueError, match="between 1 and 10000"):
        oob.read_client_log("agent-1", runner=runner, lines=10001)


def test_interaction_candidate_window_survives_verbose_dns_burst():
    nonce = "probe-http-survives"
    host = f"{nonce}.researcher.example"
    http = f"[{host}] Received HTTP interaction from 198.51.100.4 at 2026-07-16 23:07:38"
    lines = [http]
    for index in range(78):
        dns = (
            f"[{host}] Received DNS interaction (A) from 203.0.113.{index % 250 + 1} "
            "at 2026-07-16 23:07:39"
        )
        lines.extend([dns, *[f"verbose detail {index}-{detail}" for detail in range(36)]])

    raw_tail = "\n".join(lines[-2000:])
    assert "Received HTTP interaction" not in raw_tail

    candidates = [
        line
        for line in lines
        if " Received " in line and " interaction" in line
    ][-2000:]
    protocols = {item.protocol for item in oob.parse_interactsh_log("\n".join(candidates))}
    assert protocols == {"dns", "http"}


def test_read_client_log_sanitizes_name():
    from vigil_cli.docker import DockerResult

    seen = {}

    def runner(argv, **_):
        seen["argv"] = argv
        return DockerResult(0, "", "")

    oob.read_client_log("foo/../bar", runner=runner)
    joined = " ".join(seen["argv"])
    # sanitize_name collapses path separators to '-', so no traversal slash
    # reaches the log path: "foo/../bar" -> "foo-..-bar".
    label = joined.split("clients/")[1].split(".log")[0]
    assert label == "foo-..-bar"
    assert "/" not in label


def test_oob_runtime_preflight_includes_interaction_window_tools():
    from vigil_cli.docker import DockerResult

    commands = []

    def runner(argv, **_):
        commands.append(argv[-1])
        return DockerResult(0, "", "")

    oob._require_runtime_tools("vigil", runner=runner)
    joined = "\n".join(commands)
    assert "command -v grep" in joined
    assert "command -v tac" in joined


def test_oob_poll_record_limit_is_positive_and_bounded():
    import argparse

    from vigil_cli import main as main_module

    assert main_module._oob_poll_record_limit("1") == 1
    assert main_module._oob_poll_record_limit("10000") == 10000
    with pytest.raises(argparse.ArgumentTypeError, match="between 1 and 10000"):
        main_module._oob_poll_record_limit("0")
    with pytest.raises(argparse.ArgumentTypeError, match="between 1 and 10000"):
        main_module._oob_poll_record_limit("10001")


# ── client_payload_host scans the WHOLE log (busy-client registration fix) ──


def test_client_payload_host_greps_whole_log_not_a_tail():
    # The artifact: the one-time registration banner sits near the TOP of a busy
    # client log; the old tail-400 read scrolled past it and reported the client
    # unregistered ("flapping"). client_payload_host must now grep the whole log.
    from vigil_cli.docker import DockerResult

    banner = "[\x1b[34mINF\x1b[0m] researcher.example"
    seen = {}

    def runner(argv, **_):
        cmd = argv[-1]
        seen["cmd"] = cmd
        # Emulate `grep -F researcher.example <log>`: only the domain-bearing
        # lines come back — here just the banner.
        return DockerResult(0, banner + "\n", "")

    host = oob.client_payload_host("va003-browser-cb", runner=runner, oob_domain="researcher.example")
    assert host == "researcher.example"
    assert "grep" in seen["cmd"] and "tail -n" not in seen["cmd"]  # whole-log scan, not a window
    assert "/data/oob/clients/va003-browser-cb.log" in seen["cmd"]


def test_read_client_registration_log_greps_domain_over_whole_file():
    from vigil_cli.docker import DockerResult

    seen = {}

    def runner(argv, **_):
        seen["cmd"] = argv[-1]
        return DockerResult(0, "", "")

    oob.read_client_registration_log("agent-1", runner=runner, oob_domain="researcher.example")
    cmd = seen["cmd"]
    assert cmd.startswith("grep")
    assert "researcher.example" in cmd
    assert "/data/oob/clients/agent-1.log" in cmd
    assert "tail" not in cmd  # must not fall back to a bounded tail


# ── vigil oob mint CLI smoke (docker + backend mocked) ──────────────────────


class _FakeAssessmentClient:
    """Minimal AssessmentClient stand-in: records posts/gets, context manager."""

    def __init__(self):
        self.posts: list[tuple[str, dict]] = []
        self.closed = False

    def post(self, endpoint, payload):
        self.posts.append((endpoint, payload))
        return {"id": 7, "status": "pending", "technique": payload.get("technique", ""), **payload}

    def get(self, endpoint):
        return []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False


def _seed_engagement_dir(install_root: Path, key: str) -> Path:
    eng_dir = install_root / "agent" / "engagements" / key
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text("{}", encoding="utf-8")
    return eng_dir


def _mint_args(key, **over):
    import argparse

    base = dict(
        engagement=key,
        select=False,
        client=None,
        target_url="https://shop.test/api/import?url=",
        param="url",
        technique="ssrf",
        probe_kind="blind-ssrf",
        request_hash="abc",
        notes="",
        json=False,
    )
    base.update(over)
    return argparse.Namespace(**base)


def test_oob_mint_cli_binds_nonce_under_running_client(monkeypatch, tmp_path, capsys):
    from vigil_cli import main as main_module

    install_root = tmp_path
    key = "2026-05-30-120000-shop"
    _seed_engagement_dir(install_root, key)

    fake_client = _FakeAssessmentClient()
    payload_host = "researcher.example"
    # Seed the nonce deterministically; auto-resolve a single running, registered client.
    monkeypatch.setattr(main_module, "_oob_nonce_token_factory", lambda n: "deadbeefcafef00d"[:n])
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: fake_client)
    monkeypatch.setattr(main_module, "list_running_oob_clients", lambda **_: ["agent-1"])
    monkeypatch.setattr(main_module, "client_payload_host", lambda name, **_: payload_host)

    options = main_module._oob_options(install_root)
    main_module._oob_mint(_mint_args(key), install_root, options)

    out = capsys.readouterr().out
    nonce = "20260530120000shop-deadbeefcafef00d"
    # The callback host binds the nonce UNDER the client's registered id so poll can see it.
    assert nonce in out
    assert f"http://{nonce}.{payload_host}/" in out
    assert "agent-1" in out  # output names the bound client
    assert "probe\tid=7" in out

    # The probe POST carried the nonce + correlation metadata.
    assert fake_client.closed is True
    assert len(fake_client.posts) == 1
    endpoint, payload = fake_client.posts[0]
    assert endpoint == "oob-probes"
    assert payload["nonce"] == nonce
    assert payload["technique"] == "ssrf"
    assert payload["oob_domain"] == "researcher.example"
    assert payload["client_name"] == "agent-1"
    assert payload["client_payload_host"] == payload_host


def test_oob_mint_cli_honors_explicit_client(monkeypatch, tmp_path, capsys):
    from vigil_cli import main as main_module

    install_root = tmp_path
    key = "2026-05-30-120000-shop"
    _seed_engagement_dir(install_root, key)

    seen = {}
    payload_host = "researcher.example"
    monkeypatch.setattr(main_module, "_oob_nonce_token_factory", lambda n: "deadbeefcafef00d"[:n])
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: _FakeAssessmentClient())
    monkeypatch.setattr(main_module, "list_running_oob_clients", lambda **_: ["agent-1", "agent-2"])

    def fake_payload_host(name, **_):
        seen["name"] = name
        return payload_host

    monkeypatch.setattr(main_module, "client_payload_host", fake_payload_host)

    options = main_module._oob_options(install_root)
    main_module._oob_mint(_mint_args(key, client="agent-2"), install_root, options)

    out = capsys.readouterr().out
    assert seen["name"] == "agent-2"  # resolved the explicitly named client
    assert f".{payload_host}/" in out


def test_oob_mint_cli_errors_when_no_client_running(monkeypatch, tmp_path):
    from vigil_cli import main as main_module

    install_root = tmp_path
    key = "2026-05-30-120000-shop"
    _seed_engagement_dir(install_root, key)
    monkeypatch.setattr(main_module, "list_running_oob_clients", lambda **_: [])
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: _FakeAssessmentClient())

    options = main_module._oob_options(install_root)
    with pytest.raises(SystemExit) as exc:
        main_module._oob_mint(_mint_args(key), install_root, options)
    assert "client" in str(exc.value).lower()


def test_oob_mint_cli_errors_when_multiple_clients_and_no_selection(monkeypatch, tmp_path):
    from vigil_cli import main as main_module

    install_root = tmp_path
    key = "2026-05-30-120000-shop"
    _seed_engagement_dir(install_root, key)
    monkeypatch.setattr(main_module, "list_running_oob_clients", lambda **_: ["agent-1", "agent-2"])
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: _FakeAssessmentClient())

    options = main_module._oob_options(install_root)
    with pytest.raises(SystemExit) as exc:
        main_module._oob_mint(_mint_args(key), install_root, options)
    msg = str(exc.value)
    assert "--client" in msg and "agent-1" in msg and "agent-2" in msg


def test_oob_mint_cli_errors_when_explicit_client_not_running(monkeypatch, tmp_path):
    # The operator's most likely mistake: a typo'd or stopped --client name.
    from vigil_cli import main as main_module

    install_root = tmp_path
    key = "2026-05-30-120000-shop"
    _seed_engagement_dir(install_root, key)
    monkeypatch.setattr(main_module, "list_running_oob_clients", lambda **_: ["agent-1"])
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: _FakeAssessmentClient())

    options = main_module._oob_options(install_root)
    with pytest.raises(SystemExit) as exc:
        main_module._oob_mint(_mint_args(key, client="bogus"), install_root, options)
    msg = str(exc.value).lower()
    assert "not running" in msg and "bogus" in str(exc.value)


def test_oob_mint_cli_errors_when_client_unregistered(monkeypatch, tmp_path):
    from vigil_cli import main as main_module

    install_root = tmp_path
    key = "2026-05-30-120000-shop"
    _seed_engagement_dir(install_root, key)
    monkeypatch.setattr(main_module, "list_running_oob_clients", lambda **_: ["agent-1"])
    monkeypatch.setattr(main_module, "client_payload_host", lambda name, **_: "")  # not registered yet
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: _FakeAssessmentClient())

    options = main_module._oob_options(install_root)
    with pytest.raises(SystemExit) as exc:
        main_module._oob_mint(_mint_args(key), install_root, options)
    assert "register" in str(exc.value).lower()


def test_oob_poll_cli_correlates_matched_and_unmatched(monkeypatch, tmp_path, capsys):
    from vigil_cli import main as main_module
    from vigil_cli.docker import DockerResult

    install_root = tmp_path
    key = "2026-05-30-120000-poll"
    _seed_engagement_dir(install_root, key)

    # Stub the client log read: one matched (known nonce) + one stray callback.
    log = (
        "[researcher.example] Received DNS interaction (A) from 203.0.113.9 at 2026-05-30 12:00:00\n"
        "[researcher.example] Received HTTP interaction from 198.51.100.4 at 2026-05-30 12:00:05\n"
    )
    monkeypatch.setattr(main_module, "docker_run_command", lambda argv, **_: DockerResult(0, log, ""))

    class _PollClient(_FakeAssessmentClient):
        def get(self, endpoint):
            assert endpoint == "oob-probes"
            return [{
                "nonce": "knownnonce01",
                "technique": "ssrf",
                "target_url": "https://shop.test/",
                "client_name": "agent-1",
                "client_payload_host": "researcher.example",
            }]

    poll_client = _PollClient()
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: poll_client)
    monkeypatch.setattr(
        main_module,
        "poll_client_payload_host",
        lambda *_, **__: "researcher.example",
    )

    import argparse

    args = argparse.Namespace(engagement=key, select=False, client="agent-1", lines=2000, json=False)
    options = main_module._oob_options(install_root)
    main_module._oob_poll(args, install_root, options)

    out = capsys.readouterr().out
    assert "parsed\t2 interaction(s)" in out
    assert "matched\t1\tunmatched\t1" in out
    assert "knownnonce01" in out
    assert "researcher.example" in out

    # Only the matched callback was POSTed for correlation.
    correlate_posts = [p for p in poll_client.posts if p[0] == "oob-probes/interactions"]
    assert len(correlate_posts) == 1
    assert correlate_posts[0][1]["nonce"] == "knownnonce01"
    assert correlate_posts[0][1]["protocol"] == "dns"


def test_oob_poll_cli_does_not_post_probe_owned_by_another_client(
    monkeypatch, tmp_path, capsys
):
    from vigil_cli import main as main_module
    from vigil_cli.docker import DockerResult

    key = "2026-05-30-120000-poll"
    _seed_engagement_dir(tmp_path, key)
    log = (
        "[knownnonce01.client-b] Received DNS interaction (A) "
        "from 203.0.113.9 at 2026-05-30 12:00:00\n"
    )
    monkeypatch.setattr(
        main_module,
        "docker_run_command",
        lambda argv, **_: DockerResult(0, log, ""),
    )
    monkeypatch.setattr(
        main_module,
        "poll_client_payload_host",
        lambda *_, **__: "researcher.example",
    )

    class _PollClient(_FakeAssessmentClient):
        def get(self, endpoint):
            assert endpoint == "oob-probes"
            return [{
                "nonce": "knownnonce01",
                "client_name": "agent-a",
                "client_payload_host": "researcher.example",
            }]

    poll_client = _PollClient()
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda *_: poll_client)
    import argparse

    args = argparse.Namespace(
        engagement=key,
        select=False,
        client="agent-b",
        lines=2000,
        json=False,
    )
    main_module._oob_poll(args, tmp_path, main_module._oob_options(tmp_path))

    assert "matched\t0\tunmatched\t1" in capsys.readouterr().out
    assert [post for post in poll_client.posts if post[0] == "oob-probes/interactions"] == []


# ── OOB health observability: status must surface the masked-failure class ──


def test_assess_health_degraded_when_clients_running_but_unregistered():
    health, issues = oob._assess_oob_health(
        server=True, frpc=True, state="running", running=["a", "b"],
        client_health=[{"name": "a", "registered": False}, {"name": "b", "registered": False}],
        domain="researcher.example", domain_resolves=True,
    )
    assert health == "degraded"
    assert any("registered" in i.lower() for i in issues)


def test_assess_health_degraded_when_domain_unresolvable():
    health, issues = oob._assess_oob_health(
        server=True, frpc=True, state="running", running=["a"],
        client_health=[{"name": "a", "registered": True}],
        domain="researcher.example", domain_resolves=False,
    )
    assert health == "degraded"
    assert any("does not resolve" in i for i in issues)


def test_assess_health_ok_when_registered_and_resolving():
    health, issues = oob._assess_oob_health(
        server=True, frpc=True, state="running", running=["a"],
        client_health=[{"name": "a", "registered": True}],
        domain="researcher.example", domain_resolves=True,
    )
    assert health == "ok"
    assert issues == []


def test_assess_health_down_when_stopped():
    health, issues = oob._assess_oob_health(
        server=False, frpc=False, state="stopped", running=[], client_health=[],
        domain=None, domain_resolves=None,
    )
    assert health == "down"


def _status_runner(scenario):
    from vigil_cli.docker import DockerResult

    def runner(argv, **_):
        cmd = argv[-1]
        if "tmux has-session -t oob-server" in cmd:
            return DockerResult(0 if scenario["server"] else 1, "", "")
        if "tmux has-session -t frpc" in cmd:
            return DockerResult(0 if scenario["frpc"] else 1, "", "")
        if "tmux list-sessions" in cmd:
            return DockerResult(0, "".join(f"{n}\n" for n in scenario["running"]), "")
        if "clients/*.json" in cmd:
            return DockerResult(0, "".join(f"{n}\n" for n in scenario.get("configured", [])), "")
        if cmd.startswith("grep") and "clients/" in cmd and ".log" in cmd:
            # registration probe: client_payload_host greps the whole client log
            name = cmd.split("clients/")[1].split(".log")[0]
            return DockerResult(0, scenario["logs"].get(name, ""), "")
        if cmd.startswith("dig"):
            return DockerResult(0, scenario.get("dig", ""), "")
        if cmd.startswith("curl"):
            return DockerResult(
                0,
                scenario.get(
                    "http",
                    "HTTP/1.1 200 OK\nServer: researcher.example\n",
                ),
                "",
            )
        return DockerResult(0, "", "")

    return runner


def test_oob_status_degraded_reproduces_the_masked_dns_outage(monkeypatch):
    # The exact regression: sessions all "up", clients all running, yet none
    # registered and the domain does not resolve. Old status said green; now it
    # must report degraded with actionable issues.
    monkeypatch.setattr(oob.docker, "container_running", lambda *a, **k: True)
    scenario = {
        "server": True, "frpc": True,
        "running": ["ssrf-a", "ssrf-b"], "configured": ["ssrf-a", "ssrf-b"],
        "logs": {
            "ssrf-a": '[\x1b[34mVER\x1b[0m] Could not register to researcher.example: cause="no address found for host"\n',
            "ssrf-b": "[\x1b[1;31mFTL\x1b[0m] Could not create client\n",
        },
        "dig": "",  # domain does not resolve from the runtime
    }
    payload = oob.oob_status(oob_domain="researcher.example", runner=_status_runner(scenario))
    assert payload["health"] == "degraded"
    assert payload["domain_resolves"] is False
    assert all(c["registered"] is False for c in payload["client_health"])
    joined = " ".join(payload["issues"]).lower()
    assert "does not resolve" in joined
    assert "registered" in joined


def test_oob_status_ok_when_registered_and_resolving(monkeypatch):
    monkeypatch.setattr(oob.docker, "container_running", lambda *a, **k: True)
    scenario = {
        "server": True, "frpc": True, "running": ["ssrf-a"], "configured": ["ssrf-a"],
        "logs": {"ssrf-a": "[\x1b[34mINF\x1b[0m] researcher.example\n"},
        "dig": "18.223.115.81\n",
    }
    payload = oob.oob_status(oob_domain="researcher.example", runner=_status_runner(scenario))
    assert payload["health"] == "ok"
    assert payload["domain_resolves"] is True
    assert payload["client_health"][0]["registered"] is True
    assert payload["issues"] == []


def test_oob_status_recovers_from_one_transient_dns_and_registration_miss(monkeypatch):
    monkeypatch.setattr(oob.docker, "container_running", lambda *a, **k: True)
    sleeps = []
    monkeypatch.setattr(oob.time, "sleep", sleeps.append)
    scenario = {
        "server": True,
        "frpc": True,
        "running": ["ssrf-a"],
        "configured": ["ssrf-a"],
        "logs": {"ssrf-a": ""},
        "dig": "",
    }
    base_runner = _status_runner(scenario)
    calls = {"logs": 0, "dig": 0}

    def transient_runner(argv, **kwargs):
        command = argv[-1]
        if command.startswith("grep") and "clients/" in command and ".log" in command:
            calls["logs"] += 1
            if calls["logs"] == 2:
                scenario["logs"]["ssrf-a"] = (
                    "[INF] researcher.example\n"
                )
        if command.startswith("dig"):
            calls["dig"] += 1
            if calls["dig"] == 2:
                scenario["dig"] = "18.223.115.81\n"
        return base_runner(argv, **kwargs)

    payload = oob.oob_status(
        oob_domain="researcher.example",
        runner=transient_runner,
    )

    assert payload["health"] == "ok"
    assert payload["probe_attempts"] == 2
    assert sleeps == [oob.OOB_STATUS_RETRY_DELAY_SECONDS]
    assert payload["domain_resolves"] is True
    assert payload["client_health"][0]["registered"] is True
    assert payload["issues"] == []


def test_oob_status_degrades_when_dns_resolves_but_edge_http_redirects(monkeypatch):
    monkeypatch.setattr(oob.docker, "container_running", lambda *a, **k: True)
    scenario = {
        "server": True,
        "frpc": True,
        "running": ["ssrf-a"],
        "configured": ["ssrf-a"],
        "logs": {
            "ssrf-a": (
                "[INF] researcher.example\n"
            )
        },
        "dig": "3.129.117.120\n",
        "http": "HTTP/1.1 308 Permanent Redirect\nServer: Caddy\n",
    }

    payload = oob.oob_status(
        oob_domain="researcher.example",
        runner=_status_runner(scenario),
    )

    assert payload["domain_resolves"] is True
    assert payload["edge_route_healthy"] is False
    assert payload["health"] == "degraded"
    assert any("HTTP edge route" in issue for issue in payload["issues"])


def test_oob_status_shallow_skips_probes_and_does_not_false_degrade(monkeypatch):
    # deep=False (the `vigil status`/`vigil up` path) must NOT read per-client logs
    # or DNS, and must NOT report degraded just because registration is unknown.
    monkeypatch.setattr(oob.docker, "container_running", lambda *a, **k: True)
    calls = {"reg": 0, "dig": 0}
    scenario_runner = _status_runner({
        "server": True, "frpc": True, "running": ["ssrf-a", "ssrf-b"],
        "configured": ["ssrf-a", "ssrf-b"], "logs": {}, "dig": "",
    })

    def counting_runner(argv, **kw):
        cmd = argv[-1]
        if cmd.startswith("grep") and ".log" in cmd:
            calls["reg"] += 1
        if cmd.startswith("dig"):
            calls["dig"] += 1
        return scenario_runner(argv, **kw)

    payload = oob.oob_status(oob_domain="researcher.example", runner=counting_runner, deep=False)
    assert calls["reg"] == 0 and calls["dig"] == 0  # no per-client / DNS probes on the hot path
    assert payload["health"] == "ok"                 # unknown registration != degraded
    assert payload["domain_resolves"] is None
    assert all(c["registered"] is None for c in payload["client_health"])
    assert payload["domain"] == "researcher.example"  # always resolved, never None


def test_print_oob_status_exits_nonzero_and_warns_on_degraded(capsys):
    from vigil_cli import main as main_module

    payload = {
        "state": "running", "health": "degraded", "server": True, "frpc": True,
        "clients": ["a"], "running": ["a"], "client_health": [{"name": "a", "registered": False}],
        "domain": "researcher.example", "domain_resolves": False,
        "issues": ["OOB domain 'researcher.example' does not resolve from the runtime — callbacks cannot land."],
    }
    with pytest.raises(SystemExit) as exc:
        main_module._print_oob_status(payload, as_json=False)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "does not resolve" in err


def test_print_oob_status_ok_exits_zero_and_reports_health(capsys):
    from vigil_cli import main as main_module

    payload = {
        "state": "running", "health": "ok", "server": True, "frpc": True,
        "clients": ["a"], "running": ["a"], "client_health": [{"name": "a", "registered": True}],
        "domain": "researcher.example", "domain_resolves": True, "issues": [],
    }
    main_module._print_oob_status(payload, as_json=False)  # must not raise
    out = capsys.readouterr().out
    assert "health=ok" in out
    assert "registered=1/1" in out


# ── vigil oob clean: prune old, non-running client artifacts ────────────────

_DAY = 86400


def test_select_prunable_oob_clients_prunes_old_idle_only():
    now = 1_000_000_000.0
    d = oob.OOB_CLIENTS_DIR
    files = [
        (f"{d}/old-a.log", now - 10 * _DAY),      # every artifact old + not running -> prune
        (f"{d}/old-a.json", now - 10 * _DAY),
        (f"{d}/old-a.session", now - 9 * _DAY),
        (f"{d}/live-b.log", now - 30 * _DAY),     # old but RUNNING -> keep
        (f"{d}/live-b.json", now - 30 * _DAY),
        (f"{d}/fresh-c.log", now - 1 * _DAY),      # recent activity -> keep
        (f"{d}/fresh-c.json", now - 30 * _DAY),    # (even though metadata is old)
    ]
    clients, paths = oob.select_prunable_oob_clients(files, {"live-b"}, now=now, max_age_days=5)
    assert clients == ["old-a"]
    assert paths == sorted([f"{d}/old-a.log", f"{d}/old-a.json", f"{d}/old-a.session"])


def test_select_prunable_oob_clients_keeps_client_with_any_recent_artifact():
    now = 2_000_000_000.0
    d = oob.OOB_CLIENTS_DIR
    files = [(f"{d}/mix.log", now - 1 * _DAY), (f"{d}/mix.json", now - 20 * _DAY)]
    clients, paths = oob.select_prunable_oob_clients(files, set(), now=now, max_age_days=5)
    assert clients == [] and paths == []


def test_select_prunable_oob_clients_ignores_paths_outside_clients_dir():
    now = 3_000_000_000.0
    d = oob.OOB_CLIENTS_DIR
    files = [
        ("/etc/passwd", now - 999 * _DAY),                 # outside clients dir
        (f"{d}/sub/nested.log", now - 999 * _DAY),         # nested, not direct child
        (f"{d}/notes.txt", now - 999 * _DAY),              # unknown suffix
    ]
    clients, paths = oob.select_prunable_oob_clients(files, set(), now=now, max_age_days=5)
    assert clients == [] and paths == []


def test_clean_oob_clients_removes_selected_and_spares_running_and_fresh(monkeypatch):
    from vigil_cli.docker import DockerResult
    monkeypatch.setattr(oob.docker, "container_running", lambda *a, **k: True)
    now = 1_700_000_000
    d = oob.OOB_CLIENTS_DIR
    listing = (
        f"NOW {now}\n"
        f"{now - 10 * _DAY} {d}/old-a.log\n"
        f"{now - 10 * _DAY} {d}/old-a.json\n"
        f"{now - 1 * _DAY} {d}/fresh-c.log\n"
        f"{now - 30 * _DAY} {d}/live-b.log\n"
    )
    rm = {"cmd": None}

    def runner(argv, **_):
        cmd = argv[-1]
        if "find" in cmd and "clients" in cmd:
            return DockerResult(0, listing, "")
        if "tmux list-sessions" in cmd:
            return DockerResult(0, "live-b\n", "")  # live-b is running
        if cmd.startswith("rm -f --"):
            rm["cmd"] = cmd
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    payload = oob.clean_oob_clients(max_age_days=5, runner=runner)
    assert payload["clients"] == ["old-a"]
    assert payload["removed"] is True
    assert payload["kept_running"] == ["live-b"]
    assert rm["cmd"] is not None
    assert "old-a.log" in rm["cmd"] and "old-a.json" in rm["cmd"]
    assert "fresh-c" not in rm["cmd"] and "live-b" not in rm["cmd"]


def test_clean_oob_clients_dry_run_selects_but_does_not_delete(monkeypatch):
    from vigil_cli.docker import DockerResult
    monkeypatch.setattr(oob.docker, "container_running", lambda *a, **k: True)
    now = 1_700_000_000
    listing = f"NOW {now}\n{now - 100 * _DAY} {oob.OOB_CLIENTS_DIR}/ancient.log\n"
    rm_called = {"v": False}

    def runner(argv, **_):
        cmd = argv[-1]
        if "find" in cmd:
            return DockerResult(0, listing, "")
        if "tmux list-sessions" in cmd:
            return DockerResult(0, "", "")
        if cmd.startswith("rm -f"):
            rm_called["v"] = True
        return DockerResult(0, "", "")

    payload = oob.clean_oob_clients(max_age_days=5, dry_run=True, runner=runner)
    assert payload["clients"] == ["ancient"]
    assert payload["removed"] is False
    assert rm_called["v"] is False


def test_clean_oob_clients_rejects_days_below_one(monkeypatch):
    monkeypatch.setattr(oob.docker, "container_running", lambda *a, **k: True)
    with pytest.raises(SystemExit):
        oob.clean_oob_clients(max_age_days=0, runner=lambda *a, **k: None)


# ── interaction dedup hash is collision-safe across `|`-placement ──────────


def _interaction_hash(nonce, protocol, remote_address, query_type, observed_at, raw_request):
    """Mirror of the backend correlate dedup hash (state_manager/oob.py).

    The dedup key hashes a JSON-encoded field list rather than a ``|``-joined
    string so an attacker who controls a free-text field (e.g. ``raw_request``)
    cannot shift a ``|`` to forge a colliding key and suppress a real callback.
    """
    import hashlib
    import json

    return hashlib.sha256(
        json.dumps(
            [nonce, protocol, remote_address, query_type, observed_at, raw_request],
            sort_keys=False,
        ).encode("utf-8")
    ).hexdigest()


def test_interaction_dedup_hash_distinguishes_pipe_placement():
    # Two interactions that differ ONLY in where a `|` falls between adjacent
    # fields (protocol/remote_address here). Under the old `"|".join(...)`
    # scheme both collapse to the same joined string and collide; the JSON
    # encoding keeps the field boundaries unambiguous, so the digests differ.
    fields_a = ("nonce1", "dns|1.2.3.4", "q", "b", "t", "raw")  # `|` inside protocol
    fields_b = ("nonce1", "dns", "1.2.3.4|q", "b", "t", "raw")  # `|` was the real separator
    a = _interaction_hash(*fields_a)
    b = _interaction_hash(*fields_b)
    assert a != b

    # Sanity: the OLD ambiguous join genuinely collided (documents the bug
    # this fix closes — an attacker shifting a `|` forged a duplicate key).
    assert "|".join(fields_a) == "|".join(fields_b)

    # Identical fields still hash identically (dedup of true duplicates holds).
    assert b == _interaction_hash(*fields_b)


@pytest.mark.integration
def test_oob_mint_poll_live_round_trip():
    """End-to-end OAST correlation over the live interactsh/frp transport.

    Requires `vigil oob start` + a running interactsh-client and the
    orchestrator backend. Deselected by default (`-m 'not integration'`);
    cannot run in CI/this environment. Documents the manual verification:

      1. `vigil oob mint --technique ssrf` -> nonce + callback URL.
      2. curl the callback URL (or fire a payload at a target).
      3. `vigil oob poll --client <name>` -> the probe shows status=fired
         with the matched interaction.
    """
    pytest.skip("requires live interactsh/frp runtime (operator-controlled)")
