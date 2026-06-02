"""Unit tests for the OAST nonce minting + log-parse + match pure functions
and the ``aith oob mint`` CLI smoke (docker + backend mocked).

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

from ai_threat_hunting_cli import oob  # noqa: E402


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


def test_callback_urls_shape():
    urls = oob.callback_urls("abc123", "researcher.example")
    assert urls["host"] == "researcher.example"
    assert urls["http"] == "http://researcher.example/"
    assert urls["dns"] == "researcher.example"


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


def test_read_client_log_tails_the_client_log_file():
    from ai_threat_hunting_cli.docker import DockerResult

    seen = {}

    def runner(argv, **_):
        seen["argv"] = argv
        return DockerResult(0, "[researcher.example] Received DNS interaction from 203.0.113.6\n", "")

    text = oob.read_client_log("agent-1", runner=runner, lines=500)
    assert "Received DNS interaction" in text
    # Confirms it reads the SAME path `oob client logs` reads.
    joined = " ".join(seen["argv"])
    assert "/data/oob/clients/agent-1.log" in joined
    assert "tail -n 500" in joined


def test_read_client_log_sanitizes_name():
    from ai_threat_hunting_cli.docker import DockerResult

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


# ── aith oob mint CLI smoke (docker + backend mocked) ──────────────────────


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


def test_oob_mint_cli_records_probe_with_seeded_nonce(monkeypatch, tmp_path, capsys):
    from ai_threat_hunting_cli import main as main_module

    install_root = tmp_path
    key = "2026-05-30-120000-shop"
    _seed_engagement_dir(install_root, key)

    fake_client = _FakeAssessmentClient()
    # Seed the nonce deterministically and intercept the client construction.
    monkeypatch.setattr(main_module, "_oob_nonce_token_factory", lambda n: "deadbeefcafef00d"[:n])
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: fake_client)

    import argparse

    args = argparse.Namespace(
        engagement=key,
        select=False,
        target_url="https://shop.test/api/import?url=",
        param="url",
        technique="ssrf",
        probe_kind="blind-ssrf",
        request_hash="abc",
        notes="",
        json=False,
    )
    options = main_module._oob_options(install_root)
    main_module._oob_mint(args, install_root, options)

    out = capsys.readouterr().out
    # Engagement-prefixed deterministic nonce, default oob domain in the URL.
    assert "20260530120000shop-deadbeefcafef00d" in out
    assert "http://researcher.example/" in out
    assert "probe\tid=7" in out

    # The probe POST carried the nonce + correlation metadata.
    assert fake_client.closed is True
    assert len(fake_client.posts) == 1
    endpoint, payload = fake_client.posts[0]
    assert endpoint == "oob-probes"
    assert payload["nonce"] == "20260530120000shop-deadbeefcafef00d"
    assert payload["technique"] == "ssrf"
    assert payload["oob_domain"] == "researcher.example"


def test_oob_poll_cli_correlates_matched_and_unmatched(monkeypatch, tmp_path, capsys):
    from ai_threat_hunting_cli import main as main_module
    from ai_threat_hunting_cli.docker import DockerResult

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
            return [{"nonce": "knownnonce01", "technique": "ssrf", "target_url": "https://shop.test/"}]

    poll_client = _PollClient()
    monkeypatch.setattr(main_module, "_build_assessment_client", lambda ir, ek: poll_client)

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

    Requires `aith oob start` + a running interactsh-client and the
    orchestrator backend. Deselected by default (`-m 'not integration'`);
    cannot run in CI/this environment. Documents the manual verification:

      1. `aith oob mint --technique ssrf` -> nonce + callback URL.
      2. curl the callback URL (or fire a payload at a target).
      3. `aith oob poll --client <name>` -> the probe shows status=fired
         with the matched interaction.
    """
    pytest.skip("requires live interactsh/frp runtime (operator-controlled)")
