from __future__ import annotations

from types import SimpleNamespace

import pytest

from assess.lib import rate_leases


class _Client:
    instances: list["_Client"] = []

    def __init__(self, base_url: str, engagement_key: str):
        self.base_url = base_url
        self.engagement_key = engagement_key
        self.posts: list[tuple[str, dict]] = []
        self.patches: list[tuple[str, dict]] = []
        self.closed = False
        self.__class__.instances.append(self)

    def post(self, endpoint: str, payload: dict):
        self.posts.append((endpoint, payload))
        return {"lease_token": "lease-123", **payload}

    def patch(self, endpoint: str, payload: dict, **kwargs):
        self.patches.append((endpoint, payload))
        return {"lease_token": endpoint.rsplit("/", 1)[-1], **payload}

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _fake_client(monkeypatch):
    _Client.instances.clear()
    monkeypatch.setattr(rate_leases, "AssessmentClient", _Client)


def _cfg():
    return SimpleNamespace(base_url="http://vigil.test", engagement_key="eng-1")


def test_target_rate_lease_context_releases_after_success():
    with rate_leases.target_rate_lease(
        config=_cfg(),
        owner="recon-specialist",
        effective_rate_rps=7,
        ttl_seconds=120,
        command_run_id=42,
    ) as lease:
        assert lease["lease_token"] == "lease-123"

    client = _Client.instances[0]
    assert client.posts == [
        (
            "rate-leases",
            {
                "owner": "recon-specialist",
                "effective_rate_rps": 7.0,
                "ttl_seconds": 120,
                "override_reason": "",
                "command_run_id": 42,
            },
        )
    ]
    assert client.patches == [("rate-leases/lease-123", {"release": True})]
    assert client.closed is True


def test_target_rate_lease_releases_when_execution_raises():
    with pytest.raises(RuntimeError, match="tool failed"):
        with rate_leases.target_rate_lease(
            config=_cfg(), owner="specialist", effective_rate_rps=1, ttl_seconds=30
        ):
            raise RuntimeError("tool failed")

    assert _Client.instances[0].patches == [
        ("rate-leases/lease-123", {"release": True})
    ]


def test_target_rate_lease_carries_explicit_override_reason():
    with rate_leases.target_rate_lease(
        config=_cfg(),
        owner="operator",
        effective_rate_rps=25,
        ttl_seconds=60,
        override_reason="Approved coordinated burst",
    ):
        pass

    payload = _Client.instances[0].posts[0][1]
    assert payload["override_reason"] == "Approved coordinated burst"


@pytest.mark.parametrize(
    ("requested", "expected"),
    [(1, 1), (86_400, 86_400), (86_401, 86_400), (172_800, 86_400)],
)
def test_target_rate_lease_ttl_is_clamped_to_backend_contract(
    requested, expected
):
    rate_leases.acquire_target_rate_lease(
        config=_cfg(),
        owner="operator",
        effective_rate_rps=1,
        ttl_seconds=requested,
    )

    assert _Client.instances[0].posts[0][1]["ttl_seconds"] == expected


def test_target_rate_lease_release_failure_does_not_reclassify_completed_execution(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        _Client,
        "patch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("backend down")),
    )

    with rate_leases.target_rate_lease(
        config=_cfg(), owner="specialist", effective_rate_rps=1, ttl_seconds=30
    ):
        pass

    assert "lease release failed" in capsys.readouterr().err


def test_aggregate_rate_reserves_target_facing_indeterminate_command(
    tmp_path,
):
    (tmp_path / "scope.json").write_text(
        '{"hosts":["example.test"],"rate_limit_aggregate_rps":9}',
        encoding="utf-8",
    )

    reserved = rate_leases.aggregate_rate_reservation(
        str(tmp_path),
        ["sh", "-c", 'curl "https://$host/"'],
        "curl",
        {"target_facing": True},
    )

    assert reserved == 9


@pytest.mark.parametrize(
    "cmd",
    [
        ["httpx", "-rl=500", "-u", "https://example.test"],
        ["httpx", "--rate-limit=500"],
        ["nuclei", "--rate=500"],
        ["nuclei", "-rate-limit=500"],
    ],
)
def test_aggregate_rate_parses_attached_rate_flag(tmp_path, cmd):
    # A Go/pflag attached value (`-rl=500`) must be honored; falling back to the
    # 150-rps tool default here would admit a lease running above the ROE cap.
    (tmp_path / "scope.json").write_text(
        '{"hosts":["example.test"],"rate_limit_aggregate_rps":400}',
        encoding="utf-8",
    )
    reserved = rate_leases.aggregate_rate_reservation(
        str(tmp_path), cmd, cmd[0], {"target_facing": True}
    )
    assert reserved == 500.0


def test_aggregate_rate_still_parses_spaced_rate_flag(tmp_path):
    (tmp_path / "scope.json").write_text(
        '{"hosts":["example.test"],"rate_limit_aggregate_rps":400}',
        encoding="utf-8",
    )
    reserved = rate_leases.aggregate_rate_reservation(
        str(tmp_path), ["httpx", "-rl", "500"], "httpx", {"target_facing": True}
    )
    assert reserved == 500.0


@pytest.mark.parametrize(
    "cmd,expected",
    [
        # The reported breach: a minute-only argv reserving the 150-rps tool
        # default while actually running at 1000 rps.
        (["httpx", "-rlm", "60000", "-u", "https://example.test"], 1000.0),
        (["httpx", "-rlm=60000"], 1000.0),
        (["nuclei", "--rate-limit-minute", "60000"], 1000.0),
        (["katana", "--rate-limit-minute=60000"], 1000.0),
        # Sub-1-rps minute rates stay fractional rather than truncating to 0.
        (["httpx", "-rlm", "30"], 0.5),
    ],
)
def test_aggregate_rate_parses_minute_rate_flag(tmp_path, cmd, expected):
    (tmp_path / "scope.json").write_text(
        '{"hosts":["example.test"],"rate_limit_aggregate_rps":500}',
        encoding="utf-8",
    )
    reserved = rate_leases.aggregate_rate_reservation(
        str(tmp_path), cmd, cmd[0], {"target_facing": True}
    )
    assert reserved == expected


@pytest.mark.parametrize(
    "cmd,expected",
    [
        # Both families present: reserve whichever bounds MORE traffic, because
        # httpx/nuclei let -rlm replace -rl while katana lets -rl win.
        (["httpx", "-rl", "1", "-rlm", "60000"], 1000.0),
        (["httpx", "-rlm", "60", "-rl", "900"], 900.0),
        # What Vigil's own web-discovery katana emitter writes: `-rl N -rlm N*60`
        # is the same rate either way.
        (["katana", "-rl", "20", "-rlm", "1200"], 20.0),
    ],
)
def test_aggregate_rate_reserves_the_larger_of_both_rate_families(
    tmp_path, cmd, expected
):
    (tmp_path / "scope.json").write_text(
        '{"hosts":["example.test"],"rate_limit_aggregate_rps":2000}',
        encoding="utf-8",
    )
    reserved = rate_leases.aggregate_rate_reservation(
        str(tmp_path), cmd, cmd[0], {"target_facing": True}
    )
    assert reserved == expected


def test_aggregate_rate_ignores_unrelated_rate_shaped_flags(tmp_path):
    # `-rld` is nuclei's rate-limit WINDOW, not a rate, and puredns'
    # `--rate-limit-trusted` caps only the trusted-resolver pool. Reading either
    # as the run's rate would reserve a number that means something else.
    (tmp_path / "scope.json").write_text(
        '{"hosts":["example.test"],"rate_limit_aggregate_rps":400}',
        encoding="utf-8",
    )
    reserved = rate_leases.aggregate_rate_reservation(
        str(tmp_path),
        ["nuclei", "-rld", "10", "--rate-limit-trusted", "200"],
        "nuclei",
        {"target_facing": True},
    )
    assert reserved == 150.0  # nuclei's per-second default, no explicit rate


def test_aggregate_rate_skips_a_rate_flag_with_no_value(tmp_path):
    # A trailing `-rlm` with nothing after it must not crash or reserve garbage;
    # it falls through to the tool default like any unconfigured run.
    (tmp_path / "scope.json").write_text(
        '{"hosts":["example.test"],"rate_limit_aggregate_rps":400}',
        encoding="utf-8",
    )
    reserved = rate_leases.aggregate_rate_reservation(
        str(tmp_path), ["httpx", "-rlm"], "httpx", {"target_facing": True}
    )
    assert reserved == 150.0
