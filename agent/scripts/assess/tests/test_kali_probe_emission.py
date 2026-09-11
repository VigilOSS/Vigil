from __future__ import annotations

import pytest

from assess.lib import kali


class _RecordingClient:
    def __init__(self) -> None:
        self.payloads: list[dict[str, object]] = []

    def post(self, endpoint: str, payload: dict[str, object]) -> None:
        assert endpoint == "probe-runs"
        self.payloads.append(payload)


@pytest.mark.parametrize("technique", ["IDOR", "AUTH"])
@pytest.mark.parametrize(
    ("http_status", "expected_result"),
    [(401, "tested"), (403, "tested"), (404, "error"), (500, "error")],
)
def test_auth_family_probe_only_credits_actual_auth_denials(
    technique: str,
    http_status: int,
    expected_result: str,
) -> None:
    client = _RecordingClient()

    kali._emit_probe_run(
        client,
        engagement_type="web",
        technique=technique,
        probe_kind="payload",
        auth_context="user_a",
        tool_name="curl",
        agent_name="va-authz",
        return_code=0,
        timed_out=False,
        cmd=["curl", "-i", "https://api.example.test/v1/objects/7"],
        evidence_ref="scans/authz-response.txt",
        stdout_preview=f"HTTP/1.1 {http_status} response\r\n\r\nbody",
    )

    assert len(client.payloads) == 1
    assert client.payloads[0]["observed_http_status"] == http_status
    assert client.payloads[0]["result_status"] == expected_result


def test_non_auth_probe_still_rejects_an_http_denial_as_coverage() -> None:
    client = _RecordingClient()

    kali._emit_probe_run(
        client,
        engagement_type="web",
        technique="SQLI",
        probe_kind="payload",
        auth_context="unauthenticated",
        tool_name="curl",
        agent_name="va-sqli",
        return_code=0,
        timed_out=False,
        cmd=["curl", "-i", "https://api.example.test/search?q=probe"],
        evidence_ref="scans/sqli-response.txt",
        stdout_preview="HTTP/1.1 403 forbidden\r\n\r\nbody",
    )

    assert client.payloads[0]["result_status"] == "error"
