"""What closes each per-host recon objective, and what a deferral may name.

``per_host_coverage`` evaluates the ``PER_HOST_OBJECTIVES`` and nothing else, so
that tuple is the whole vocabulary a ``coverage_deferral`` can close. Work that
is not one of those objectives belongs in an ungated decision such as
``phase_step_deferral``, and the refusal says so.

``waf_tier`` is closed by a WAF measurement, which is either a vendor-named
tech-component row or a structured ``provenance.waf`` result that names the
measured hosts and the command run behind it. A measured "no WAF" closes the
objective for the hosts it names without claiming a WAF is present.
"""
from __future__ import annotations

import typing
import uuid

import pytest
from app.api.assessment_operator import CoverageDeferralPayload
from app.services import intel as intel_service
from app.services import state_manager
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-11-14-100000-objectives"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"
INTEL_BASE = f"/engagements/{ENGAGEMENT_KEY}/intel"


@pytest.fixture
def engagement_id(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _service(engagement_id: int, endpoint: str) -> None:
    state_manager.record_service(
        engagement_id,
        endpoint=endpoint,
        protocol="tcp",
        port=None,
        service="",
        state="up",
        coverage_status="pending",
        banner="",
        notes="",
        discovered_by="test",
        target_identity=None,
    )


def _command_run(
    client,
    *argv: str,
    target_host: str = "",
    status: str = "completed",
    return_code: int | None = 0,
    tool_name: str = "wafw00f",
    command: str | None = None,
) -> int:
    """A wafw00f run; the gate reads its outcome and the hosts it targeted.

    ``argv`` defaults to a single-target run against ``api.example.com``.
    """
    argv = argv or ("wafw00f", "-a", "https://api.example.com")
    response = client.post(
        f"{ASSESSMENT_BASE}/command-runs",
        json={
            "run_uuid": f"objective-records-{uuid.uuid4().hex[:12]}",
            "command": command if command is not None else " ".join(argv),
            "argv": list(argv),
            "tool_name": tool_name,
            "agent_name": "recon-specialist-1",
            "phase": "recon",
            "status": status,
            "return_code": return_code,
            "timed_out": status == "timed_out",
            "target_host": target_host,
            "started_at": "2026-11-14T09:02:00Z",
            "completed_at": "" if status in {"queued", "running"} else "2026-11-14T09:02:30Z",
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _measure(client, run_id: int, hosts: list[str], verdict: str = "none_detected"):
    return client.post(
        f"{INTEL_BASE}/tech-components",
        json={
            "component": "WAF: none detected" if verdict == "none_detected" else "Generic WAF",
            "source_name": "recon-specialist",
            "provenance": {"command_run_id": run_id, "waf": {"verdict": verdict, "hosts": hosts}},
        },
    )


def _tech(client, payload: dict) -> dict:
    response = client.post(f"{INTEL_BASE}/tech-components", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _by_host(client) -> dict[str, dict]:
    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    return {row["host"]: row for row in body["hosts"]}


# ---------------------------------------------------------------------------
# coverage_deferral vocabulary
# ---------------------------------------------------------------------------


def test_deferral_objective_vocabulary_is_the_gate_objectives():
    field = CoverageDeferralPayload.model_fields["deferred_objectives"]
    (item_type,) = typing.get_args(field.annotation)
    assert typing.get_args(item_type) == state_manager.PER_HOST_OBJECTIVES


def test_cli_objective_mirror_matches_backend():
    from assess.lib import coverage_checks

    assert coverage_checks._PER_HOST_OBJECTIVES == state_manager.PER_HOST_OBJECTIVES


def test_every_gate_objective_can_be_deferred(client, engagement_id):
    for objective in state_manager.PER_HOST_OBJECTIVES:
        response = client.post(
            f"{ASSESSMENT_BASE}/dispatch-decisions",
            json={
                "kind": "coverage_deferral",
                "payload": {
                    "host": "api.example.com",
                    "deferred_objectives": [objective],
                    "reason": "scope brief",
                },
            },
        )
        assert response.status_code == 201, (objective, response.text)


def test_non_objective_deferral_is_refused_toward_phase_step_deferral(client, engagement_id):
    response = client.post(
        f"{ASSESSMENT_BASE}/dispatch-decisions",
        json={
            "kind": "coverage_deferral",
            "payload": {
                "hosts": ["api.example.com"],
                "deferred_objectives": ["authenticated_recon"],
                "reason": "no test account yet",
            },
        },
    )
    assert response.status_code == 422, response.text
    detail = str(response.json()["detail"])
    assert "phase_step_deferral" in detail
    assert "'authenticated_recon'" in detail
    for objective in state_manager.PER_HOST_OBJECTIVES:
        assert objective in detail


# ---------------------------------------------------------------------------
# waf_tier: a structured WAF measurement
# ---------------------------------------------------------------------------


def test_measured_no_waf_closes_waf_tier_for_named_hosts_only(
    client, engagement_id
):
    _service(engagement_id, "api.example.com")
    _service(engagement_id, "www.example.com")
    run_id = _command_run(client)
    _tech(
        client,
        {
            "component": "WAF: none detected",
            "source_name": "recon-specialist",
            "provenance": {
                "command_run_id": run_id,
                "waf": {"verdict": "none_detected", "hosts": ["api.example.com"]},
            },
        },
    )

    rows = _by_host(client)
    cell = rows["api.example.com"]["outcomes"]["waf_tier"]
    assert cell["met"] is True
    assert cell["waf_detected"] is False
    assert "waf_tier" not in rows["api.example.com"]["unmet_objectives"]
    # The measurement names one host; the other stays unmeasured.
    assert rows["www.example.com"]["outcomes"]["waf_tier"]["met"] is False


def test_structured_detection_closes_waf_tier_without_a_known_vendor(
    client, engagement_id
):
    _service(engagement_id, "api.example.com")
    run_id = _command_run(client)
    _tech(
        client,
        {
            "component": "Generic WAF",
            "source_name": "recon-specialist",
            "provenance": {
                "command_run_id": run_id,
                "waf": {"verdict": "detected", "hosts": ["https://api.example.com/"]},
            },
        },
    )

    cell = _by_host(client)["api.example.com"]["outcomes"]["waf_tier"]
    assert cell["met"] is True
    assert cell["waf_detected"] is True


def test_measured_no_waf_overrides_engagement_level_vendor_presence(
    client, engagement_id
):
    _service(engagement_id, "api.example.com")
    _service(engagement_id, "origin.example.com")
    run_id = _command_run(client, "wafw00f", "https://origin.example.com")
    _tech(client, {"component": "Cloudflare", "source_name": "wafw00f"})
    _tech(
        client,
        {
            "component": "WAF: none detected",
            "provenance": {
                "command_run_id": run_id,
                "waf": {"verdict": "none_detected", "hosts": ["origin.example.com"]},
            },
        },
    )

    rows = _by_host(client)
    assert rows["api.example.com"]["outcomes"]["waf_tier"]["waf_detected"] is True
    origin = rows["origin.example.com"]["outcomes"]["waf_tier"]
    assert origin["met"] is True
    assert origin["waf_detected"] is False


def test_free_text_no_waf_component_does_not_close_waf_tier(client, engagement_id):
    _service(engagement_id, "api.example.com")
    _tech(
        client,
        {
            "component": "No WAF detected",
            "source_name": "wafw00f",
            "notes": "wafw00f -a found no WAF on api.example.com",
        },
    )

    cell = _by_host(client)["api.example.com"]["outcomes"]["waf_tier"]
    assert cell["met"] is False


def test_waf_result_citing_a_run_outside_the_engagement_is_refused(client, engagement_id):
    response = client.post(
        f"{INTEL_BASE}/tech-components",
        json={
            "component": "WAF: none detected",
            "provenance": {
                "command_run_id": 999999,
                "waf": {"verdict": "none_detected", "hosts": ["api.example.com"]},
            },
        },
    )
    assert response.status_code == 422, response.text
    assert "999999" in response.text


@pytest.mark.parametrize(
    ("status", "return_code"),
    [("failed", 1), ("timed_out", None), ("killed", None), ("running", None)],
)
def test_waf_result_citing_a_run_that_did_not_succeed_is_refused(
    client, engagement_id, status, return_code
):
    _service(engagement_id, "api.example.com")
    run_id = _command_run(client, status=status, return_code=return_code)

    response = _measure(client, run_id, ["api.example.com"])

    assert response.status_code == 422, response.text
    assert str(run_id) in response.text
    assert status in response.text
    assert _by_host(client)["api.example.com"]["outcomes"]["waf_tier"]["met"] is False


def test_waf_result_citing_a_run_with_no_host_evidence_is_refused_naming_the_host(
    client, engagement_id
):
    # A host-list run records no per-host target: nothing structured says it
    # reached api.example.com.
    run_id = _command_run(client, "wafw00f", "-a", "-i", "scans/live_hosts.txt")

    response = _measure(client, run_id, ["api.example.com"])

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "api.example.com" in detail
    assert "target_host" in detail


def test_waf_result_naming_a_host_the_run_did_not_target_is_refused(client, engagement_id):
    run_id = _command_run(client, "wafw00f", "https://api.example.com")

    response = _measure(client, run_id, ["api.example.com", "www.example.com"])

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "www.example.com" in detail
    assert "api.example.com" in detail  # what the run did target


@pytest.mark.parametrize(
    ("argv", "tool_name", "command"),
    [
        # The host is only text the run printed.
        (("echo", "https://api.example.com"), "exec", None),
        # A proxy is not what wafw00f measured.
        (("wafw00f", "-p", "http://api.example.com:8080", "https://other.example.com"), "exec", None),
        # A request header naming the host is request content, not the target.
        (("curl", "-H", "Origin: https://api.example.com", "https://other.example.com"), "exec", None),
        # The command text names the host; the argv the run executed does not.
        (("wafw00f", "https://other.example.com"), "wafw00f",
         "wafw00f https://other.example.com # api.example.com"),
        (("bash", "-c", "wafw00f https://api.example.com"), "exec", None),
    ],
    ids=["echo", "proxy", "origin-header", "comment-text", "shell-body"],
)
def test_waf_result_citing_a_run_that_only_mentions_the_host_is_refused(
    client, engagement_id, argv, tool_name, command
):
    _service(engagement_id, "api.example.com")
    run_id = _command_run(client, *argv, tool_name=tool_name, command=command)

    response = _measure(client, run_id, ["api.example.com"])

    assert response.status_code == 422, response.text
    assert "api.example.com" in response.json()["detail"]
    assert _by_host(client)["api.example.com"]["outcomes"]["waf_tier"]["met"] is False


@pytest.mark.parametrize(
    "argv",
    [
        ("wafw00f", "-a", "https://api.example.com"),
        ("/usr/bin/wafw00f", "-p", "http://proxy.example:8080", "api.example.com"),
        ("wafw00f", "--proxy=http://proxy.example:8080", "https://api.example.com:443/"),
    ],
    ids=["positional-url", "path-head-bare-host", "inline-proxy"],
)
def test_waf_result_accepts_the_target_a_wafw00f_argv_names(client, engagement_id, argv):
    _service(engagement_id, "api.example.com")
    run_id = _command_run(client, *argv, tool_name="exec")

    response = _measure(client, run_id, ["api.example.com"])

    assert response.status_code == 201, response.text
    assert _by_host(client)["api.example.com"]["outcomes"]["waf_tier"]["met"] is True


def test_waf_result_accepts_each_host_a_run_stored_as_its_targets(client, engagement_id):
    _service(engagement_id, "api.example.com")
    _service(engagement_id, "www.example.com:8443")
    run_id = _command_run(
        client,
        "wafw00f", "-a", "-i", "scans/live_hosts.txt",
        target_host="api.example.com, WWW.example.com",
    )

    response = _measure(
        client, run_id, ["https://api.example.com/", "www.example.com:8443"], verdict="detected"
    )

    assert response.status_code == 201, response.text
    rows = _by_host(client)
    assert rows["api.example.com"]["outcomes"]["waf_tier"]["met"] is True
    assert rows["www.example.com"]["outcomes"]["waf_tier"]["met"] is True


def test_waf_measurement_answers_waf_tier_only(client, engagement_id):
    _service(engagement_id, "api.example.com")
    run_id = _command_run(client)
    _tech(
        client,
        {
            "component": "WAF: none detected",
            "source_name": "recon-specialist",
            "provenance": {
                "command_run_id": run_id,
                "waf": {"verdict": "none_detected", "hosts": ["api.example.com"]},
            },
        },
    )

    outcomes = _by_host(client)["api.example.com"]["outcomes"]
    assert outcomes["waf_tier"]["met"] is True
    assert outcomes["tech_fingerprint"]["met"] is False
    assert outcomes["osint"]["met"] is False


def test_malformed_measurement_written_by_patch_is_named_not_counted(client, engagement_id):
    _service(engagement_id, "api.example.com")
    row = _tech(client, {"component": "WAF: none detected"})
    # A PATCH that leaves out the run is refused like a record.
    refused = client.patch(
        f"{INTEL_BASE}/tech-components/{row['id']}",
        json={"payload": {"provenance": {"waf": {"verdict": "none_detected", "hosts": ["api.example.com"]}}}},
    )
    assert refused.status_code == 422, refused.text
    # A row that reached the table malformed anyway closes nothing and is named.
    intel_service.update_intel(
        engagement_id,
        "tech-component",
        row["id"],
        {"provenance": {"waf": {"verdict": "none_detected", "hosts": ["api.example.com"]}}},
    )

    body = client.get(f"{ASSESSMENT_BASE}/coverage-readiness/by-host").json()
    (ignored,) = body["engagement_signals"]["waf_measurements_ignored"]
    assert ignored["intel_id"] == row["id"]
    assert "command_run_id" in ignored["problem"]
    host = {r["host"]: r for r in body["hosts"]}["api.example.com"]
    assert host["outcomes"]["waf_tier"]["met"] is False


@pytest.mark.parametrize(
    "provenance",
    [
        {"waf": {"verdict": "none_detected", "hosts": ["api.example.com"]}},
        {"command_run_id": 1, "waf": {"verdict": "absent", "hosts": ["api.example.com"]}},
        {"command_run_id": 1, "waf": {"verdict": "none_detected", "hosts": []}},
        {"command_run_id": 1, "waf": {"verdict": "none_detected", "hosts": ["api.example.com"], "vendor": "x"}},
    ],
)
def test_malformed_waf_result_is_refused_at_record_time(client, engagement_id, provenance):
    response = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "WAF: none detected", "provenance": provenance},
    )
    assert response.status_code == 422, response.text
    assert "provenance.waf" in response.text


def test_cli_record_schema_mirrors_the_waf_measurement_vocabulary():
    from assess.lib.schema_validation import collect_validation_errors, load_schema

    from app.services.state_manager.coverage_readiness import WAF_MEASUREMENT_VERDICTS

    schema = load_schema("intel-tech-component.schema.json")
    waf = schema["properties"]["provenance"]["properties"]["waf"]
    assert tuple(waf["properties"]["verdict"]["enum"]) == WAF_MEASUREMENT_VERDICTS
    measured = {
        "component": "WAF: none detected",
        "provenance": {
            "command_run_id": 7,
            "waf": {"verdict": "none_detected", "hosts": ["api.example.com"]},
        },
    }
    assert collect_validation_errors(measured, schema) == []
    measured["provenance"]["waf"]["verdict"] = "absent"
    assert collect_validation_errors(measured, schema)


def test_wafw00f_value_flags_mirror_the_cli_target_parser():
    from assess.lib import kali_audit

    from app.services.state_manager.coverage_readiness import WAFW00F_VALUE_FLAGS

    assert WAFW00F_VALUE_FLAGS == kali_audit._WAFW00F_VALUE_FLAGS
