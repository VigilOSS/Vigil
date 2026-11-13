"""`finding record` holds its payload to the contract the backend enforces.

Two record-time axes the CLI did not own:

1. ``verification_status``. ``finding-record.schema.json`` lists all seven
   values because it also validates STORED and captured records, but the create
   request model pins ``Literal["unreviewed"]`` — so a payload that opened at
   ``confirmed`` cleared client validation and came back a 422 with no pointer
   at ``finding verify``, which is the verb that owns every other transition
   (and its evidence gates).
2. ``evidence_type``. ``finding update`` has had ``--evidence-type`` since the
   column landed; ``finding record`` had no flag at all, so the label could only
   be set by hand-editing the JSON payload.

Plus the client half of the ``chain_required`` -> ``chain_rationale`` pair gate:
the schema now carries the same if/then the backend enforces, so the refusal
lands before the POST.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import record_finding
from assess.lib.client import AssessError
from assess.lib.schema_validation import collect_validation_errors
from _fake_client import StubClient


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    record_finding.register(parser.add_subparsers(dest="command"))
    return parser


def _normalize(payload: dict, **kwargs):
    return record_finding._normalize_payload(
        payload, agent_name="hunter-a", candidate_slug="VA-001", **kwargs
    )


@pytest.mark.parametrize(
    "status",
    ["confirmed", "downgraded", "disputed", "pending_runtime_proof", "blocked", "false_positive"],
)
def test_record_refuses_a_verification_status_the_backend_would_reject(status, capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        _normalize({"title": "Missing authorization", "verification_status": status})

    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert status in err
    assert "finding verify" in err


def test_record_still_accepts_an_explicit_unreviewed() -> None:
    payload = _normalize({"title": "Missing authorization", "verification_status": "unreviewed"})

    assert payload["verification_status"] == "unreviewed"


def test_record_accepts_an_evidence_type_flag() -> None:
    args = _parser().parse_args(
        ["record", "vulnerability-analyst", "f.json", "--evidence-type", "theoretical"]
    )

    assert args.evidence_type == "theoretical"


def test_the_evidence_type_flag_lands_on_the_payload() -> None:
    payload = _normalize({"title": "Blind SQLi"}, evidence_type="theoretical")

    assert payload["evidence_type"] == "theoretical"


def test_evidence_type_stays_absent_when_nobody_labels_it() -> None:
    payload = _normalize({"title": "Blind SQLi"})

    assert "evidence_type" not in payload


def test_a_flag_that_contradicts_the_payload_is_refused(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        _normalize(
            {"title": "Blind SQLi", "evidence_type": "code-inferred"},
            evidence_type="theoretical",
        )

    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert "code-inferred" in err and "theoretical" in err


def test_a_flag_that_restates_the_payload_is_accepted() -> None:
    payload = _normalize(
        {"title": "Blind SQLi", "evidence_type": "theoretical"}, evidence_type="theoretical"
    )

    assert payload["evidence_type"] == "theoretical"


def test_the_schema_holds_chain_required_to_its_rationale() -> None:
    """The client mirror of ``_validate_chain_rationale_pair`` (backend)."""
    payload = {
        "title": "Internal host reachable from the URL parser",
        "severity": "medium",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "ssrf",
        "root_cause_key": "",
        "auth_context": "anonymous",
        "canonical_location": "https://app.example/fetch",
        "summary": "Summary",
        "evidence_ref": "",
        "notes": "",
        "details": {"evidence": "proof", "impact": "impact", "chain_required": True},
    }

    errors = collect_validation_errors(payload, record_finding._FINDING_SCHEMA)
    assert any("chain_rationale" in error for error in errors), errors

    payload["details"]["chain_rationale"] = "Reaches the metadata service once VA-002 lands."
    assert collect_validation_errors(payload, record_finding._FINDING_SCHEMA) == []

    # An explicit "this stands alone" is not dragged in with the flag's presence.
    payload["details"] = {"evidence": "proof", "impact": "impact", "chain_required": False}
    assert collect_validation_errors(payload, record_finding._FINDING_SCHEMA) == []


class _Cfg:
    def __init__(self, engagement_dir) -> None:
        self.engagement_dir = str(engagement_dir)
        self.base_url = "http://backend.invalid"
        self.engagement_key = "acme-web"


class _FakeClient(StubClient):
    """Every HTTP read/write `finding record` makes, and nothing above it."""

    def __init__(self, stored: dict | None = None) -> None:
        self.stored = stored
        self.posts: list[tuple[str, dict]] = []

    def get(self, path: str):
        if path == "findings?view=list":
            return [self.stored] if self.stored else []
        if path.startswith("findings/"):
            if self.stored is None:
                raise AssessError("HTTP 404 not found")
            return dict(self.stored)
        if path.startswith("dispatches/"):
            return {"agent_id": path.split("/", 1)[1]}
        if path == "code/repos":
            return [
                {
                    "id": 1,
                    "repo_key": "acme-service",
                    "active_generation": 4,
                    "source_manifest_digest": "ab" * 32,
                }
            ]
        if path.startswith("code/repos/"):
            return {
                "id": int(path.rsplit("/", 1)[1]),
                "repo_key": "acme-service",
                "active_generation": 4,
                "source_manifest_digest": "ab" * 32,
            }
        raise AssessError(f"unexpected GET {path}")

    def post(self, path: str, payload: dict):
        self.posts.append((path, payload))
        return {"finding": {"slug": payload.get("slug", ""), "title": payload.get("title", "t")}}

    def post_event(self, _payload: dict) -> None:
        return None


def _record_args(tmp_path, payload: dict, *, update_slug: str = "", **over):
    json_path = tmp_path / "finding.json"
    json_path.write_text(json.dumps(payload), encoding="utf-8")
    args = _parser().parse_args(
        [
            "record",
            "vulnerability-analyst",
            str(json_path),
            "--agent-id",
            "HUNT-1",
            *(["--update", update_slug] if update_slug else []),
        ]
    )
    args.engagement_dir = str(tmp_path)
    for key, value in over.items():
        setattr(args, key, value)
    return args


def _run_record(tmp_path, monkeypatch, payload, *, stored=None, update_slug=""):
    fake = _FakeClient(stored)
    monkeypatch.setattr(record_finding, "load_config", lambda *a, **k: _Cfg(tmp_path))
    monkeypatch.setattr(record_finding, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(record_finding, "next_finding_id", lambda *a, **k: "VA-001")
    record_finding.run(_record_args(tmp_path, payload, update_slug=update_slug))
    return fake


def _network_payload(**over) -> dict:
    payload = {
        "title": "IDOR in /api/orders/{id}",
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "auth_context": "member",
        "canonical_location": "https://app.example/api/orders",
        "summary": "Any member reads another member's order.",
        "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
    }
    payload.update(over)
    return payload


def _source_payload(**over) -> dict:
    payload = {
        "title": "Unchecked length reaches a fixed-size copy",
        "severity": "high",
        "defect_family": "buffer-overflow",
        "root_cause_key": "parse_packet-length",
        "canonical_location": "file:src/parser.c:41",
        "summary": "An attacker-controlled length reaches a fixed-size copy.",
        "details": {"evidence": "The copy length is attacker controlled.", "impact": "Memory corruption"},
    }
    payload.update(over)
    return payload


# -- The refusal carries the contract sections it needs, not the whole verb ----


def _refused_record(tmp_path, monkeypatch, capsys, payload) -> str:
    monkeypatch.setattr(record_finding, "load_config", lambda *a, **k: _Cfg(tmp_path))
    monkeypatch.setattr(record_finding, "AssessmentClient", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(record_finding, "next_finding_id", lambda *a, **k: "VA-001")

    with pytest.raises(SystemExit) as exit_info:
        record_finding.run(_record_args(tmp_path, payload))

    assert exit_info.value.code == 1
    return capsys.readouterr().err


def test_a_rejected_key_prints_the_sections_of_the_fields_it_points_at(
    tmp_path, monkeypatch, capsys
):
    """The refusal names the error, the did-you-mean, and the contract lines for
    the fields that fix it, plus the pointer that prints any other field.

    The sections stay scoped to the offending fields so the lines that matter
    are not buried under the whole ~48 KB ``finding record`` contract.
    """
    payload = _network_payload()
    payload["details"]["risk"] = "High: any member can read another member's order."

    err = _refused_record(tmp_path, monkeypatch, capsys, payload)

    assert "payload.details.risk is not allowed" in err
    assert "details.severity_rationale" in err
    lines = err.splitlines()
    assert any(line.startswith("  - details.impact (") for line in lines), err
    assert any(line.startswith("  - details.severity_rationale (") for line in lines), err
    assert "`vigil assess contract finding record --field <name>`" in err
    # Bounded: the sections for the named fields, never the whole verb.
    assert len(err.encode("utf-8")) < 4096, len(err.encode("utf-8"))
    # The errors come last, so a truncated tail still shows them.
    assert "risk" in lines[-1], err


def test_a_bad_enum_value_prints_that_field_s_domain(tmp_path, monkeypatch, capsys):
    err = _refused_record(
        tmp_path, monkeypatch, capsys, _network_payload(severity="urgent")
    )

    assert "payload.severity must be one of" in err
    section = [line for line in err.splitlines() if line.startswith("  - severity (")]
    assert section and "one of: info, low, medium, high, critical" in section[0], err
    assert len(err.encode("utf-8")) < 4096


def test_an_unrouteable_key_still_names_itself_and_the_pointer(
    tmp_path, monkeypatch, capsys
):
    payload = _network_payload()
    payload["details"]["fizzbuzz"] = "x"

    err = _refused_record(tmp_path, monkeypatch, capsys, payload)

    assert "payload.details.fizzbuzz is not allowed" in err
    assert "`vigil assess contract finding record --field <name>`" in err
    assert len(err.encode("utf-8")) < 4096
    assert "fizzbuzz" in err.splitlines()[-1], err


def test_the_errors_still_print_when_the_contract_sections_cannot_render(
    tmp_path, monkeypatch, capsys
):
    """The sections are help; the errors are the refusal. A renderer fault must
    not replace them with a traceback."""

    def _broken(*_args, **_kwargs):
        raise KeyError("details.risk")

    monkeypatch.setattr(record_finding, "refusal_sections", _broken)
    payload = _network_payload()
    payload["details"]["risk"] = "High."

    err = _refused_record(tmp_path, monkeypatch, capsys, payload)

    assert "payload.details.risk is not allowed" in err
    assert "risk" in err.splitlines()[-1], err
    assert "`vigil assess contract finding record --field <name>`" in err


# -- Defect: a title-only re-record moved the dedup axes ----------------------


def test_update_does_not_derive_the_dedup_axes_from_a_corrected_title(
    tmp_path, monkeypatch, capsys
):
    """``defect_family`` is an INVALIDATE axis; title is deliberately KEEP.

    The helper defaulted ``defect_family`` (and ``summary``) to the TITLE before
    schema validation, so ``finding record --update <slug>`` with a corrected
    title sent a changed dedup family and a one-line summary over the author's
    real one — returning ``changed_axes: ["title", "defect_family"]`` and
    resetting the verdict. ``auth_context`` is the same shape with a constant:
    it defaulted to ``anonymous`` over whatever privilege was stored.
    """
    stored = {
        "slug": "VA-007",
        "title": "IDOR in /api/orders",
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "auth_context": "member",
        "canonical_location": "https://app.example/api/orders",
        "workflow_status": "active",
        "provenance": {"agent_id": "HUNT-1"},
    }
    fake = _run_record(
        tmp_path,
        monkeypatch,
        {
            "title": "IDOR in /api/orders/{id} reads another member's order",
            "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
        },
        stored=stored,
        update_slug="VA-007",
    )
    capsys.readouterr()

    assert len(fake.posts) == 1
    _path, sent = fake.posts[0]
    assert sent["slug"] == "VA-007"
    assert sent["title"].endswith("another member's order")
    # Empty is how the backend upsert spells "preserve what is stored".
    assert sent["defect_family"] == ""
    assert sent["summary"] == ""
    assert sent["root_cause_key"] == ""
    assert sent["canonical_location"] == ""
    # auth_context is non-nullable server-side, so it is seeded from the row.
    assert sent["auth_context"] == "member"


def test_a_new_record_still_falls_back_to_its_title(tmp_path, monkeypatch, capsys):
    """The title fallback is a sane floor for a finding that has no stored row."""
    fake = _run_record(
        tmp_path,
        monkeypatch,
        {
            "title": "IDOR in /api/orders/{id}",
            "root_cause_key": "missing-object-authz",
            "canonical_location": "https://app.example/api/orders",
            "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
        },
    )
    capsys.readouterr()

    _path, sent = fake.posts[0]
    assert sent["defect_family"] == "IDOR in /api/orders/{id}"
    assert sent["summary"] == "IDOR in /api/orders/{id}"
    assert sent["auth_context"] == "anonymous"


def test_update_still_honours_an_explicitly_authored_dedup_axis(
    tmp_path, monkeypatch, capsys
):
    stored = {
        "slug": "VA-007",
        "title": "IDOR in /api/orders",
        "defect_family": "access-control",
        "auth_context": "member",
        "workflow_status": "active",
        "provenance": {"agent_id": "HUNT-1"},
    }
    fake = _run_record(
        tmp_path,
        monkeypatch,
        {
            "title": "IDOR in /api/orders",
            "defect_family": "broken-object-authz",
            "auth_context": "admin",
            "summary": "Rewritten claim.",
            "details": {"evidence": "e", "impact": "i"},
        },
        stored=stored,
        update_slug="VA-007",
    )
    capsys.readouterr()

    _path, sent = fake.posts[0]
    assert sent["defect_family"] == "broken-object-authz"
    assert sent["auth_context"] == "admin"
    assert sent["summary"] == "Rewritten claim."


# -- Defect: the evidence-ref warning fired on source-derived findings --------


@pytest.mark.parametrize(
    ("payload", "exempt"),
    [
        (_source_payload(provenance={"code_snapshot": {"repo_id": 1, "repo_generation": 4, "source_manifest_digest": "ab" * 32}}), True),
        (_source_payload(provenance={}), False),
        (_source_payload(provenance={"code_snapshot": {"repo_id": 1}}), False),
        (_network_payload(), False),
    ],
)
def test_the_source_bound_evidence_exemption_predicate(payload, exempt):
    """Source-bound location PLUS a complete code-snapshot binding, or nothing.

    Paired with report-readiness by design: silencing only the record-time
    warning would hide a blocker that still fires at report time.
    """
    assert record_finding.source_bound_evidence_exempt(payload) is exempt


def test_a_source_derived_file_finding_is_not_warned_about_evidence(
    tmp_path, monkeypatch, capsys
):
    """Its proof is the sealed source and its source-observation receipts.

    The binding is derived here from the repository's current identity, so the
    record carries one even when the author transcribed none.
    """
    fake = _run_record(tmp_path, monkeypatch, _source_payload())
    err = capsys.readouterr().err

    assert len(fake.posts) == 1
    assert fake.posts[0][1]["provenance"]["code_snapshot"]["repo_generation"] == 4
    assert "evidence_ref" not in err, err


def test_a_network_finding_with_no_evidence_is_still_warned(
    tmp_path, monkeypatch, capsys
):
    _run_record(tmp_path, monkeypatch, _network_payload())
    err = capsys.readouterr().err

    assert "no evidence_ref set" in err


# -- Defect: the record door refused provenance the update door accepted ------


def test_the_record_door_accepts_the_provenance_the_skills_prescribe(
    tmp_path, monkeypatch, capsys
):
    """``provenance`` was creatable-or-maintainable, pick one.

    The record door validated the whole payload against a four-key provenance
    vocabulary and refused ``reported_by`` / ``captured_at`` / ``artifact_ref`` /
    ``evidence_quote`` — which the update door accepted, the backend stored, the
    report-generation skill prescribes and the operator views render.
    """
    prescribed = {
        "reported_by": "Acme Security Research",
        "captured_at": "2026-10-08T11:04:00Z",
        "artifact_ref": "scans/idor-capture.txt",
        "evidence_quote": "HTTP/1.1 200 OK",
    }
    fake = _run_record(
        tmp_path,
        monkeypatch,
        _network_payload(provenance=dict(prescribed)),
    )
    capsys.readouterr()

    assert len(fake.posts) == 1
    sent = fake.posts[0][1]["provenance"]
    for key, value in prescribed.items():
        assert sent[key] == value


def test_the_record_door_still_refuses_an_unknown_provenance_key(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(record_finding, "load_config", lambda *a, **k: _Cfg(tmp_path))
    monkeypatch.setattr(record_finding, "AssessmentClient", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(record_finding, "next_finding_id", lambda *a, **k: "VA-001")

    with pytest.raises(SystemExit):
        record_finding.run(
            _record_args(
                tmp_path, _network_payload(provenance={"reportedby": "Acme"})
            )
        )

    lines = [line for line in capsys.readouterr().err.splitlines() if line.strip()]
    assert "reportedby" in lines[-1] and "reported_by" in lines[-1], lines[-1]


# -- What the backend fills in is named, never silent ---------------------------


class _EnvelopeClient(_FakeClient):
    def post(self, path: str, payload: dict):
        response = super().post(path, payload)
        response["derived"] = [{
            "field": "severity",
            "value": "medium",
            "derived_from": "cvss_vector",
            "detail": "severity was not supplied; stored the value of cvss_vector",
        }]
        response["advisories"] = [{"kind": "acme_advisory", "detail": "Acme advisory text."}]
        return response


def _run_envelope_record(tmp_path, monkeypatch, **over):
    fake = _EnvelopeClient()
    monkeypatch.setattr(record_finding, "load_config", lambda *a, **k: _Cfg(tmp_path))
    monkeypatch.setattr(record_finding, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(record_finding, "next_finding_id", lambda *a, **k: "VA-001")
    record_finding.run(_record_args(tmp_path, _network_payload(), **over))


def test_record_names_each_derived_value_and_advisory_on_stderr(
    tmp_path, monkeypatch, capsys
):
    _run_envelope_record(tmp_path, monkeypatch)

    err = capsys.readouterr().err
    assert "finding record: derived severity" in err
    assert "stored the value of cvss_vector" in err
    assert "finding record: advisory [acme_advisory] Acme advisory text." in err


def test_record_quiet_silences_advisories_but_still_names_derived_values(
    tmp_path, monkeypatch, capsys
):
    _run_envelope_record(tmp_path, monkeypatch, quiet=True)

    err = capsys.readouterr().err
    assert "finding record: derived severity" in err
    assert "advisory [acme_advisory]" not in err
    count_line = next(line for line in err.splitlines() if "not printed" in line)
    assert "1 advisory" in count_line
    assert "acme_advisory" in count_line
    assert "--quiet" in count_line
