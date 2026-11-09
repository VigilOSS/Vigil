"""Per-field pin for the run-audit backend row validators.

`vigil assess run-audit` refuses a backend row whose shape it cannot vouch for,
and the refusal is the whole guarantee: a field that silently stops being
checked turns a malformed or mis-identified row into accounting the operator
reads as durable truth. The CLI-level suite exercises the families through
argv and mangles one or two fields; this module pins every field of every
family, so dropping a field from the checked set — or widening an exact-value
check to "any type" — fails here rather than passing unnoticed.

Each canonical row below is the shape the backend returns today. For every key
the row carries, the validator must refuse when the key is missing (unless the
family tolerates its absence, listed per family) and must refuse when the key
holds a value of the wrong type. The cross-field relations, the identity
narrowing, the nested command object and the read/write refusal texts are
pinned alongside them.
"""
from __future__ import annotations

import pytest

from assess.commands import run_audit
from assess.lib.client import AssessError


SHA = "a" * 64
RUN_ID = 17
SENTINEL = object()


def _source() -> dict:
    return {
        "id": 31,
        "run_id": RUN_ID,
        "target_key": "service-a",
        "declared_root": ".",
        "path": "src/main.py",
        "content_sha256": SHA,
        "byte_size": 120,
        "line_count": 8,
        "encoding": "utf-8",
        "inventory_status": "included",
        "exclusion_reason": "",
        "parser_status": "parsed",
        "parser_error": "",
    }


def _source_read() -> dict:
    return {
        "id": 41,
        "run_id": RUN_ID,
        "source_id": 31,
        "dispatch_id": 4,
        "dispatch_agent_id": "HUNT-1",
        "attempt": 1,
        "byte_start": 0,
        "byte_end": 120,
        "line_start": 1,
        "line_end": 8,
        "proof_receipt_id": None,
        "source_sha256": SHA,
        "source_path": "src/main.py",
        "target_key": "service-a",
        "encoding": "utf-8",
    }


def _obligation() -> dict:
    return {
        "id": 51,
        "run_id": RUN_ID,
        "identity_key": "flow:input-to-open",
        "obligation_kind": "cross_file_flow",
        "object_type": "source",
        "object_key": "service-a:src/main.py",
        "hard": True,
        "status": "open",
        "resolution": "",
        "proof_receipt_ids": [],
    }


def _candidate() -> dict:
    return {
        "id": 61,
        "run_id": RUN_ID,
        "identity_key": "candidate:path-traversal:main:7",
        "target_key": "service-a",
        "source_id": 31,
        "source_anchor": "src/main.py:7",
        "vulnerability_family": "CWE-22",
        "hypothesis": "user input reaches open",
        "originating_result_id": None,
        "dispatch_id": 4,
        "proof_receipt_ids": [],
        "state": "open",
        "finding_slug": "",
    }


def _tool_signal() -> dict:
    return {
        "id": 81,
        "run_id": RUN_ID,
        "identity_key": "asan:main:7",
        "signal_kind": "reproducible_crash",
        "dispatch_id": 4,
        "target_key": "service-a",
        "source_id": 31,
        "source_anchor": "src/main.py:7",
        "vulnerability_family": "memory-safety",
        "hypothesis": "input reaches unsafe copy",
        "observed_signature": "ASan heap overflow",
        "exact_input_sha256": SHA,
        "command_run_id": 91,
        "proof_receipt_ids": [71],
        "candidate_id": 61,
        "record_sha256": SHA,
        "created_at": "2026-09-09T12:00:00+00:00",
    }


def _discovery_pass() -> dict:
    return {
        "id": 82,
        "run_id": RUN_ID,
        "identity_key": "discovery:pass-1",
        "dispatch_id": 4,
        "frontier_identity_sha256": SHA,
        "terminal_reason": "frontier_exhausted",
        "candidate_identity_keys": ["candidate:path-traversal:main:7"],
        "candidate_delta": 1,
        "proof_receipt_ids": [71],
        "record_sha256": SHA,
        "created_at": "2026-09-09T12:00:00+00:00",
    }


def _code_receipt() -> dict:
    return {
        "id": 83,
        "run_id": RUN_ID,
        "receipt_kind": "variant_check",
        "receipt_id": 101,
        "target_key": "service-a",
        "obligation_id": 51,
        "candidate_ids": [61],
        "signal_ids": [],
        "proof_receipt_ids": [71],
        "obligation_status": "resolved",
        "record_sha256": SHA,
        "created_at": "2026-09-09T12:00:00+00:00",
    }


def _command_receipt() -> dict:
    return {
        "id": 71,
        "audit_run_id": RUN_ID,
        "run_id": RUN_ID,
        "origin_run_id": RUN_ID,
        "producer_dispatch_id": 4,
        "producer_dispatch_agent_id": "HUNT-1",
        "producer_dispatch_agent_role": "code-vuln-hunter",
        "evidence_kind": "command",
        "expected_result": "expected",
        "observed_result": "observed",
        "artifact_id": None,
        "source_read_id": None,
        "command_run_id": 91,
        "artifact_relative_path": "",
        "evidence_sha256": SHA,
        "evidence_health": "healthy",
        "tombstone_reason": "",
        "created_at": "2026-09-09T12:00:00+00:00",
        "command": {
            "id": 91,
            "run_uuid": "command-91",
            "command": "python -m compileall src",
            "argv": ["python", "-m", "compileall", "src"],
            "status": "completed",
        },
    }


def _observed_event() -> dict:
    return {
        "id": 72,
        "audit_run_id": RUN_ID,
        "run_id": RUN_ID,
        "origin_run_id": RUN_ID,
        "producer_dispatch_id": 4,
        "producer_dispatch_agent_id": "HUNT-1",
        "producer_dispatch_agent_role": "code-vuln-hunter",
        "evidence_kind": "http_exchange",
        "expected_result": "expected",
        "observed_result": "observed",
        "artifact_id": 81,
        "source_read_id": None,
        "command_run_id": None,
        "artifact_relative_path": "evidence/event.json",
        "evidence_sha256": SHA,
        "evidence_health": "healthy",
        "tombstone_reason": "",
        "created_at": "2026-09-09T12:00:00+00:00",
    }


def _decision_event() -> dict:
    return {
        "id": "candidate:81",
        "audit_run_id": RUN_ID,
        "object_type": "candidate",
        "object_id": 61,
        "origin_run_id": RUN_ID,
        "from_status": "open",
        "to_status": "rejected",
        "detail": "decisive contrary evidence",
        "proof_receipt_ids": [71],
        "created_at": "2026-09-09T12:00:00+00:00",
    }


# family -> (canonical row builder, keys whose absence the family tolerates)
_FAMILY_ROWS = {
    "sources": (_source, frozenset()),
    "source-read": (_source_read, frozenset({"proof_receipt_id"})),
    "obligation": (_obligation, frozenset()),
    "candidate": (_candidate, frozenset({"source_id", "originating_result_id"})),
    "tool-signal": (_tool_signal, frozenset({"source_id"})),
    "discovery-pass": (_discovery_pass, frozenset()),
    "code-receipt": (_code_receipt, frozenset()),
    "commands": (_command_receipt, frozenset({"artifact_id", "source_read_id"})),
    "observed-events": (
        _observed_event,
        frozenset({"source_read_id", "command_run_id"}),
    ),
    "decision-history": (_decision_event, frozenset({"from_status"})),
}

# Write verbs validate the same rows and say the write may have committed. The
# tuple is the extra identity the write path narrows on.
_WRITE_FAMILIES = {
    "sources": {},
    "source-read": {"requested_source_id": 31},
    "obligation": {"requested_id": 51},
    "candidate": {"requested_id": 61},
    "tool-signal": {"requested_id": 81},
    "discovery-pass": {"requested_id": 82},
    "code-receipt": {"requested_id": 83},
}


def _family_validator(family: str):
    """Resolve a family's row validator through either module shape.

    The consolidated module keys endpoint name, noun and validator off one
    ``_FAMILIES`` table; before that the three lived in parallel dicts. Reading
    both means this pin runs unchanged against either, which is what makes its
    pass on the pre-consolidation module evidence of anything.
    """
    families = getattr(run_audit, "_FAMILIES", None)
    if families is not None:
        return families[family][2]
    return run_audit._ROW_VALIDATORS[family]


def _validate(family: str, row: object, **kwargs) -> dict:
    validator = _family_validator(family)
    return validator(row, operation=f"{family} list", requested_run_id=RUN_ID, **kwargs)


def _keyed_cases() -> list[tuple[str, str]]:
    return [
        (family, key)
        for family, (build, _tolerated) in _FAMILY_ROWS.items()
        for key in build()
    ]


@pytest.mark.parametrize("family", sorted(_FAMILY_ROWS))
def test_canonical_row_is_returned_unchanged(family: str) -> None:
    build, _tolerated = _FAMILY_ROWS[family]
    row = build()
    assert _validate(family, row) is row


@pytest.mark.parametrize(("family", "key"), _keyed_cases())
def test_every_row_field_is_type_checked(family: str, key: str) -> None:
    """A value of the wrong type is refused for every key the row carries."""
    build, _tolerated = _FAMILY_ROWS[family]
    row = build()
    row[key] = SENTINEL
    with pytest.raises(AssessError):
        _validate(family, row)


@pytest.mark.parametrize(("family", "key"), _keyed_cases())
def test_required_row_fields_are_refused_when_missing(family: str, key: str) -> None:
    build, tolerated = _FAMILY_ROWS[family]
    row = build()
    row.pop(key)
    if key in tolerated:
        assert _validate(family, row) is row
        return
    with pytest.raises(AssessError):
        _validate(family, row)


@pytest.mark.parametrize("family", sorted(_FAMILY_ROWS))
def test_a_row_that_is_not_an_object_is_refused(family: str) -> None:
    with pytest.raises(AssessError) as refusal:
        _validate(family, ["not", "an", "object"])
    assert str(refusal.value) == f"run-audit {family} list: malformed backend response"


@pytest.mark.parametrize("family", sorted(_FAMILY_ROWS))
def test_a_row_from_another_run_is_refused(family: str) -> None:
    build, _tolerated = _FAMILY_ROWS[family]
    row = build()
    row["audit_run_id" if "audit_run_id" in row else "run_id"] = RUN_ID + 9000
    with pytest.raises(AssessError):
        _validate(family, row)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("byte_end", -1),
        ("line_end", 0),
    ],
)
def test_source_read_byte_and_line_bounds_stay_in_range(key: str, value: int) -> None:
    row = _source_read()
    row[key] = value
    with pytest.raises(AssessError):
        _validate("source-read", row)


@pytest.mark.parametrize(
    ("start_key", "end_key"),
    [("byte_start", "byte_end"), ("line_start", "line_end")],
)
def test_source_read_refuses_a_span_that_runs_backwards(
    start_key: str, end_key: str
) -> None:
    row = _source_read()
    row[start_key], row[end_key] = 5, 4
    with pytest.raises(AssessError):
        _validate("source-read", row)


def test_discovery_pass_candidate_keys_are_bounded_strings() -> None:
    row = _discovery_pass()
    row["candidate_identity_keys"] = ["x" * 1024]
    assert _validate("discovery-pass", row) is row
    row["candidate_identity_keys"] = ["x" * 1025]
    with pytest.raises(AssessError):
        _validate("discovery-pass", row)


@pytest.mark.parametrize("value", [None, {"migrated_from": "legacy"}])
def test_receipt_legacy_provenance_is_optional_but_typed(value: object) -> None:
    row = _command_receipt()
    row["legacy_derivative_provenance"] = value
    assert _validate("commands", row) is row
    row["legacy_derivative_provenance"] = "legacy"
    with pytest.raises(AssessError):
        _validate("commands", row)


@pytest.mark.parametrize("key", sorted(_command_receipt()["command"]))
@pytest.mark.parametrize("mutation", ["missing", "wrong-type"])
def test_the_nested_command_object_is_checked(key: str, mutation: str) -> None:
    """`run_uuid` is carried but not vouched for; every other key is."""
    row = _command_receipt()
    if mutation == "missing":
        row["command"].pop(key)
    else:
        row["command"][key] = SENTINEL
    if key == "run_uuid":
        assert _validate("commands", row) is row
        return
    with pytest.raises(AssessError):
        _validate("commands", row)


def test_a_command_receipt_without_its_command_is_refused() -> None:
    row = _command_receipt()
    row["command"] = None
    with pytest.raises(AssessError):
        _validate("commands", row)


def test_a_command_receipt_rejects_another_evidence_kind() -> None:
    row = _command_receipt()
    row["evidence_kind"] = "http_exchange"
    with pytest.raises(AssessError):
        _validate("commands", row)


def test_an_observed_event_rejects_a_command_receipt() -> None:
    row = _observed_event()
    row["evidence_kind"] = "command"
    with pytest.raises(AssessError):
        _validate("observed-events", row)


@pytest.mark.parametrize(
    ("key", "value"), [("artifact_id", None), ("artifact_relative_path", "")]
)
def test_an_observed_event_must_name_its_stored_artifact(key: str, value: object) -> None:
    row = _observed_event()
    row[key] = value
    with pytest.raises(AssessError):
        _validate("observed-events", row)


@pytest.mark.parametrize("family", sorted(_WRITE_FAMILIES))
def test_write_refusals_say_the_write_may_have_committed(family: str) -> None:
    build, _tolerated = _FAMILY_ROWS[family]
    extra = _WRITE_FAMILIES[family]
    validator = _family_validator(family)
    row = build()
    assert (
        validator(
            row,
            operation=f"{family} record",
            requested_run_id=RUN_ID,
            write=True,
            **extra,
        )
        is row
    )
    malformed = build()
    malformed.pop("id")
    with pytest.raises(AssessError) as refusal:
        validator(
            malformed,
            operation=f"{family} record",
            requested_run_id=RUN_ID,
            write=True,
            **extra,
        )
    assert str(refusal.value) == (
        f"run-audit {family} record: backend response did not identify the canonical "
        "durable result; the write may have committed, so inspect the relevant "
        "run-audit list/history state and do not retry automatically"
    )


@pytest.mark.parametrize("family", sorted(_WRITE_FAMILIES))
def test_a_write_response_for_another_row_is_refused(family: str) -> None:
    build, _tolerated = _FAMILY_ROWS[family]
    extra = _WRITE_FAMILIES[family]
    if not extra:
        pytest.skip("sources writes narrow on run_id only")
    narrowed = {key: 999_999 for key in extra}
    validator = _family_validator(family)
    with pytest.raises(AssessError):
        validator(
            build(),
            operation=f"{family} record",
            requested_run_id=RUN_ID,
            write=True,
            **narrowed,
        )
