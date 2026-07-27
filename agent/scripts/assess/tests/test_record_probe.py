"""CLI tests for `vigil assess record-probe` (the single probe-recording verb).

record-probe absorbed the former record-attempt: it POSTs EVERY probe outcome to
the shared ``probe-runs`` route — the COVERING pair (tested|signal, evidence
required) and the NON-covering four (attempted|blocked|no-signal|error, evidence
optional). Backend + runtime are stubbed. These pin: the full argparse status
vocabulary, the CONDITIONAL evidence gate (required iff covering), the FK-link +
default-cascade override/suppress flags (--work-item-ids / --resolve-surface /
--no-drain) always being available, the named input-slot round-trip, the shared
--finding slug->id resolution + 404, and the WARN-first out-of-vocab family.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import record_probe


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self, findings: dict | None = None) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.gets: list[str] = []
        self._findings = findings or {}

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {"id": len(self.posts), **payload}

    def get(self, endpoint: str) -> dict:
        self.gets.append(endpoint)
        slug = endpoint.split("/", 1)[1]
        if slug not in self._findings:
            from assess.lib.client import AssessError

            raise AssessError(f"HTTP 404: finding {slug} not found")
        return self._findings[slug]

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    record_probe.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(record_probe, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(record_probe, "AssessmentClient", lambda *a, **k: fake)


# -- covering path -------------------------------------------------------------


def test_record_probe_covering_roundtrip_with_links(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe",
            "--result-status", "tested",
            "--attack-family", "IDOR",  # normalized to idor
            "--target-host", "app.example.com",
            "--target-path", "/orders/1001",
            "--input-slot", "path:id",  # named input preserved
            "--auth-context", "member",
            "--evidence-ref", "scans/idor-orders.txt",
            "--request-variant-id", "42",
            "--service-id", "7",
            "--coverage-item-id", "77",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()

    endpoint, payload = fake.posts[0]
    assert endpoint == "probe-runs"
    assert payload["result_status"] == "tested"
    assert payload["attack_family"] == "idor"
    assert payload["input_slot"] == "path:id"  # named slot round-trips
    assert payload["evidence_ref"] == "scans/idor-orders.txt"
    assert payload["request_variant_id"] == 42
    assert payload["service_id"] == 7
    assert payload["coverage_item_id"] == 77


def test_record_probe_covering_requires_evidence(tmp_path, monkeypatch, capsys):
    """A covering verdict with no --evidence-ref is not coverage — hard error, no post."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "tested", "--attack-family", "ssrf",
            "--target-host", "h", "--input-slot", "query:x", "--auth-context", "anonymous",
        ],
        str(tmp_path),
    )
    with pytest.raises(SystemExit):
        record_probe.run(args)
    err = capsys.readouterr().err
    assert "--evidence-ref is required" in err
    assert fake.posts == []


def test_record_probe_signal_requires_evidence(tmp_path, monkeypatch, capsys):
    """`signal` is covering too — evidence is mandatory for it as well."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "signal", "--attack-family", "ssrf",
            "--target-host", "h", "--input-slot", "query:x", "--auth-context", "anonymous",
        ],
        str(tmp_path),
    )
    with pytest.raises(SystemExit):
        record_probe.run(args)
    assert "--evidence-ref is required" in capsys.readouterr().err
    assert fake.posts == []


def test_record_probe_signal_without_outcome_assertion_is_inconclusive(
    tmp_path, monkeypatch, capsys
):
    """A status/size-only signal is evidence of a request, not of a bypass."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "signal", "--attack-family", "idor",
            "--target-host", "h", "--input-slot", "path:id", "--auth-context", "member",
            "--evidence-ref", "scans/response.txt", "--observed-status", "200",
        ],
        str(tmp_path),
    )

    record_probe.run(args)

    err = capsys.readouterr().err
    assert "--outcome-assertion" in err
    assert fake.posts[0][1]["result_status"] == "attempted"
    assert fake.posts[0][1]["outcome_assertion"] == ""


# -- non-covering path (folded in from the former record-attempt) --------------


@pytest.mark.parametrize("status", ["attempted", "blocked", "no-signal", "error"])
def test_record_probe_noncovering_needs_no_evidence(tmp_path, monkeypatch, capsys, status):
    """The four non-covering statuses record WITHOUT --evidence-ref (touched-but-
    inconclusive leads are captured for the resume-brief Attempts ledger)."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", status, "--attack-family", "SSRF",
            "--lens", "tenant-boundary", "--target-host", "api.example.com",
            "--target-path", "/fetch", "--target-port", "443",
            "--input-slot", "query:url", "--auth-context", "member",
            "--notes", "WAF 403 on internal hosts",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()
    endpoint, payload = fake.posts[0]
    assert endpoint == "probe-runs"
    assert payload["result_status"] == status
    assert payload["attack_family"] == "ssrf"  # normalized
    assert payload["lens"] == "tenant-boundary"
    assert payload["target_port"] == 443
    assert payload["tool_name"] == "manual"  # helper default
    assert "finding_id" not in payload  # no --finding given


def test_record_probe_rejects_unknown_status(tmp_path, monkeypatch, capsys):
    """A --result-status miss re-renders through the scoped formatter (did-you-mean,
    no usage dump) and appends the contract pointer — on the parse ERROR path."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    with pytest.raises(SystemExit):
        _parse(
            ["record-probe", "--result-status", "confirmed", "--attack-family", "ssrf",
             "--evidence-ref", "x", "--target-host", "h", "--input-slot", "query:x",
             "--auth-context", "anon"],
            str(tmp_path),
        )
    err = capsys.readouterr().err
    assert "--result-status 'confirmed' is not valid" in err
    assert "See: vigil assess contract record-probe" in err
    assert "usage:" not in err  # scoped: no multi-line usage dump
    assert fake.posts == []


# -- default-cascade override/suppress flags -----------------------------------


def test_record_probe_cascade_override_flags_plumb_through(tmp_path, monkeypatch, capsys):
    """--work-item-ids / --resolve-surface / --no-drain thread into the payload so
    the backend default cascade can be narrowed or suppressed (1b)."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "tested", "--attack-family", "idor",
            "--target-host", "h", "--input-slot", "path:id", "--auth-context", "member",
            "--evidence-ref", "e", "--work-item-ids", "3", "4", "--resolve-surface", "9",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()
    payload = fake.posts[0][1]
    assert payload["work_item_ids"] == [3, 4]
    assert payload["resolve_surface_id"] == 9
    assert "no_drain" not in payload  # only sent when the flag is set


def test_record_probe_no_drain_flag(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "tested", "--attack-family", "idor",
            "--target-host", "h", "--input-slot", "path:id", "--auth-context", "member",
            "--evidence-ref", "e", "--coverage-item-id", "77", "--no-drain",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()
    payload = fake.posts[0][1]
    assert payload["no_drain"] is True
    assert payload["coverage_item_id"] == 77


def test_record_probe_default_omits_cascade_control_fields(tmp_path, monkeypatch, capsys):
    """The default payload carries no cascade-control keys, so the BACKEND default
    derivation stays in force (recording auto-drains/advances covering probes)."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "tested", "--attack-family", "idor",
            "--target-host", "h", "--input-slot", "path:id", "--auth-context", "member",
            "--evidence-ref", "e", "--coverage-item-id", "77",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()
    payload = fake.posts[0][1]
    assert "work_item_ids" not in payload
    assert "resolve_surface_id" not in payload
    assert "no_drain" not in payload
    assert payload["coverage_item_id"] == 77  # link is still sent (cascade keys on it)


# -- --finding resolution ------------------------------------------------------


def test_record_probe_resolves_finding_slug(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(findings={"VA-047": {"id": 91, "slug": "VA-047"}})
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "signal", "--attack-family", "ssrf",
            "--target-host", "api.example.com", "--input-slot", "query:url",
            "--auth-context", "anonymous", "--evidence-ref", "scans/ssrf.txt",
            "--outcome-assertion", "OOB callback nonce matched the request",
            "--finding", "VA-047",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()
    assert fake.gets == ["findings/VA-047"]
    assert fake.posts[0][1]["finding_id"] == 91
    assert fake.posts[0][1]["outcome_assertion"] == "OOB callback nonce matched the request"


def test_record_probe_finding_numeric_id_passthrough(tmp_path, monkeypatch, capsys):
    """A bare integer --finding is used directly without a slug lookup (works on a
    non-covering attempt too)."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "error", "--attack-family", "sqli",
            "--target-host", "app.example.com", "--input-slot", "body:q",
            "--auth-context", "anonymous", "--finding", "12",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()
    assert fake.gets == []  # numeric id => no GET
    assert fake.posts[0][1]["finding_id"] == 12


def test_record_probe_missing_finding_slug_errors(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(findings={})
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "attempted", "--attack-family", "ssrf",
            "--target-host", "app.example.com", "--input-slot", "query:x",
            "--auth-context", "anonymous", "--finding", "NOPE-1",
        ],
        str(tmp_path),
    )
    from assess.lib.client import AssessError

    with pytest.raises(AssessError):
        record_probe.run(args)
    assert fake.posts == []  # never records when the link cannot resolve


def test_record_probe_unknown_family_warns_but_records(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-probe", "--result-status", "tested", "--attack-family", "not-a-real-class",
            "--target-host", "h", "--input-slot", "query:x", "--auth-context", "anonymous",
            "--evidence-ref", "e",
        ],
        str(tmp_path),
    )
    record_probe.run(args)
    err = capsys.readouterr().err
    assert "WARN" in err and "not a known" in err
    assert fake.posts[0][1]["attack_family"] == "not-a-real-class"


# -- WS3 required-input guards (run()-time, block-not-warn) --------------------


def _probe_argv(**overrides) -> list[str]:
    """A record-probe argv that PASSES every guard; overrides tweak one field."""
    base = {
        "--result-status": "tested",
        "--attack-family": "idor",
        "--target-host": "app.example.com",
        "--input-slot": "path:id",
        "--auth-context": "member",
        "--evidence-ref": "scans/e.txt",
    }
    base.update(overrides)
    argv = ["record-probe"]
    for k, v in base.items():
        if v is not None:
            argv += [k, v]
    return argv


def test_record_probe_rejects_missing_input_slot(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(_probe_argv(**{"--input-slot": None}), str(tmp_path))
    with pytest.raises(SystemExit):
        record_probe.run(args)
    err = capsys.readouterr().err
    assert "--input-slot is required" in err
    assert "See: vigil assess contract record-probe" in err
    assert fake.posts == []


def test_record_probe_rejects_unknown_input_slot(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(_probe_argv(**{"--input-slot": "unknown"}), str(tmp_path))
    with pytest.raises(SystemExit):
        record_probe.run(args)
    assert "--input-slot is required" in capsys.readouterr().err
    assert fake.posts == []


def test_record_probe_input_slot_bad_prefix_did_you_mean(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(_probe_argv(**{"--input-slot": "quer:uid"}), str(tmp_path))
    with pytest.raises(SystemExit):
        record_probe.run(args)
    err = capsys.readouterr().err
    assert "not a known slot class" in err
    assert "Did you mean: query?" in err
    assert "See: vigil assess contract record-probe" in err
    assert fake.posts == []


def test_record_probe_rejects_missing_auth_context(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(_probe_argv(**{"--auth-context": None}), str(tmp_path))
    with pytest.raises(SystemExit):
        record_probe.run(args)
    err = capsys.readouterr().err
    assert "--auth-context is required" in err
    assert "See: vigil assess contract record-probe" in err
    assert fake.posts == []


def test_record_probe_rejects_missing_target_anchor(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    # No --target-host and no FK anchor => unmappable => reject.
    args = _parse(_probe_argv(**{"--target-host": None}), str(tmp_path))
    with pytest.raises(SystemExit):
        record_probe.run(args)
    err = capsys.readouterr().err
    assert "--target-host is required" in err
    assert "--request-variant-id" in err  # merged verb ALWAYS exposes the FK anchor
    assert fake.posts == []


def test_record_probe_target_anchor_satisfied_by_fk(tmp_path, monkeypatch, capsys):
    """A --request-variant-id FK anchors the probe even with no --target-host."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        _probe_argv(**{"--target-host": None}) + ["--request-variant-id", "42"],
        str(tmp_path),
    )
    record_probe.run(args)
    capsys.readouterr()
    assert fake.posts[0][1]["request_variant_id"] == 42


def test_record_probe_missing_required_flag_shows_pointer(tmp_path, monkeypatch, capsys):
    """A missing argparse-required flag (--attack-family) surfaces the contract
    pointer on the ERROR path (not just on --help)."""
    with pytest.raises(SystemExit):
        _parse(
            ["record-probe", "--result-status", "blocked", "--target-host", "h",
             "--input-slot", "query:x", "--auth-context", "anonymous"],
            str(tmp_path),
        )
    err = capsys.readouterr().err
    assert "See: vigil assess contract record-probe" in err


# -- evidence_ref shape: WARN, never block -------------------------------------
#
# `finding record` has warned on composite / URL / prose refs for a while;
# record-probe writes the same field and had no check, so a ref that can never be
# indexed as proof entered the ledger unremarked. The check WARNS: losing a
# recorded probe mid-hunt costs more than a malformed pointer that
# check-phase-readiness will flag anyway.


def _install_probe_args_config(monkeypatch, tmp_path) -> None:
    """probe_args resolves the engagement itself, so point it at tmp_path too."""
    from assess.lib import probe_args

    monkeypatch.setattr(probe_args, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))


@pytest.mark.parametrize(
    ("ref", "marker"),
    [
        ("scans/a.txt;scans/b.txt", "is not a single engagement-local path"),
        ("command-runs 56052/56054/56060", "is not a single engagement-local path"),
        ("https://example.test/proof", "is a URL, not a registered artifact path"),
        ("see my notes above", "is not a single engagement-local path"),
        ("scans/does-not-exist.txt", "looks like a path but nothing exists there"),
    ],
)
def test_record_probe_warns_on_malformed_evidence_ref_but_records(
    tmp_path, monkeypatch, capsys, ref, marker
):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    _install_probe_args_config(monkeypatch, tmp_path)
    args = _parse(_probe_argv(**{"--evidence-ref": ref}), str(tmp_path))

    record_probe.run(args)

    err = capsys.readouterr().err
    assert "record-probe: warning" in err
    assert marker in err
    # HARNESS, NOT GATE: the probe still lands, with the ref stored verbatim.
    assert len(fake.posts) == 1
    assert fake.posts[0][1]["evidence_ref"] == ref


def test_record_probe_is_silent_for_an_existing_engagement_artifact(
    tmp_path, monkeypatch, capsys
):
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "e.txt").write_text("proof", encoding="utf-8")
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    _install_probe_args_config(monkeypatch, tmp_path)
    args = _parse(_probe_argv(), str(tmp_path))

    record_probe.run(args)

    assert "warning" not in capsys.readouterr().err
    assert len(fake.posts) == 1


def test_record_probe_evidence_ref_check_survives_unresolvable_config(
    tmp_path, monkeypatch, capsys
):
    """Config resolution failure must degrade to a shape check, never abort the write."""
    from assess.lib import probe_args

    def _boom(*a, **k):
        raise SystemExit("Cannot resolve engagement directory.")

    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    monkeypatch.setattr(probe_args, "load_config", _boom)
    args = _parse(_probe_argv(**{"--evidence-ref": "see my notes above"}), str(tmp_path))

    record_probe.run(args)

    assert "is not a single engagement-local path" in capsys.readouterr().err
    assert len(fake.posts) == 1
