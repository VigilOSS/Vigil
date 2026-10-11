"""Target-scope admission contracts: `vigil assess filter-scope` and endpoint ingest.

These cover the in-scope-host boundary (ADR 0019 keeps it: it protects
third parties who did not consent, not the operator). The `PreToolUse`
command-filtering hook that this file also used to exercise is gone — see
ADR 0019, "PreToolUse command-filtering hooks are not reintroduced".
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# Wildcard-includes-apex semantics — `vigil assess filter-scope` regressions (1F.1)
# ---------------------------------------------------------------------------


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_filter_scope_module():
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = (
        Path(__file__).resolve().parents[3]
        / "agent"
        / "scripts"
        / "assess"
        / "commands"
        / "filter_scope.py"
    )
    spec = importlib.util.spec_from_file_location("test_filter_scope_apex_module", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stub_decided_hosts(monkeypatch, module) -> None:
    """Return no recorded scope decisions without dialling the orchestrator.

    These tests are about which hosts scope admits, not about the Vendor-SaaS
    decision fetch. Left unstubbed, ``_vendor_saas_decided_hosts`` builds a real
    ``AssessmentClient`` against the fake ``base_url`` above and spends 3.02s of
    wall clock per test in ``AssessmentClient``'s retry backoff (three attempts,
    1s then 2s) before its ``except AssessError`` branch returns this same empty
    set — and how fast it gets there depends on the host's DNS. Stubbing it is
    the same idiom ``test_filter_scope_allows_same_file_output`` already uses.
    """
    monkeypatch.setattr(module, "_vendor_saas_decided_hosts", lambda _cfg: set())


def _run_filter_scope(monkeypatch, engagement_dir: Path, lines: list[str], capsys):
    module = _load_filter_scope_module()
    input_file = engagement_dir / "input.txt"
    input_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir_flag=None: SimpleNamespace(
            engagement_dir=str(engagement_dir),
            engagement_key="eng",
            base_url="http://example.test",),
    )
    _stub_decided_hosts(monkeypatch, module)
    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement_dir),
            input_file=str(input_file),
            output=None,
        )
    )
    return capsys.readouterr()


def test_apex_filter_with_wildcard_only_admits_apex(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Wildcard scope admits the bare apex (HackerOne / Bugcrowd / VDP convention)."""
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["*.example.test"]}),
        encoding="utf-8",
    )

    captured = _run_filter_scope(
        monkeypatch,
        engagement_dir,
        [
            "https://example.test/",
            "https://example.test/login",
            "https://corp.example.test/api",
        ],
        capsys,
    )

    assert captured.out.splitlines() == [
        "https://example.test/",
        "https://example.test/login",
        "https://corp.example.test/api",
    ]


def test_filter_scope_streams_stdin(monkeypatch, tmp_path: Path, capsys) -> None:
    """``filter-scope`` reads stdin lazily without buffering the full stream.

    A generator-backed StringIO substitute for ``sys.stdin`` exposes the
    streaming contract: after the first matching line is emitted the
    underlying generator must still have items left, which only holds when
    the command iterates the file object lazily rather than calling
    ``readlines()``.
    """
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["target.example"]}),
        encoding="utf-8",
    )

    module = _load_filter_scope_module()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir_flag=None: SimpleNamespace(
            engagement_dir=str(engagement_dir),
            engagement_key="eng",
            base_url="http://example.test",),
    )

    consumed: list[str] = []

    def _gen():
        for line in [
            "https://target.example/a\n",
            "https://target.example/b\n",
            "https://target.example/c\n",
        ]:
            consumed.append(line)
            yield line

    class _Stream:
        def __init__(self, generator):
            self._gen = generator

        def __iter__(self):
            return self._gen

    monkeypatch.setattr(module.sys, "stdin", _Stream(_gen()))
    _stub_decided_hosts(monkeypatch, module)

    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement_dir),
            input_file="-",
            output=None,
        )
    )
    captured = capsys.readouterr()

    assert captured.out.splitlines() == [
        "https://target.example/a",
        "https://target.example/b",
        "https://target.example/c",
    ]
    # Streaming contract: iteration occurred lazily — the generator yielded
    # exactly the three lines we set up rather than being drained eagerly
    # into a list ahead of processing.
    assert consumed == [
        "https://target.example/a\n",
        "https://target.example/b\n",
        "https://target.example/c\n",
    ]


def test_filter_scope_allows_same_file_output(monkeypatch, tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["target.example"]}),
        encoding="utf-8",
    )
    input_file = engagement_dir / "input.txt"
    input_file.write_text(
        "https://target.example/a\nhttps://other.example/b\nhttps://target.example/c\n",
        encoding="utf-8",
    )

    module = _load_filter_scope_module()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir_flag=None: SimpleNamespace(
            engagement_dir=str(engagement_dir),
            engagement_key="eng",
            base_url="http://example.test",
        ),
    )
    monkeypatch.setattr(module, "_vendor_saas_decided_hosts", lambda _cfg: set())

    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement_dir),
            input_file=str(input_file),
            output=str(input_file),
        )
    )

    assert input_file.read_text(encoding="utf-8").splitlines() == [
        "https://target.example/a",
        "https://target.example/c",
    ]


def test_idn_apex_a_label_url_matches_u_label_scope(monkeypatch, tmp_path: Path, capsys) -> None:
    """U-label scope entries must match A-label (punycode) URLs and vice versa."""
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    # Scope authored as a U-label; URL arrives as an A-label.
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["café.test", "*.café.test"]}),
        encoding="utf-8",
    )

    captured = _run_filter_scope(
        monkeypatch,
        engagement_dir,
        [
            "https://xn--caf-dma.test/",
            "https://corp.xn--caf-dma.test/api",
            "https://other.test/",
        ],
        capsys,
    )

    assert captured.out.splitlines() == [
        "https://xn--caf-dma.test/",
        "https://corp.xn--caf-dma.test/api",
    ]


def test_idn_apex_u_label_url_matches_a_label_scope(monkeypatch, tmp_path: Path, capsys) -> None:
    """A-label scope entries must match U-label URLs."""
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["xn--caf-dma.test", "*.xn--caf-dma.test"]}),
        encoding="utf-8",
    )

    captured = _run_filter_scope(
        monkeypatch,
        engagement_dir,
        [
            "https://café.test/",
            "https://corp.café.test/api",
        ],
        capsys,
    )

    assert "https://corp.café.test/api" in captured.out
    assert "https://café.test/" in captured.out


def test_apex_match_with_explicit_entry(monkeypatch, tmp_path: Path, capsys) -> None:
    """An explicit apex entry alongside the wildcard still reports both entries.

    The wildcard entry already admits apex coverage. Listing the apex separately
    keeps a distinct reporting row for that explicit target while filter-scope
    still passes both apex and subdomain URLs.
    """
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hosts": ["example.test", "*.example.test"]}),
        encoding="utf-8",
    )

    captured = _run_filter_scope(
        monkeypatch,
        engagement_dir,
        [
            "https://example.test/",
            "https://example.test/login",
            "https://corp.example.test/api",
        ],
        capsys,
    )

    assert captured.out.splitlines() == [
        "https://example.test/",
        "https://example.test/login",
        "https://corp.example.test/api",
    ]


# ---------------------------------------------------------------------------
# Wildcard-includes-apex semantics — `vigil assess ingest-endpoints` regressions
# ---------------------------------------------------------------------------


def _load_ingest_endpoints_module():
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = (
        Path(__file__).resolve().parents[3]
        / "agent"
        / "scripts"
        / "assess"
        / "commands"
        / "ingest_endpoints.py"
    )
    spec = importlib.util.spec_from_file_location("test_ingest_apex_module", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeIngestClient:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.closed = False

    def post(self, endpoint: str, payload: dict) -> dict:
        if endpoint == "request-observations/bulk":
            records = []
            for item in payload.get("items", []):
                self.posts.append(("request-observations", item))
                records.append(self._observation_receipt(item, 1 + len(self.posts)))
            return {"count": len(records), "records": records}
        if endpoint == "coverage-items/bulk":
            records = []
            for item in payload.get("items", []):
                self.posts.append(("coverage-items", item))
                records.append(self._coverage_receipt(item, 1 + len(self.posts)))
            return {"count": len(records), "records": records}
        self.posts.append((endpoint, payload))
        if endpoint == "request-observations":
            return self._observation_receipt(payload, 1 + len(self.posts))
        if endpoint == "coverage-items":
            return self._coverage_receipt(payload, 1 + len(self.posts))
        return {}

    @staticmethod
    def _observation_receipt(item: dict, row_id: int) -> dict:
        return {
            "request_variant": {
                "id": row_id,
                "method": str(item.get("method") or "GET").upper(),
            },
            "request_observation": {
                "id": row_id,
                "request_variant_id": row_id,
                "observed_url": item.get("url"),
            },
            "service": {"id": 7},
        }

    @staticmethod
    def _coverage_receipt(item: dict, row_id: int) -> dict:
        return {
            "id": row_id,
            "request_variant_id": item.get("request_variant_id"),
            "service_id": item.get("service_id"),
            "auth_context": item.get("auth_context", "anonymous"),
            "input_slot": item.get("input_slot", "endpoint"),
            "attack_family": item.get("attack_family"),
        }

    def close(self) -> None:
        self.closed = True
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()
        return False


def _ingest_setup(
    monkeypatch,
    engagement_dir: Path,
    *,
    scope_payload: dict | None,
    input_lines: list[str],
):
    """Common setup for ingest-endpoints `run` invocations.

    Writes scope.json (when ``scope_payload`` is not None) and an input file with
    the URLs the caller wants to feed in. ingest-endpoints no longer opens a
    local cases.db — every admitted URL is POSTed as a request-observation and
    every out-of-scope URL is recorded directly via ``work-items/bulk`` (both
    captured by the fake client), so no on-disk DB is built here. Returns
    ``(module, args, fake_client)`` for the caller to invoke.
    """
    if scope_payload is not None:
        (engagement_dir / "scope.json").write_text(
            json.dumps(scope_payload), encoding="utf-8"
        )

    input_file = engagement_dir / "input.txt"
    input_file.write_text("\n".join(input_lines) + "\n", encoding="utf-8")

    module = _load_ingest_endpoints_module()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir_flag=None: SimpleNamespace(
            engagement_dir=str(engagement_dir),
            engagement_key="eng",
            base_url="http://example.test",),
    )
    monkeypatch.setattr(module, "auth_active_context", lambda eng_dir: "anonymous")

    fake = _FakeIngestClient()
    monkeypatch.setattr(module, "AssessmentClient", lambda *args, **kwargs: fake)

    args = SimpleNamespace(
        engagement_dir=str(engagement_dir),
        source="test",
        input_file=str(input_file),
        egress_blocked_hosts=None,
        budget_override=None,
        sitemap_host=None,
    )
    return module, args, fake


def test_ingest_admits_apex_under_wildcard_scope(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Apex URL under ``*.example.test`` is admitted by the wildcard itself
    (HackerOne / Bugcrowd / VDP convention treats ``*.example.com`` as covering
    ``example.com``)."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    module, args, fake = _ingest_setup(
        monkeypatch,
        eng,
        scope_payload={"hosts": ["*.example.test"]},
        input_lines=[
            "https://example.test/login",
            "https://corp.example.test/api",
        ],
    )

    module.run(args)

    # Ingest now ALSO posts class-typed `coverage-items` (no `url` key) for
    # gf-bucket matches, additively to the `request-observations` posts. Scope
    # the URL assertion to the observation posts so the additive coverage POST
    # doesn't trip a KeyError.
    posted_urls = [
        payload["url"]
        for endpoint, payload in fake.posts
        if endpoint == "request-observations"
    ]
    assert "https://example.test/login" in posted_urls
    assert "https://corp.example.test/api" in posted_urls

    # Nothing was recorded out-of-scope: the wildcard admits the apex, so no URL
    # is diverted to the direct `work-items/bulk` skipped path. This is the
    # new-backend analog of the old `SELECT COUNT(*) ... status='rejected'` being
    # zero (there is no `rejected` status in the assessment_work_items enum;
    # out-of-scope URLs post as skipped rows via `work-items/bulk`).
    skipped_posts = [
        payload for endpoint, payload in fake.posts if endpoint == "work-items/bulk"
    ]
    assert skipped_posts == []


def test_ingest_rejects_missing_scope_json(monkeypatch, tmp_path: Path, capsys) -> None:
    """A missing authorization boundary stops ingestion before any URL is posted."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    module, args, fake = _ingest_setup(
        monkeypatch,
        eng,
        scope_payload=None,
        input_lines=["https://example.test/login"],
    )

    with pytest.raises(SystemExit, match="scope.json not found"):
        module.run(args)
    assert fake.posts == []


def test_ingest_idn_apex_a_label_url_admitted_under_u_label_wildcard(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """A wildcard authored as U-label (``*.café.test``) admits A-label apex URLs.
    Comparison runs through punycode normalization so the U-label scope and
    the A-label URL match the same A-label host."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    module, args, fake = _ingest_setup(
        monkeypatch,
        eng,
        scope_payload={"hosts": ["*.café.test"]},
        input_lines=[
            "https://xn--caf-dma.test/login",
            "https://corp.xn--caf-dma.test/api",
        ],
    )

    module.run(args)
    posted_urls = [
        payload["url"]
        for endpoint, payload in fake.posts
        if endpoint == "request-observations"
    ]
    assert "https://xn--caf-dma.test/login" in posted_urls
    assert "https://corp.xn--caf-dma.test/api" in posted_urls


# Pytest is referenced by the new tests above.
