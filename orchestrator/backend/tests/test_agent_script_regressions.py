from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
import sys
from urllib.parse import parse_qs

import pytest


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_script_module(name: str, relative_path: str):
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = Path(__file__).resolve().parents[3] / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_proxy_addon_module():
    mitmproxy_module = ModuleType("mitmproxy")
    mitmproxy_module.http = SimpleNamespace(HTTPFlow=object)
    mitmproxy_module.ctx = SimpleNamespace(
        options=SimpleNamespace(engagements_root="", registry_poll_seconds=30),
        log=SimpleNamespace(info=lambda *a, **k: None, warn=lambda *a, **k: None, error=lambda *a, **k: None),
    )
    sys.modules["mitmproxy"] = mitmproxy_module
    return _load_script_module("test_proxy_addon_module", "agent/scripts/proxy_addon.py")


def test_assess_cli_imports_agent_work_buffer_without_legacy_dispatch_module() -> None:
    """Top-level ``vigil assess`` must not expose ``dispatch``; agent + work-buffer are canonical."""
    import ast

    repo_root = Path(__file__).resolve().parents[3]
    path = repo_root / "agent/scripts/assess/cli.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "assess.commands":
            imported.update(alias.name for alias in node.names)
    assert "agent" in imported
    assert "work_buffer" in imported
    assert "dispatch" not in imported


def test_agent_action_help_is_action_specific(capsys) -> None:
    """`vigil assess agent list --help` should show list usage, not only umbrella help."""
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    import assess.cli as cli

    with pytest.raises(SystemExit) as exc:
        cli.main(["agent", "list", "--limit", "5", "--help"])

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Usage: vigil assess agent list" in captured.out
    assert "--filter-role" in captured.out
    assert "start-swarm" not in captured.out


def test_agent_list_accepts_json_flag(monkeypatch, capsys) -> None:
    """JSON-producing list verbs accept --json consistently."""
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    import assess.cli as cli
    from assess.commands import dispatch

    monkeypatch.setattr(dispatch, "_list_dispatches", lambda args: print("{}"))

    cli.main(["agent", "list", "--limit", "5", "--json"])

    assert capsys.readouterr().out.strip() == "{}"


def test_get_command_run_accepts_json_flag(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_get_command_run_module",
        "agent/scripts/assess/commands/get_command_run.py",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    captured_endpoints: list[str] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            pass

        def get(self, endpoint: str):
            captured_endpoints.append(endpoint)
            return {"id": 123, "stdout_preview": "ok"}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    module.register(sub)
    args = parser.parse_args(["get", "123", "--json"])
    args.engagement_dir = tmp_path
    args.func(args)

    assert captured_endpoints == ["command-runs/123"]
    assert json.loads(capsys.readouterr().out) == {"id": 123, "stdout_preview": "ok"}


def test_get_command_run_live_reads_current_on_disk_tails(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    module = _load_script_module(
        "test_get_command_run_live_module",
        "agent/scripts/assess/commands/get_command_run.py",
    )
    output_dir = tmp_path / "scans" / "kali"
    output_dir.mkdir(parents=True)
    stdout = output_dir / "run.out"
    stderr = output_dir / "run.err"
    stdout.write_text("still running\nlatest stdout\n", encoding="utf-8")
    stderr.write_text("latest stderr\n", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, *args):
            pass

        def get(self, endpoint: str):
            return {
                "id": 123,
                "status": "running",
                "stdout_path": str(stdout),
                "stderr_path": str(stderr),
                "stdout_preview": "old preview",
            }

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    module.register(sub)
    args = parser.parse_args(["get", "123", "--live"])
    args.engagement_dir = tmp_path

    args.func(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["live_output"]["stdout"] == "still running\nlatest stdout\n"
    assert payload["live_output"]["stderr"] == "latest stderr\n"


def test_get_command_run_live_refuses_paths_outside_engagement(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    module = _load_script_module(
        "test_get_command_run_live_refusal_module",
        "agent/scripts/assess/commands/get_command_run.py",
    )
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("must not leak", encoding="utf-8")
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )

    class FakeClient:
        def __init__(self, *args):
            pass

        def get(self, endpoint: str):
            return {"id": 123, "stdout_path": str(outside), "stderr_path": None}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    module.register(sub)
    args = parser.parse_args(["get", "123", "--live"])
    args.engagement_dir = tmp_path

    args.func(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["live_output"]["stdout"] == "[refused: path outside engagement]"
    assert "must not leak" not in json.dumps(payload)


def test_fetch_auto_pages_bounded_assessment_lists(capsys) -> None:
    module = _load_script_module(
        "test_fetch_module_auto_pages",
        "agent/scripts/assess/commands/fetch.py",
    )
    calls: list[str] = []

    class FakeClient:
        def get_all_pages(self, endpoint: str, *, page_size: int = 5000):
            calls.append(endpoint)
            assert page_size == 5000
            return [{"id": i} for i in range(5001)]

    rows = module._fetch_assessment_endpoint(FakeClient(), "surfaces")

    assert len(rows) == 5001
    assert calls == ["surfaces"]
    err = capsys.readouterr().err
    assert "auto-paging surfaces with page_size=5000" in err
    assert "stdout will be one combined JSON array" in err
    assert "fetched 5001 surfaces row(s) across all pages" in err


def test_fetch_respects_explicit_pagination_query(capsys) -> None:
    module = _load_script_module(
        "test_fetch_module_explicit_page",
        "agent/scripts/assess/commands/fetch.py",
    )
    calls: list[str] = []

    class FakeClient:
        def get(self, endpoint: str):
            calls.append(endpoint)
            return [{"id": 1}]

    rows = module._fetch_assessment_endpoint(FakeClient(), "surfaces?limit=10&offset=20")

    assert rows == [{"id": 1}]
    assert calls == ["surfaces?limit=10&offset=20"]
    assert capsys.readouterr().err == ""


def test_assessment_client_get_all_pages_fetches_every_page() -> None:
    _load_script_module(
        "test_fetch_module_imports_client",
        "agent/scripts/assess/commands/fetch.py",
    )
    client_module = importlib.import_module("assess.lib.client")
    client = client_module.AssessmentClient("http://example.test", "eng")
    calls: list[str] = []

    def fake_get(endpoint: str):
        calls.append(endpoint)
        if endpoint == "surfaces?status=open&limit=2&offset=0":
            return [{"id": 1}, {"id": 2}]
        if endpoint == "surfaces?status=open&limit=2&offset=2":
            return [{"id": 3}]
        raise AssertionError(endpoint)

    client.get = fake_get

    rows = client.get_all_pages("surfaces?status=open", page_size=2)

    assert rows == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert calls == [
        "surfaces?status=open&limit=2&offset=0",
        "surfaces?status=open&limit=2&offset=2",
    ]


def test_export_surfaces_fetches_all_pages(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_export_surfaces_module_all_pages",
        "agent/scripts/assess/commands/export_surfaces.py",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    calls: list[str] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get_all_pages(self, endpoint: str):
            calls.append(endpoint)
            return [{"id": 1}, {"id": 2}]

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=tmp_path))

    assert calls == ["surfaces"]
    assert (tmp_path / "surfaces.jsonl").read_text(encoding="utf-8").splitlines() == [
        '{"id": 1}',
        '{"id": 2}',
    ]


def test_check_phase_readiness_scope_gate_fetches_all_surfaces(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_check_phase_readiness_all_surfaces",
        "agent/scripts/assess/commands/check_phase_readiness.py",
    )
    (tmp_path / "scope.json").write_text(
        json.dumps({"hosts": ["example.test"]}),
        encoding="utf-8",
    )
    calls: list[tuple[str, str]] = []
    captured: dict[str, Any] = {}

    class FakeClient:
        def get(self, endpoint: str):
            calls.append(("get", endpoint))
            if endpoint == "services":
                return []
            raise AssertionError(endpoint)

        def get_all_pages(self, endpoint: str):
            calls.append(("get_all_pages", endpoint))
            return [{"id": 1, "target_descriptor": "https://example.test/"}]

    def fake_build_scope_coverage_report(**kwargs):
        captured.update(kwargs)
        return {"ready": True}

    monkeypatch.setattr(module.cc, "_vendor_saas_decided_hosts", lambda _client: set())
    # `_load_work_items_by_host` now takes an AssessmentClient (it rolls the work
    # buffer up from the backend via `client.get_all_pages("work-items")`), not a
    # cases.db Path.
    monkeypatch.setattr(module.cc, "_load_work_items_by_host", lambda _client: {})
    monkeypatch.setattr(module.cc, "build_scope_coverage_report", fake_build_scope_coverage_report)

    cfg = SimpleNamespace(engagement_key="eng", engagement_dir=str(tmp_path))
    args = SimpleNamespace(strict_vendor_saas=False)
    report, failed = module._run_scope_gate(cfg, FakeClient(), args, "enum")

    assert report == {"ready": True}
    assert failed is False
    assert calls == [("get", "services"), ("get_all_pages", "surfaces")]
    assert captured["surfaces"] == [
        {"id": 1, "target_descriptor": "https://example.test/"}
    ]


def test_list_findings_pushes_filters_and_limit_to_backend(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_list_findings_module",
        "agent/scripts/assess/commands/list_findings.py",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    captured: list[str] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            pass

        def get(self, endpoint: str):
            captured.append(endpoint)
            return [
                {
                    "slug": "VA-123",
                    "severity": "high",
                    "workflow_status": "active",
                    "verification_state": "verified",
                    "verification_disposition": "confirmed",
                    "source_name": "vulnerability-analyst",
                    "canonical_location": "https://example.test/oidc",
                    "summary": "OIDC state result",
                    "title": "Filtered result",
                }
            ]

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(
        SimpleNamespace(
            engagement_dir=tmp_path,
            severity="high",
            workflow_status="active",
            verification_state="verified",
            verification_disposition="confirmed",
            source_name="vulnerability-analyst",
            slug="",
            root_cause_slug="",
            search="OIDC state",
            holding=False,
            limit=25,
            offset=50,
            all=False,
            json=False,
        )
    )

    assert captured == [
        "findings?severity=high&workflow_status=active&verification_state=verified&"
        "verification_disposition=confirmed&source_name=vulnerability-analyst&search=OIDC%20state&"
        "limit=25&offset=50"
    ]
    assert "VA-123 | high | active | verified/confirmed" in capsys.readouterr().out


def test_kali_runtime_dockerfiles_do_not_bake_audit_enums() -> None:
    """audit_enums.py is a HOST-side assess library (imported by `vigil assess
    kali` on the host), not a runtime-image artifact. The in-container Kali-MCP
    server that once imported it is retired and nothing in the image reads it, so
    the runtime image must NOT bake it: baking coupled the image to host-lib churn
    and forced spurious `vigil runtime build` rebuilds for changes the container
    never reads. This guards against re-introducing that coupling."""
    repo_root = Path(__file__).resolve().parents[3]
    for dockerfile in (
        repo_root / "agent" / "docker" / "runtime-full" / "Dockerfile",
        repo_root / "agent" / "docker" / "runtime-lightweight" / "Dockerfile",
    ):
        contents = dockerfile.read_text(encoding="utf-8")
        assert "audit_enums.py" not in contents, (
            f"{dockerfile.name} must not bake the host-side audit_enums.py"
        )


def test_kali_runtime_dockerfiles_package_ping_for_mcp_smoke_tests() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    for dockerfile in (
        repo_root / "agent" / "docker" / "runtime-full" / "Dockerfile",
        repo_root / "agent" / "docker" / "runtime-lightweight" / "Dockerfile",
    ):
        contents = dockerfile.read_text(encoding="utf-8")
        assert re.search(r"\biputils-ping(?:=\S+)?\b", contents)


def test_list_intel_search_uses_canonical_entity_type(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_list_intel_search_module",
        "agent/scripts/assess/commands/list_intel.py",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    captured: list[tuple[str, str]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get_engagement(self, endpoint: str, query: str = ""):
            captured.append((endpoint, query))
            return []

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    for intel_type in ("cve", "tech-component"):
        module.run(
            SimpleNamespace(
                engagement_dir=tmp_path,
                q="2024",
                intel_type=intel_type,
                limit=50,
                as_json=True,
            )
        )

    assert [endpoint for endpoint, _ in captured] == ["intel/search", "intel/search"]
    assert parse_qs(captured[0][1])["entity_type"] == ["cve"]
    assert parse_qs(captured[1][1])["entity_type"] == ["tech_component"]
    assert "[]" in capsys.readouterr().out


def test_proxy_addon_loads_legacy_scope_keys(tmp_path: Path) -> None:
    """The filesystem fallback supports the same legacy scope-key aliases as
    before (``hosts`` / ``scope_hosts`` / ``scope`` plus ``hostname``)."""
    module = _load_proxy_addon_module()
    engagements_root = tmp_path / "engagements"
    engagement_dir = engagements_root / "eng-1"
    engagement_dir.mkdir(parents=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_hosts": ["*.example.com"],
                "scope": ["legacy.example.net"],
            }
        ),
        encoding="utf-8",
    )

    collector = module.CaseCollector()
    collector.engagements_root = engagements_root
    collector._reload_registry(force=True)

    assert collector._match_engagement("example.com") is not None
    assert collector._match_engagement("api.example.com") is not None
    assert collector._match_engagement("legacy.example.net") is not None
    assert collector._match_engagement("out-of-scope.test") is None


def test_filter_scope_keeps_in_scope_hosts(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_filter_scope_module",
        "agent/scripts/assess/commands/filter_scope.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    # `*.example.com` admits the bare apex (HackerOne / Bugcrowd / VDP
    # convention) and every subdomain.
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hosts": [
                    "*.example.com",
                    "https://app.other.test/base",
                    "api.example.net",
                ]
            }
        ),
        encoding="utf-8",
    )
    input_file = tmp_path / "urls.txt"
    input_file.write_text(
        "\n".join(
            [
                "https://api.example.com/a",
                "https://example.com/apex",
                "https://evil-example.com/no",
                "https://app.other.test/v1",
                "api.example.net:8443",
                "https://api.example.net.evil.test",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir=None: SimpleNamespace(
            engagement_dir=str(engagement_dir),
            engagement_key="eng",
            base_url="http://example.test",
        ),
    )
    module.run(
        SimpleNamespace(
            engagement_dir=engagement_dir,
            input_file=str(input_file),
            output=None,
        )
    )

    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "https://api.example.com/a",
        "https://example.com/apex",
        "https://app.other.test/v1",
        "api.example.net:8443",
    ]


def test_filter_scope_excludes_out_of_scope_carve_out(monkeypatch, tmp_path: Path, capsys) -> None:
    """An out_of_scope carve-out is dropped even when an in-scope wildcard
    would otherwise admit it. The denylist wins.
    """
    module = _load_script_module(
        "test_filter_scope_oos_module",
        "agent/scripts/assess/commands/filter_scope.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hosts": ["*.acme-regional.example"],
                "out_of_scope": ["appointments.acme-regional.example"],
            }
        ),
        encoding="utf-8",
    )
    input_file = tmp_path / "urls.txt"
    input_file.write_text(
        "\n".join(
            [
                "https://app.acme-regional.example/a",
                "https://appointments.acme-regional.example/booking",
                "https://acme-regional.example/apex",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir=None: SimpleNamespace(
            engagement_dir=str(engagement_dir),
            engagement_key="eng",
            base_url="http://example.test",
        ),
    )
    module.run(
        SimpleNamespace(
            engagement_dir=engagement_dir,
            input_file=str(input_file),
            output=None,
        )
    )

    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "https://app.acme-regional.example/a",
        "https://acme-regional.example/apex",
    ]


def test_ingest_candidates_preserve_metadata_and_route(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    ingest_module = _load_script_module(
        "test_ingest_candidates_module",
        "agent/scripts/assess/commands/ingest_candidates.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    candidate_path = tmp_path / "candidate_records.jsonl"
    candidate_path.write_text(
        json.dumps(
            {
                "url": "https://portal.acme-agency.example/svc-core/api/logout",
                "method": "GET",
                "path": "/svc-core/api/logout",
                "type": "auth_entry",
                "priority_score": 245,
                "priority_reason": "TAAP auth API workflow",
                "cluster_key": "gf:auth_workflow",
                "signals": ["api", "auth", "workflow"],
                "selected_by": "auth",
                "triage_rationale": "Selected from GAU because it is an auth workflow endpoint.",
                "live_status": "live",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        ingest_module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(ingest_module, "auth_active_context", lambda _eng_dir: "anonymous")

    posts: list[tuple[str, dict[str, object]]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict[str, object]):
            if endpoint == "request-observations/bulk":
                records = []
                for item in payload.get("items", []):
                    posts.append(("request-observations", item))
                    records.append({"request_variant": {"id": 701}})
                return {"count": len(records), "records": records}
            posts.append((endpoint, payload))
            return {"request_variant": {"id": 701}}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(ingest_module, "AssessmentClient", FakeClient)

    ingest_module.run(
        SimpleNamespace(
            source="surface-collector-curated",
            records_file=str(candidate_path),
            engagement_dir=engagement_dir,
        )
    )

    # The command no longer writes a local cases.db; it POSTs one
    # request-observation per candidate carrying the curated work-item
    # derivation block (the backend derives the assessment_work_items row +
    # routing server-side, ADR 0013). Assert on the captured observation payload
    # instead of on cases.db rows — the candidate's metadata is preserved and its
    # case_type/cluster_key (which drive server-side routing to the
    # vulnerability-analyst) are correct.
    assert len(posts) == 1
    endpoint, observation = posts[0]
    assert endpoint == "request-observations"
    assert observation["url"] == "https://portal.acme-agency.example/svc-core/api/logout"
    assert observation["method"] == "GET"

    work_item = observation["work_item"]
    assert work_item["url_path"] == "/svc-core/api/logout"
    assert work_item["case_type"] == "auth_entry"
    assert work_item["status"] == "pending"
    assert work_item["priority_score"] == 245
    assert work_item["priority_reason"] == "TAAP auth API workflow"
    assert work_item["cluster_key"] == "gf:auth_workflow"
    assert json.loads(work_item["signals"]) == ["api", "auth", "workflow"]
    assert work_item["selected_by"] == "auth"
    assert (
        work_item["triage_rationale"]
        == "Selected from GAU because it is an auth workflow endpoint."
    )
    assert work_item["live_status"] == "live"
    assert (
        observation["observation_payload"]["candidate_metadata"]["priority_score"]
        == 245
    )


def test_ingest_candidates_route_real_bia_candidate_shapes(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    ingest_module = _load_script_module(
        "test_ingest_real_candidate_shapes_module",
        "agent/scripts/assess/commands/ingest_candidates.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    candidate_path = tmp_path / "candidate_records.jsonl"
    records = [
        {
            "url": "https://www.acme-agency.example/org-event-feed/37221",
            "path": "/org-event-feed/37221",
            "score": 95,
            "selection_reasons": [
                "current Drupal workflow/auth route",
                "operator/Phase 1 artifact",
                "source-map/source-analysis route",
            ],
            "signals": [],
            "sources": ["osint-gau", "source-analysis"],
        },
        {
            "url": "https://www.acme-agency.example/fb.log",
            "path": "/fb.log",
            "score": 80,
            "selection_reasons": ["admin/debug/config/secret signal"],
            "signals": ["backup_config"],
            "sources": ["osint-gau"],
        },
        {
            "url": "https://www.acme-agency.example/web-guidance",
            "path": "/web-guidance",
            "score": 105,
            "selection_reasons": [
                "OSINT priority URL",
                "operator/Phase 1 artifact",
                "source-map/source-analysis route",
            ],
            "signals": [],
            "sources": ["osint-gau", "osint-priority", "source-analysis"],
        },
    ]
    candidate_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        ingest_module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(ingest_module, "auth_active_context", lambda _eng_dir: "anonymous")

    posts: list[dict[str, object]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key
            self.next_id = 800

        def post(self, endpoint: str, payload: dict[str, object]):
            if endpoint == "request-observations/bulk":
                records = []
                for item in payload.get("items", []):
                    posts.append(item)
                    self.next_id += 1
                    records.append({"request_variant": {"id": self.next_id}})
                return {"count": len(records), "records": records}
            self.next_id += 1
            return {"request_variant": {"id": self.next_id}}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(ingest_module, "AssessmentClient", FakeClient)

    ingest_module.run(
        SimpleNamespace(
            source="surface-collector-curated",
            records_file=str(candidate_path),
            engagement_dir=engagement_dir,
        )
    )

    # No cases.db: each candidate is POSTed as a request-observation whose
    # work_item derivation block carries the curated type/score/reason/cluster.
    # Assert the per-URL classification + metadata on the captured observations
    # (the case_type/cluster_key are what route each to the vulnerability-analyst
    # server-side).
    rows = {
        observation["url"]: observation["work_item"] for observation in posts
    }
    assert set(rows) == {
        "https://www.acme-agency.example/org-event-feed/37221",
        "https://www.acme-agency.example/fb.log",
        "https://www.acme-agency.example/web-guidance",
    }

    feed = rows["https://www.acme-agency.example/org-event-feed/37221"]
    assert feed["case_type"] == "event_feed"
    assert feed["priority_score"] == 95
    assert feed["priority_reason"] == (
        "current Drupal workflow/auth route; operator/Phase 1 artifact; "
        "source-map/source-analysis route"
    )
    assert feed["cluster_key"] == "gf:current_drupal_workflow_auth_route"

    debug = rows["https://www.acme-agency.example/fb.log"]
    assert debug["case_type"] == "debug_config"
    assert debug["priority_score"] == 80
    assert debug["priority_reason"] == "admin/debug/config/secret signal"
    assert debug["cluster_key"] == "gf:backup_config"

    guidance = rows["https://www.acme-agency.example/web-guidance"]
    assert guidance["case_type"] == "unknown"
    assert guidance["priority_score"] == 105
    assert guidance["priority_reason"] == (
        "OSINT priority URL; operator/Phase 1 artifact; "
        "source-map/source-analysis route"
    )
    assert guidance["cluster_key"] == "gf:osint_priority_url"
    assert json.loads(guidance["signals"]) == [
        "osint_priority_url",
        "operator_phase_1_artifact",
        "source-map_source-analysis_route",
    ]
    assert guidance["selected_by"] == "osint_priority_url"
    assert guidance["triage_rationale"] == (
        "OSINT priority URL; operator/Phase 1 artifact; "
        "source-map/source-analysis route"
    )


def test_code_ingest_posts_backend_contract_fields(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_code_ingest_contract_module",
        "agent/scripts/assess/commands/code_ingest.py",
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "service.py").write_text("def parse(data):\n    return data\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    calls: list[tuple[str, dict[str, object]]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict[str, object]):
            calls.append((endpoint, payload))
            if endpoint == "code/repos/refresh/start":
                return {"repo_id": 41, "refresh_token": "refresh-41"}
            if endpoint == "code/repos/41/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/41/refresh/commit":
                return {"inserted": 1, "changed": 0, "renamed": 0, "deleted": 0}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            repo_path=str(repo_dir),
            name="demo-repo",
            language=None,
            repo_key=None,
            engagement_dir=Path("/tmp/eng"),
        )
    )

    repo_call = next(payload for endpoint, payload in calls if endpoint == "code/repos/refresh/start")
    files_call = next(payload for endpoint, payload in calls if endpoint == "code/repos/41/refresh/files")

    assert "repo_key" in repo_call
    assert "repo_path" in repo_call
    assert "path" not in repo_call
    assert "primary_language" not in repo_call
    assert files_call["files"][0]["file_path"] == "service.py"
    assert "file_hash" in files_call["files"][0]
    assert "path" not in files_call["files"][0]
    assert "sha256" not in files_call["files"][0]


def test_code_ingest_records_skipped_minified_manifest(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_code_ingest_skipped_manifest_module",
        "agent/scripts/assess/commands/code_ingest.py",
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.js").write_text("fetch('/api/profile')\n", encoding="utf-8")
    (repo_dir / "app.min.js").write_text("fetch('/api/profile')", encoding="utf-8")
    build_dir = repo_dir / "build"
    build_dir.mkdir()
    (build_dir / "ResetPassword.min.js").write_text("fetch('/reset')", encoding="utf-8")
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir_arg: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    calls: list[tuple[str, dict[str, object]]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            return None

        def post(self, endpoint: str, payload: dict[str, object]):
            calls.append((endpoint, payload))
            if endpoint == "code/repos/refresh/start":
                return {"repo_id": 41, "refresh_token": "refresh-41"}
            if endpoint == "code/repos/41/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/41/refresh/commit":
                return {"inserted": 1, "changed": 0, "renamed": 0, "deleted": 0}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            repo_path=str(repo_dir),
            name="demo-repo",
            language=None,
            repo_key="demo",
            engagement_dir=engagement_dir,
            include_minified=False,
            include_skipped=False,
            include_path=[],
            max_included_skipped_bytes=2_000_000,
            skipped_manifest=None,
        )
    )

    files_call = next(payload for endpoint, payload in calls if endpoint == "code/repos/41/refresh/files")
    assert [row["file_path"] for row in files_call["files"]] == ["app.js"]
    manifest_path = engagement_dir / "tools" / "analysis-state" / "skipped-artifacts" / "demo.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    skipped_paths = {row["path"]: row for row in manifest["skipped_artifacts"]}
    assert skipped_paths["app.min.js"]["reason"] == "minified_or_bundle"
    assert skipped_paths["app.min.js"]["source_equivalent_candidate"] == "app.js"
    assert skipped_paths["build"]["reason"] == "skipped_dir:build"


def test_code_ingest_include_path_can_queue_security_relevant_build_artifact(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_code_ingest_include_path_module",
        "agent/scripts/assess/commands/code_ingest.py",
    )
    repo_dir = tmp_path / "repo"
    build_dir = repo_dir / "build"
    build_dir.mkdir(parents=True)
    (repo_dir / "app.js").write_text("console.log('source')\n", encoding="utf-8")
    (build_dir / "ResetPassword.min.js").write_text("fetch('/reset')", encoding="utf-8")
    engagement_dir = tmp_path / "eng"
    engagement_dir.mkdir()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir_arg: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    calls: list[tuple[str, dict[str, object]]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            return None

        def post(self, endpoint: str, payload: dict[str, object]):
            calls.append((endpoint, payload))
            if endpoint == "code/repos/refresh/start":
                return {"repo_id": 42, "refresh_token": "refresh-42"}
            if endpoint == "code/repos/42/refresh/files":
                return {"staged": len(payload["files"])}
            if endpoint == "code/repos/42/refresh/commit":
                return {"inserted": 2, "changed": 0, "renamed": 0, "deleted": 0}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            repo_path=str(repo_dir),
            name="demo-repo",
            language=None,
            repo_key="demo",
            engagement_dir=engagement_dir,
            include_minified=False,
            include_skipped=False,
            include_path=["**/ResetPassword.min.js"],
            max_included_skipped_bytes=2_000_000,
            skipped_manifest=None,
        )
    )

    files_call = next(payload for endpoint, payload in calls if endpoint == "code/repos/42/refresh/files")
    paths = {row["file_path"] for row in files_call["files"]}
    assert paths == {"app.js", "build/ResetPassword.min.js"}


def test_export_findings_uses_canonical_findings_and_renders_details(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_export_findings_module",
        "agent/scripts/assess/commands/export_findings.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "load_scope", lambda engagement_dir, **kwargs: {"engagement_name": "Demo Engagement"})

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            if endpoint == "finding-groups":
                return []
            assert endpoint == "findings"
            return [
                {
                    "slug": "finding-002",
                    "title": "False positive finding",
                    "severity": "low",
                    "workflow_status": "false_positive",
                    "verification_state": "verified",
                    "verification_disposition": "false_positive",
                    "summary": "Should still be exported",
                    "details_json": json.dumps({}),
                },
                {
                    "slug": "finding-001",
                    "title": "Parser issue",
                    "severity": "high",
                    "workflow_status": "merged",
                    "verification_state": "disputed",
                    "verification_disposition": "downgraded",
                    "summary": "Summary text",
                    "merged_into_slug": "finding-010",
                    "details_json": json.dumps(
                        {
                            "request_method": "POST",
                            "cwe_id": "CWE-79",
                            "references": ["https://example.test/advisory", {"id": 7}, 42],
                            "entry_point": "parse_input",
                            "sink": "render_output",
                            "steps_to_reproduce": ["send payload", 2],
                        }
                    ),
                },
            ]

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=engagement_dir))

    output = capsys.readouterr().out
    findings_md = (engagement_dir / "findings.md").read_text(encoding="utf-8")

    assert "Exported 2 findings" in output
    assert "False positive finding" in findings_md
    assert "- **Workflow**: false_positive" in findings_md
    assert "Parser issue" in findings_md
    assert "- **Merged Into**: finding-010" in findings_md
    assert "- **Location**: POST" not in findings_md
    assert "- **CWE**: CWE-79" in findings_md
    assert "- **Entry Point**: parse_input" in findings_md
    assert "- **Sink**: render_output" in findings_md
    assert "- **References**: https://example.test/advisory, {'id': 7}, 42" in findings_md
    # Steps render exactly as authored: no counter and no list marker are added, so
    # authored text is never rewritten. A list renders one step per paragraph (a
    # non-string entry is still coerced to text by ``string_list``).
    assert "**Steps to Reproduce:**\nsend payload\n\n2" in findings_md


def test_export_findings_separates_sections_with_blank_line(monkeypatch, tmp_path: Path, capsys) -> None:
    """``export-findings`` joins per-finding blocks with a blank line (``\\n\\n``)
    so consecutive ``##`` headings are not glued onto the previous section's
    last line (which most Markdown renderers collapse into one finding)."""
    module = _load_script_module(
        "test_export_findings_blank_line_module",
        "agent/scripts/assess/commands/export_findings.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "load_scope", lambda engagement_dir, **kwargs: {"engagement_name": "Demo"})

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            if endpoint == "finding-groups":
                return []
            assert endpoint == "findings"
            return [
                {
                    "slug": "finding-aaa",
                    "title": "First",
                    "severity": "high",
                    "summary": "first summary",
                    "details_json": json.dumps({}),
                },
                {
                    "slug": "finding-bbb",
                    "title": "Second",
                    "severity": "high",
                    "summary": "second summary",
                    "details_json": json.dumps({}),
                },
            ]

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=engagement_dir))

    findings_md = (engagement_dir / "findings.md").read_text(encoding="utf-8")
    # The second section header must be preceded by a blank line, i.e. the two
    # blocks are joined by "\n\n" rather than a bare "\n".
    assert "\n\n## [finding-bbb] Second" in findings_md
    # And the two headers must not be glued together on adjacent lines.
    assert "\n## [finding-aaa] First\n## [finding-bbb] Second" not in findings_md


def test_list_report_findings_uses_grouped_projection(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_list_report_findings_module",
        "agent/scripts/assess/commands/list_report_findings.py",
    )

    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(base_url="http://backend", engagement_key="demo"),
    )
    requested: list[str] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            requested.append(endpoint)
            return {
                "groups": [
                    {
                        "root": {
                            "report_id": "001",
                            "slug": "VA-001",
                            "title": "Missing authorization",
                            "severity": "high",
                        },
                        "siblings": [
                            {
                                "slug": "VA-002",
                                "title": "Account takeover outcome",
                                "severity": "critical",
                                "root_cause_effect": "eliminates_attack_path",
                            }
                        ],
                        "sibling_count": 1,
                        "residual_path_count": 1,
                        "highest_severity": "critical",
                    }
                ],
                "standalone": [],
            }

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=engagement_dir, mode="final", json=False))

    output = capsys.readouterr().out
    assert requested == ["report-findings?mode=final"]
    assert "1 root-cause groups, 0 standalone findings" in output
    assert "VA-002 [critical] residual: Account takeover outcome" in output


def test_export_findings_preserves_legacy_non_mapping_poc_headers() -> None:
    module = _load_script_module(
        "test_export_findings_headers_module",
        "agent/scripts/assess/commands/export_findings.py",
    )

    rendered = module._render_finding(
        {
            "slug": "finding-001",
            "title": "Legacy headers",
            "details_json": json.dumps(
                {
                    "poc_request": {
                        "method": "GET",
                        "url": "https://example.test",
                        "headers": "Accept: text/html",
                    },
                    "poc_response": {
                        "status": 200,
                        "headers": ["Content-Type: text/plain"],
                        "body_excerpt": "ok",
                    },
                }
            ),
        }
    )

    assert "**PoC Request:**" in rendered
    assert "GET https://example.test" in rendered
    assert "Accept: text/html" in rendered
    assert "**PoC Response:**" in rendered
    assert "HTTP 200" in rendered
    assert "Content-Type: text/plain" in rendered


def test_render_finding_accepts_poc_response_body_as_well_as_body_excerpt() -> None:
    """A response body under either key reaches the render — it is the proof.

    Recorders write ``body_excerpt``; a hand-authored or tool-captured response
    often carries plain ``body``. ``export submission``'s structured-proof block
    reads both keys, and this renderer must agree, or one finding's response body
    appears in the submission reference and vanishes from ``findings.md``.
    """
    module = _load_script_module(
        "test_export_findings_body_key_module",
        "agent/scripts/assess/commands/export_findings.py",
    )

    rendered = module._render_finding(
        {
            "slug": "finding-001",
            "title": "Plain body key",
            "details_json": json.dumps(
                {
                    "poc_response": {
                        "status": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"owner":"someone-else"}',
                    },
                }
            ),
        }
    )

    assert "**PoC Response:**" in rendered
    assert '{"owner":"someone-else"}' in rendered


def test_render_finding_widens_fence_when_poc_code_contains_backtick_run() -> None:
    """``_fence_for`` must widen the markdown code fence past the longest
    backtick run inside the fenced content. A ``poc_code`` that itself contains
    a triple-backtick run would otherwise close the block early; the emitted
    fence must therefore be >= 4 backticks so the embedded content cannot break
    out of the fence."""
    module = _load_script_module(
        "test_export_findings_fence_module",
        "agent/scripts/assess/commands/export_findings.py",
    )

    poc_code = "before\n```\nnested fenced block\n```\nafter"
    rendered = module._render_finding(
        {
            "slug": "finding-001",
            "title": "Fence escaping",
            "details_json": json.dumps({"poc_code": poc_code}),
        }
    )

    assert "**PoC Code:**" in rendered
    lines = rendered.splitlines()
    poc_idx = lines.index("**PoC Code:**")
    # The fence line is the first non-empty line after the "**PoC Code:**" label.
    fence_line = next(line for line in lines[poc_idx + 1:] if line.strip())
    fence = fence_line.strip()
    assert set(fence) == {"`"}, f"expected an all-backtick fence, got {fence!r}"
    # >= 4 backticks: one longer than the triple-backtick run embedded in poc_code.
    assert len(fence) >= 4
    # The widened fence must appear as the closing fence too, so the block is
    # balanced and the embedded ``` cannot terminate it.
    assert rendered.count(f"\n{fence}") >= 2


def test_code_index_sync_requires_repo_id_for_multi_repo_engagement(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_code_index_sync_multi_repo_module",
        "agent/scripts/assess/commands/code_index_sync.py",
    )
    engagement_dir = tmp_path / "engagement"
    manifest_dir = engagement_dir / "tools" / "analysis-state"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "structural-index-manifest.json").write_text(
        json.dumps({"path_to_index": {"src/main.go": "a.json"}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/repos"
            return [{"id": 1}, {"id": 2}]

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                manifest=None,
                index_dir=None,
                repo_id=None,
            )
        )

    assert excinfo.value.code == 1
    assert "--repo-id" in capsys.readouterr().err


def test_code_index_sync_repo_id_scopes_aggregate_to_matching_manifest(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    module = _load_script_module(
        "test_code_index_sync_repo_id_scopes_aggregate_module",
        "agent/scripts/assess/commands/code_index_sync.py",
    )
    engagement_dir = tmp_path / "engagement"
    manifest_dir = engagement_dir / "tools" / "analysis-state"
    index_dir = manifest_dir / "structural-index"
    (index_dir / "repo-a").mkdir(parents=True)
    (index_dir / "repo-b").mkdir(parents=True)
    (index_dir / "repo-a" / "a.json").write_text(
        json.dumps(
            {"total_functions": 99, "entry_points": [], "security_sinks": [], "exports": []}
        ),
        encoding="utf-8",
    )
    (index_dir / "repo-b" / "b.json").write_text(
        json.dumps(
            {"total_functions": 7, "entry_points": [], "security_sinks": [], "exports": []}
        ),
        encoding="utf-8",
    )
    (index_dir / "repo-a-manifest.json").write_text(
        json.dumps({"repo_key": "repo-a", "path_to_index": {"shared.py": "repo-a/a.json"}}),
        encoding="utf-8",
    )
    (index_dir / "repo-b-manifest.json").write_text(
        json.dumps({"repo_key": "repo-b", "path_to_index": {"shared.py": "repo-b/b.json"}}),
        encoding="utf-8",
    )
    (manifest_dir / "structural-index-manifest.json").write_text(
        json.dumps(
            {
                "schema": "structural-index-aggregate/v1",
                "repos": {
                    "repo-a": {"manifest_path": "structural-index/repo-a-manifest.json"},
                    "repo-b": {"manifest_path": "structural-index/repo-b-manifest.json"},
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        posts: list[tuple[str, dict[str, object]]] = []
        file_requests: list[str] = []

        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            if endpoint == "code/repos":
                return [
                    {"id": 1, "repo_key": "repo-a", "name": "repo-a"},
                    {"id": 2, "repo_key": "repo-b", "name": "repo-b"},
                ]
            self.file_requests.append(endpoint)
            assert endpoint == "code/files?limit=5000&offset=0&repo_id=2"
            return [{"id": 202, "file_path": "shared.py"}]

        def post(self, endpoint: str, payload: dict[str, object]):
            self.posts.append((endpoint, payload))
            return {"updated": 1, "skipped": 0}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    FakeClient.posts = []
    FakeClient.file_requests = []
    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=engagement_dir,
            manifest=None,
            index_dir=None,
            repo_id=2,
            repo_key=None,
        )
    )

    assert FakeClient.file_requests == ["code/files?limit=5000&offset=0&repo_id=2"]
    assert len(FakeClient.posts) == 1
    _, payload = FakeClient.posts[0]
    assert payload["updates"] == [
        {
            "file_id": 202,
            "total_functions": 7,
            "total_entry_points": 0,
            "total_sinks": 0,
            "total_exports": 0,
        }
    ]
    assert "across 1 repos" in capsys.readouterr().err


def test_code_index_sync_rejects_mismatched_repo_id_and_repo_key(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    module = _load_script_module(
        "test_code_index_sync_rejects_mismatched_repo_id_module",
        "agent/scripts/assess/commands/code_index_sync.py",
    )
    engagement_dir = tmp_path / "engagement"
    manifest_dir = engagement_dir / "tools" / "analysis-state"
    index_dir = manifest_dir / "structural-index"
    index_dir.mkdir(parents=True)
    (index_dir / "repo-a-manifest.json").write_text(
        json.dumps({"repo_key": "repo-a", "path_to_index": {"shared.py": "repo-a/a.json"}}),
        encoding="utf-8",
    )
    (manifest_dir / "structural-index-manifest.json").write_text(
        json.dumps(
            {
                "schema": "structural-index-aggregate/v1",
                "repos": {
                    "repo-a": {"manifest_path": "structural-index/repo-a-manifest.json"},
                    "repo-b": {"manifest_path": "structural-index/repo-b-manifest.json"},
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/repos"
            return [
                {"id": 1, "repo_key": "repo-a", "name": "repo-a"},
                {"id": 2, "repo_key": "repo-b", "name": "repo-b"},
            ]

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                manifest=None,
                index_dir=None,
                repo_id=2,
                repo_key="repo-a",
            )
        )

    assert excinfo.value.code == 1
    assert "does not match per-repo manifest repo-a" in capsys.readouterr().err


def test_code_record_modules_rejects_auto_derived_key_collisions(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_code_record_modules_collision_module",
        "agent/scripts/assess/commands/code_record_modules.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    modules_path = tmp_path / "modules.json"
    modules_path.write_text(
        json.dumps(
            [
                {"name": "Auth/API"},
                {"name": "Auth API"},
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "code/modules?repo_id=5"
            return []

        def post(self, endpoint: str, payload: dict[str, object]):
            raise AssertionError("should not post when derived keys collide")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                repo_id="5",
                modules_json=str(modules_path),
            )
        )

    assert excinfo.value.code == 1
    assert "Provide explicit module_key values" in capsys.readouterr().err


def test_code_record_modules_rejects_generic_auto_pattern_labels(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """C25: reject 'auth_module_1' / 'module_2' / 'unknown_module' style labels
    at the CLI so the backend never accumulates undescriptive rows that
    code-architect + report-writer cannot map to a real subsystem."""
    module = _load_script_module(
        "test_code_record_modules_generic_module",
        "agent/scripts/assess/commands/code_record_modules.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    modules_path = tmp_path / "modules.json"
    modules_path.write_text(
        json.dumps([{"module_key": "auth_module_1", "name": "Auth Module 1"}]),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            raise AssertionError("should reject before fetching existing modules")

        def post(self, endpoint: str, payload: dict[str, object]):
            raise AssertionError("should reject before posting")

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                repo_id="5",
                modules_json=str(modules_path),
            )
        )

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "generic auto-pattern" in err
    assert "Pick a meaningful identifier" in err


def test_code_record_modules_accepts_meaningful_labels(
    monkeypatch, tmp_path: Path
) -> None:
    """C25: meaningful module keys/names continue to post normally."""
    module = _load_script_module(
        "test_code_record_modules_meaningful",
        "agent/scripts/assess/commands/code_record_modules.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    modules_path = tmp_path / "modules.json"
    modules_path.write_text(
        json.dumps([
            {"module_key": "auth_login", "name": "Authentication and login flow"},
            {"module_key": "payment_settlement", "name": "Payment settlement"},
        ]),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    posted: dict = {}

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            return []

        def post(self, endpoint: str, payload: dict[str, object]):
            posted["endpoint"] = endpoint
            posted["payload"] = payload
            return [
                {"id": 1, "module_key": "auth_login", "name": "Authentication and login flow"},
                {"id": 2, "module_key": "payment_settlement", "name": "Payment settlement"},
            ]

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=engagement_dir,
            repo_id="5",
            modules_json=str(modules_path),
        )
    )

    assert posted["endpoint"] == "code/modules"
    assert len(posted["payload"]["modules"]) == 2


def test_list_command_runs_failed_excludes_timeouts_by_default() -> None:
    module = _load_script_module(
        "test_list_command_runs_module",
        "agent/scripts/assess/commands/list_command_runs.py",
    )

    query = module._build_query(
        SimpleNamespace(
            q="",
            agent_name="",
            phase="",
            tool_name="",
            tool_bin="",
            audit_source="",
            technique="",
            probe_kind="",
            intent_q="",
            success=False,
            failed=True,
            destructive=False,
            not_destructive=False,
            timed_out=False,
            include_output=False,
            limit=50,
            offset=0,
        )
    )

    assert "success=false" in query
    assert "timed_out=false" in query


def test_list_command_runs_table_displays_tool_bin_for_execute_command() -> None:
    module = _load_script_module(
        "test_list_command_runs_render_module",
        "agent/scripts/assess/commands/list_command_runs.py",
    )

    rendered = module._render_table(
        [
            {
                "id": 1,
                "created_at": "2026-04-22T00:00:00Z",
                "phase": "recon",
                "agent_name": "recon-specialist",
                "tool_name": "command",
                "tool_bin": "nuclei",
                "technique": "RECON",
                "probe_kind": "fingerprint",
                "destructive": False,
                "return_code": 0,
                "timed_out": False,
                "intent": "reactive sweep",
                "command": "nuclei -l /engagements/eng/scans/targets.txt",
            }
        ]
    )

    assert "nuclei(command)" in rendered
    assert "\tcommand\t" not in rendered


def test_log_actor_kind_parses_before_or_after_subcommand() -> None:
    module = _load_script_module(
        "test_log_entry_actor_kind_module",
        "agent/scripts/assess/commands/log_entry.py",
    )

    parser = argparse.ArgumentParser(prog="vigil assess")
    parser.add_argument(
        "--actor-kind",
        dest="actor_kind",
        default=None,
        choices=["operator", "agent", "hook", "system"],
    )
    subparsers = parser.add_subparsers(dest="command")
    module.register(subparsers)

    before = parser.parse_args(
        ["--actor-kind", "operator", "log", "agent", "title", "action", "result"]
    )
    after = parser.parse_args(
        ["log", "agent", "title", "action", "result", "--actor-kind", "operator"]
    )

    assert before.actor_kind == "operator"
    assert after.actor_kind == "operator"


def test_list_command_runs_failed_with_timed_out_preserves_timeout_filter() -> None:
    module = _load_script_module(
        "test_list_command_runs_timeout_module",
        "agent/scripts/assess/commands/list_command_runs.py",
    )

    query = module._build_query(
        SimpleNamespace(
            q="",
            agent_name="",
            phase="",
            tool_name="",
            tool_bin="",
            audit_source="",
            technique="",
            probe_kind="",
            intent_q="",
            success=False,
            failed=True,
            destructive=False,
            not_destructive=False,
            timed_out=True,
            include_output=False,
            limit=50,
            offset=0,
        )
    )

    assert "success=false" in query
    assert "timed_out=true" in query
    assert "timed_out=false" not in query


def test_review_exploits_lists_backend_candidates(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_review_exploits_module",
        "agent/scripts/assess/commands/review_exploits.py",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(
        module,
        "load_scope",
        lambda engagement_dir, **kwargs: {
            "current_phase": "exploit",
            "exploit_policy": "selected",
            "exploit_review_state": "pending",
        },
    )

    monkeypatch.setattr(
        module,
        "load_exploit_candidates",
        lambda cfg: [
            {
                "slug": "ACTIVE-001",
                "severity": "high",
                "workflow_status": "active",
                "verification_state": "verified",
                "verification_disposition": "confirmed",
                "candidate_reason": "verified_high",
                "title": "Live issue",
                "canonical_location": "file:src/parser.py:10",
            },
            {
                "slug": "CHAIN-001",
                "severity": "info",
                "workflow_status": "active",
                "verification_state": "verified",
                "verification_disposition": "downgraded",
                "candidate_reason": "verified_chain_required",
                "title": "Chain-only primitive",
                "canonical_location": "https://example.test/export",
            },
        ],
    )

    module.run(SimpleNamespace(engagement_dir=tmp_path))

    output = capsys.readouterr().out
    assert "candidate_rule: verified findings only" in output
    assert "ACTIVE-001 | high | active | confirmed | verified_high | Live issue" in output
    assert "CHAIN-001 | info | active | downgraded | verified_chain_required | Chain-only primitive" in output


def _run_phase_report(monkeypatch, tmp_path: Path, payload: dict):
    """Drive ``check-phase-readiness --phase report`` against a report payload."""
    module = _load_script_module(
        "test_check_phase_readiness_report_module",
        "agent/scripts/assess/commands/check_phase_readiness.py",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            if endpoint.startswith("phase-readiness"):
                return {
                    "phase": "report",
                    "report_readiness": payload,
                    "intel": {"applicable": False, "engagement_type": "red",
                              "open_high_cves": [], "open_leads": [],
                              "exploited_unlinked_cves": [], "dangling_links": []},
                }
            # report is a depth phase (ADR 0012): the report gate now PREVIEWS the
            # depth ledger + the would-block set. Both are web-only skipped here.
            if endpoint == "application-units/depth-ledger":
                return {"skipped": True, "units": [], "summary": {}}
            if endpoint == "application-units/terminal-block":
                return {"skipped": True, "blocking": [], "warned_under_observed": [],
                        "deferred": [], "deferral_count": 0}
            raise AssertionError(f"unexpected endpoint {endpoint}")

        def get_engagement(self, endpoint: str, query: str = ""):
            return {"applicable": False, "engagement_type": "red",
                    "open_high_cves": [], "open_leads": [],
                    "exploited_unlinked_cves": [], "dangling_links": []}

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    args = SimpleNamespace(
        engagement_dir=str(tmp_path), phase="report", as_json=False, verbose=False,
        strict_vendor_saas=False, by_host=False, include_discovered=False,
        auto_redispatch=False, max_recommendations=10, depth=False,
        by_app_unit=False, include_intel=False, strict=False, strict_deep=False,
    )
    return module, args


def test_check_report_readiness_surfaces_backend_blockers(monkeypatch, tmp_path: Path, capsys) -> None:
    module, args = _run_phase_report(
        monkeypatch,
        tmp_path,
        {
            "ready": False,
            "blockers": [
                {
                    "kind": "verification",
                    "slug": "VA-001",
                    "detail": "Finding remains unreviewed.",
                }
            ],
        },
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(args)

    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "Final report blockers remain:" in out
    assert "verification | VA-001: Finding remains unreviewed." in out


def test_check_report_readiness_prints_advisories_without_failing(monkeypatch, tmp_path: Path, capsys) -> None:
    module, args = _run_phase_report(
        monkeypatch,
        tmp_path,
        {
            "ready": True,
            "blockers": [],
            "advisories": [
                {
                    "kind": "draft_finding_needs_disposition",
                    "slug": "VA-009",
                    "detail": "finding VA-009 is parked in workflow_status='draft'",
                },
                {
                    "kind": "unlinked_markdown_note",
                    "path": "notes/loose.md",
                    "detail": "markdown note 'notes/loose.md' is indexed but not linked",
                },
            ],
        },
    )

    module.run(args)
    captured = capsys.readouterr()
    assert "report readiness: ok" in captured.out
    assert "Advisories (not blocking" in captured.out
    assert "draft_finding_needs_disposition | VA-009:" in captured.out
    assert "unlinked_markdown_note:" in captured.out


def test_check_report_readiness_prints_advisories_alongside_blockers(monkeypatch, tmp_path: Path, capsys) -> None:
    module, args = _run_phase_report(
        monkeypatch,
        tmp_path,
        {
            "ready": False,
            "blockers": [
                {"kind": "finding_verification_state", "slug": "VA-001", "detail": "unreviewed"},
            ],
            "advisories": [
                {
                    "kind": "stale_dispatch_ready_handoff",
                    "agent_id": "HF-009",
                    "detail": "stale ready handoff; bulk-close with reconcile-stale",
                },
            ],
        },
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(args)
    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "Final report blockers remain:" in out
    assert "finding_verification_state | VA-001: unreviewed" in out
    assert "Advisories (not blocking" in out
    assert "stale_dispatch_ready_handoff: stale ready handoff" in out


# ---------------------------------------------------------------------------
# C3 — Curated adversarial-mindset rollout
#
# The rule drives "think like an attacker, not a test-case checker" framing
# and only belongs in roles where adversarial framing materially improves
# output. report-writer (pure backend-state transformation) and
# surface-collector (rule-based triage) are explicitly excluded because
# adversarial framing skews their output toward exaggeration / speculation.
# operator loads it via the always-active rules list in operator-core.md.
# ---------------------------------------------------------------------------

_ADVERSARIAL_MINDSET_INCLUDED = {
    # Roles that actively probe and were already wired up.
    "recon-specialist",
    "vulnerability-analyst",
    "exploit-developer",
    # Roles where adversarial framing materially improves output.
    "source-analyzer",
    "osint-analyst",
    "fuzzer",
    "code-vuln-hunter",
    "code-variant-hunter",
    "code-fuzz-engineer",
    # Lean-add roles.
    "code-architect",
    "code-vuln-verifier",
}

_ADVERSARIAL_MINDSET_EXCLUDED = {
    # Pure backend-state transformation — adversarial framing would push
    # toward severity inflation, contradicting reporting.md §3.
    "report-writer",
    # Rule-based triage — adversarial framing would skew the work-buffer
    # toward speculative entries.
    "surface-collector",
}


def _agents_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "agents"


@pytest.mark.parametrize("role", sorted(_ADVERSARIAL_MINDSET_INCLUDED))
def test_specialist_loads_adversarial_mindset(role: str) -> None:
    """Roles in the curated include-set must list adversarial-mindset.md
    in their Load First section so the wrapper carries it into specialist
    context. Drift in either direction fails the test."""
    body = (_agents_dir() / f"{role}.md").read_text(encoding="utf-8")
    assert "agent/rules/adversarial-mindset.md" in body, (
        f"{role} should load adversarial-mindset.md per the C3 curated rollout"
    )


@pytest.mark.parametrize("role", sorted(_ADVERSARIAL_MINDSET_EXCLUDED))
def test_specialist_does_not_load_adversarial_mindset(role: str) -> None:
    """Explicitly excluded roles must NOT load adversarial-mindset.md.
    These roles summarize or operate infrastructure; injecting an offensive
    ideation stance would push them toward inflation or speculation."""
    body = (_agents_dir() / f"{role}.md").read_text(encoding="utf-8")
    assert "agent/rules/adversarial-mindset.md" not in body, (
        f"{role} should NOT load adversarial-mindset.md "
        "(would push toward inflation/speculation)"
    )


# ---------------------------------------------------------------------------
# C21 — swarm dispatch mode + start-swarm helper
# ---------------------------------------------------------------------------


def test_start_swarm_records_N_rows_with_worker_encoded_task(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """C21: vigil assess agent start-swarm splits an items file into worker
    batches and writes one backend dispatch row per worker. Each row's task
    encodes the worker index, batch range, and items file name so the
    specialist can read its own slice via `agent get <agent_id>`. The helper
    does NOT spawn specialists — that's the operator's manual step via
    @agent-name (Claude Code) or spawn_agent (Codex)."""
    agent_mod = _load_script_module(
        "test_start_swarm_module",
        "agent/scripts/assess/commands/agent.py",
    )
    # Stub the dispatch helpers so the helper does not need a real backend.
    recorded: list[dict] = []

    class _FakeClient:
        def __init__(self) -> None:
            self.seq = 0

        def record_dispatch(self, payload: dict) -> dict:
            self.seq += 1
            recorded.append(dict(payload))
            return {
                "id": self.seq,
                "agent_id": payload.get("agent_id"),
                "agent_role": payload.get("agent_role"),
                "status": "in-progress",
            }

        def close(self) -> None:
            return None

    fake_client = _FakeClient()
    monkeypatch.setattr(
        agent_mod.dispatch,
        "_client_for",
        lambda _args: (fake_client, SimpleNamespace(engagement_dir=str(tmp_path))),
    )
    # _build_register_payload pulls from args; let it through unchanged so we
    # exercise the real payload-construction path.
    items_path = tmp_path / "items.txt"
    items_path.write_text("\n".join(f"file_{i}.js" for i in range(1, 13)), encoding="utf-8")
    # tmp_path stands in for the engagement dir; a real one always has scope.json
    # (the resolver requires it so a scope-less subdir can't masquerade as the root).
    (tmp_path / "scope.json").write_text("{}", encoding="utf-8")

    args = SimpleNamespace(
        action="start-swarm",
        agent_id=None,
        agent_role="code-vuln-hunter",
        task="scan for hardcoded credentials and exploitable patterns",
        scope_host=None,
        dispatch_model="gpt-5.5",
        reasoning="low",
        dispatch_mode_arg=None,
        skills="code-vulnerability-analysis",
        from_json=None,
        allow_duplicate=False,
        swarm_workers=3,
        swarm_batch_size=5,
        swarm_items_file=str(items_path),
        finding_slugs=None,
        engagement_dir=str(tmp_path),
        extra=[],
    )

    agent_mod._start_swarm(args)  # noqa: SLF001

    # 12 items / batch_size 5 / workers 3 → 3 batches of 5+5+2 items.
    assert len(recorded) == 3
    assert all(r["agent_role"] == "code-vuln-hunter" for r in recorded)
    assert all(r["dispatch_mode"] == "swarm" for r in recorded)
    # Each task encodes worker index and contiguous item range.
    assert "[swarm 1/3 items 1-5 from items.txt]" in recorded[0]["task"]
    assert "[swarm 2/3 items 6-10 from items.txt]" in recorded[1]["task"]
    assert "[swarm 3/3 items 11-12 from items.txt]" in recorded[2]["task"]
    # agent_ids are unique, sequential, prefixed by role-swarm-<uuid>-NN.
    agent_ids = [r["agent_id"] for r in recorded]
    assert len(set(agent_ids)) == 3
    for idx, aid in enumerate(agent_ids, start=1):
        assert aid.startswith("code-vuln-hunter-swarm-")
        assert aid.endswith(f"-{idx:02d}")
    # Summary table printed to stdout for the operator to paste into spawn calls.
    out = capsys.readouterr().out
    assert "## Swarm Dispatch Table" in out
    assert "workers: 3" in out
    assert "batch_size: 5" in out


def test_start_swarm_rejects_empty_items_file(monkeypatch, tmp_path: Path, capsys) -> None:
    """C21: empty items file must error out instead of recording zero rows."""
    agent_mod = _load_script_module(
        "test_start_swarm_empty_module",
        "agent/scripts/assess/commands/agent.py",
    )
    items_path = tmp_path / "items.txt"
    items_path.write_text("", encoding="utf-8")
    args = SimpleNamespace(
        action="start-swarm",
        agent_id=None,
        agent_role="code-vuln-hunter",
        task="scan",
        scope_host=None,
        dispatch_model=None,
        reasoning=None,
        dispatch_mode_arg=None,
        skills="code-vulnerability-analysis",
        from_json=None,
        allow_duplicate=False,
        swarm_workers=3,
        swarm_batch_size=5,
        swarm_items_file=str(items_path),
        finding_slugs=None,
        engagement_dir=str(tmp_path),
        extra=[],
    )
    with pytest.raises(SystemExit) as excinfo:
        agent_mod._start_swarm(args)  # noqa: SLF001
    assert excinfo.value.code == 1
    assert "items file is empty" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# C4c — dispatch honesty: terminal handoff-less dispatches
#
# A dispatch that lands on a terminal status (failed/aborted) with NO handoff
# row at all is silent state-loss: resume-brief's terminal_no_handoff list and
# `agent reconcile-stale` can only ever report the bare fact afterward, never
# why the dispatch died. `agent done` is the last chance to warn the operator
# before that context is gone. WARN-only (never a hard gate) — crash-recovery
# force-close must stay possible.
# ---------------------------------------------------------------------------


class _NoHandoffAssessmentClient:
    """Fake AssessmentClient: no handoff exists for any agent_id."""

    def __init__(self, *_a, **_k) -> None:
        pass

    def get_handoff(self, agent_id: str):
        return None

    def update_dispatch(self, agent_id: str, patch: dict) -> dict:
        return {"agent_id": agent_id, **patch}

    def close(self) -> None:
        return None


def _patch_dispatch_client(monkeypatch, module, client_cls) -> None:
    """Patch the AssessmentClient class + load_config at their home module
    (``dispatch.agent``, i.e. ``agent/scripts/assess/commands/dispatch/agent.py``).

    `_client_for` is defined once in that module and re-exported by name onto
    the `dispatch` package (`from .agent import _client_for`); every caller —
    whether it reaches it as `dispatch._client_for` or as a bare `_client_for`
    call from inside `dispatch.agent` itself (e.g. `_update_dispatch_status`)
    — is the SAME function object, and it always resolves `AssessmentClient`
    via its home module's globals. Patching `dispatch._client_for` directly
    would miss the latter call path (used internally by `agent done`).
    """
    monkeypatch.setattr(module.dispatch.agent, "AssessmentClient", client_cls)
    monkeypatch.setattr(
        module.dispatch.agent,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )


def test_agent_done_status_failed_warns_when_no_handoff_exists(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_script_module(
        "test_agent_done_no_handoff_warn_module",
        "agent/scripts/assess/commands/agent.py",
    )
    _patch_dispatch_client(monkeypatch, module, _NoHandoffAssessmentClient)

    module.run(
        SimpleNamespace(
            action="done",
            extra=["recon-died-1"],
            agent_id=None,
            dispatch_status="failed",
            completed_at=None,
            finding_slugs=None,
            engagement_dir="/tmp/eng",
        )
    )

    err = capsys.readouterr().err
    assert "WARN agent done: no handoff found for recon-died-1 closing as 'failed'" in err
    assert "silent state-loss" in err


def test_agent_done_status_aborted_warns_when_no_handoff_exists(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Same WARN fires for `--status aborted`, matching the `terminal_no_handoff`
    scope (failed/aborted) used by resume-brief and `reconcile-stale`."""
    module = _load_script_module(
        "test_agent_done_no_handoff_warn_aborted_module",
        "agent/scripts/assess/commands/agent.py",
    )
    _patch_dispatch_client(monkeypatch, module, _NoHandoffAssessmentClient)

    module.run(
        SimpleNamespace(
            action="done",
            extra=["recon-died-2"],
            agent_id=None,
            dispatch_status="aborted",
            completed_at=None,
            finding_slugs=None,
            engagement_dir="/tmp/eng",
        )
    )

    err = capsys.readouterr().err
    assert "WARN agent done: no handoff found for recon-died-2 closing as 'aborted'" in err


def test_agent_done_status_completed_warns_when_no_handoff_exists(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Completed-without-handoff is still unaccounted specialist output."""
    module = _load_script_module(
        "test_agent_done_no_handoff_completed_module",
        "agent/scripts/assess/commands/agent.py",
    )
    _patch_dispatch_client(monkeypatch, module, _NoHandoffAssessmentClient)

    module.run(
        SimpleNamespace(
            action="done",
            extra=["recon-finished-1"],
            agent_id=None,
            dispatch_status="completed",
            completed_at=None,
            finding_slugs=None,
            engagement_dir="/tmp/eng",
        )
    )

    err = capsys.readouterr().err
    assert "no handoff found" in err
    assert "dispatch_reconciliation" in err


# ---------------------------------------------------------------------------
# C64 — details_json / --inline drift guard
#
# The backend stores finding metadata in a column literally named
# `details_json` (TEXT, JSON-encoded). The CLI write path on
# `update-finding --inline` accepts `details` (dict) and the API
# encodes it back into the column. Operators are warned about this
# asymmetry in agent/rules/hunting.md §20 and the report-generation
# skill. This regression test locks in the current correct state:
# NO operator-facing prompt should instruct invoking
# `update-finding --inline` (or its --details-json equivalent) with
# the wrong field name. References to `details_json` as a READ-side
# column or as part of a "not details_json" warning remain legitimate.
# ---------------------------------------------------------------------------


def _agent_prompt_files() -> list[Path]:
    repo_root = Path(__file__).resolve().parents[3]
    roots = [
        repo_root / "agent" / "agents",
        repo_root / "agent" / "skills",
        repo_root / "agent" / "rules",
        repo_root / "agent" / "references",
    ]
    files: list[Path] = []
    for root in roots:
        if root.is_dir():
            files.extend(sorted(root.rglob("*.md")))
    return files


# (C45 review-mode heading-pin test removed: per the repository's
# "Markdown prompt/doc testing policy" (root AGENTS.md), prompt/doc wording and
# exact headings are not asserted in tests — brittle heading pins turn normal
# prompt editing into fixture maintenance and reward stale phrasing. Review-mode
# section presence is a prompt-authoring-checklist concern, not a CI gate.)


def test_no_operator_prompt_invokes_update_finding_with_details_json() -> None:
    """C64: an operator-facing prompt must not instruct passing
    `details_json` as the field name to `vigil assess update-finding`.
    The canonical write-side field is `details` (a dict); the
    storage column happens to be `details_json` (a JSON string) and
    is correctly referenced on the READ side. This test catches the
    drift case where a future skill / rule mistakenly tells the
    operator to write under `details_json`."""
    offending: list[tuple[str, int, str]] = []
    # Match actual invocation shapes only — JSON-style keys, --details-json
    # flag, or "use details_json:" recipe phrasing. Lines that mention
    # `details_json` in a warning context ("not details_json", "if a recipe
    # says to pass details_json...") are LEGITIMATE and excluded.
    bad_patterns = (
        # JSON-literal: "details_json": {...}  inside an update/record-finding example
        re.compile(r'update-finding[^\n]*--inline[^\n]*"details_json"\s*:', re.IGNORECASE),
        re.compile(r'record-finding[^\n]*"details_json"\s*:', re.IGNORECASE),
        # Hypothetical CLI flag form (does not exist; flag if anyone documents one)
        re.compile(r"update-finding[^\n]*--details-json[ =]", re.IGNORECASE),
    )
    for path in _agent_prompt_files():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern in bad_patterns:
                if pattern.search(line):
                    offending.append((str(path), line_no, line.strip()))
                    break

    assert offending == [], (
        "Operator-facing prompts must not invoke update-finding / record-finding "
        "with `details_json` as the field name (canonical write field is `details`). "
        "Offending lines:\n"
        + "\n".join(f"  {p}:{n}: {line}" for p, n, line in offending)
    )


# ---------------------------------------------------------------------------
# render-operator-prompts.sh check — drift detection
# ---------------------------------------------------------------------------


def test_render_check_flags_missing_wrapper_as_drift(tmp_path: Path) -> None:
    """A deleted/missing specialist wrapper must be reported as drift.

    Before this guard, the per-wrapper diff block was wrapped in `[[ -f ]]`,
    so deleting `.claude/agents/recon-specialist.md` from the repo silently
    passed render-check — operators reading from the wrapper directory then
    hit a missing file at dispatch time.
    """
    import shutil
    import subprocess

    agent_root = _scripts_root().parent  # .../agent
    output_dir = tmp_path / "agent-tree"
    shutil.copytree(agent_root, output_dir, symlinks=False)

    # Sanity: the file should exist before we delete it.
    victim = output_dir / ".claude" / "agents" / "recon-specialist.md"
    assert victim.is_file()
    victim.unlink()

    script = _scripts_root() / "render-operator-prompts.sh"
    proc = subprocess.run(
        ["bash", str(script), "check", str(output_dir)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode != 0, (
        "render-check should exit non-zero when a wrapper is missing. "
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    assert "recon-specialist.md" in proc.stderr
    assert "missing" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# resume-brief: must not crash on a fresh/empty engagement when the backend
# returns a non-dict body (empty string, or the SPA index.html for an unknown
# route). Regression for AttributeError: 'str' object has no attribute 'get'.
# ---------------------------------------------------------------------------

def _run_resume_brief(monkeypatch, tmp_path, body, *, as_json):
    module = _load_script_module(
        "resume_brief_regression",
        "agent/scripts/assess/commands/resume_brief.py",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            pass

        def get(self, endpoint: str):
            return body

        def close(self) -> None:
            return None
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)
    module.run(
        SimpleNamespace(
            engagement_dir=tmp_path,
            q="",
            finding="",
            agent_id="",
            max_age_hours=None,
            since="",
            as_json=as_json,
        )
    )


def test_list_report_findings_409_is_concise(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_list_report_findings_module",
        "agent/scripts/assess/commands/list_report_findings.py",
    )
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )

    detail = {
        "detail": {
            "ready": False,
            "blocker_count": 2,
            "blockers": [
                {"kind": "coverage", "detail": "Coverage blockers remain", "blocker_count": 7},
                {"kind": "finding_verification_state", "slug": "VA-001", "detail": "unreviewed"},
            ],
        }
    }

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            pass

        def get(self, endpoint: str):
            raise module.AssessError(f"HTTP 409:\n{json.dumps(detail)}")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as exc:
        module.run(SimpleNamespace(engagement_dir=tmp_path, mode="final", json=False))

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Final report blockers remain" in captured.err
    assert "coverage: Coverage blockers remain" in captured.err
    assert "VA-001: unreviewed" in captured.err
    assert len(captured.err) < 1000


@pytest.mark.parametrize("body", ["", "<!doctype html><html>SPA</html>"])
def test_resume_brief_handles_non_dict_body(monkeypatch, tmp_path, capsys, body):
    _run_resume_brief(monkeypatch, tmp_path, body, as_json=False)
    out = capsys.readouterr().out
    assert "No prior state" in out  # no AttributeError, clean notice


def test_resume_brief_non_dict_body_json_emits_valid_object(monkeypatch, tmp_path, capsys):
    _run_resume_brief(monkeypatch, tmp_path, "", as_json=True)
    payload = json.loads(capsys.readouterr().out)  # valid JSON object, not a bare string
    assert isinstance(payload, dict)
    assert payload["engagement"] == {}
    assert "note" in payload


def test_resume_brief_dict_body_still_renders(monkeypatch, tmp_path, capsys):
    body = {"engagement": {"key": "eng", "current_phase": "recon", "host_count": 3}}
    _run_resume_brief(monkeypatch, tmp_path, body, as_json=False)
    out = capsys.readouterr().out
    assert "Resume Brief: eng" in out
    assert "phase: recon" in out
    # A minimal body carries no surfaces/work_buffer block — those sections must
    # stay absent rather than render empty headers.
    assert "## Surfaces" not in out
    assert "## Work Buffer" not in out


def test_resume_brief_renders_surfaces_and_work_buffer(monkeypatch, tmp_path, capsys):
    body = {
        "engagement": {"key": "eng"},
        "surfaces": {
            "total": 4,
            "open_count": 3,
            "by_status": {"discovered": 2, "covered": 1, "deferred": 1},
            "by_status_type": [
                {"status": "discovered", "surface_type": "auth_entry", "count": 1},
                {"status": "discovered", "surface_type": "object_reference", "count": 1},
            ],
            "top_uncovered": [
                {"status": "discovered", "surface_type": "auth_entry", "target_descriptor": "https://x/login", "source_name": "surface-collector"},
                {"status": "deferred", "surface_type": "file_handling", "target_descriptor": "https://x/upload", "source_name": ""},
            ],
        },
        "work_buffer": {"pending_total": 3, "by_bucket": {"idor": 2, "ssrf": 1}},
    }
    _run_resume_brief(monkeypatch, tmp_path, body, as_json=False)
    out = capsys.readouterr().out
    assert "## Surfaces" in out
    assert "total: 4 (open: 3)" in out
    assert "discovered/auth_entry: 1" in out
    assert "discovered auth_entry: https://x/login [surface-collector]" in out
    assert "## Work Buffer" in out
    assert "pending total: 3" in out
    assert "idor: 2" in out
    assert "ssrf: 1" in out


def test_resume_brief_renders_zero_state_surfaces_and_work_buffer(monkeypatch, tmp_path, capsys):
    # A real backend on an empty engagement emits the keys with zero counts, so
    # the headers DO render (with explicit zero-state lines) — unlike a synthetic
    # body that omits the keys entirely (which stays header-less).
    body = {
        "engagement": {"key": "eng"},
        "surfaces": {"total": 0, "open_count": 0, "by_status": {}, "by_status_type": [], "top_uncovered": []},
        "work_buffer": {"pending_total": 0, "by_bucket": {}},
    }
    _run_resume_brief(monkeypatch, tmp_path, body, as_json=False)
    out = capsys.readouterr().out
    assert "## Surfaces" in out
    assert "total: 0 (open: 0)" in out
    assert "top uncovered (0):" in out
    assert "## Work Buffer" in out
    assert "pending by gf-bucket: -" in out


def test_resume_brief_findings_always_show_medium_plus(monkeypatch, tmp_path, capsys):
    def _finding(slug, severity):
        return {
            "slug": slug,
            "severity": severity,
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "title": f"{slug} title",
        }

    rows = [_finding(f"L{i}", "low") for i in range(1, 8)] + [_finding("CRIT-1", "critical")]
    body = {"engagement": {"key": "eng"}, "findings": {"active": rows}}
    _run_resume_brief(monkeypatch, tmp_path, body, as_json=False)
    out = capsys.readouterr().out
    # The critical is shown even though it sits behind 7 low rows; the 7th low
    # (beyond the 6-row floor) is dropped, and the truncation note is printed.
    assert "CRIT-1 critical" in out
    assert "L7 low" not in out
    assert "showing 7 of 8 (medium+ always shown)" in out


def test_resume_brief_renders_read_first_intel_notes(monkeypatch, tmp_path, capsys):
    body = {
        "engagement": {"key": "eng"},
        "intel": {
            "summary": {"notes": 2},
            "open_high_cves": [],
            "open_leads": [],
            "read_first_notes": [
                {"id": 5, "title": "Coverage map for /api", "tags": ["coverage"], "lead_status": ""},
                {"id": 6, "title": "Read me: WAF bypass", "tags": ["read-first"], "lead_status": "open"},
            ],
        },
    }
    _run_resume_brief(monkeypatch, tmp_path, body, as_json=False)
    out = capsys.readouterr().out
    assert "read-first / coverage notes (2):" in out
    assert "id=5 (coverage) Coverage map for /api" in out
    assert "id=6 (read-first) [open] Read me: WAF bypass" in out


# ---------------------------------------------------------------------------
# Engagement-dir / key resolution hardening + relative cases.db anchoring.
# Regression for: a scope-less explicit selector deriving key="scans", and
# a bare relative cases.db opening the wrong (empty) DB from a drifted cwd.
# ---------------------------------------------------------------------------

def _import_assess_config():
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    import assess.lib.config as config
    return config


def test_resolve_engagement_dir_rejects_scopeless_subdir(monkeypatch, tmp_path):
    config = _import_assess_config()
    eng = tmp_path / "2026-05-29-eng"
    (eng / "scans").mkdir(parents=True)
    (eng / "scope.json").write_text("{}", encoding="utf-8")
    monkeypatch.delenv("VIGIL_SESSION_ENGAGEMENT_DIR", raising=False)

    # The engagement root (has scope.json) resolves and the key is its basename.
    assert config.resolve_engagement_dir(str(eng)) == str(eng.resolve())

    # A scope-less subdir via --engagement-dir fails loud (the cd-into-subdir trap).
    with pytest.raises(SystemExit):
        config.resolve_engagement_dir(str(eng / "scans"))

    # Same trap via a malformed launcher-session binding.
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(eng / "scans"))
    with pytest.raises(SystemExit):
        config.resolve_engagement_dir(None)


def test_anchor_engagement_relative_uses_session_engagement(monkeypatch, tmp_path):
    config = _import_assess_config()
    eng = tmp_path / "2026-05-29-eng2"
    eng.mkdir()
    (eng / "scope.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(eng))

    # Relative cases.db anchors to the engagement dir even when cwd is elsewhere.
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert config.anchor_engagement_relative("cases.db", None) == str(eng.resolve() / "cases.db")

    # Absolute paths are returned unchanged.
    assert config.anchor_engagement_relative("/abs/cases.db", None) == "/abs/cases.db"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def _load_record_finding_module():
    return _load_script_module(
        "record_finding_evidence_validation",
        "agent/scripts/assess/commands/record_finding.py",
    )


def test_evidence_ref_accepts_existing_file(tmp_path):
    mod = _load_record_finding_module()
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "proof.txt").write_text("evidence", encoding="utf-8")
    # Relative to engagement dir, and the container-path form, both resolve.
    for ref in ("scans/proof.txt", "/engagements/eng/scans/proof.txt"):
        mod._normalize_evidence_ref(
            {"evidence_ref": ref}, eng_dir=str(tmp_path), engagement_key="eng", allow_unindexed=False
        )  # no SystemExit


def test_evidence_ref_url_is_rerouted_not_rejected(tmp_path, capsys):
    mod = _load_record_finding_module()
    payload = {"evidence_ref": "https://target.example/proof", "details": {}}
    mod._normalize_evidence_ref(  # no SystemExit
        payload, eng_dir=str(tmp_path), engagement_key="eng", allow_unindexed=False,
    )
    assert payload["details"]["references"] == ["https://target.example/proof"]
    assert payload["evidence_ref"] == ""
    assert "rerouted into details.references" in capsys.readouterr().err


def test_evidence_ref_url_rerouted_even_when_details_missing(tmp_path):
    mod = _load_record_finding_module()
    payload = {"evidence_ref": "http://t.example/x"}
    mod._normalize_evidence_ref(
        payload, eng_dir=str(tmp_path), engagement_key="eng", allow_unindexed=True,
    )
    assert payload["details"]["references"] == ["http://t.example/x"]
    assert payload["evidence_ref"] == ""


def test_evidence_ref_prose_warns_not_rejects(tmp_path, capsys):
    mod = _load_record_finding_module()
    mod._normalize_evidence_ref(
        {"evidence_ref": "kali run_id 13992 listMethods proved this"},
        eng_dir=str(tmp_path), engagement_key="eng", allow_unindexed=False,
    )
    assert "prose" in capsys.readouterr().err


def test_evidence_ref_missing_path_warns_not_rejects(tmp_path, capsys):
    mod = _load_record_finding_module()
    mod._normalize_evidence_ref(
        {"evidence_ref": "scans/does-not-exist.txt"},
        eng_dir=str(tmp_path), engagement_key="eng", allow_unindexed=False,
    )
    # "nothing exists", not "no file exists": a DIRECTORY is a valid
    # evidence_ref too, so the warning must not imply only a file would count.
    assert "nothing exists there" in capsys.readouterr().err


def test_evidence_ref_empty_warns_not_rejects(tmp_path, capsys):
    mod = _load_record_finding_module()
    mod._normalize_evidence_ref(
        {"evidence_ref": ""}, eng_dir=str(tmp_path), engagement_key="eng", allow_unindexed=False
    )
    assert "no evidence_ref set" in capsys.readouterr().err


def test_evidence_ref_allow_unindexed_silences_warning(tmp_path, capsys):
    mod = _load_record_finding_module()
    mod._normalize_evidence_ref(
        {"evidence_ref": "just prose here"},
        eng_dir=str(tmp_path), engagement_key="eng", allow_unindexed=True,
    )
    assert capsys.readouterr().err == ""


def test_evidence_ref_prose_containing_scheme_is_not_a_url(tmp_path, capsys):
    mod = _load_record_finding_module()
    payload = {"evidence_ref": "attacker forces http:// downgrade then steals cookie", "details": {}}
    mod._normalize_evidence_ref(
        payload, eng_dir=str(tmp_path), engagement_key="eng", allow_unindexed=False,
    )
    assert payload["evidence_ref"] == "attacker forces http:// downgrade then steals cookie"
    assert "references" not in payload["details"]
    assert "warning" in capsys.readouterr().err


def test_record_time_schema_allows_finding_without_report_time_fields():
    mod = _load_record_finding_module()
    payload = mod._normalize_payload(
        {
            "title": "Suspected IDOR on /api/orders/{id}",
            "severity": "medium",
            "details": {
                "evidence": "Sequential order IDs returned other tenants' rows in a manual probe",
                "impact": "Cross-tenant data exposure",
            },
        },
        agent_name="vulnerability-analyst",
        candidate_slug="f-0001",
    )
    errors = mod.collect_validation_errors(payload, mod._FINDING_SCHEMA)
    assert errors == [], errors


def test_record_time_schema_still_requires_evidence_and_impact():
    mod = _load_record_finding_module()
    payload = mod._normalize_payload(
        {"title": "Bare finding", "severity": "low", "details": {}},
        agent_name="va",
        candidate_slug="f-0002",
    )
    errors = mod.collect_validation_errors(payload, mod._FINDING_SCHEMA)
    joined = " ".join(errors)
    assert errors, "expected record-time floor (evidence + impact) to still be enforced"
    assert "evidence" in joined and "impact" in joined, joined


def test_update_finding_notes_replace_without_notes_errors():
    from types import SimpleNamespace
    mod = _load_script_module("update_finding_guard", "agent/scripts/assess/commands/update_finding.py")
    with pytest.raises(SystemExit):
        mod.run(SimpleNamespace(notes_replace=True, notes=None, inline_payload=None, payload=None))




def _run_ingest_spec(monkeypatch, tmp_path: Path, spec: dict, scope: dict):
    """Drive ingest-spec.run against an in-process FakeClient.

    ingest-spec no longer writes a local cases.db; it POSTs one
    request-observation per operation (in bulk) whose ``work_item`` derivation
    block carries the per-op url/method/params (ADR 0013 — the backend derives
    the assessment_work_items row). Returns ``(posts, rows)`` where ``posts`` is
    the list of captured observation payloads and ``rows`` reconstructs the
    ``(url, method, query_params, body_params, path_params, cookie_params)``
    tuples the old cases.db ``work_items`` SELECT produced (params as JSON text),
    so the S10/S11 callers assert unchanged.
    """
    module = _load_script_module(
        "test_ingest_spec_module",
        "agent/scripts/assess/commands/ingest_spec.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")

    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir=None: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "auth_active_context", lambda _eng_dir: "anonymous")

    posts: list[dict] = []

    class FakeClient:
        def __init__(self, *a, **k) -> None:
            self._next_id = 200

        def post(self, endpoint, payload):
            if endpoint == "request-observations/bulk":
                records = []
                for observation in payload.get("items", []):
                    posts.append(observation)
                    self._next_id += 1
                    records.append({"request_variant": {"id": self._next_id}})
                return {"count": len(records), "records": records}
            # Individual-fallback path (bulk endpoint missing / payload error).
            posts.append(payload)
            self._next_id += 1
            return {"request_variant": {"id": self._next_id}}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            spec_file=str(spec_path),
            engagement_dir=str(engagement_dir),
        )
    )

    rows = [
        (
            observation["url"],
            observation["method"],
            observation["work_item"]["query_params"],
            observation["work_item"]["body_params"],
            observation["work_item"]["path_params"],
            observation["work_item"]["cookie_params"],
        )
        for observation in posts
    ]
    return posts, rows


def test_s10_relative_servers_spec_still_ingests_paths(monkeypatch, tmp_path, capsys):
    """S10: an OpenAPI spec whose only `servers` url is RELATIVE (`/api`) used to
    hit the absolute-URL check and sys.exit(1), ingesting ZERO paths. It must now
    resolve against the engagement target host and ingest its paths."""
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api"}],
        "paths": {
            "/users": {"get": {"responses": {"200": {}}}},
            "/login": {"post": {"responses": {"200": {}}}},
        },
    }
    scope = {"hosts": ["app.example.com"]}
    posts, rows = _run_ingest_spec(monkeypatch, tmp_path, spec, scope)

    assert len(rows) == 2
    urls = sorted(r[0] for r in rows)
    assert urls == [
        "https://app.example.com/api/login",
        "https://app.example.com/api/users",
    ]
    err = capsys.readouterr().err
    assert "relative servers url" in err


def test_s10_relative_servers_no_scope_host_skips_loudly(monkeypatch, tmp_path, capsys):
    """S10: with no resolvable host, a relative-base spec CANNOT form
    absolute URLs (the backend requires them). Instead of silently POSTing
    relative URLs that the backend rejects one-by-one (zero coverage + a false
    'it ran' signal), ingest-spec warns ONCE with the root cause and ingests
    nothing — never a hard-exit, never a silent partial."""
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api"}],
        "paths": {"/ping": {"get": {"responses": {"200": {}}}}},
    }
    scope = {"hosts": ["10.0.0.0/24"]}
    posts, rows = _run_ingest_spec(monkeypatch, tmp_path, spec, scope)
    assert rows == []
    err = capsys.readouterr().err
    assert "ABSOLUTE request URLs" in err
    assert "Add a host to" in err


def test_s11_spec_parses_refs_composed_form_and_pathlevel_params(monkeypatch, tmp_path):
    """S11: path-level params, $ref params, multipart/form bodies, array and
    composed (allOf) schemas must all surface in the ingested param inventory."""
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com"}],
        "components": {
            "parameters": {
                "ApiKey": {"name": "api_key", "in": "query", "schema": {"type": "string"}},
            },
            "schemas": {
                "Base": {"type": "object", "properties": {"a": {"type": "string"}}},
                "Child": {
                    "allOf": [
                        {"$ref": "#/components/schemas/Base"},
                        {"type": "object", "properties": {"b": {"type": "string"}}},
                    ]
                },
            },
        },
        "paths": {
            "/items/{id}": {
                "parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/ApiKey"}],
                    "responses": {"200": {}},
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"file": {"type": "string", "format": "binary"}},
                                }
                            },
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Child"}
                            },
                        }
                    },
                    "responses": {"200": {}},
                },
            },
        },
    }
    scope = {"hosts": ["api.example.com"]}
    posts, rows = _run_ingest_spec(monkeypatch, tmp_path, spec, scope)
    assert len(rows) == 2

    by_method = {r[1]: r for r in rows}
    get_query = json.loads(by_method["GET"][2])
    get_path = json.loads(by_method["GET"][4])
    assert "api_key" in get_query
    assert "id" in get_path

    post_body = json.loads(by_method["POST"][3])
    post_path = json.loads(by_method["POST"][4])
    assert {"file", "a", "b"} <= set(post_body.keys())
    assert "id" in post_path


def test_opencode_works_inline_claude_codex_dispatch_carveout() -> None:
    """OpenCode works the engagement INLINE, while Claude/Codex (and Goose) keep
    the normal dispatch model.

    The 2026-06-18 switch to "OpenCode dispatches specialists exactly like
    Claude/Codex" was REVERTED: on headless ``opencode run`` the built-in
    ``task`` tool's ``subagent_type`` enum exposes only the server-registered
    built-ins (``explore``/``general``), so our ``.opencode/agent/*.md`` custom
    roles are not dispatchable (opencode#29616). Mandating dispatch on OpenCode
    regressed a bench family 100%->60%, so the operator works OpenCode targets
    inline (issuing the sanctioned ``vigil assess kali`` probes itself). This
    guards that operator-core.md carries the opencode#29616-keyed INLINE
    carve-out and that it rendered into AGENTS.md, while Claude/Codex keep
    dispatching. Kept consistent with the passing
    ``tests/test_bench.py::test_dispatch_doctrine_opencode_inline_carveout*``
    tests.
    """
    repo_root = Path(__file__).resolve().parents[3]
    core = (repo_root / "agent" / "operator-core.md").read_text(encoding="utf-8")
    agents = (repo_root / "agent" / "AGENTS.md").read_text(encoding="utf-8")

    assert "### Runtime Dispatch Syntax" in core
    assert "### Runtime Dispatch Syntax" in agents

    # The reverted "dispatch normally on OpenCode" framing is GONE from both the
    # source and the render — that posture regressed the bench.
    for gone in ("Dispatch specialists normally", "dispatches exactly like Claude"):
        assert gone not in core, f"operator-core.md still carries reverted text: {gone!r}"
        assert gone not in agents, f"AGENTS.md still carries reverted text: {gone!r}"

    # The OpenCode INLINE carve-out is present and rendered (Runtime Dispatch
    # Syntax now uses a table; locate the OpenCode row by its table cell marker).
    for src, name in ((core, "operator-core.md"), (agents, "AGENTS.md")):
        oc_idx = src.index("| **OpenCode**")
        oc_row = src[oc_idx:].split("\n", 1)[0]
        assert "INLINE" in oc_row, f"{name}: OpenCode row lost INLINE posture"
        # Claude/Codex keep the normal dispatch model.
        assert "Claude Code and Codex keep the normal dispatch model" in src, name

    # Claude/Codex rows carry NO inline-probe override — they dispatch.
    claude_idx = core.index("| **Claude Code**")
    codex_idx = core.index("| **Codex**")
    oc_idx = core.index("| **OpenCode**")
    assert claude_idx < codex_idx < oc_idx
    assert "INLINE" not in core[claude_idx:oc_idx]
