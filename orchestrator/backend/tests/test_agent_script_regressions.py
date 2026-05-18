from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sqlite3
from pathlib import Path
from types import ModuleType, SimpleNamespace
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
        options=SimpleNamespace(engagement_dir=""),
        log=SimpleNamespace(info=lambda *a, **k: None, warn=lambda *a, **k: None, error=lambda *a, **k: None),
    )
    sys.modules["mitmproxy"] = mitmproxy_module
    return _load_script_module("test_proxy_addon_module", "agent/scripts/proxy_addon.py")


def test_assess_cli_imports_agent_work_buffer_without_legacy_dispatch_module() -> None:
    """Top-level ``aith assess`` must not expose ``dispatch``; agent + work-buffer are canonical."""
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


def test_kali_runtime_dockerfiles_package_audit_enum_module() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    required_copy = "COPY agent/scripts/assess/lib/audit_enums.py /opt/mcp-tools/audit_enums.py"
    for dockerfile in (
        repo_root / "agent" / "docker" / "runtime-full" / "Dockerfile",
        repo_root / "agent" / "docker" / "runtime-lightweight" / "Dockerfile",
    ):
        contents = dockerfile.read_text(encoding="utf-8")
        assert required_copy in contents


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


def test_record_proposal_rejects_invalid_finding_payload(tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_record_proposal_module",
        "agent/scripts/assess/commands/record_proposal.py",
    )
    session_dir = tmp_path / "session-a"
    session_dir.mkdir()
    payload_path = tmp_path / "proposal.json"
    payload_path.write_text(
        json.dumps({"type": "finding_record", "payload": {"severity": "high"}}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(session_dir=str(session_dir), json_file=str(payload_path)))

    assert excinfo.value.code == 1
    assert "payload.title is required" in capsys.readouterr().err
    assert not (session_dir / "proposals" / "proposals.jsonl").exists()


def test_record_proposal_accepts_valid_credential_payload(tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_record_proposal_valid_module",
        "agent/scripts/assess/commands/record_proposal.py",
    )
    session_dir = tmp_path / "session-a"
    session_dir.mkdir()
    payload_path = tmp_path / "proposal.json"
    payload_path.write_text(
        json.dumps(
            {
                "type": "credential",
                "payload": {
                    "credential_key": "vpn-admin",
                    "kind": "password",
                    "principal": "admin@example.com",
                    "secret": "hunter2",
                    "status": "discovered",
                },
            }
        ),
        encoding="utf-8",
    )

    module.run(SimpleNamespace(session_dir=str(session_dir), json_file=str(payload_path)))
    output = capsys.readouterr().out
    proposals_file = session_dir / "proposals" / "proposals.jsonl"

    assert "Recorded proposal" in output
    lines = proposals_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    recorded = json.loads(lines[0])
    assert recorded["type"] == "credential"
    assert recorded["payload"]["credential_key"] == "vpn-admin"


def test_proxy_addon_loads_legacy_scope_keys(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
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
    collector.engagement_dir = str(engagement_dir)
    collector._load_scope()

    assert collector._is_in_scope("example.com") is True
    assert collector._is_in_scope("api.example.com") is True
    assert collector._is_in_scope("legacy.example.net") is True
    assert collector._is_in_scope("out-of-scope.test") is False


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


def test_ingest_candidates_preserve_metadata_and_route(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    ingest_module = _load_script_module(
        "test_ingest_candidates_module",
        "agent/scripts/assess/commands/ingest_candidates.py",
    )
    dispatch_module = _load_script_module(
        "test_ingest_candidate_dispatch_module",
        "agent/scripts/assess/commands/dispatch.py",
    )
    db_module = _load_script_module(
        "test_ingest_candidate_db_module",
        "agent/scripts/assess/lib/db.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    db_path = engagement_dir / "cases.db"
    db_path.touch()
    db_module.db_init(str(db_path))
    db_module.db_insert_work_item(
        str(db_path),
        queue_key="variant:701:unknown",
        request_variant_id=701,
        method="GET",
        url="https://portal.agency.example/taap-core/api/logout",
        url_path="/taap-core/api/logout",
        case_type="unknown",
        source="plain-url-ingest",
    )

    candidate_path = tmp_path / "candidate_records.jsonl"
    candidate_path.write_text(
        json.dumps(
            {
                "url": "https://portal.agency.example/taap-core/api/logout",
                "method": "GET",
                "path": "/taap-core/api/logout",
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
            posts.append((endpoint, payload))
            return {"request_variant": {"id": 701}}

        def close(self) -> None:
            return None

    monkeypatch.setattr(ingest_module, "AssessmentClient", FakeClient)

    ingest_module.run(
        SimpleNamespace(
            db_path=str(db_path),
            source="surface-collector-curated",
            records_file=str(candidate_path),
            engagement_dir=engagement_dir,
        )
    )

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            """SELECT type, status, priority_score, priority_reason, cluster_key,
                      signals, selected_by, triage_rationale, live_status
               FROM work_items
               WHERE queue_key = ?""",
            ("variant:701:auth_entry",),
        ).fetchone()
        row_count = conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]
    finally:
        conn.close()

    assert row_count == 1
    assert row[0:5] == (
        "auth_entry",
        "pending",
        245,
        "TAAP auth API workflow",
        "gf:auth_workflow",
    )
    assert json.loads(row[5]) == ["api", "auth", "workflow"]
    assert row[6:] == (
        "auth",
        "Selected from GAU because it is an auth workflow endpoint.",
        "live",
    )
    assert posts[0][1]["observation_payload"]["candidate_metadata"]["priority_score"] == 245

    capsys.readouterr()
    dispatch_module.run(
        SimpleNamespace(
            db_path=str(db_path),
            action="fetch-by-priority",
            extra=["10", "auto"],
            by="status",
            reason="",
            max_lines=40,
            include_evidence=False,
        )
    )

    payload = json.loads(capsys.readouterr().out)
    assert [item["queue_key"] for item in payload] == ["variant:701:auth_entry"]
    assert payload[0]["assigned_agent"] == "vulnerability-analyst"


def test_ingest_candidates_route_real_bia_candidate_shapes(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    ingest_module = _load_script_module(
        "test_ingest_real_candidate_shapes_module",
        "agent/scripts/assess/commands/ingest_candidates.py",
    )
    dispatch_module = _load_script_module(
        "test_ingest_real_candidate_shapes_dispatch_module",
        "agent/scripts/assess/commands/dispatch.py",
    )
    db_module = _load_script_module(
        "test_ingest_real_candidate_shapes_db_module",
        "agent/scripts/assess/lib/db.py",
    )
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    db_path = engagement_dir / "cases.db"
    db_path.touch()
    db_module.db_init(str(db_path))

    candidate_path = tmp_path / "candidate_records.jsonl"
    records = [
        {
            "url": "https://www.agency.example/org-event-feed/37221",
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
            "url": "https://www.agency.example/fb.log",
            "path": "/fb.log",
            "score": 80,
            "selection_reasons": ["admin/debug/config/secret signal"],
            "signals": ["backup_config"],
            "sources": ["osint-gau"],
        },
        {
            "url": "https://www.agency.example/web-guidance",
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

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key
            self.next_id = 800

        def post(self, endpoint: str, payload: dict[str, object]):
            self.next_id += 1
            return {"request_variant": {"id": self.next_id}}

        def close(self) -> None:
            return None

    monkeypatch.setattr(ingest_module, "AssessmentClient", FakeClient)

    ingest_module.run(
        SimpleNamespace(
            db_path=str(db_path),
            source="surface-collector-curated",
            records_file=str(candidate_path),
            engagement_dir=engagement_dir,
        )
    )

    conn = sqlite3.connect(str(db_path))
    try:
        rows = {
            row[0]: row[1:]
            for row in conn.execute(
                """SELECT url, type, priority_score, priority_reason, cluster_key,
                          signals, selected_by, triage_rationale
                   FROM work_items
                   ORDER BY url"""
            ).fetchall()
        }
    finally:
        conn.close()

    assert rows["https://www.agency.example/org-event-feed/37221"][0:4] == (
        "event_feed",
        95,
        "current Drupal workflow/auth route; operator/Phase 1 artifact; source-map/source-analysis route",
        "gf:current_drupal_workflow_auth_route",
    )
    assert rows["https://www.agency.example/fb.log"][0:4] == (
        "debug_config",
        80,
        "admin/debug/config/secret signal",
        "gf:backup_config",
    )
    assert rows["https://www.agency.example/web-guidance"][0:4] == (
        "unknown",
        105,
        "OSINT priority URL; operator/Phase 1 artifact; source-map/source-analysis route",
        "gf:osint_priority_url",
    )
    assert json.loads(rows["https://www.agency.example/web-guidance"][4]) == [
        "osint_priority_url",
        "operator_phase_1_artifact",
        "source-map_source-analysis_route",
    ]
    assert rows["https://www.agency.example/web-guidance"][5:] == (
        "osint_priority_url",
        "OSINT priority URL; operator/Phase 1 artifact; source-map/source-analysis route",
    )

    capsys.readouterr()
    dispatch_module.run(
        SimpleNamespace(
            db_path=str(db_path),
            action="fetch-by-priority",
            extra=["10", "auto"],
            by="status",
            reason="",
            max_lines=40,
            include_evidence=False,
        )
    )

    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 3
    assert {item["assigned_agent"] for item in payload} == {"vulnerability-analyst"}


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
            if endpoint == "code/repos":
                return {"id": 41}
            if endpoint == "code/files":
                return {"inserted": len(payload["files"])}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None

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

    repo_call = next(payload for endpoint, payload in calls if endpoint == "code/repos")
    files_call = next(payload for endpoint, payload in calls if endpoint == "code/files")

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
            if endpoint == "code/repos":
                return {"id": 41}
            if endpoint == "code/files":
                return {"inserted": len(payload["files"])}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None

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

    files_call = next(payload for endpoint, payload in calls if endpoint == "code/files")
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
            if endpoint == "code/repos":
                return {"id": 42}
            if endpoint == "code/files":
                return {"inserted": len(payload["files"])}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        def close(self) -> None:
            return None

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

    files_call = next(payload for endpoint, payload in calls if endpoint == "code/files")
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
    monkeypatch.setattr(module, "load_scope", lambda engagement_dir: {"engagement_name": "Demo Engagement"})

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
    assert "1. send payload" in findings_md
    assert "2. 2" in findings_md


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


def test_merge_session_posts_workflow_status_without_legacy_status(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_merge_session_module",
        "agent/scripts/assess/commands/merge_session.py",
    )
    engagement_dir = tmp_path / "engagement"
    session_dir = engagement_dir / "sessions" / "session-a"
    proposals_dir = session_dir / "proposals"
    proposals_dir.mkdir(parents=True)
    (proposals_dir / "proposals.jsonl").write_text(
        json.dumps(
            {
                "type": "finding_record",
                "payload": {
                    "title": "Parser trust boundary bypass",
                    "status": "confirmed",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [{"session_id": "session-a", "status": "open", "assigned_targets": ["EX-001"]}]
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
    monkeypatch.setattr(module, "session_dir_path", lambda eng_dir, session_id: str(session_dir))
    monkeypatch.setattr(module, "finding_lock_path", lambda eng_dir: str(engagement_dir / ".findings.lock"))
    monkeypatch.setattr(module, "next_finding_id", lambda base_url, engagement_key, source_name: "EX-001")

    captured: list[tuple[str, dict[str, object]]] = []

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict[str, object]):
            captured.append((endpoint, payload))
            return {"finding": {"slug": payload["slug"], "title": payload["title"]}}

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(SimpleNamespace(engagement_dir=engagement_dir, session_id="session-a", yes=True))

    endpoint, payload = captured[0]
    assert endpoint == "findings"
    assert payload["workflow_status"] == "active"
    assert "status" not in payload
    session_index = json.loads((engagement_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
    assert session_index[0]["assigned_targets"] == ["EX-001"]
    assert "assigned_findings" not in session_index[0]


def test_merge_session_validates_session_index_before_backend_posts(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_merge_session_prevalidate_module",
        "agent/scripts/assess/commands/merge_session.py",
    )
    engagement_dir = tmp_path / "engagement"
    session_dir = engagement_dir / "sessions" / "session-a"
    proposals_dir = session_dir / "proposals"
    proposals_dir.mkdir(parents=True)
    (proposals_dir / "proposals.jsonl").write_text(
        json.dumps(
            {
                "type": "finding_record",
                "payload": {
                    "title": "Parser trust boundary bypass",
                    "status": "confirmed",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [{"session_id": "session-a", "status": "open", "assigned_findings": ["EX-001"]}]
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
    monkeypatch.setattr(module, "session_dir_path", lambda eng_dir, session_id: str(session_dir))

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def post(self, endpoint: str, payload: dict[str, object]):
            raise AssertionError("should validate session index before backend posts")

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit, match="assigned_findings is no longer supported"):
        module.run(SimpleNamespace(engagement_dir=engagement_dir, session_id="session-a", yes=True))


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

    parser = argparse.ArgumentParser(prog="aith assess")
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


def test_session_index_rejects_legacy_assigned_findings_key(tmp_path: Path) -> None:
    module = _load_script_module(
        "test_sessions_module",
        "agent/scripts/assess/lib/sessions.py",
    )
    engagement_dir = tmp_path / "engagement"
    sessions_dir = engagement_dir / "sessions"
    sessions_dir.mkdir(parents=True)
    (sessions_dir / "index.json").write_text(
        json.dumps(
            [{"session_id": "session-a", "status": "open", "assigned_findings": ["EX-001"]}]
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="assigned_findings is no longer supported"):
        module.load_session_index(str(engagement_dir))


def test_save_session_index_rejects_legacy_assigned_findings_key(tmp_path: Path) -> None:
    module = _load_script_module(
        "test_sessions_save_module",
        "agent/scripts/assess/lib/sessions.py",
    )
    engagement_dir = tmp_path / "engagement"
    (engagement_dir / "sessions").mkdir(parents=True)

    with pytest.raises(SystemExit, match="assigned_findings is no longer supported"):
        module.save_session_index(
            str(engagement_dir),
            [{"session_id": "session-a", "status": "open", "assigned_findings": ["EX-001"]}],
        )


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
        lambda engagement_dir: {
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


def test_launch_session_prompt_uses_workflow_status(monkeypatch, tmp_path: Path) -> None:
    module = _load_script_module(
        "test_launch_session_module",
        "agent/scripts/assess/commands/launch_session.py",
    )
    engagement_dir = tmp_path / "engagement"
    (engagement_dir / "sessions").mkdir(parents=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "current_phase": "exploit",
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_targets": ["ACTIVE-001"],
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "ensure_session_index", lambda eng_dir: None)
    monkeypatch.setattr(module, "resolve_approved_target_slugs", lambda cfg, scope: ["ACTIVE-001"])

    class FakeClient:
        def __init__(self, base_url: str, engagement_key: str) -> None:
            self.base_url = base_url
            self.engagement_key = engagement_key

        def get(self, endpoint: str):
            assert endpoint == "findings"
            return [
                {
                    "slug": "ACTIVE-001",
                    "severity": "high",
                    "workflow_status": "active",
                    "title": "Live issue",
                }
            ]

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            engagement_dir=engagement_dir,
            session_id="session-a",
            slugs=["ACTIVE-001"],
        )
    )

    prompt = (engagement_dir / "sessions" / "session-a" / "prompt.md").read_text(encoding="utf-8")
    assignment = json.loads(
        (engagement_dir / "sessions" / "session-a" / "assignment.json").read_text(encoding="utf-8")
    )
    session_index = json.loads((engagement_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
    assert "ACTIVE-001 | high | active | Live issue" in prompt
    assert assignment["assigned_targets"] == ["ACTIVE-001"]
    assert session_index[0]["assigned_targets"] == ["ACTIVE-001"]


def test_launch_session_rejects_existing_session_without_truncating_proposals(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_launch_session_existing_module",
        "agent/scripts/assess/commands/launch_session.py",
    )
    engagement_dir = tmp_path / "engagement"
    session_dir = engagement_dir / "sessions" / "session-a"
    proposals_dir = session_dir / "proposals"
    proposals_dir.mkdir(parents=True)
    proposals_file = proposals_dir / "proposals.jsonl"
    proposals_file.write_text('{"type":"finding_record"}\n', encoding="utf-8")
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "current_phase": "exploit",
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_targets": ["ACTIVE-001"],
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps([{"session_id": "session-a", "status": "active"}]),
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
    monkeypatch.setattr(module, "resolve_approved_target_slugs", lambda cfg, scope: ["ACTIVE-001"])

    with pytest.raises(SystemExit) as excinfo:
        module.run(
            SimpleNamespace(
                engagement_dir=engagement_dir,
                session_id="session-a",
                slugs=["ACTIVE-001"],
            )
        )

    assert excinfo.value.code == 1
    assert "session already exists: session-a" in capsys.readouterr().err
    assert proposals_file.read_text(encoding="utf-8") == '{"type":"finding_record"}\n'


def test_check_report_readiness_surfaces_backend_blockers(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_script_module(
        "test_check_report_readiness_module",
        "agent/scripts/assess/commands/check_report_readiness.py",
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
            assert endpoint == "report-readiness"
            return {
                "ready": False,
                "blockers": [
                    {
                        "kind": "verification",
                        "slug": "VA-001",
                        "detail": "Finding remains unreviewed.",
                    }
                ],
            }

        def close(self) -> None:
            return None

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        module.run(SimpleNamespace(engagement_dir=tmp_path))

    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Final report blockers remain:" in err
    assert "verification | VA-001: Finding remains unreviewed." in err


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
    See C3 rationale in TODOv2.md V14."""
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
    """C21: aith assess agent start-swarm splits an items file into worker
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


_C45_REVIEW_MODE_SECTIONS = {
    "recon-specialist.md": "## Review Mode (Phase 1 → 2 exit)",
    "exploit-developer.md": "## Review Mode (Phase 5 → 6 exit)",
    "vulnerability-analyst.md": "## Root-Cause Review Mode (Phase 4 → 5 exit)",
}


@pytest.mark.parametrize(
    "agent_file,heading",
    sorted(_C45_REVIEW_MODE_SECTIONS.items()),
)
def test_c45_review_mode_section_present(agent_file: str, heading: str) -> None:
    """C45: each of recon-specialist / exploit-developer / vulnerability-analyst
    carries a review-mode section. The headings are exact so future renames
    surface as a clear test failure. report-writer is intentionally NOT here —
    it already has Review-and-Fix QA Mode in report-generation/SKILL.md."""
    repo_root = Path(__file__).resolve().parents[3]
    body = (repo_root / "agent" / "agents" / agent_file).read_text(encoding="utf-8")
    assert heading in body, (
        f"{agent_file} should carry the C45 review-mode section with heading "
        f"'{heading}'"
    )


def test_no_operator_prompt_invokes_update_finding_with_details_json() -> None:
    """C64: an operator-facing prompt must not instruct passing
    `details_json` as the field name to `aith assess update-finding`.
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
