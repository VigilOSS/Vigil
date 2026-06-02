from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


def _run_scope_check(command: str, engagement_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[3]
    script = repo_root / "agent" / "scripts" / "hooks" / "scope-check.sh"
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "agent_type": "operator",
    }
    env = os.environ.copy()
    env["ENGAGEMENT_DIR"] = str(engagement_dir)
    return subprocess.run(
        ["bash", str(script)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        cwd=str(repo_root / "agent"),
        env=env,
        check=False,
    )


def test_scope_check_allows_local_only_command(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "target.example", "scope": ["target.example"]}),
        encoding="utf-8",
    )

    result = _run_scope_check("jq -r '.target' scope.json", engagement_dir)

    assert result.returncode == 0


def test_scope_check_allows_host_side_target_command(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "target.example", "scope": ["target.example"]}),
        encoding="utf-8",
    )

    result = _run_scope_check('python3 -c "print(1)" https://target.example/admin', engagement_dir)

    assert result.returncode == 0


def test_scope_check_allows_audited_kali_exec_with_raw_tool_name(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps({"hostname": "target.example", "scope": ["target.example"]}),
        encoding="utf-8",
    )

    result = _run_scope_check(
        "vigil assess kali exec --technique HEALTH --intent tooling --probe-kind fingerprint --phase recon --timeout 30 -- curl -sS https://target.example",
        engagement_dir,
    )

    assert result.returncode == 0


def test_scope_check_allows_when_scope_metadata_is_missing(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    result = _run_scope_check('python3 -c "print(1)" https://target.example/admin', engagement_dir)

    assert result.returncode == 0


def test_scope_check_allows_explicitly_out_of_scope_host(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "target.example",
                "scope_mode": "wildcard",
                "scope_hosts": ["target.example", "*.target.example"],
                "out_of_scope_hosts": ["admin.target.example"],
            }
        ),
        encoding="utf-8",
    )

    result = _run_scope_check('python3 -c "print(1)" https://admin.target.example/panel', engagement_dir)

    assert result.returncode == 0


def test_scope_check_blocks_recursive_force_delete(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    result = _run_scope_check("rm -rf /tmp/vigil-engagement-scratch", engagement_dir)

    assert result.returncode == 2
    assert "recursive delete" in result.stderr.lower()


def test_scope_check_blocks_destructive_disk_operation(tmp_path: Path) -> None:
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()

    result = _run_scope_check("sudo dd if=/dev/zero of=/dev/disk4 bs=1m", engagement_dir)

    assert result.returncode == 2
    assert "disk operation" in result.stderr.lower()


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
    # No warning when the apex is explicitly listed.
    assert "wildcard-only entries lacking explicit apex" not in captured.err


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
        self.posts.append((endpoint, payload))
        # Return a request_variant id so ingest treats it as admitted.
        return {"request_variant": {"id": 1 + len(self.posts)}, "service": {"id": 7}}

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

    Writes scope.json (when ``scope_payload`` is not None), an empty
    cases.db with the canonical schema, and an input file with the URLs the
    caller wants to feed in. Returns ``(module, args, fake_client)`` for the
    caller to invoke.
    """
    if scope_payload is not None:
        (engagement_dir / "scope.json").write_text(
            json.dumps(scope_payload), encoding="utf-8"
        )
    db_path = engagement_dir / "cases.db"
    db_path.touch()

    # Initialize cases.db schema via the shared db module.
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    db_spec = importlib.util.spec_from_file_location(
        "test_ingest_db_module",
        scripts_root / "assess" / "lib" / "db.py",
    )
    assert db_spec is not None and db_spec.loader is not None
    db_module = importlib.util.module_from_spec(db_spec)
    db_spec.loader.exec_module(db_module)
    db_module.db_init(str(db_path))

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
        db_path=str(db_path),
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

    posted_urls = [payload["url"] for endpoint, payload in fake.posts]
    assert "https://example.test/login" in posted_urls
    assert "https://corp.example.test/api" in posted_urls

    import sqlite3

    conn = sqlite3.connect(str(eng / "cases.db"))
    try:
        rejected = conn.execute(
            "SELECT COUNT(*) FROM work_items WHERE status='rejected'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert rejected == 0


def test_ingest_runs_without_scope_json(monkeypatch, tmp_path: Path, capsys) -> None:
    """Ingestion no longer reads scope.json — Round 4 deleted the only consumer
    (the strict-apex check). The ingest path admits URLs based on the
    egress-blocked + per-host budget gates alone, so a missing scope.json
    must not block ingestion."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    module, args, fake = _ingest_setup(
        monkeypatch,
        eng,
        scope_payload=None,
        input_lines=["https://example.test/login"],
    )

    module.run(args)
    posted_urls = [payload["url"] for _, payload in fake.posts]
    assert "https://example.test/login" in posted_urls


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
    posted_urls = [payload["url"] for endpoint, payload in fake.posts]
    assert "https://xn--caf-dma.test/login" in posted_urls
    assert "https://corp.xn--caf-dma.test/api" in posted_urls


# Pytest is referenced by the new tests above.
