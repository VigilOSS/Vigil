"""Tests for `vigil assess scaffold-probe` (write-probe-script capability, Phase 4).

The command writes a templated probe into the engagement's ``scripts/`` dir and
pre-registers it via the existing artifacts POST path. We drive it in-process
with a monkeypatched ``AssessmentClient`` and a real temp engagement dir (with a
``scope.json`` marker, since ``config.resolve_engagement_dir`` requires one), so
the tests stay hermetic and never spin up FastAPI or a container — mirroring the
loader + monkeypatch pattern in ``test_agent_script_regressions.py``.

Key assertions:
- the file lands at ``<engagement>/scripts/<name>.py`` (the canonical scripts dir),
- the artifact is registered through ``AssessmentClient.post("artifacts", ...)``
  with the relative path + finding slug,
- the rendered template is syntactically valid Python (``ast.parse`` +
  ``py_compile``), and the shipped reference probes are too.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import py_compile
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


# ---------------------------------------------------------------------------
# Module loader (mirrors test_agent_script_regressions.py / test_check_scope_coverage.py)
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_script_module(name: str, relative_path: str):
    scripts_root = _repo_root() / "agent" / "scripts"
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = _repo_root() / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_scaffold_probe():
    return _load_script_module(
        "test_scaffold_probe_module",
        "agent/scripts/assess/commands/scaffold_probe.py",
    )


def _make_engagement(tmp_path: Path) -> Path:
    """A minimal engagement root: a dir containing scope.json."""
    eng = tmp_path / "engagements" / "acme"
    eng.mkdir(parents=True)
    (eng / "scope.json").write_text(
        json.dumps({"target": "https://target.example"}), encoding="utf-8"
    )
    return eng


class _FakeClient:
    """Stand-in for AssessmentClient that records the artifacts POST.

    Behaves as a context manager (the command uses ``with AssessmentClient(...)``)
    and echoes back a plausible artifact row so the human-readable branch renders.
    """

    posts: list[tuple[str, dict]] = []

    def __init__(self, base_url: str, engagement_key: str) -> None:
        self.base_url = base_url
        self.engagement_key = engagement_key

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> None:
        return None

    def post(self, endpoint: str, payload: dict) -> dict:
        type(self).posts.append((endpoint, payload))
        return {
            "id": 7,
            "relative_path": payload["path"],
            "kind": payload.get("kind"),
            "related_finding_slug": payload.get("related_finding_slug"),
            "present": True,
        }


@pytest.fixture(autouse=True)
def _reset_fake_posts():
    _FakeClient.posts = []
    yield
    _FakeClient.posts = []


def _patch_config_and_client(monkeypatch, module, eng_dir: Path) -> None:
    """Point load_config at the temp engagement and swap in the fake client.

    The command resolves config via ``load_config`` (which would otherwise try
    to verify a backend); we replace it with a static Config so the test never
    touches the network. ``AssessmentClient`` is patched in the command module's
    namespace (it imported the name directly).
    """
    cfg = SimpleNamespace(
        base_url="http://127.0.0.1:18000",
        engagement_dir=str(eng_dir),
        engagement_key=eng_dir.name,
        agent_root=str(eng_dir.parent.parent),
    )
    monkeypatch.setattr(module, "load_config", lambda _flag: cfg)
    monkeypatch.setattr(module, "AssessmentClient", _FakeClient)


def _args(eng_dir: Path, name: str, **overrides) -> SimpleNamespace:
    base = dict(
        name=name,
        engagement_dir=str(eng_dir),
        finding="",
        purpose="",
        force=False,
        register_artifact=True,
        as_json=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_scaffold_probe_writes_file_to_scripts_dir_and_registers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_scaffold_probe()
    eng = _make_engagement(tmp_path)
    _patch_config_and_client(monkeypatch, module, eng)

    module.run(_args(eng, "traversal_diff", finding="LFI-001"))

    # 1. File written to the canonical engagement scripts/ dir.
    script_path = eng / "scripts" / "traversal_diff.py"
    assert script_path.is_file()

    # 2. Artifact registered via the existing artifacts POST path, with the
    #    engagement-relative path and the finding slug.
    assert _FakeClient.posts, "expected an artifacts POST"
    endpoint, payload = _FakeClient.posts[-1]
    assert endpoint == "artifacts"
    assert payload["path"] == "scripts/traversal_diff.py"
    assert payload["kind"] == "probe-script"
    assert payload["related_finding_slug"] == "LFI-001"

    out = capsys.readouterr().out
    assert "wrote scripts/traversal_diff.py" in out
    assert "registered artifact id=7" in out


def test_scaffold_probe_template_is_valid_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_scaffold_probe()
    eng = _make_engagement(tmp_path)
    _patch_config_and_client(monkeypatch, module, eng)

    module.run(_args(eng, "shape_probe"))
    script_path = eng / "scripts" / "shape_probe.py"

    source = script_path.read_text(encoding="utf-8")
    # ast.parse proves syntactic validity; py_compile proves it bytecode-compiles.
    ast.parse(source)
    py_compile.compile(str(script_path), doraise=True)

    # The finding-return convention + the oob-mint hook must be present so the
    # skeleton actually teaches the conventions the SKILL.md documents.
    assert '"finding"' in source
    assert "vigil oob mint" in source
    assert "scripts/shape_probe.py" in source  # name substituted into the header


def test_scaffold_probe_no_register_skips_post_but_writes_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_scaffold_probe()
    eng = _make_engagement(tmp_path)
    _patch_config_and_client(monkeypatch, module, eng)

    module.run(_args(eng, "local_only", register_artifact=False))

    assert (eng / "scripts" / "local_only.py").is_file()
    assert _FakeClient.posts == []


def test_scaffold_probe_refuses_overwrite_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_scaffold_probe()
    eng = _make_engagement(tmp_path)
    _patch_config_and_client(monkeypatch, module, eng)

    module.run(_args(eng, "dup"))
    sentinel = eng / "scripts" / "dup.py"
    sentinel.write_text("# edited by the agent\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        module.run(_args(eng, "dup"))
    assert excinfo.value.code == 1
    # The user's edits are preserved (not clobbered) when --force is absent.
    assert sentinel.read_text(encoding="utf-8") == "# edited by the agent\n"

    # With --force the file is regenerated.
    module.run(_args(eng, "dup", force=True))
    assert "# edited by the agent" not in sentinel.read_text(encoding="utf-8")


@pytest.mark.parametrize("bad_name", ["../escape", "with/slash", ".hidden", "has space", ""])
def test_scaffold_probe_rejects_unsafe_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_name: str
) -> None:
    module = _load_scaffold_probe()
    eng = _make_engagement(tmp_path)
    _patch_config_and_client(monkeypatch, module, eng)

    with pytest.raises(SystemExit) as excinfo:
        module.run(_args(eng, bad_name))
    assert excinfo.value.code == 2
    assert _FakeClient.posts == []


def test_scaffold_probe_registration_failure_is_non_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_scaffold_probe()
    eng = _make_engagement(tmp_path)
    _patch_config_and_client(monkeypatch, module, eng)

    from assess.lib.client import AssessError

    class _BoomClient(_FakeClient):
        def post(self, endpoint: str, payload: dict) -> dict:
            raise AssessError("backend unreachable")

    monkeypatch.setattr(module, "AssessmentClient", _BoomClient)

    # Must NOT raise — the file is written regardless; registration failure warns.
    module.run(_args(eng, "resilient"))
    assert (eng / "scripts" / "resilient.py").is_file()
    err = capsys.readouterr().err
    assert "artifact registration failed" in err
    assert "artifact register scripts/resilient.py" in err


def test_reference_probe_examples_are_valid_python() -> None:
    """The shipped reference probes must compile (they are copy-paste seeds)."""
    probe_dir = _repo_root() / "agent" / "references" / "probe-scripts"
    probes = sorted(probe_dir.glob("*.py"))
    assert probes, "expected at least one reference probe example"
    for probe in probes:
        ast.parse(probe.read_text(encoding="utf-8"))
        py_compile.compile(str(probe), doraise=True)
