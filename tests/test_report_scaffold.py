"""Submission-first scaffold: no red/code/android report.md, blue preserved,
ISSUES-AND-ENHANCEMENTS.md seeded, and export_pdf repointed to submissions.

Covers the `engagements.py` submission-first scaffold contract. Blue incident
scaffolding must remain byte-for-byte unchanged.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote, urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


# ── _write_report: red family no longer seeds report.md, blue still does ──────

@pytest.mark.parametrize("etype", ["web", "code", "both", "android", "other-fallback"])
def test_write_report_seeds_nothing_for_red_family(tmp_path, etype):
    from vigil_cli import engagements

    engagements._write_report(
        tmp_path, etype, name="acme", target="https://acme.test",
        repos=[{"path": "/src/acme", "name": "acme"}], date_label="2026-07-06",
    )
    assert not (tmp_path / "report.md").exists()


def test_blue_report_body_is_byte_for_byte_the_legacy_scaffold(tmp_path):
    """Guard the do-not-break invariant: the blue report.md bytes must match the
    exact scaffold the old branch produced, so blue report-writer dispatch is
    unaffected by retiring the red/code/android branches.
    """
    from vigil_cli import engagements

    engagements._write_report(
        tmp_path, "blue", name="AcmeCorp", target="AcmeCorp:m365",
        repos=[], date_label="2026-07-06",
    )
    expected = "\n".join([
        "# Engagement Report",
        "",
        "- **Customer**: AcmeCorp",
        "- **Scope**: AcmeCorp:m365",
        "- **Report Kind**: Incident (blue)",
        "- **Engagement Date**: 2026-07-06",
        "- **Status**: Pending - report not yet generated",
        "",
        "---",
        "",
    ])
    assert (tmp_path / "report.md").read_text(encoding="utf-8") == expected


# ── ISSUES-AND-ENHANCEMENTS.md ───────────────────────────────────────────────

def test_issues_doc_seeded_and_scopes_to_reusable_lessons(tmp_path):
    from vigil_cli import engagements

    engagements._write_issues_doc(tmp_path)
    doc = tmp_path / "ISSUES-AND-ENHANCEMENTS.md"
    assert doc.exists()
    text = doc.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert "# Issues & Enhancements" in text
    # It is explicitly NOT a findings log; findings stay backend-owned.
    assert "NOT a findings log" in text
    assert "vigil assess" in text


# ── create_engagement end-to-end (heavy side effects stubbed) ────────────────

def _create(tmp_path, monkeypatch, etype, **extra):
    """Drive the real `create_engagement` with only the network / template /
    launcher side effects neutralized, so scaffold-file behavior (report.md
    absence, ISSUES presence, blue report.md presence) is exercised through the
    genuine create path rather than the seams alone.
    """
    from vigil_cli import engagements
    from vigil_cli.engagements import CreateEngagementOptions

    # Seed the canonical installed prompts create_engagement now requires up front,
    # so its precondition stays exercised here rather than stubbed away.
    agent_root = tmp_path / "agent"
    agent_root.mkdir(parents=True, exist_ok=True)
    (agent_root / "AGENTS.md").write_text("# Canonical operator instructions\n")
    (agent_root / "operator-core-code.md").write_text("# Canonical code operator instructions\n")
    (agent_root / "AGENTS-blue.md").write_text("# Canonical blue operator instructions\n")

    for name in (
        "_write_prompt_wrappers",
        "_write_codex_config",
        "_write_claude_config",
        "_write_opencode_config",
        "_write_goose_config",
        "_write_launchers",
        "_verify_backend_install_root",
        "_emit_post_create_footer",
        "_emit_bootstrap_scope_summary",
    ):
        monkeypatch.setattr(engagements, name, lambda *a, **k: None)
    # Force the client-config/launcher branches off entirely.
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *a, **k: "none")

    opts = CreateEngagementOptions(install_root=tmp_path, engagement_type=etype, **extra)
    return engagements.create_engagement(opts)


def test_create_web_engagement_writes_no_report_but_seeds_issues(tmp_path, monkeypatch):
    created = _create(tmp_path, monkeypatch, "web", target="acme.test")
    assert not (created.path / "report.md").exists()
    assert (created.path / "ISSUES-AND-ENHANCEMENTS.md").exists()


def test_create_code_engagement_writes_no_report_but_seeds_issues(tmp_path, monkeypatch):
    created = _create(tmp_path, monkeypatch, "code", name="acme-src")
    assert not (created.path / "report.md").exists()
    assert (created.path / "ISSUES-AND-ENHANCEMENTS.md").exists()


def test_create_android_engagement_writes_no_report_but_seeds_issues(tmp_path, monkeypatch):
    created = _create(tmp_path, monkeypatch, "android", name="com.acme.app")
    assert not (created.path / "report.md").exists()
    assert (created.path / "ISSUES-AND-ENHANCEMENTS.md").exists()


def test_create_blue_engagement_still_writes_report_and_seeds_issues(tmp_path, monkeypatch):
    created = _create(
        tmp_path, monkeypatch, "blue",
        customer="AcmeCorp", platforms=["m365"],
    )
    report = created.path / "report.md"
    assert report.exists()
    assert "Incident (blue)" in report.read_text(encoding="utf-8")
    assert (created.path / "ISSUES-AND-ENHANCEMENTS.md").exists()


# ── export_pdf repoint ───────────────────────────────────────────────────────

def _stub_render_tools(engagements_mod, tmp_path, monkeypatch):
    """Make pandoc/chrome discovery succeed with recorded, inert subprocess
    calls so export_pdf runs end-to-end without the real toolchain.
    """
    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("", encoding="utf-8")
    monkeypatch.setattr(engagements_mod, "_CHROME_PATHS", [str(fake_chrome)])
    monkeypatch.setattr(
        engagements_mod.shutil, "which",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else None,
    )
    calls: list[list] = []
    rendered_markdown: list[str] = []

    def _run(args, **_kwargs):
        calls.append(args)
        if args and str(args[0]).endswith("pandoc") and "--to=json" in args:
            rendered_markdown.extend(
                Path(arg).read_text(encoding="utf-8")
                for arg in args[1:]
                if str(arg).endswith(".md")
            )
            return SimpleNamespace(
                stdout=json.dumps(
                    {"pandoc-api-version": [1, 23, 1], "meta": {}, "blocks": []}
                )
            )
        if args and str(args[0]).endswith("pandoc"):
            html_path = Path(args[args.index("-o") + 1])
            html_path.write_text("<html><body>rendered</body></html>", encoding="utf-8")
            return SimpleNamespace(stdout="")
        else:
            html_uri = str(args[-1])
            html_path = Path(unquote(urlparse(html_uri).path))
            assert html_path.read_text(encoding="utf-8") == "<html><body>rendered</body></html>"
            pdf_arg = next(str(arg) for arg in args if str(arg).startswith("--print-to-pdf="))
            Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.7\n")

    monkeypatch.setattr(engagements_mod.subprocess, "run", _run)
    return calls, rendered_markdown


def test_export_pdf_errors_when_nothing_to_render(tmp_path):
    from vigil_cli import engagements

    eng = tmp_path / "eng"
    eng.mkdir()
    with pytest.raises(SystemExit) as exc:
        engagements.export_pdf(eng)
    message = str(exc.value)
    assert "export submission" in message
    # Fails before touching the toolchain (no report.md AND no submissions).
    assert "no report.md" in message


def test_export_pdf_renders_submissions_when_no_report(tmp_path, monkeypatch):
    from vigil_cli import engagements

    eng = tmp_path / "eng"
    sub = eng / "submissions" / "va-001-idor"
    sub.mkdir(parents=True)
    submission = sub / "submission.md"
    submission.write_text(
        "# Finding\n\n---\n\n## OPERATOR DETAILS — NOT FOR SUBMISSION\n\nsecret\n",
        encoding="utf-8",
    )

    calls, rendered_markdown = _stub_render_tools(engagements, tmp_path, monkeypatch)
    out = engagements.export_pdf(eng)

    assert out == eng / "report.pdf"
    pandoc_argv = [str(a) for a in calls[0]]
    assert str(submission) not in pandoc_argv
    assert any("/.report-export-" in arg for arg in pandoc_argv)
    assert rendered_markdown == ["# Finding\n"]
    assert len(calls) == 3
    chrome_argv = [str(arg) for arg in calls[2]]
    assert f"--print-to-pdf={out}" in chrome_argv
    assert out.read_bytes().startswith(b"%PDF-")
    assert not list(eng.glob(".report-export-*"))


def test_export_pdf_prefers_report_md_and_ignores_submissions(tmp_path, monkeypatch):
    """Blue path preserved: when report.md is present it is the sole render
    source, even if a submissions tree also exists.
    """
    from vigil_cli import engagements

    eng = tmp_path / "eng"
    eng.mkdir()
    report = eng / "report.md"
    report.write_text("# Engagement Report\n", encoding="utf-8")
    sub = eng / "submissions" / "va-001"
    sub.mkdir(parents=True)
    (sub / "submission.md").write_text("# Finding\n", encoding="utf-8")

    calls, rendered_markdown = _stub_render_tools(engagements, tmp_path, monkeypatch)
    engagements.export_pdf(eng)

    pandoc_argv = [str(a) for a in calls[0]]
    assert str(report) not in pandoc_argv
    assert str(sub / "submission.md") not in pandoc_argv
    assert rendered_markdown == ["# Engagement Report\n"]
    assert not list(eng.glob(".report-export-*"))


def test_export_pdf_preserves_preexisting_paths_with_legacy_temp_names(
    tmp_path, monkeypatch
):
    from vigil_cli import engagements

    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "report.md").write_text("# Engagement Report\n", encoding="utf-8")
    legacy_html = eng / ".report_tmp.html"
    legacy_html.write_text("operator-owned html\n", encoding="utf-8")
    legacy_dir = eng / ".submission_tmp"
    legacy_dir.mkdir()
    sentinel = legacy_dir / "operator-owned.txt"
    sentinel.write_text("keep me\n", encoding="utf-8")
    _stub_render_tools(engagements, tmp_path, monkeypatch)

    engagements.export_pdf(eng)

    assert legacy_html.read_text(encoding="utf-8") == "operator-owned html\n"
    assert sentinel.read_text(encoding="utf-8") == "keep me\n"
    assert not list(eng.glob(".report-export-*"))


def test_export_pdf_concurrent_runs_use_distinct_render_inputs(tmp_path, monkeypatch):
    from vigil_cli import engagements

    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "report.md").write_text("# Engagement Report\n", encoding="utf-8")
    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("", encoding="utf-8")
    monkeypatch.setattr(engagements, "_CHROME_PATHS", [str(fake_chrome)])
    monkeypatch.setattr(
        engagements.shutil,
        "which",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else None,
    )

    pandoc_barrier = threading.Barrier(2)
    lock = threading.Lock()
    html_inputs: list[Path] = []

    def _run(args, **_kwargs):
        if str(args[0]).endswith("pandoc") and "--to=json" in args:
            return SimpleNamespace(
                stdout=json.dumps(
                    {"pandoc-api-version": [1, 23, 1], "meta": {}, "blocks": []}
                )
            )
        if str(args[0]).endswith("pandoc"):
            html_path = Path(args[args.index("-o") + 1])
            html_path.write_text("<html>rendered</html>", encoding="utf-8")
            pandoc_barrier.wait(timeout=5)
            return SimpleNamespace(stdout="")
        html_path = Path(unquote(urlparse(str(args[-1])).path))
        assert html_path.read_text(encoding="utf-8") == "<html>rendered</html>"
        with lock:
            html_inputs.append(html_path)
        pdf_arg = next(str(arg) for arg in args if str(arg).startswith("--print-to-pdf="))
        Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.7\n")

    monkeypatch.setattr(engagements.subprocess, "run", _run)
    outputs = [eng / "first.pdf", eng / "second.pdf"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        rendered = list(pool.map(lambda output: engagements.export_pdf(eng, output), outputs))

    assert rendered == outputs
    assert all(output.read_bytes().startswith(b"%PDF-") for output in outputs)
    assert len(html_inputs) == 2
    assert html_inputs[0] != html_inputs[1]
    assert not list(eng.glob(".report-export-*"))


def test_export_pdf_cleans_render_directory_when_chrome_fails(tmp_path, monkeypatch):
    from vigil_cli import engagements

    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "report.md").write_text("# Engagement Report\n", encoding="utf-8")
    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("", encoding="utf-8")
    monkeypatch.setattr(engagements, "_CHROME_PATHS", [str(fake_chrome)])
    monkeypatch.setattr(
        engagements.shutil,
        "which",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else None,
    )

    def _run(args, **_kwargs):
        if str(args[0]).endswith("pandoc") and "--to=json" in args:
            return SimpleNamespace(
                stdout=json.dumps(
                    {"pandoc-api-version": [1, 23, 1], "meta": {}, "blocks": []}
                )
            )
        if str(args[0]).endswith("pandoc"):
            Path(args[args.index("-o") + 1]).write_text("<html></html>", encoding="utf-8")
            return SimpleNamespace(stdout="")
        raise engagements.subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(engagements.subprocess, "run", _run)

    with pytest.raises(engagements.subprocess.CalledProcessError):
        engagements.export_pdf(eng)

    assert not (eng / "report.pdf").exists()
    assert not list(eng.glob(".report-export-*"))


def test_export_pdf_accepts_complete_pdf_when_chrome_lingers(tmp_path, monkeypatch):
    from vigil_cli import engagements

    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "report.md").write_text("# Engagement Report\n", encoding="utf-8")
    _stub_render_tools(engagements, tmp_path, monkeypatch)
    run = engagements.subprocess.run

    def lingering_chrome(args, **kwargs):
        if str(args[0]).endswith("pandoc"):
            return run(args, **kwargs)
        pdf_arg = next(str(arg) for arg in args if str(arg).startswith("--print-to-pdf="))
        Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.7\n%%EOF\n")
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(engagements.subprocess, "run", lingering_chrome)

    output = engagements.export_pdf(eng)

    assert output.read_bytes().endswith(b"%%EOF\n")


def test_export_pdf_makes_target_controlled_resources_inert(tmp_path, monkeypatch):
    from vigil_cli import engagements

    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "report.md").write_text(
        "![target image](http://127.0.0.1:9/beacon.png)\n\n<script>alert(1)</script>\n",
        encoding="utf-8",
    )
    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("", encoding="utf-8")
    monkeypatch.setattr(engagements, "_CHROME_PATHS", [str(fake_chrome)])
    monkeypatch.setattr(
        engagements.shutil,
        "which",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else None,
    )

    source_ast = {
        "pandoc-api-version": [1, 23, 1],
        "meta": {},
        "blocks": [
            {
                "t": "Para",
                "c": [
                    {
                        "t": "Image",
                        "c": [
                            ["", [], []],
                            [{"t": "Str", "c": "target image"}],
                            ["http://127.0.0.1:9/beacon.png", ""],
                        ],
                    }
                ],
            },
            {"t": "RawBlock", "c": ["html", "<script>alert(1)</script>"]},
        ],
    }
    sanitized: dict[str, object] | None = None

    def _run(args, **kwargs):
        nonlocal sanitized
        if str(args[0]).endswith("pandoc") and "--to=json" in args:
            return SimpleNamespace(stdout=json.dumps(source_ast))
        if str(args[0]).endswith("pandoc"):
            assert "--from=json" in args
            sanitized = json.loads(kwargs["input"])
            Path(args[args.index("-o") + 1]).write_text(
                "<html><body>safe</body></html>", encoding="utf-8"
            )
            return SimpleNamespace(stdout="")
        chrome_argv = [str(arg) for arg in args]
        assert "--no-sandbox" not in chrome_argv
        assert any(arg.startswith("--user-data-dir=") for arg in chrome_argv)
        pdf_arg = next(arg for arg in chrome_argv if arg.startswith("--print-to-pdf="))
        Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.7\n")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(engagements.subprocess, "run", _run)

    engagements.export_pdf(eng)

    assert sanitized is not None
    encoded = json.dumps(sanitized)
    assert '"Image"' not in encoded
    assert '"RawBlock"' not in encoded
    assert "http://127.0.0.1:9/beacon.png" in encoded
    assert "<script>alert(1)</script>" in encoded
