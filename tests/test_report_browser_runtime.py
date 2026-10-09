from __future__ import annotations

import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_ROOT = REPO_ROOT / "orchestrator" / "report"
CHROME_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome",
    "chromium",
    "chromium-browser",
)


def _chrome() -> str | None:
    for candidate in CHROME_CANDIDATES:
        path = Path(candidate)
        if path.is_file():
            return str(path)
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


@pytest.mark.integration
def test_built_report_renders_offline_from_file_url(tmp_path: Path) -> None:
    """Exercise the replacement inliner through Vite and a real browser.

    This is integration-marked because it requires Node dependencies and a
    Chrome-compatible browser. Release validation runs it explicitly; ordinary
    unit runs remain portable.
    """
    npm = shutil.which("npm")
    chrome = _chrome()
    if npm is None or chrome is None or not (REPORT_ROOT / "node_modules").is_dir():
        pytest.skip("requires npm-installed report dependencies and Chrome/Chromium")

    build = subprocess.run(
        [npm, "run", "build"],
        cwd=REPORT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    template = REPORT_ROOT / "dist" / "template.html"
    built = template.read_text(encoding="utf-8")
    assert sorted(path.name for path in template.parent.iterdir()) == ["template.html"]
    assert built.count('"__VIGIL_REPORT_DATA__"</script>') == 1

    report = tmp_path / "report.html"
    report.write_text(built, encoding="utf-8")
    browser = subprocess.run(
        [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-background-networking",
            "--host-resolver-rules=MAP * ~NOTFOUND",
            "--dump-dom",
            report.resolve().as_uri(),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert browser.returncode == 0, browser.stderr
    assert "Security Assessment" in browser.stdout
    assert "Acme Corp" in browser.stdout
    assert '<div id="root"></div>' not in browser.stdout
    assert "ERROR:CONSOLE" not in browser.stderr


@pytest.mark.integration
def test_pdf_export_does_not_fetch_markdown_resources(tmp_path: Path) -> None:
    """Exercise Pandoc sanitization and Chrome PDF printing as one runtime path."""
    if shutil.which("pandoc") is None or _chrome() is None:
        pytest.skip("requires Pandoc and Chrome/Chromium")

    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            requests.append(self.path)
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        engagement = tmp_path / "engagement"
        engagement.mkdir()
        (engagement / "report.md").write_text(
            f"# Report\n\n![evidence](http://127.0.0.1:{port}/pixel)\n",
            encoding="utf-8",
        )

        from vigil_cli.engagements import export_pdf

        output = export_pdf(engagement)
        assert output.is_file()
        assert output.stat().st_size > 0
        assert requests == []
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
