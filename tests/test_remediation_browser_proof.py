"""Pure browser evidence validation without a backend database or HTTP client."""
from __future__ import annotations

import base64
import hashlib
import json
import pytest

from app.services import remediation


@pytest.mark.parametrize("only_cleanup", [False, True])
def test_browse_evidence_requires_ui_commands_and_accepts_cleanup(tmp_path, monkeypatch, only_cleanup):
    case = tmp_path / 'remediation' / 'cases' / '1' / 'browse' / 'run'
    case.mkdir(parents=True)
    files = {
        'red.txt': 'failed', 'green.txt': 'passed', 'script.py': 'async def run(browser, output_dir): pass',
        'result.json': json.dumps({'status': 'passed', 'purpose': 'happy-path', 'observed': 'Form worked', 'proved': 'Happy path', 'served_revision': 'sha', 'steps': [{'action': 'Submit', 'observation': 'Saved'}]}),
        'commands.json': json.dumps([
            {'argv': ['browse', 'snapshot', '--local', '--session', 'owned'], 'returncode': 0, 'stdout': 'Form', 'stderr': ''},
            {'argv': ['browse', 'stop', '--session', 'owned'], 'returncode': 0, 'stdout': '{"stopped":true}', 'stderr': ''},
        ]),
    }
    for name, content in files.items():
        (case / name).write_text(content)
    if only_cleanup:
        transcript = json.loads((case / 'commands.json').read_text())
        (case / 'commands.json').write_text(json.dumps(transcript[1:]))
    (case / 'screen.png').write_bytes(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aXioAAAAASUVORK5CYII='))
    evidence = []
    for file in case.iterdir():
        kind = {'red.txt': 'red-test', 'green.txt': 'green-test', 'screen.png': 'screenshot'}.get(file.name, 'browse')
        evidence.append({'kind': kind, 'method': 'Laravel' if kind.endswith('-test') else 'browse', 'outcome': 'failed_as_expected' if kind == 'red-test' else 'passed', 'command': 'run', 'revision': 'sha', 'artifact_path': str(file.relative_to(tmp_path)), 'artifact_sha256': hashlib.sha256(file.read_bytes()).hexdigest()})
    missing = remediation._browser_evidence_missing({'id': 1, 'worktree_revision': 'sha'}, evidence, tmp_path)
    assert bool(missing) is only_cleanup
