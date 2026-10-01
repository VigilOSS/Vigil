from __future__ import annotations

import argparse
import subprocess

import pytest

from vigil_cli import remediation


def test_browser_parser_defaults_to_subscription_driven_browse():
    parser = argparse.ArgumentParser()
    remediation.register_remediation_parser(parser.add_subparsers(dest='command'))
    try:
        args = parser.parse_args(['remediation', '-k', 'project', 'browser', '1', '--script', 'ui.py', '--revision', 'abc', '--purpose', 'happy-path'])
    except SystemExit:
        pytest.fail('canonical browser command is missing')
    assert args.driver == 'browse'


def test_pr_content_accepts_reviewed_browse_evidence():
    case = {'approvals': [{'evidence_cutoff_id': 3}], 'evidence': [
        {'id': n, 'kind': kind, 'method': 'browse' if kind == 'browse' else 'Laravel'}
        for n, kind in enumerate(('red-test', 'green-test', 'browse'), 1)
    ]}
    assert len(remediation._required_reviewed_evidence_lines(case)) == 3


def test_browse_executes_local_commands_and_retains_transcript_without_keys(tmp_path, monkeypatch):
    import asyncio
    import json
    execute = getattr(remediation, '_execute_browse', None)
    assert callable(execute), 'local subscription-driven browse runner is missing'
    script = tmp_path / 'script.py'
    script.write_text('async def run(browser, output_dir):\n    text = await browser.command("snapshot")\n    return {"status": "passed", "observed": text, "proved": "form visible", "steps": [{"action": "Inspect form", "observation": text}], "served_revision": "sha"}\n')
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return __import__('subprocess').CompletedProcess(argv, 0, 'Form visible', '')
    monkeypatch.setattr('vigil_cli.remediation_browser.subprocess.run', run)
    result = asyncio.run(execute(script, tmp_path, {}))
    assert result['observed'] == 'Form visible'
    argv, options = calls[0]
    assert '--local' in argv
    assert '--session' in argv
    assert options['env']['BROWSE_LOAD_DOTENV'] == '0'
    assert json.loads((tmp_path / 'commands.json').read_text())[0]['stdout'] == 'Form visible'


def test_browse_failed_command_cannot_be_swallowed_by_rehearsal(tmp_path, monkeypatch):
    import asyncio
    script = tmp_path / 'script.py'
    script.write_text('async def run(browser, output_dir):\n    try:\n        await browser.command("snapshot")\n    except SystemExit:\n        pass\n    return {"status": "passed"}\n')
    monkeypatch.setattr('vigil_cli.remediation_browser.subprocess.run', lambda argv, **kw: subprocess.CompletedProcess(argv, 1, '', 'No page'))
    with pytest.raises(SystemExit, match='failed browser commands'):
        asyncio.run(remediation._execute_browse(script, tmp_path, {}))


def test_browse_rehearsal_requires_more_than_cleanup(tmp_path, monkeypatch):
    import asyncio
    script = tmp_path / 'script.py'
    script.write_text('async def run(browser, output_dir):\n    await browser.command("stop")\n    return {"status": "passed"}\n')
    monkeypatch.setattr('vigil_cli.remediation_browser.subprocess.run', lambda argv, **kw: subprocess.CompletedProcess(argv, 0, '', ''))
    with pytest.raises(SystemExit, match='UI command'):
        asyncio.run(remediation._execute_browse(script, tmp_path, {}))


def test_browse_session_fits_unix_socket_path_on_macos(tmp_path, monkeypatch):
    import asyncio
    import socket
    import tempfile
    from pathlib import Path
    from vigil_cli.remediation_browser import BrowseSession

    with tempfile.TemporaryDirectory(prefix='vigil-socket-', dir='/tmp') as temporary:
        parent = Path(temporary)
        runtime = parent / ('s' * (70 - len(str(parent)) - 1))
        runtime.mkdir()
        def run(argv, **kwargs):
            name = argv[argv.index('--session') + 1]
            with socket.socket(socket.AF_UNIX) as daemon:
                daemon.bind(str(runtime / f'{name}.sock'))
            return subprocess.CompletedProcess(argv, 0, 'fixture', '')
        monkeypatch.setattr('vigil_cli.remediation_browser.subprocess.run', run)
        assert asyncio.run(BrowseSession(tmp_path).command('snapshot')) == 'fixture'


@pytest.mark.parametrize('flags', [('open', 'http://localhost', '--remote'), ('snapshot', '--session', 'other')])
def test_browse_keeps_configured_local_target_and_session(tmp_path, flags, monkeypatch):
    import asyncio
    from vigil_cli.remediation_browser import BrowseSession
    monkeypatch.setattr("vigil_cli.remediation_browser.subprocess.run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "", ""))
    with pytest.raises(SystemExit, match='target and session'):
        asyncio.run(BrowseSession(tmp_path).command(*flags))


@pytest.mark.parametrize('script_failure', [False, True])
def test_browse_cleanup_stops_only_its_named_managed_session(tmp_path, monkeypatch, script_failure):
    import asyncio
    script = tmp_path / 'script.py'
    script.write_text('async def run(browser, output_dir):\n    await browser.command("snapshot")\n' + ('    raise ValueError("rehearsal failed")\n' if script_failure else '    return {"status": "passed"}\n'))
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, 'ok', '')
    monkeypatch.setattr('vigil_cli.remediation_browser.subprocess.run', run)
    if script_failure:
        with pytest.raises(ValueError, match='rehearsal failed'):
            asyncio.run(remediation._execute_browse(script, tmp_path, {}))
    else:
        asyncio.run(remediation._execute_browse(script, tmp_path, {}))
    assert len(calls) == 2
    session = calls[0][calls[0].index('--session') + 1]
    assert calls[-1] == ['browse', 'stop', '--session', session]


def test_browse_cleanup_failure_is_recorded_and_cannot_claim_pass(tmp_path, monkeypatch):
    import asyncio
    import json
    script = tmp_path / 'script.py'
    script.write_text('async def run(browser, output_dir):\n    await browser.command("snapshot")\n    return {"status": "passed"}\n')
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1 if argv[1] == 'stop' else 0, 'snapshot', 'cleanup denied')
    monkeypatch.setattr('vigil_cli.remediation_browser.subprocess.run', run)
    with pytest.raises(SystemExit, match='cleanup denied'):
        asyncio.run(remediation._execute_browse(script, tmp_path, {}))
    transcript = json.loads((tmp_path / 'commands.json').read_text())
    assert transcript[-1]['returncode'] == 1


def test_browse_cleanup_preserves_original_failure_when_cleanup_also_fails(tmp_path, monkeypatch):
    import asyncio
    import json
    script = tmp_path / 'script.py'
    script.write_text('async def run(browser, output_dir):\n    await browser.command("snapshot")\n    raise ValueError("original rehearsal failure")\n')
    monkeypatch.setattr('vigil_cli.remediation_browser.subprocess.run', lambda argv, **kw: subprocess.CompletedProcess(argv, 1 if argv[1] == 'stop' else 0, '', 'cleanup failed'))
    with pytest.raises(ValueError, match='original rehearsal failure'):
        asyncio.run(remediation._execute_browse(script, tmp_path, {}))
    assert json.loads((tmp_path / 'commands.json').read_text())[-1]['returncode'] == 1


def test_browse_refuses_external_cdp_until_vendor_supports_safe_disconnect(tmp_path):
    from vigil_cli.remediation_browser import BrowseSession
    with pytest.raises(SystemExit, match='closes externally attached Chrome'):
        BrowseSession(tmp_path, 'http://127.0.0.1:9222')
