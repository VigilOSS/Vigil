"""Execute and retain paired red/green proof at a single case revision."""

import json
import os
import signal
from pathlib import Path
import subprocess
import uuid
from types import SimpleNamespace


def run_regression(args, install_root: Path, engagement: Path, key: str, case: dict, config: dict):
    from . import remediation as cli
    from assess.lib.remediation_regression import scratch_source  # type: ignore[import-not-found]

    if not args.expected_failure.strip():
        raise SystemExit('Name the expected regression failure from the command output')
    timeout = getattr(args, 'timeout_seconds', 600)
    if timeout <= 0:
        raise SystemExit('Command timeout must be positive')
    workspace = cli._require_case_worktree(case, Path(str(config['repository'])))
    cli._require_clean_worktree(workspace)
    revision = cli._revision(workspace)
    if revision != case.get('worktree_revision') or not case.get('base_revision'):
        raise SystemExit('Sync the committed case revision and review base before regression verification')
    requirements = (case.get('verification_requirements') or {}).get('requirements', [])
    selected = [r for r in requirements if r['kind'] == 'red-test' and args.method.casefold() in {m.casefold() for m in r['methods']}]
    paths = args.fix_path or (selected[0].get('fix_paths', []) if len(selected) == 1 else [])
    if selected and not any(sorted(paths) == sorted(requirement.get('fix_paths', [])) for requirement in selected):
        raise SystemExit('Fix files must match the selected red-test verification requirement')
    output = engagement / 'remediation/cases' / str(case['id']) / 'tests' / uuid.uuid4().hex
    output.mkdir(parents=True)
    endpoint = cli._case_path(str(case['id'])) + '/evidence'

    def command_run(command, cwd, environment, name):
        stdout_path, stderr_path = output / f'{name}.stdout', output / f'{name}.stderr'
        with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
            process = subprocess.Popen(['/bin/sh', '-c', command], cwd=cwd, env=environment,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise SystemExit(f'{name} exceeded {timeout} seconds; full output retained in {output}') from None
        if stdout_path.stat().st_size + stderr_path.stat().st_size > 16 * 1024 * 1024:
            raise SystemExit(f'{name} output exceeds the receipt limit; full output retained in {output}')
        return SimpleNamespace(returncode=returncode, stdout=stdout_path.read_text(errors='surrogateescape'),
                               stderr=stderr_path.read_text(errors='surrogateescape'))

    def execute(source, kind, proof=None):
        cwd = (source / args.directory).resolve()
        if not cwd.is_relative_to(source.resolve()) or not cwd.is_dir():
            raise SystemExit('Regression directory must exist inside the tested source')
        environment = {**os.environ, 'VIGIL_REPOSITORY': str(config['repository']),
                       'VIGIL_CASE_WORKTREE': str(source), 'VIGIL_CASE_REVISION': revision,
                       'VIGIL_CASE_BASE_REVISION': case['base_revision']}
        if args.setup_command:
            setup = command_run(args.setup_command, cwd, environment, f'{kind}-setup')
            if setup.returncode:
                raise SystemExit(f'Regression setup failed; inspect {output}')
        run = command_run(args.test_command, cwd, environment, kind)
        red = kind == 'red-test'
        valid = (run.returncode > 0 and args.expected_failure in run.stdout + run.stderr) if red else run.returncode == 0
        source_changed = False
        if proof:
            from assess.lib import remediation_vcs as vcs  # type: ignore[import-not-found]
            if vcs.is_jj(source):
                unchanged = vcs.tree_id(source, vcs.revision(source)) == proof['scratch_tree']
            else:
                unchanged = subprocess.run(['git', '-C', str(source), 'diff-files', '--quiet'], capture_output=True).returncode == 0
                unchanged = unchanged and not any(vcs.untracked(source))
                unchanged = unchanged and subprocess.check_output(['git', '-C', str(source), 'write-tree'], text=True).strip() == proof['scratch_tree']
            source_changed = not unchanged
        if cli._revision(workspace) != revision or cli._worktree_status(workspace):
            source_changed = True
        valid = valid and not source_changed
        if proof:
            proof['exit_code'] = run.returncode
        artifact = output / f'{kind}.json'
        artifact.write_text(json.dumps({'command': args.test_command, 'directory': str(cwd), 'revision': revision,
                                        'exit_code': run.returncode, 'scratch_proof': proof,
                                        'source_changed': source_changed,
                                        'stdout': run.stdout, 'stderr': run.stderr}, indent=2) + '\n')
        payload = {'kind': kind, 'method': args.method, 'environment': 'local', 'command': args.test_command,
                   'revision': revision, 'executed_revision': revision, 'executed_directory': str(cwd),
                   'execution': 'executed', 'outcome': ('failed_as_expected' if red else 'passed') if valid else 'failed',
                   'observed': f'exit {run.returncode}; source changed: {source_changed}',
                   'proved': ('Expected regression failure' if red else 'Regression passes with the fix') if valid else 'Command did not establish the expected result',
                   'artifact_path': str(artifact.relative_to(engagement)), 'scratch_proof': proof}
        cli._api(install_root, engagement, key, 'POST', endpoint, payload)
        if not valid:
            raise SystemExit(f'{kind} did not establish the expected result; inspect {artifact}')

    with scratch_source(workspace, case['base_revision'], revision, paths) as (scratch, proof):
        proof['expected_failure'] = args.expected_failure
        execute(scratch, 'red-test', proof)
    execute(workspace, 'green-test')
    return {'revision': revision, 'outcome': 'passed', 'artifacts': str(output)}
