import json
import os
import sys

import pytest

from vigil_cli import runtime, runtime_images
from vigil_cli.docker import DockerResult
from vigil_cli.image_freshness import IMAGE_INPUTS_LABEL


@pytest.fixture
def release(tmp_path, monkeypatch):
    for path in runtime.runtime_image_inputs(tmp_path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('input\n')
    (tmp_path / 'orchestrator').mkdir()
    monkeypatch.setenv('VIGIL_APPLICATION_DIR', str(tmp_path))
    monkeypatch.setattr(runtime, 'build_runtime', lambda *a, **kw: None)
    digest = runtime.runtime_inputs_digest(tmp_path)
    ref = 'ghcr.io/vigiloss/vigil-runtime@sha256:' + 'a' * 64
    manifest = {'schema_version': 1, 'reference': ref, 'inputs_digest': digest, 'platforms': ['linux/amd64', 'linux/arm64']}
    pin = tmp_path / 'agent/docker/runtime-full/release-image.json'
    pin.write_text(json.dumps(manifest))
    return tmp_path, ref, digest, pin


def test_matching_release_pulls_digest_and_checks_label_before_tagging(release):
    root, ref, digest, _ = release
    calls = []

    def metadata(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ['docker', 'image', 'inspect'] and '-f' in argv:
            return DockerResult(0, digest if argv[-1] == ref else '', '')
        return DockerResult(1, '', 'not present')

    def streaming(argv, **kwargs):
        calls.append(argv)
        return DockerResult(0, '', '')

    runtime_images.ensure_runtime_image(root, runner=metadata, build_runner=streaming)
    assert ['docker', 'pull', ref] in calls
    assert ['docker', 'tag', ref, 'vigil:latest'] in calls
    label_check = next(i for i, argv in enumerate(calls) if argv[-1] == ref and IMAGE_INPUTS_LABEL in ' '.join(argv))
    assert calls.index(['docker', 'pull', ref]) < label_check < calls.index(['docker', 'tag', ref, 'vigil:latest'])


def test_release_label_mismatch_does_not_replace_existing_tag(release):
    root, ref, _, _ = release
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return DockerResult(0, 'wrong-label', '')

    with pytest.raises(SystemExit, match='inputs'):
        runtime_images.ensure_runtime_image(root, runner=runner, build_runner=runner)
    assert ['docker', 'pull', ref] in calls
    assert not any(argv[:2] == ['docker', 'tag'] for argv in calls)


def test_release_pull_failure_keeps_local_tag_and_explains_recovery(release):
    root, _, _, _ = release
    def runner(argv, **kwargs):
        return DockerResult(1, '', 'registry unavailable')
    with pytest.raises(SystemExit, match='vigil runtime build'):
        runtime_images.ensure_runtime_image(root, runner=runner, build_runner=runner)


def test_edited_runtime_inputs_build_locally_instead_of_pulling_an_old_release(release, monkeypatch):
    root, _, _, _ = release
    runtime.runtime_image_inputs(root)[0].write_text('changed\n')
    built = []
    monkeypatch.setattr(runtime, 'build_runtime', lambda *a, **kw: built.append(a[0]))
    runtime_images.ensure_runtime_image(root, runner=lambda *a, **k: DockerResult(1, '', ''), build_runner=lambda *a, **k: pytest.fail('must build locally'))
    assert built == [root]


def test_unpinned_checkout_builds_locally(release, monkeypatch):
    root, _, _, pin = release
    pin.write_text('{"schema_version":1}')
    built = []
    monkeypatch.setattr(runtime, 'build_runtime', lambda *a, **kw: built.append(a[0]))
    runtime_images.ensure_runtime_image(root, runner=lambda *a, **k: DockerResult(1, '', ''))
    assert built == [root]


@pytest.mark.parametrize('override', [{'reference': 'ghcr.io/vigiloss/vigil-runtime:latest'}, {'platforms': ['linux/amd64']}])
def test_invalid_release_pin_fails_before_network_or_local_build(release, override):
    root, _, _, pin = release
    data = json.loads(pin.read_text()) | override
    pin.write_text(json.dumps(data))
    def no_network(*args, **kwargs):
        pytest.fail('invalid release pin must not cause network access')
    with pytest.raises(SystemExit, match='release image'):
        runtime_images.ensure_runtime_image(root, runner=no_network, build_runner=no_network)


def test_release_image_uses_application_inputs_and_keeps_private_workspace_untouched(release, tmp_path, monkeypatch):
    application, ref, digest, _ = release
    workspace = tmp_path / 'private-workspace'
    workspace.mkdir()
    (workspace / '.env').write_text('PRIVATE_VALUE=fixture\n')
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv)
        if '-f' in argv:
            return DockerResult(0, digest if argv[-1] == ref else '', '')
        return DockerResult(1, '', '')
    def build(argv, **kwargs):
        calls.append(argv)
        return DockerResult(0, '', '')
    runtime_images.ensure_runtime_image(workspace, runner=runner, build_runner=build)
    assert ['docker', 'pull', ref] in calls
    assert (workspace / '.env').read_text() == 'PRIVATE_VALUE=fixture\n'


def test_default_image_preparation_streams_child_output_to_stderr(release, tmp_path, monkeypatch, capfd):
    root, ref, digest, _ = release
    executable = tmp_path / 'bin' / 'docker'
    executable.parent.mkdir()
    executable.write_text(f'#!{sys.executable}\nprint("Acme image preparation")\n')
    executable.chmod(0o755)
    monkeypatch.setenv('PATH', str(executable.parent) + os.pathsep + os.environ['PATH'])

    def metadata(argv, **kwargs):
        return DockerResult(0, digest, '') if argv[-1] == ref else DockerResult(1, '', 'missing')

    runtime_images.ensure_runtime_image(root, runner=metadata)
    output = capfd.readouterr()
    assert output.out == ''
    assert 'Acme image preparation' in output.err


@pytest.mark.parametrize('published', [True, False], ids=['pull', 'build'])
def test_image_preparation_explains_work_before_long_operation(release, monkeypatch, capsys, published):
    root, ref, digest, pin = release
    if not published:
        pin.write_text('{"schema_version":1}')
    announced = []

    def operation(*args, **kwargs):
        announced.append(capsys.readouterr().err)
        return DockerResult(0, '', '')

    monkeypatch.setattr(runtime, 'build_runtime', operation)
    runtime_images.ensure_runtime_image(
        root,
        runner=lambda argv, **kwargs: DockerResult(0, digest, '') if argv[-1] == ref else DockerResult(1, '', 'missing'),
        build_runner=operation,
    )
    assert announced
    assert ('Pulling' if published else 'Building') in announced[0]
    assert 'minutes' in announced[0]
