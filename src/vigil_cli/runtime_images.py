"""Resolve release-pinned runtime images using the canonical build-input digest.

The release pipeline fills the tracked pin after publishing its multi-platform
image. Editable trees with changed baked inputs build locally. Pulling an image
never replaces a running container or changes the local tag before validation.
"""
from __future__ import annotations

import json
import re
import sys
from functools import partial
from pathlib import Path

from . import docker, image_freshness
from .application import application_root_for_workspace
from .service_locks import service_start_lock

PIN_PATH = Path('agent/docker/runtime-full/release-image.json')
PLATFORMS = frozenset({'linux/amd64', 'linux/arm64'})
_REFERENCE = re.compile(r'ghcr\.io/vigiloss/vigil-runtime@sha256:[0-9a-f]{64}\Z')


def release_image_pin(install_root: Path) -> dict | None:
    path = install_root / PIN_PATH
    if not path.exists():
        return None
    try:
        pin = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(pin, dict) or pin.get('schema_version') != 1:
            raise ValueError('unsupported schema')
        if set(pin) == {'schema_version'}:
            return None
        if not isinstance(pin.get('reference'), str) or not _REFERENCE.fullmatch(pin['reference']):
            raise ValueError('reference must pin the project image by SHA256 digest')
        if not isinstance(pin.get('inputs_digest'), str) or not re.fullmatch('[0-9a-f]{64}', pin['inputs_digest']):
            raise ValueError('missing build-input digest')
        if not isinstance(pin.get('platforms'), list) or set(pin['platforms']) != PLATFORMS:
            raise ValueError('both Linux AMD64 and ARM64 images are required')
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit(f'Invalid runtime release image pin: {exc}') from exc
    return pin


def ensure_runtime_image(
    install_root: Path,
    *,
    image: str = 'vigil:latest',
    runner: docker.Runner = docker.run_command,
    build_runner: docker.Runner = partial(docker.run_command_streaming, stderr_output=True),
) -> None:
    """Pull an exact matching release or build the editable runtime locally."""
    with service_start_lock(f"runtime-image:{image}"):
        from .runtime import build_runtime, runtime_image_build_state, runtime_inputs_digest

        if image != 'vigil:latest':
            if not docker.image_exists(image, runner=runner):
                raise SystemExit(f'Custom runtime image is unavailable: {image}. Pull or build it explicitly.')
            return
        install_root = application_root_for_workspace(install_root)
        pin = release_image_pin(install_root)
        current_digest = runtime_inputs_digest(install_root)
        if runtime_image_build_state(install_root, image=image, runner=runner) == 'current':
            return
        if pin is None or pin['inputs_digest'] != current_digest:
            print('Building the testing runtime image; initial setup may take several minutes.', file=sys.stderr, flush=True)
            build_runtime(install_root, runner=build_runner, daemon_runner=runner)
            return
        reference = pin['reference']
        print('Pulling the testing runtime image; initial setup may take several minutes.', file=sys.stderr, flush=True)
        pulled = build_runner(['docker', 'pull', reference])
        if pulled.returncode:
            raise SystemExit(
                f'Could not pull the pinned runtime release image: {pulled.stderr or pulled.stdout}\n'
                'Retry when the registry is available, or build locally with `vigil runtime build`.'
            )
        inspected = runner(['docker', 'image', 'inspect', '-f', '{{ index .Config.Labels "' + image_freshness.IMAGE_INPUTS_LABEL + '" }}', reference])
        if inspected.returncode or inspected.stdout.strip() != current_digest:
            raise SystemExit('Pinned runtime image inputs do not match this release; local image tag was preserved. Use `vigil runtime build`.')
        argv = ['docker', 'tag', reference, image]
        docker.require_success(build_runner(argv), argv)
