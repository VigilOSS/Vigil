"""Runtime tooling contract — verify the `aith-threat-hunting` runtime container has every
binary the subdomain-enumeration pipeline assumes.

The 2026-04-24 SSA engagement burned a Phase 1a slot when puredns ran without massdns and
silently produced empty output. This test pins the binary set so an image drift can be caught
at CI/handoff time, before an engagement loses time to silent degradation.

Marked `@pytest.mark.integration` so CI without docker (or with a stale image tag) skips
cleanly via the bundled `addopts = -m 'not integration'`. To run this test explicitly after
rebuilding the runtime image:

    cd orchestrator/backend && uv run pytest tests/test_runtime_tooling_contract.py -m integration -v

The same test also runs as a non-integration smoke check that just asserts the Dockerfile
declares each binary — that branch does not need docker on PATH and is part of the default
suite.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_FULL_DOCKERFILE = REPO_ROOT / "agent" / "docker" / "runtime-full" / "Dockerfile"


# Binaries the subdomain-enumeration SKILL preflights via
# `aith assess kali exec -- which massdns puredns dnsx subfinder cero alterx asnmap bbot shuffledns`.
SUBDOMAIN_ENUM_BINARIES = (
    "massdns",
    "puredns",
    "dnsx",
    "subfinder",
    "cero",
    "alterx",
    "asnmap",
    "bbot",
    "shuffledns",
)


def test_runtime_full_dockerfile_declares_subdomain_enum_binaries():
    """Static check: every binary the subdomain-enum preflight expects is referenced in the
    runtime-full Dockerfile. This is the always-on guard that catches an accidental removal of
    a `go install` / `pipx install` line from the Dockerfile during a refactor.

    The Dockerfile reference can be a `go install` line, a pipx install, an apt package name,
    or a binary path inside `cp /root/go/bin/<name>` — any literal mention of the binary name
    counts. This is intentionally loose because the Dockerfile structure varies across binaries
    (some are go-installed, some apt-installed, some pipx-installed); we want a single guard
    that catches "the binary was deleted from the image" without locking the install mechanism.
    """
    text = RUNTIME_FULL_DOCKERFILE.read_text(encoding="utf-8")
    missing = [name for name in SUBDOMAIN_ENUM_BINARIES if name not in text]
    assert not missing, (
        "agent/docker/runtime-full/Dockerfile is missing references to: "
        f"{missing}. The subdomain-enumeration SKILL preflights these binaries; if any are "
        "dropped from the runtime image, the 2026-04-24 SSA-style silent-degradation failure "
        "mode reappears."
    )


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed on host")
def test_runtime_full_container_has_subdomain_enum_binaries():
    """Live check: every preflight binary resolves inside the running runtime container.

    Skipped when:
    - The default pytest invocation is used (`addopts = -m 'not integration'` in
      `pyproject.toml` deselects the `integration` mark).
    - `docker` is not on PATH.
    - The container `security-research` is not running (we report the missing container as
      a `pytest.skip` rather than a failure, since a pre-engagement state without the runtime
      up is legitimate at handoff time).
    """
    container = "security-research"
    ps = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}", "--filter", f"name=^{container}$"],
        capture_output=True,
        text=True,
        check=False,
    )
    if ps.returncode != 0 or container not in ps.stdout:
        pytest.skip(
            f"runtime container `{container}` is not running; start it with "
            "`aith runtime start` before running the integration tooling contract test"
        )

    proc = subprocess.run(
        ["docker", "exec", container, "which", *SUBDOMAIN_ENUM_BINARIES],
        capture_output=True,
        text=True,
        check=False,
    )
    # `which` returns 0 only when EVERY arg resolves. A non-zero exit means at least one
    # binary is missing — emit the resolved set so the failure message is actionable.
    resolved = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    resolved_names = {Path(p).name for p in resolved}
    missing = [name for name in SUBDOMAIN_ENUM_BINARIES if name not in resolved_names]
    assert not missing, (
        f"runtime container `{container}` is missing subdomain-enum binaries: {missing}. "
        f"Resolved: {resolved}. Image drift — rebuild `agent/docker/runtime-full/Dockerfile` "
        f"and run `aith runtime restart`."
    )
