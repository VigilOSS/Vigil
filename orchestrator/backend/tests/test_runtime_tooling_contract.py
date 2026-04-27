"""Runtime tooling contract — verify the `aith-threat-hunting` runtime container has every
binary the subdomain-enumeration pipeline assumes.

puredns silently fails when massdns is missing (zero output, exit code 0); the dnsx fallback
against a typical bruteforce wordlist then spikes container CPU. This test pins the binary set
so an image drift can be caught at CI/handoff time, before a Phase 1a dispatch loses time to
silent degradation.

Marked `@pytest.mark.integration` so CI without docker (or with a stale image tag) skips
cleanly via the bundled `addopts = -m 'not integration'`. To run this test explicitly after
rebuilding the runtime image:

    cd orchestrator/backend && uv run pytest tests/test_runtime_tooling_contract.py -m integration -v

The same test also runs as a non-integration smoke check that just asserts the Dockerfile
declares each binary via an actual install line — that branch does not need docker on PATH
and is part of the default suite.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_FULL_DOCKERFILE = REPO_ROOT / "agent" / "docker" / "runtime-full" / "Dockerfile"


# Binaries the subdomain-enumeration SKILL preflights via
# `aith assess kali exec -- which alterx asnmap bbot cero dnsx massdns puredns shuffledns subfinder`.
# Order is alphabetical (F22 — keep aligned with operator-core.md and
# subdomain-enumeration/SKILL.md).
SUBDOMAIN_ENUM_BINARIES = (
    "alterx",
    "asnmap",
    "bbot",
    "cero",
    "dnsx",
    "massdns",
    "puredns",
    "shuffledns",
    "subfinder",
)

# port-scanning/SKILL.md "Per-host port-data presence assertion" depends on
# xmllint (libxml2-utils package) for the Layer-2 XML XPath check.
PORT_SCAN_BINARIES = ("xmllint",)


def _dockerfile_has_install_line(text: str, binary: str) -> bool:
    """Return True iff the Dockerfile contains an actual install line for the
    binary, not just a literal mention. Accepts:
      - `go install ...<binary>` or `cp /root/go/bin/<binary>`
      - `apt-get install ... <binary>` / `apt-get install -y ... <binary>`
      - apt package list entries (`<binary>=<version>`)
      - `pipx install <binary>` / `pip install <binary>`
      - `libxml2-utils` (the apt package that ships xmllint)
    """
    install_patterns = (
        rf"go install .*\b{re.escape(binary)}\b",
        rf"cp /root/go/bin/{re.escape(binary)}\b",
        rf"apt-get install[^\n]*\b{re.escape(binary)}\b",
        rf"\b{re.escape(binary)}=\S+",  # apt package=version pin
        rf"pipx install\s+{re.escape(binary)}\b",
        rf"pip install[^\n]*\b{re.escape(binary)}\b",
    )
    for pattern in install_patterns:
        if re.search(pattern, text):
            return True
    # xmllint ships with the libxml2-utils apt package — accept either form.
    if binary == "xmllint" and "libxml2-utils" in text:
        return True
    return False


def test_runtime_full_dockerfile_declares_subdomain_enum_binaries():
    """Static check: every binary the subdomain-enum preflight expects is installed via an
    actual install line in the runtime-full Dockerfile. This is the always-on guard that
    catches an accidental removal of a `go install` / `pipx install` / `apt-get install` line
    during a refactor.

    F20: the original guard accepted any literal mention; tighten to require an actual install
    line (`go install`, `apt-get install`, `pipx install`, `pip install`, or `cp /root/go/bin/<name>`)
    so a comment that mentions the binary cannot satisfy the contract.
    """
    text = RUNTIME_FULL_DOCKERFILE.read_text(encoding="utf-8")
    missing = [
        name for name in SUBDOMAIN_ENUM_BINARIES if not _dockerfile_has_install_line(text, name)
    ]
    assert not missing, (
        "agent/docker/runtime-full/Dockerfile is missing install lines for: "
        f"{missing}. The subdomain-enumeration SKILL preflights these binaries; if any are "
        "dropped from the runtime image, the silent-degradation failure mode (puredns→empty / "
        "dnsx fallback CPU spike) reappears."
    )


def test_runtime_full_dockerfile_declares_port_scan_binaries():
    """F20 — port-scanning/SKILL.md depends on `xmllint` (libxml2-utils package) for the Layer-2
    XML XPath assertion. Without it, the per-host port-data presence gate falls back to text-only
    output and silently misses host-timeout failures.
    """
    text = RUNTIME_FULL_DOCKERFILE.read_text(encoding="utf-8")
    missing = [
        name for name in PORT_SCAN_BINARIES if not _dockerfile_has_install_line(text, name)
    ]
    assert not missing, (
        "agent/docker/runtime-full/Dockerfile is missing install lines for: "
        f"{missing}. port-scanning/SKILL.md `Per-host port-data presence assertion` "
        "depends on these binaries."
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

    expected = (*SUBDOMAIN_ENUM_BINARIES, *PORT_SCAN_BINARIES)
    proc = subprocess.run(
        ["docker", "exec", container, "which", *expected],
        capture_output=True,
        text=True,
        check=False,
    )
    # `which` returns 0 only when EVERY arg resolves. A non-zero exit means at least one
    # binary is missing — emit the resolved set so the failure message is actionable.
    resolved = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    resolved_names = {Path(p).name for p in resolved}
    missing = [name for name in expected if name not in resolved_names]
    assert not missing, (
        f"runtime container `{container}` is missing subdomain-enum / port-scan binaries: {missing}. "
        f"Resolved: {resolved}. Image drift — rebuild `agent/docker/runtime-full/Dockerfile` "
        f"and run `aith runtime restart`."
    )
