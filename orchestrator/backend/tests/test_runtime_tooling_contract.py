"""Runtime tooling contract — verify the `vigil-threat-hunting` runtime container has every
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
RUNTIME_FULL_EXTERNAL_INSTALLER = (
    REPO_ROOT / "agent" / "docker" / "runtime-full" / "install-external-tools.sh"
)


# Binaries the subdomain-enumeration SKILL preflights via
# `vigil assess kali exec -- which alterx asnmap bbot cero dnsx github-subdomains
#  massdns puredns shuffledns subfinder tlsx`.
# Order is alphabetical (F22 — keep aligned with operator-core.md and
# subdomain-enumeration/SKILL.md). github-subdomains is a Phase-0 passive source
# (needs GITHUB_TOKEN at runtime, installed at build); tlsx is the Phase-3
# TLS-SAN harvester. Both ship via go_install in install-external-tools.sh.
SUBDOMAIN_ENUM_BINARIES = (
    "alterx",
    "asnmap",
    "bbot",
    "cero",
    "dnsx",
    "github-subdomains",
    "massdns",
    "puredns",
    "shuffledns",
    "subfinder",
    "tlsx",
)

# Cloud-exposure specialist tools (agent/skills/cloud-exposure/SKILL.md): s3scanner
# is a Go bucket scanner built from a pinned clone (its v3 go.mod path is unversioned,
# so `go install ...@v3.x` is rejected — see install-external-tools.sh); cloud_enum is
# a Python multi-cloud OSINT
# enumerator cloned at a pinned tag with a /usr/local/bin/cloud_enum wrapper (its
# pyproject does not package the fuzz wordlist as data, so it is NOT pip-installed).
CLOUD_EXPOSURE_TOOLS = (
    "cloud_enum",
    "s3scanner",
)

# port-scanning/SKILL.md "Per-host port-data presence assertion" depends on
# xmllint (libxml2-utils package) for the Layer-2 XML XPath check.
PORT_SCAN_BINARIES = ("xmllint",)

# Android APK engagements preflight these tools before static/dynamic mobile
# analysis so an APK-only review does not stall on first use.
ANDROID_APK_BINARIES = (
    "adb",
    "aapt",
    "apkeep",
    "apktool",
    "apksigner",
    "bundletool",
    "jadx",
)


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
        rf"\bgo_install\s+{re.escape(binary)}\b",
        rf"cp /root/go/bin/{re.escape(binary)}\b",
        rf"apt-get install[^\n]*\b{re.escape(binary)}\b",
        rf"\b{re.escape(binary)}=\S+",  # apt package=version pin
        rf"ARG APT_[A-Z_]*PACKAGES=.*\b{re.escape(binary)}\b",
        rf"pipx install\s+{re.escape(binary)}\b",
        rf"pip install[^\n]*\b{re.escape(binary)}\b",
    )
    for pattern in install_patterns:
        if re.search(pattern, text):
            return True
    # xmllint ships with the libxml2-utils apt package — accept either form.
    if binary == "xmllint" and "libxml2-utils" in text:
        return True
    if re.search(rf"ARG APT_ANDROID_PACKAGES=.*\b{re.escape(binary)}\b", text):
        return True
    if binary == "adb" and "android-tools-adb" in text:
        return True
    if binary == "apkeep" and "apkeep-${apkeep_arch}-unknown-linux-gnu" in text:
        return True
    if binary == "bundletool" and "bundletool-all-${BUNDLETOOL_VERSION}.jar" in text:
        return True
    # cloud_enum is cloned (not go/pip/pipx-installed) and exposed via a wrapper —
    # accept the pinned-tag git clone of its repo as the install line.
    if binary == "cloud_enum" and "cloud_enum.git" in text:
        return True
    # s3scanner's v3 go.mod path is unversioned (no /v3), so it is built from a pinned
    # clone via `go build`, not `go install` — accept the clone of its repo.
    if binary == "s3scanner" and "sa7mon/S3Scanner" in text:
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
    text = (
        RUNTIME_FULL_DOCKERFILE.read_text(encoding="utf-8")
        + "\n"
        + RUNTIME_FULL_EXTERNAL_INSTALLER.read_text(encoding="utf-8")
    )
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
    text = (
        RUNTIME_FULL_DOCKERFILE.read_text(encoding="utf-8")
        + "\n"
        + RUNTIME_FULL_EXTERNAL_INSTALLER.read_text(encoding="utf-8")
    )
    missing = [
        name for name in PORT_SCAN_BINARIES if not _dockerfile_has_install_line(text, name)
    ]
    assert not missing, (
        "agent/docker/runtime-full/Dockerfile is missing install lines for: "
        f"{missing}. port-scanning/SKILL.md `Per-host port-data presence assertion` "
        "depends on these binaries."
    )


def test_runtime_full_dockerfile_declares_android_apk_binaries():
    """Android APK review needs acquisition, decompilation, signing metadata,
    and optional device access tools available before dispatch starts."""
    text = (
        RUNTIME_FULL_DOCKERFILE.read_text(encoding="utf-8")
        + "\n"
        + RUNTIME_FULL_EXTERNAL_INSTALLER.read_text(encoding="utf-8")
    )
    missing = [
        name for name in ANDROID_APK_BINARIES if not _dockerfile_has_install_line(text, name)
    ]
    assert not missing, (
        "agent/docker/runtime-full/Dockerfile is missing install lines for Android APK tools: "
        f"{missing}. Android artifact engagements preflight these binaries before analysis."
    )


def test_runtime_full_dockerfile_declares_cloud_exposure_tools():
    """The cloud-exposure specialist (agent/skills/cloud-exposure/SKILL.md) drives
    bucket/blob enumeration and S3-claimability screening with cloud_enum + s3scanner.
    If either is dropped from the runtime image, that skill's Step 0 discovery pass
    and Step 2 takeover-screening invocations die on first use."""
    text = (
        RUNTIME_FULL_DOCKERFILE.read_text(encoding="utf-8")
        + "\n"
        + RUNTIME_FULL_EXTERNAL_INSTALLER.read_text(encoding="utf-8")
    )
    missing = [
        name for name in CLOUD_EXPOSURE_TOOLS if not _dockerfile_has_install_line(text, name)
    ]
    assert not missing, (
        "agent/docker/runtime-full/Dockerfile is missing install lines for cloud-exposure tools: "
        f"{missing}. The cloud-exposure SKILL preflights these for bucket enumeration and "
        "S3-takeover claimability screening."
    )


def test_external_installer_validates_preloaded_go_tools(tmp_path):
    """PRELOADED_TOOLS=1 is allowed only for a base image that already carries
    the script-owned tools. Missing tools must fail loudly during build instead
    of producing a successful image with degraded runtime coverage."""
    bash = shutil.which("bash")
    assert bash, "bash is required to run the runtime external installer"
    empty_path = tmp_path / "bin"
    empty_path.mkdir()

    proc = subprocess.run(
        [bash, str(RUNTIME_FULL_EXTERNAL_INSTALLER), "go-tools"],
        env={"PRELOADED_TOOLS": "1", "PATH": str(empty_path)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode != 0
    assert "PRELOADED_TOOLS=1 but required tool is missing: nuclei" in proc.stderr


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed on host")
def test_runtime_full_container_has_subdomain_enum_binaries():
    """Live check: every preflight binary resolves inside the running runtime container.

    Skipped when:
    - The default pytest invocation is used (`addopts = -m 'not integration'` in
      `pyproject.toml` deselects the `integration` mark).
    - `docker` is not on PATH.
    - The container `vigil` is not running (we report the missing container as
      a `pytest.skip` rather than a failure, since a pre-engagement state without the runtime
      up is legitimate at handoff time).
    """
    container = "vigil"
    ps = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}", "--filter", f"name=^{container}$"],
        capture_output=True,
        text=True,
        check=False,
    )
    if ps.returncode != 0 or container not in ps.stdout:
        pytest.skip(
            f"runtime container `{container}` is not running; start it with "
            "`vigil runtime start` before running the integration tooling contract test"
        )

    expected = (
        *SUBDOMAIN_ENUM_BINARIES,
        *PORT_SCAN_BINARIES,
        *ANDROID_APK_BINARIES,
        *CLOUD_EXPOSURE_TOOLS,
    )
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
        f"and run `vigil runtime restart`."
    )
