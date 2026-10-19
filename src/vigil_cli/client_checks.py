"""Read-only native client prerequisites, independent of engagement startup.

No provider requests, application activation, bundle materialization, repairs or
service probes belong here. Installed configuration is never runtime proof.
"""
from __future__ import annotations

import plistlib
import hashlib
import json
import os
from contextlib import ExitStack
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

from .install_fs import open_pinned_directory
from .status import Check

PROBE_TIMEOUT_SECONDS = 10
OPENCODE_MINIMUM = (1, 18, 10)
ZCODE_MINIMUM = (3, 14, 3)
MAX_CONTEXTS = 128
MAX_RECEIPTS = 256
MAX_JSON_BYTES = 1024 * 1024
REQUIRED_TOOLS = ("uv", "bash", "jq", "node")


def _executable_check(name: str, value: str) -> Check:
    path = Path(value)
    if not path.is_absolute():
        return Check(name, "FAIL", "Expected a resolved absolute executable path.", True)
    try:
        pin = open_pinned_directory(path.parent)
        assert pin is not None
        with pin:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pin.fd)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111 or not os.access(path, os.X_OK):
                    raise ValueError("Path is not an executable regular file")
                pin.require_attached()
            finally:
                os.close(descriptor)
    except (OSError, ValueError) as exc:
        return Check(name, "FAIL", f"Cannot use recorded executable {path}: {exc}", True)
    return Check(name, "OK", str(path), True)


def _dependency_checks() -> list[Check]:
    checks = []
    for name in REQUIRED_TOOLS:
        executable = shutil.which(name)
        if executable is None:
            checks.append(Check(f"dependency:{name}", "MISSING", f"Install {name} before preparing a client workspace.", True))
            continue
        try:
            resolved = str(Path(executable).resolve(strict=True))
        except OSError as exc:
            checks.append(Check(f"dependency:{name}", "FAIL", f"Cannot resolve executable: {exc}", True))
        else:
            checks.append(_executable_check(f"dependency:{name}", resolved))
    return checks


def _known_pointer(path: Path, expected: Path, *, directory: bool) -> None:
    pin = open_pinned_directory(path.parent)
    assert pin is not None
    with pin:
        if os.readlink(path.name, dir_fd=pin.fd) != str(expected):
            raise ValueError(f"Managed pointer has an unexpected target: {path}")
        if directory:
            target = open_pinned_directory(expected)
            assert target is not None
            with target:
                target.require_attached()
        else:
            _read_regular(expected)
        pin.require_attached()


def _read_regular(path: Path, *, limit: int = MAX_JSON_BYTES) -> bytes:
    """Read bounded existing bytes without following links or creating paths."""
    pin = open_pinned_directory(path.parent)
    assert pin is not None
    with pin:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pin.fd)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("Nonregular or oversized diagnostic input")
            chunks = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ) or not remaining:
                raise ValueError("Diagnostic input changed or exceeded its bound")
            pin.require_attached()
            return b"".join(chunks)
        finally:
            os.close(descriptor)


def _object(raw: bytes) -> dict:
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Expected diagnostic JSON object")
    return parsed


def _manifest_check(workspace: Path, binding_bytes: bytes | None = None, *,
                    check_name: str = "managed-assets", required_files: tuple[str, ...] = ()) -> Check:
    try:
        manifest = _object(_read_regular(workspace / ".vigil-managed-files.json"))
    except FileNotFoundError:
        return Check(check_name, "FAIL" if required_files else "UNVERIFIED",
                     "No managed-file digest manifest is installed.", bool(required_files))
    if not manifest or len(manifest) > 1024:
        raise ValueError("Invalid managed-file manifest inventory")
    if binding_bytes is not None and manifest.get(".vigil-client-context.json") != hashlib.sha256(binding_bytes).hexdigest():
        raise ValueError("Managed manifest does not match the context binding")
    if not set(required_files).issubset(manifest):
        raise ValueError("Managed plugin manifest omits required native assets")
    total = 0
    for name, digest in manifest.items():
        relative = PurePosixPath(name)
        if (not name or relative.is_absolute() or ".." in relative.parts or "." in relative.parts
                or str(relative) != name or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("Invalid managed-file manifest entry")
        data = _read_regular(workspace / name, limit=8 * MAX_JSON_BYTES)
        total += len(data)
        if total > 64 * MAX_JSON_BYTES or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Managed assets differ from their recorded content digests")
    return Check(check_name, "OK", f"Verified {len(manifest)} recorded file digests in {workspace}.")


def _observed_context_checks(client: str, engagement: Path, mode: str | None,
                             install_root: Path | None, context_file: Path | None = None) -> tuple[list[Check], dict[str, list[str]]]:
    checks: list[Check] = []
    observed: dict[str, list[str]] = {name: [] for name in ("startup-hook", "compact-hook", "context-injection")}
    if mode is not None and mode not in {"web", "code"}:
        return [Check("client-context", "FAIL", "Select web or code mode.", True)], observed
    if install_root is None:
        return [Check("client-context", "UNVERIFIED", "Explicit private install root is required.")], observed
    if not engagement.is_absolute() or not install_root.is_absolute():
        raise ValueError("Diagnostic engagement and install roots must be absolute")
    expected_application = None
    application_path = os.environ.get("VIGIL_APPLICATION_DIR")
    if application_path:
        from .application import application_provenance

        expected_application = application_provenance(Path(application_path))
    else:
        checks.append(Check("pinned-release", "UNVERIFIED", "No explicit application pin; no bundle was materialized."))
    root = engagement / "client-context"
    if context_file is not None:
        if (not context_file.is_absolute() or context_file.name != ".vigil-client-context.json"
                or context_file.parent.name != client or context_file.parent.parent.parent != root
                or not re.fullmatch(r"[0-9a-f]{24}", context_file.parent.parent.name)):
            raise ValueError("Explicit client context does not belong to the selected engagement/client")
    pin = open_pinned_directory(root, missing_ok=True)
    if pin is None:
        return [*checks, Check("client-context", "MISSING", "No prepared client workspace exists.", True)], observed
    matched = 0
    context_pins = []
    with pin, ExitStack() as opened:
        names = os.listdir(pin.fd)
        if len(names) > MAX_CONTEXTS:
            raise ValueError("Too many retained contexts; inspect explicitly before retrying")
        for name in sorted(names):
            if not re.fullmatch(r"[0-9a-f]{24}", name):
                continue
            if context_file is not None and name != context_file.parent.parent.name:
                continue
            workspace = root / name / client
            candidate_pin = open_pinned_directory(workspace, missing_ok=True)
            if candidate_pin is None:
                continue
            context_pins.append(opened.enter_context(candidate_pin))
            try:
                raw = _read_regular(workspace / ".vigil-client-context.json")
            except FileNotFoundError:
                continue
            binding = _object(raw)
            if binding.get("mode") not in {"web", "code"}:
                raise ValueError("Invalid recorded client mode")
            if mode and binding["mode"] != mode:
                continue
            if (binding.get("schema_version") != 1 or binding.get("client") != client
                    or binding.get("workspace") != str(workspace)
                    or binding.get("engagement_dir") != str(engagement)
                    or binding.get("engagement_key") != engagement.name
                    or binding.get("install_root") != str(install_root)
                    or binding.get("vigil_cli") != str(workspace / "bin/vigil")
                    or not isinstance(binding.get("release_id"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", binding["release_id"])):
                raise ValueError("Client context root/client/workspace binding mismatch")
            application = binding.get("application")
            if (not isinstance(application, dict) or not isinstance(application.get("root"), str)
                    or not Path(application["root"]).is_absolute()
                    or binding.get("agent_root") != str(Path(application["root"]) / "agent")
                    or not isinstance(application.get("content_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", application["content_sha256"])
                    or not isinstance(application.get("version"), str)):
                raise ValueError("Invalid client application binding")
            if expected_application is not None and application != expected_application:
                checks.append(Check(f"retained-context:{name}", "STALE", "Retained workspace belongs to another pinned release."))
                continue
            matched += 1
            checks.append(_manifest_check(workspace, raw))
            tools = binding.get("tools")
            if not isinstance(tools, dict) or not all(isinstance(tools.get(tool), str) for tool in REQUIRED_TOOLS):
                raise ValueError("Client binding lacks resolved executable dependencies")
            for tool in REQUIRED_TOOLS:
                checks.append(_executable_check(f"bound-dependency:{tool}", tools[tool]))
            checks.append(_executable_check("bound-helper", binding["vigil_cli"]))
            _known_pointer(workspace / "agent", Path(binding["agent_root"]), directory=True)
            _known_pointer(workspace / "scope.json", engagement / "scope.json", directory=False)
            checks.append(Check("managed-pointers", "OK", "Agent and scope pointers match the bound application/engagement."))
            if client == "zcode":
                plugin = install_root / "client-plugins" / binding["release_id"][:24] / "zcode"
                plugin_pin = open_pinned_directory(plugin)
                assert plugin_pin is not None
                context_pins.append(opened.enter_context(plugin_pin))
                _known_pointer(workspace / "plugin", plugin, directory=True)
                checks.append(_manifest_check(plugin, check_name="plugin-assets", required_files=(
                    ".zcode-plugin/plugin.json", "marketplace.json", "hooks/hooks.json", "hooks/context.mjs", "vigil-release.json")))
                if _object(_read_regular(plugin / "vigil-release.json")).get("release_id") != binding["release_id"]:
                    raise ValueError("Native plugin release does not match the client context")
            workspace_pin = open_pinned_directory(workspace)
            assert workspace_pin is not None
            with workspace_pin:
                receipts = [entry for entry in os.listdir(workspace_pin.fd)
                            if re.fullmatch(r"\.vigil-health-[0-9a-f]{64}\.json", entry)]
                if len(receipts) > MAX_RECEIPTS:
                    raise ValueError("Too many native hook receipts")
                for entry in sorted(receipts):
                    row = _object(_read_regular(workspace / entry, limit=65536))
                    session = row.get("session_id")
                    if (row.get("schema_version") != 1 or row.get("client") != client
                            or row.get("release_id") != binding["release_id"]
                            or row.get("binding_sha256") != hashlib.sha256(raw).hexdigest()
                            or not isinstance(session, str) or not session
                            or entry != ".vigil-health-" + hashlib.sha256(session.encode()).hexdigest() + ".json"):
                        raise ValueError("Native hook receipt does not match its exact context/session")
                    if expected_application is not None:
                        detail = (f"Historical receipt for {binding['mode']} workspace {workspace}; session {session}. "
                                  "This does not establish current native desktop/engine capability or conversation readiness.")
                        for check_name, field in (("startup-hook", "startup_observed"),
                                                  ("compact-hook", "compact_observed"),
                                                  ("context-injection", "context_injected")):
                            if row.get(field) is True:
                                observed[check_name].append(detail)
                workspace_pin.require_attached()
        for candidate_pin in context_pins:
            candidate_pin.require_attached()
        pin.require_attached()
    checks.append(Check("client-context", "OK" if matched else "MISSING",
                        f"Found {matched} matching existing workspace(s).", True))
    return checks, observed


def _version_check(name: str, version: str, minimum: tuple[int, int, int], major: int) -> Check:
    match = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)\s*", version)
    if not match:
        return Check(name, "UNVERIFIED", "Unrecognized native release version; verify a stable release.", True)
    parsed = tuple(map(int, match.groups()))
    supported = minimum <= parsed < (major + 1, 0, 0)
    return Check(name, "OK" if supported else "FAIL", version.strip(), True)


def _opencode_checks() -> list[Check]:
    executable = shutil.which("opencode")
    if executable is None:
        return [Check("opencode", "MISSING", "Install a stable OpenCode 1.x release >= 1.18.10.", True)]
    try:
        result = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                check=False, timeout=PROBE_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        return [Check("opencode", "UNVERIFIED", "The bounded --version probe failed; verify the CLI.", True)]
    if result.returncode != 0:
        return [Check("opencode", "FAIL", "The native --version probe exited unsuccessfully.", True)]
    return [_version_check("opencode", result.stdout or result.stderr, OPENCODE_MINIMUM, 1)]


def _zcode_checks() -> list[Check]:
    if sys.platform != "darwin":
        return [Check("zcode", "FAIL", "Desktop integration currently targets macOS.", True)]
    for application in (Path("/Applications/ZCode.app"), Path.home() / "Applications/ZCode.app"):
        metadata = application / "Contents/Info.plist"
        try:
            if not metadata.is_file():
                continue
            info = plistlib.loads(metadata.read_bytes())
            version = info.get("CFBundleShortVersionString") if isinstance(info, dict) else None
        except (OSError, ValueError, plistlib.InvalidFileException):
            return [Check("zcode", "FAIL", f"Cannot read application metadata: {metadata}", True)]
        if not isinstance(version, str):
            return [Check("zcode", "UNVERIFIED", "Application metadata has no release version.", True)]
        return [_version_check("zcode", version, ZCODE_MINIMUM, 3)]
    return [Check("zcode", "MISSING", "Install ZCode.app in /Applications or your Applications folder.", True)]


def collect_client_checks(client: str, *, engagement: Path | None = None,
                          mode: str | None = None, install_root: Path | None = None,
                          context_file: Path | None = None) -> list[Check]:
    """Inspect native prerequisites without reading credentials or changing state."""
    if client not in {"opencode", "zcode"}:
        raise ValueError(f"Unsupported client: {client}")
    checks = _opencode_checks() if client == "opencode" else _zcode_checks()
    checks.extend(_dependency_checks())
    checks.extend([
        Check("authentication-model", "UNVERIFIED",
              "Use the client's provider/model settings to select Z.AI Coding Plan and an entitled model. "
              "Credentials and provider connectivity were not inspected."),
        Check("startup-hook", "UNVERIFIED", "Installed files do not prove startup dispatch or context injection."),
        Check("compact-hook", "UNVERIFIED", "Automatic recovery requires native verification on the exact client/engine build."),
        Check("context-injection", "UNVERIFIED", "No exact-context native injection receipt was inspected."),
        Check("native-build-validation", "UNVERIFIED",
              "Historical event receipts do not verify the current native desktop/engine build's lifecycle behavior."),
        Check("backend-hydration", "UNVERIFIED", "No backend was contacted; hook injection alone does not prove hydration."),
    ])
    if engagement is not None:
        try:
            context_checks, observations = _observed_context_checks(client, engagement, mode, install_root, context_file)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
            checks.append(Check("client-context", "FAIL", f"Cannot verify existing context: {exc}", True))
        else:
            checks.extend(context_checks)
            checks = [Check(check.name, "OBSERVED", " ".join(observations[check.name]))
                      if observations.get(check.name) else check for check in checks]
    return checks
