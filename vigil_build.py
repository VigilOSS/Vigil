"""Build matched application releases without collecting operator workspaces.

Publishing from a checkout needs Node to build the two locked UI projects.
The sdist carries those outputs and their provenance; building its wheel is
entirely Python-only. Editable installs remain development checkouts.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib

_ROOT_FILES = (
    "README.md", "CHANGELOG.md", "LICENSE", "THIRD_PARTY_NOTICES.md",
    "SECURITY.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "CODE-MAP.md", "AGENTS.md",
)
_AGENT_DIRS = (
    "agents", "commands", "docker", "phases", "references", "rules", "schemas",
    "scripts", "skills", ".claude", ".codex", ".goose", ".opencode",
)
_EXCLUDED = {
    ".private", ".git", ".jj", ".venv", "__pycache__", "node_modules", "dist",
    "build", "engagements", "state", "cache", "logs", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "tests", ".DS_Store", "_bundle",
}
_EXTENSIONS = {".py", ".md", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".sh", ".txt", ".tsv", ".lock", ".html", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".css", ".svg", ".png"}
_PRIVATE_FILES = {"auth.json", "cookies.json", "credentials.json", "tokens.json", "subfinder-provider-config.yaml"}


def _allowed(path: Path) -> bool:
    parts = path.parts
    if path.name in _PRIVATE_FILES or path.name.startswith((".credentials", "settings.local.")) or ".local." in path.name:
        return False
    if any(part in _EXCLUDED or part.endswith(".egg-info") for part in parts):
        return False
    if any(part.startswith(".env") and part != ".env.example" for part in parts):
        return False
    if "tenants" in parts and not path.name.startswith("_template-"):
        return False
    if "data" in parts and not ("assess" in parts and "resolvers" in parts and path.suffix == ".txt"):
        return False
    return path.suffix in _EXTENSIONS or path.name in {"Dockerfile", ".env.example", ".dockerignore"}


def _publisher_inventory(source: Path) -> frozenset[Path]:
    if (source / ".jj").is_dir():
        argv = ["jj", "--repository", str(source), "--ignore-working-copy", "file", "list"]
        separator = "\n"
    elif (source / ".git").exists():
        argv = ["git", "-C", str(source), "ls-files", "-z"]
        separator = "\0"
    else:
        raise ValueError(
            "Source publishing requires a tracked Git/Jujutsu checkout and Node. "
            "Install the release wheel or bundled sdist for Python-only installation."
        )
    try:
        result = subprocess.run(argv, cwd=source, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("Cannot read publisher tracked-file inventory; use a prepared Git/Jujutsu checkout") from exc
    inventory = frozenset(source / name for name in result.stdout.split(separator) if name)
    if not inventory:
        raise ValueError("Publisher tracked-file inventory is empty")
    return inventory


def _copy_file(source: Path, target: Path, *, tracked: frozenset[Path] | None = None) -> None:
    if tracked is not None and source not in tracked:
        raise ValueError(f"Required release input is not tracked: {source.name}; snapshot intended sources before publishing")
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"Application asset must be a regular file: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)


def _copy_tree(source: Path, target: Path, *, tracked: frozenset[Path] | None = None) -> None:
    if not source.exists():
        return
    if source.is_symlink():
        raise ValueError(f"Application directory must not be a symlink: {source}")
    for base, directories, files in os.walk(source):
        directories[:] = sorted(name for name in directories if name not in _EXCLUDED and not name.endswith(".egg-info"))
        if tracked is not None:
            directories[:] = [name for name in directories if any(path.is_relative_to(Path(base) / name) for path in tracked)]
        if any((Path(base) / name).is_symlink() for name in directories):
            raise ValueError(f"Application directory must not contain symlinks: {base}")
        for name in sorted(files):
            item = Path(base) / name
            relative = item.relative_to(source)
            if _allowed(relative) and (tracked is None or item in tracked):
                _copy_file(item, target / relative)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(bundle: Path, version: str) -> dict:
    files = {path.relative_to(bundle).as_posix(): _sha256(path) for path in sorted(bundle.rglob("*")) if path.is_file() and path.name != "bundle.json"}
    executables = sorted(name for name in files if (bundle / name).stat().st_mode & 0o111)
    payload = {"files": files, "executables": executables}
    return {
        "schema_version": 1, "version": version, **payload,
        "content_sha256": hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }


@contextmanager
def _staged_cli(bundle: Path):
    """Import the staged release's owners without reusing the publisher's CLI."""
    previous_modules = {name: module for name, module in sys.modules.items() if name == "vigil_cli" or name.startswith("vigil_cli.")}
    previous_path, previous_bytecode = list(sys.path), sys.dont_write_bytecode
    for name in previous_modules:
        del sys.modules[name]
    sys.path.insert(0, str(bundle / "cli"))
    sys.dont_write_bytecode = True
    try:
        from vigil_cli import restart_manifest
        yield restart_manifest
    finally:
        for name in list(sys.modules):
            if name == "vigil_cli" or name.startswith("vigil_cli."):
                del sys.modules[name]
        sys.modules.update(previous_modules)
        sys.path[:] = previous_path
        sys.dont_write_bytecode = previous_bytecode


def _validate_bundle(bundle: Path, version: str) -> None:
    recorded = json.loads((bundle / "bundle.json").read_text())
    if recorded != _manifest(bundle, version):
        raise ValueError("Application bundle content or release version does not match its manifest")
    provenance = json.loads((bundle / "build-provenance.json").read_text())
    with _staged_cli(bundle) as restart_manifest:
        for component, inputs in (("frontend", restart_manifest.frontend_build_inputs), ("report", restart_manifest.report_build_inputs)):
            package = bundle / "orchestrator" / component
            digest = restart_manifest.image_freshness.inputs_digest(inputs(package), root=package)
            if provenance[component]["inputs_sha256"] != digest:
                raise ValueError(f"Prebuilt {component} does not match bundled source inputs")
            for name, expected in provenance[component]["outputs"].items():
                if _sha256(bundle / name) != expected:
                    raise ValueError(f"Prebuilt output does not match provenance: {name}")


def _validate_cli_snapshot(outer: Path, bundle: Path) -> None:
    def inventory(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): _sha256(path)
            for path in sorted(root.rglob("*.py"))
            if path.is_file() and _allowed(path.relative_to(root))
        }
    cli = inventory(outer)
    if not cli or cli != inventory(bundle / "cli/vigil_cli"):
        raise ValueError(
            "CLI snapshot differs from the application bundle. Rebuild the release "
            "from its original source checkout instead of combining different CLI assets."
        )


def _build_bundle(source: Path, bundle: Path, version: str, *, tracked: frozenset[Path]) -> None:
    for name in _ROOT_FILES:
        _copy_file(source / name, bundle / name, tracked=tracked)
    _copy_tree(source / "docs", bundle / "docs", tracked=tracked)
    _copy_tree(source / "third_party", bundle / "third_party", tracked=tracked)
    _copy_tree(source / "docker", bundle / "docker", tracked=tracked)
    _copy_tree(source / "src/vigil_cli", bundle / "cli/vigil_cli", tracked=tracked)
    for path in (source / "agent").iterdir():
        if path in tracked and path.is_file() and _allowed(Path(path.name)):
            _copy_file(path, bundle / "agent" / path.name)
    for name in _AGENT_DIRS:
        _copy_tree(source / "agent" / name, bundle / "agent" / name, tracked=tracked)
    for name in ("app", "scripts"):
        _copy_tree(source / "orchestrator/backend" / name, bundle / "orchestrator/backend" / name, tracked=tracked)
    for name in ("pyproject.toml", "uv.lock"):
        _copy_file(source / "orchestrator/backend" / name, bundle / "orchestrator/backend" / name, tracked=tracked)
    provenance = {}
    with _staged_cli(bundle) as restart_manifest:
        for component, inputs in (("frontend", restart_manifest.frontend_build_inputs), ("report", restart_manifest.report_build_inputs)):
            package = bundle / "orchestrator" / component
            _copy_tree(source / "orchestrator" / component, package, tracked=tracked)
            # Builds run in the isolated stage, never altering the source checkout.
            subprocess.run(["npm", "ci", "--no-audit", "--no-fund"], cwd=package, check=True)
            subprocess.run(["npm", "run", "build"], cwd=package, check=True)
            digest = restart_manifest.image_freshness.inputs_digest(inputs(package), root=package)
            if component == "frontend":
                restart_manifest.record_frontend_build(bundle)
            else:
                restart_manifest.record_report_build(bundle)
            provenance[component] = {
                "inputs_sha256": digest,
                "outputs": {path.relative_to(bundle).as_posix(): _sha256(path) for path in sorted((package / "dist").rglob("*")) if path.is_file()},
            }
            shutil.rmtree(package / "node_modules")
    (bundle / "build-provenance.json").write_text(json.dumps(provenance, sort_keys=True, indent=2) + "\n")
    for path in bundle.rglob("*"):
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    manifest = bundle / "bundle.json"
    manifest.write_text(json.dumps(_manifest(bundle, version), sort_keys=True, indent=2) + "\n")
    manifest.chmod(0o644)


@contextmanager
def _stage():
    source = Path.cwd()
    version = tomllib.loads((source / "pyproject.toml").read_text())["project"]["version"]
    bundled = source / "src/vigil_cli/_bundle"
    tracked = None if bundled.is_dir() else _publisher_inventory(source)
    with tempfile.TemporaryDirectory(prefix="vigil-release-") as directory:
        stage = Path(directory)
        for name in ("pyproject.toml", "MANIFEST.in", "vigil_build.py", *_ROOT_FILES):
            _copy_file(source / name, stage / name, tracked=tracked)
        _copy_tree(source / "third_party", stage / "third_party", tracked=tracked)
        _copy_tree(source / "src/vigil_cli", stage / "src/vigil_cli", tracked=tracked)
        bundle = stage / "src/vigil_cli/_bundle"
        if bundled.is_dir():
            _validate_cli_snapshot(source / "src/vigil_cli", bundled)
            _validate_bundle(bundled, version)
            shutil.copytree(bundled, bundle, dirs_exist_ok=True)
        else:
            assert tracked is not None
            _build_bundle(source, bundle, version, tracked=tracked)
        _validate_bundle(bundle, version)
        _validate_cli_snapshot(stage / "src/vigil_cli", bundle)
        # Regenerate the table when rebuilding the sdist, which already carries it.
        project = stage / "pyproject.toml"
        project.write_text(project.read_text().split("\n[tool.setuptools.package-data]\n")[0])
        # Exact package-data entries include hidden generated client trees.
        with (stage / "pyproject.toml").open("a") as stream:
            stream.write("\n[tool.setuptools.package-data]\nvigil_cli = " + json.dumps(sorted(path.relative_to(stage / "src/vigil_cli").as_posix() for path in bundle.rglob("*") if path.is_file())) + "\n")
        os.chdir(stage)
        try:
            yield stage
        finally:
            os.chdir(source)


def build_sdist(sdist_directory, config_settings=None):
    from setuptools import build_meta
    output = str(Path(sdist_directory).absolute())
    with _stage():
        filename = build_meta.build_sdist(output, config_settings)
    # Python's tarfile otherwise publishes the local account name/uid. Keep
    # canonical archive identity regardless of the publisher's environment.
    archive_path = Path(output) / filename
    with tempfile.TemporaryDirectory(prefix="vigil-archive-") as directory:
        normalized = Path(directory) / filename
        with tarfile.open(archive_path, "r:gz") as source, tarfile.open(normalized, "w:gz") as target:
            for member in source.getmembers():
                member.uid, member.gid, member.uname, member.gname = 0, 1, "root", "daemon"
                member.pax_headers = {key: value for key, value in member.pax_headers.items() if key not in {"uid", "gid", "uname", "gname"}}
                target.addfile(member, source.extractfile(member) if member.isfile() else None)
        shutil.copyfile(normalized, archive_path)
    return filename


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    from setuptools import build_meta
    output = str(Path(wheel_directory).absolute())
    with _stage():
        return build_meta.build_wheel(output, config_settings, metadata_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    from setuptools import build_meta
    return build_meta.build_editable(wheel_directory, config_settings, metadata_directory)


def get_requires_for_build_editable(config_settings=None):
    from setuptools import build_meta
    return build_meta.get_requires_for_build_editable(config_settings)


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    from setuptools import build_meta
    return build_meta.prepare_metadata_for_build_editable(metadata_directory, config_settings)


def get_requires_for_build_sdist(config_settings=None):
    from setuptools import build_meta
    return build_meta.get_requires_for_build_sdist(config_settings)


def get_requires_for_build_wheel(config_settings=None):
    from setuptools import build_meta
    return build_meta.get_requires_for_build_wheel(config_settings)


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    from setuptools import build_meta
    return build_meta.prepare_metadata_for_build_wheel(metadata_directory, config_settings)
