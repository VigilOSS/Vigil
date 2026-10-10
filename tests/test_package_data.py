from __future__ import annotations

import os
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_sdist_builds_an_installable_wheel_with_a_working_cli(tmp_path: Path) -> None:
    """Prove the published path, not an editable checkout.

    Build an sdist, build the wheel from that archive, install it in an isolated
    environment, and invoke the console entrypoint from an unrelated directory.
    """
    uv = shutil.which("uv")
    assert uv is not None, "the repository test matrix requires uv"

    dist_dir = tmp_path / "dist"
    subprocess.run(
        [uv, "build", "--sdist", "--out-dir", str(dist_dir), str(REPO_ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )
    sdists = list(dist_dir.glob("vigil-*.tar.gz"))
    assert len(sdists) == 1
    with tarfile.open(sdists[0]) as archive:
        members = archive.getmembers()
        assert members
        assert all(member.uid == 0 and member.uname == "root" for member in members)
        assert all(member.gname == "daemon" for member in members)
        assert all("uname" not in member.pax_headers for member in members)

    # Build the wheel from the source archive, not the working tree, so ignored
    # build directories cannot make a missing package-data declaration pass.
    unavailable_tools = tmp_path / "unavailable-tools"
    unavailable_tools.mkdir()
    for name in ("node", "npm", "git"):
        stub = unavailable_tools / name
        stub.write_text("#!/bin/sh\nexit 97\n")
        stub.chmod(0o755)
    consumer_env = os.environ.copy()
    consumer_env["PATH"] = str(unavailable_tools) + os.pathsep + consumer_env.get("PATH", "")
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(dist_dir), str(sdists[0])],
        check=True,
        capture_output=True,
        text=True,
        env=consumer_env,
    )
    wheels = list(dist_dir.glob("vigil-*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        required = {
            "vigil_cli/_bundle/bundle.json",
            "vigil_cli/_bundle/agent/AGENTS.md",
            "vigil_cli/_bundle/agent/references/reporting/bugcrowd-vrt.tsv",
            "vigil_cli/_bundle/docker/callback_listener.py",
            "vigil_cli/_bundle/docker/start-callback.sh",
            "vigil_cli/_bundle/agent/.claude/agents/recon-specialist.md",
            "vigil_cli/_bundle/orchestrator/backend/app/main.py",
            "vigil_cli/_bundle/orchestrator/backend/uv.lock",
            "vigil_cli/_bundle/orchestrator/frontend/dist/index.html",
            "vigil_cli/_bundle/orchestrator/report/dist/template.html",
            "vigil_cli/_bundle/docs/engagements.md",
            "vigil_cli/_bundle/LICENSE",
            "vigil_cli/_bundle/CHANGELOG.md",
            "vigil_cli/_bundle/THIRD_PARTY_NOTICES.md",
            "vigil_cli/_bundle/cli/vigil_cli/main.py",
            "vigil_cli/_bundle/build-provenance.json",
        }
        assert required <= names, f"release is missing application assets: {required - names}"
        prefix = "vigil_cli/_bundle/"
        manifest = json.loads(archive.read(prefix + "bundle.json"))
        assert manifest["schema_version"] == 1
        assert manifest["version"] == "1.1.0"
        payload = {key: manifest[key] for key in ("files", "executables")}
        assert manifest["content_sha256"] == hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert set(manifest["files"]) == {
            name.removeprefix(prefix) for name in names
            if name.startswith(prefix) and name != prefix + "bundle.json"
        }
        for name, digest in manifest["files"].items():
            assert hashlib.sha256(archive.read(prefix + name)).hexdigest() == digest
            mode = archive.getinfo(prefix + name).external_attr >> 16 & 0o777
            assert mode == (0o755 if name in manifest["executables"] else 0o644)
        for name in names:
            if name.startswith("vigil_cli/") and name.endswith(".py") and "/_bundle/" not in name:
                assert archive.read(name) == archive.read(prefix + "cli/" + name)
        assert all(
            not ({".private", ".git", ".jj", "node_modules", "__pycache__", "engagements", "data", ".venv"} & set(Path(name).parts))
            for name in names
            if "/assess/data/resolvers/" not in name
        )
        assert not any("/references/tenants/" in name and "/_template-" not in name for name in names)
        provenance = json.loads(archive.read(prefix + "build-provenance.json"))
        for component in ("frontend", "report"):
            record = provenance[component]
            assert record["inputs_sha256"] == archive.read(
                prefix + f"orchestrator/{component}/dist/.vigil-inputs"
            ).decode().strip()
            for name, digest in record["outputs"].items():
                assert hashlib.sha256(archive.read(prefix + name)).hexdigest() == digest

    venv_dir = tmp_path / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [str(python), "-m", "pip", "install", str(wheels[0])],
        check=True,
        capture_output=True,
        text=True,
    )

    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    env = {
        key: value for key, value in consumer_env.items()
        if not key.startswith(("VIGIL_", "ORCHESTRATOR_", "ENGAGEMENT_", "AGENT_"))
    }
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HOME"] = str(tmp_path / "home")
    env["VIGIL_CONFIG"] = str(tmp_path / "config.json")
    env["VIGIL_APPLICATION_CACHE"] = str(tmp_path / "applications")
    env["VIGIL_INSTALL_DIR"] = str(tmp_path / "workspace")
    env["ORCHESTRATOR_BASE_URL"] = "http://127.0.0.1:19997"
    (tmp_path / "home").mkdir()
    version = subprocess.run(
        [str(python), "-I", "-c", "import vigil_cli; print(vigil_cli.__version__)"],
        cwd=probe_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert version.stdout.strip() == "1.1.0"

    executable = venv_dir / ("Scripts/vigil.exe" if os.name == "nt" else "bin/vigil")
    cli_version = subprocess.run(
        [str(executable), "--version"],
        cwd=probe_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "1.1.0" in cli_version.stdout
    help_result = subprocess.run(
        [str(executable), "--help"],
        cwd=probe_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "usage: vigil" in help_result.stdout.lower()
    assert "engagement" in help_result.stdout
    application_probe = subprocess.run(
        [str(python), "-c", "from vigil_cli.application import resolve_application_root; print(resolve_application_root())"],
        cwd=probe_dir, env=env, check=True, capture_output=True, text=True,
    )
    application = Path(application_probe.stdout.strip())
    assert application.parent == tmp_path / "applications"
    assert (application / "docs/engagements.md").is_file()
    assert (application / "orchestrator/report/dist/template.html").is_file()
    image_inputs = subprocess.run(
        [str(python), "-c", "from pathlib import Path; from vigil_cli.application import resolve_application_root; from vigil_cli.runtime import runtime_image_inputs; from vigil_cli.mitmproxy import mitmproxy_image_inputs; r=resolve_application_root(); missing=[str(p) for p in runtime_image_inputs(r)+mitmproxy_image_inputs(r) if not p.exists()]; assert not missing, missing"],
        cwd=probe_dir, env=env, check=True, capture_output=True, text=True,
    )
    assert image_inputs.returncode == 0
    subprocess.run(
        [str(executable), "install", str(tmp_path / "workspace"), "--skip-image-check"],
        cwd=probe_dir, env=env, check=True, capture_output=True, text=True,
    )
    workspace = tmp_path / "workspace"
    assert (workspace / "workspace.json").is_file()
    assert (workspace / "engagements").is_dir()
    assert (workspace / "state").is_dir()
    assert not (workspace / "agent").exists()
    assert not (workspace / "orchestrator").exists()
    assess_help = subprocess.run(
        [str(executable), "assess", "--help"],
        cwd=probe_dir, env=env, check=True, capture_output=True, text=True,
    )
    assert "usage:" in assess_help.stdout.lower()
    # A source archive cannot combine a newer entrypoint with an older retained
    # helper snapshot, even if both independently remain valid Python.
    tampered = tmp_path / "tampered-sdist"
    tampered.mkdir()
    with tarfile.open(sdists[0]) as archive:
        archive.extractall(tampered, filter="data")
    [source] = tampered.iterdir()
    main = source / "src/vigil_cli/main.py"
    main.write_text("# synthetic mismatched CLI snapshot\n" + main.read_text())
    mixed = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(tmp_path / "rejected"), str(source)],
        cwd=probe_dir, env=consumer_env, capture_output=True, text=True,
    )
    assert mixed.returncode != 0
    assert "CLI snapshot" in mixed.stderr


def test_application_staging_excludes_private_state_and_rejects_symlinks(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("vigil_build", REPO_ROOT / "vigil_build.py")
    assert spec is not None and spec.loader is not None
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    source = tmp_path / "source"
    source.mkdir()
    for name in (
        ".private/operator.md", "engagements/acme/scope.json", "state/operator.json",
        "cache/operator.json", "logs/operator.json", "__pycache__/cache.py",
        ".claude/settings.local.json", "cookies.json", "credentials.json", "tokens.json",
        ".codex/auth.json", ".claude/.credentials.json", ".opencode/auth.json",
        "settings.local.toml", ".credentials", ".credentials.yaml",
        "docker/subfinder-provider-config.yaml",
        ".env", "references/tenants/acme.md", "data/operator.json", "private-key.pem",
        ".claude/agents/recon-specialist.md", "references/tenants/_template-generic.md",
        "references/reporting/bugcrowd-vrt.tsv",
        "scripts/assess/data/resolvers/trusted.txt", "scripts/proxy_addon.py",
    ):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic fixture\n")
    target = tmp_path / "target"
    backend._copy_tree(source, target)
    assert {path.relative_to(target).as_posix() for path in target.rglob("*") if path.is_file()} == {
        ".claude/agents/recon-specialist.md", "references/tenants/_template-generic.md",
        "references/reporting/bugcrowd-vrt.tsv",
        "scripts/assess/data/resolvers/trusted.txt", "scripts/proxy_addon.py",
    }
    (source / "linked.py").symlink_to(source / "scripts/proxy_addon.py")
    import pytest
    with pytest.raises(ValueError, match="regular file"):
        backend._copy_tree(source, tmp_path / "reject")


def test_publisher_inventory_excludes_untracked_files_inside_source_trees(tmp_path):
    spec = importlib.util.spec_from_file_location("vigil_build", REPO_ROOT / "vigil_build.py")
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    source = tmp_path / "source"
    source.mkdir()
    known = source / "canonical.md"
    known.write_text("Acme canonical application source\n")
    (source / "private.md").write_text("synthetic untracked private note\n")
    (source / "unknown-private.json").write_text('{"synthetic":"untracked private state"}\n')
    target = tmp_path / "target"
    backend._copy_tree(source, target, tracked=frozenset({known}))
    assert {path.name for path in target.iterdir()} == {"canonical.md"}


def test_bundle_validation_uses_staged_helpers_and_restores_parent_imports(tmp_path):
    from vigil_cli import restart_manifest
    spec = importlib.util.spec_from_file_location("vigil_build", REPO_ROOT / "vigil_build.py")
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    bundle = tmp_path / "bundle"
    cli = bundle / "cli/vigil_cli"
    cli.mkdir(parents=True)
    (cli / "__init__.py").write_text("# synthetic staged helper package\n")
    (cli / "restart_manifest.py").write_text(
        "from types import SimpleNamespace\n"
        "def frontend_build_inputs(root): return []\n"
        "def report_build_inputs(root): return []\n"
        "image_freshness = SimpleNamespace(inputs_digest=lambda *a, **k: 'e'*64)\n"
    )
    (bundle / "build-provenance.json").write_text(json.dumps({
        name: {"inputs_sha256": "e" * 64, "outputs": {}} for name in ("frontend", "report")
    }))
    (bundle / "bundle.json").write_text(json.dumps(backend._manifest(bundle, "1.1.0")))
    backend._validate_bundle(bundle, "1.1.0")
    assert sys.modules["vigil_cli.restart_manifest"] is restart_manifest


def test_source_build_without_node_names_the_requirement(tmp_path, monkeypatch):
    import pytest
    spec = importlib.util.spec_from_file_location("vigil_build", REPO_ROOT / "vigil_build.py")
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    monkeypatch.setattr(backend.shutil, "which", lambda _name: None)
    with pytest.raises(ValueError, match="Node.*npm.*release wheel"):
        backend._build_bundle(REPO_ROOT, tmp_path / "bundle", "1.1.0", tracked=frozenset())
