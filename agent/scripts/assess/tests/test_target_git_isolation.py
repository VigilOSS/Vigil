"""Git never runs a command the ingested repository configured.

A repository delivered with its `.git` directory controls that directory's
config, attributes, hooks and submodule metadata. Each vector below names a
program Git would run; every one writes a marker file when it runs. The
positive controls prove the hostile fixtures are live under a plain invocation,
so the isolation assertions cannot pass vacuously. The twin assertions prove
isolation costs nothing: a hostile repository yields exactly the provenance,
churn and security history of a benign one with the same history.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from assess.commands import code_ingest
from assess.lib.trusted_exec import (
    TargetGit,
    git_command,
    resolve_trusted_tool,
    trusted_environment,
)

_IDENTITY = {
    "GIT_AUTHOR_NAME": "Acme Dev",
    "GIT_AUTHOR_EMAIL": "dev@acme.example",
    "GIT_COMMITTER_NAME": "Acme Dev",
    "GIT_COMMITTER_EMAIL": "dev@acme.example",
}


@pytest.fixture(scope="module")
def git_bin(tmp_path_factory) -> str:
    resolved = resolve_trusted_tool("git", source_root=tmp_path_factory.mktemp("no-source"))
    if not resolved:
        pytest.skip("trusted Git executable not available")
    return resolved


def _git(cwd: Path, *args: str, date: str = "2026-06-01T12:00:00Z") -> str:
    """Fixture-building Git with no ambient configuration."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
        **_IDENTITY,
    }
    result = subprocess.run(
        ["git", "-c", "protocol.file.allow=always", *args],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _commit(repo: Path, message: str, date: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message, date=date)
    return _git(repo, "rev-parse", "HEAD")


def _signed_commit(repo: Path, message: str) -> str:
    """A commit carrying a gpgsig header, so `log.showSignature` has work."""
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    parent = _git(repo, "rev-parse", "HEAD")
    body = (
        f"tree {tree}\nparent {parent}\n"
        "author Acme Dev <dev@acme.example> 1780315200 +0000\n"
        "committer Acme Dev <dev@acme.example> 1780315200 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n"
        f"\n{message}\n"
    )
    (repo.parent / "signed-commit.txt").write_text(body, encoding="utf-8")
    commit = _git(repo, "hash-object", "-t", "commit", "-w", str(repo.parent / "signed-commit.txt"))
    _git(repo, "update-ref", "refs/heads/main", commit)
    return commit


def _benign_repo(root: Path) -> Path:
    repo = root / "acme-app"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    # Tracked attributes name drivers; only configuration can make them run.
    _write(
        repo,
        ".gitattributes",
        "*.txt filter=acme diff=acme\n*.ini filter=direct\n*.py filter=acme-proc\n",
    )
    _write(repo, "config/app.ini", "[acme]\nmode = prod\n")
    _write(repo, "docs/guide.md", "# Acme guide\n")
    _write(repo, "docs/readme.txt", "Acme app\n")
    _write(repo, "src/app.py", "def handler():\n    return 1\n")
    _commit(repo, "Initial import", "2026-05-01T09:00:00Z")
    _write(repo, "src/app.py", "def handler():\n    return 2\n")
    _commit(repo, "fix CVE-2026-0001 in the login handler", "2026-05-02T09:00:00Z")
    _git(repo, "checkout", "-q", "-b", "feature")
    _write(repo, "src/feature.py", "FEATURE = True\n")
    _commit(repo, "vulnerability triage for feature flags", "2026-05-03T09:00:00Z")
    _git(repo, "checkout", "-q", "main")
    _write(repo, "docs/readme.txt", "Acme app, second edition\n")
    _commit(repo, "Update readme", "2026-05-04T09:00:00Z")
    _signed_commit(repo, "Signed release notes")
    _git(repo, "reset", "-q", "--hard")
    # Ignored only by repository-local excludes: still clean.
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "exclude").write_text("build.log\n", encoding="utf-8")
    _write(repo, "build.log", "noise\n")
    return repo


def _marker_script(bin_dir: Path, markers: Path, name: str, *, passthrough: bool = False) -> str:
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / name
    tail = "exec cat\n" if passthrough else "exit 1\n"
    script.write_text(f"#!/bin/sh\n: > '{markers / name}'\n{tail}", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def _set(config: Path, key: str, value: str) -> None:
    _git(config.parent, "config", "--file", str(config), key, value)


def _arm(git_dir: Path, bin_dir: Path, markers: Path) -> None:
    """Configure every repository-controlled execution vector in *git_dir*."""
    config = git_dir / "config"

    def mark(name: str, *, passthrough: bool = False) -> str:
        return _marker_script(bin_dir, markers, name, passthrough=passthrough)

    _set(config, "filter.direct.clean", mark("filter-clean", passthrough=True))
    # include.path below redefines this driver; the included value wins.
    _set(config, "filter.acme.clean", mark("filter-clean-shadowed", passthrough=True))
    _set(config, "filter.acme.smudge", mark("filter-smudge", passthrough=True))
    _set(config, "filter.acme-proc.process", mark("filter-process"))
    _set(config, "filter.info.clean", mark("info-attributes-clean", passthrough=True))
    _set(config, "diff.acme.textconv", mark("diff-textconv", passthrough=True))
    _set(config, "diff.acme.command", mark("diff-command"))
    _set(config, "diff.external", mark("diff-external"))
    _set(config, "core.fsmonitor", mark("fsmonitor"))
    _set(config, "core.pager", mark("core-pager"))
    _set(config, "pager.log", mark("pager-log"))
    _set(config, "pager.status", mark("pager-status"))
    _set(config, "log.showSignature", "true")
    _set(config, "gpg.program", mark("gpg-program"))
    _set(config, "gpg.ssh.program", mark("gpg-ssh-program"))
    _set(config, "gpg.x509.program", mark("gpg-x509-program"))
    _set(config, "core.sshCommand", mark("ssh-command"))
    _set(config, "core.askPass", mark("askpass"))
    _set(config, "credential.helper", "!" + mark("credential-helper"))
    _set(config, "core.alternateRefsCommand", mark("alternate-refs"))
    _set(config, "uploadpack.packObjectsHook", mark("pack-objects-hook"))
    _set(config, "remote.origin.url", "ssh://git@acme.example/acme-app.git")
    _set(config, "remote.origin.uploadpack", mark("remote-uploadpack"))
    _set(config, "remote.origin.receivepack", mark("remote-receivepack"))
    _set(config, "url.ext::" + mark("url-rewrite") + ".insteadOf", "ssh://git@acme.example/")
    _set(config, "protocol.allow", "always")
    _set(config, "safe.directory", "*")
    hooks = git_dir / "custom-hooks"
    hooks.mkdir(exist_ok=True)
    for hook in ("pre-commit", "post-checkout", "post-index-change", "reference-transaction"):
        for directory in (hooks, git_dir / "hooks"):
            directory.mkdir(exist_ok=True)
            target = directory / hook
            shutil.copyfile(mark(f"hook-{hook}"), target)
            target.chmod(0o755)
    _set(config, "core.hooksPath", str(hooks))
    included = git_dir / "included.config"
    _set(included, "filter.acme.clean", mark("include-clean", passthrough=True))
    _set(config, "include.path", str(included))
    _set(config, f"includeIf.gitdir:{git_dir}/.path", str(included))
    info = git_dir / "info"
    info.mkdir(exist_ok=True)
    (info / "attributes").write_text("*.md filter=info\n", encoding="utf-8")


def _hostile_twin(benign: Path, root: Path) -> tuple[Path, Path]:
    """A byte-identical copy of *benign* whose `.git` is armed."""
    markers = root / "markers"
    markers.mkdir(parents=True)
    hostile = root / "acme-app"
    shutil.copytree(benign, hostile, symlinks=True)
    _arm(hostile / ".git", root / "bin", markers)
    return hostile, markers


def _captured(repo: Path, git: str) -> tuple:
    """Everything code-ingest records from Git for *repo*."""
    path = str(repo)
    return (
        code_ingest._git_provenance(path, git),
        code_ingest._git_commit_count(path),
        code_ingest._git_churn_scores(path, since="10years"),
        code_ingest._git_security_files(path, ["--all"]),
    )


def _plain(repo: Path, git: str, *args: str) -> subprocess.CompletedProcess:
    """Git over the repository's own metadata directory, with today's safe flags."""
    return subprocess.run(
        git_command(git, repo, *args),
        env=trusted_environment(source_root=repo),
        capture_output=True,
        text=True,
        check=False,
    )


def _touch_index_stat(repo: Path) -> None:
    """Make every tracked file stat-dirty so status must re-read its content."""
    for path in repo.rglob("*"):
        if ".git" in path.relative_to(repo).parts or not path.is_file():
            continue
        os.utime(path, (1_700_000_000, 1_700_000_000))


# --- positive controls ---------------------------------------------------------


def test_the_hostile_fixture_runs_its_commands_under_a_plain_invocation(tmp_path, git_bin):
    benign = _benign_repo(tmp_path / "benign")
    hostile, markers = _hostile_twin(benign, tmp_path / "hostile")
    _touch_index_stat(hostile)

    _plain(hostile, git_bin, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", ".")
    _plain(hostile, git_bin, "log", "--all", "--format=%H", "--name-only")

    fired = {path.name for path in markers.iterdir()}
    assert {
        "filter-clean",
        "filter-process",
        "include-clean",
        "info-attributes-clean",
        "gpg-program",
    } <= fired


# --- isolation -----------------------------------------------------------------


def test_no_repository_configured_command_runs_during_capture(tmp_path, git_bin):
    benign = _benign_repo(tmp_path / "benign")
    hostile, markers = _hostile_twin(benign, tmp_path / "hostile")
    _touch_index_stat(hostile)

    _captured(hostile, git_bin)
    code_ingest._verify_git_provenance(
        str(hostile), git_bin, code_ingest._git_provenance(str(hostile), git_bin)
    )

    assert sorted(path.name for path in markers.iterdir()) == []


def test_a_hostile_repository_yields_its_benign_twins_provenance(tmp_path, git_bin):
    benign = _benign_repo(tmp_path / "benign")
    hostile, _markers = _hostile_twin(benign, tmp_path / "hostile")
    _touch_index_stat(benign)
    _touch_index_stat(hostile)

    head, branch, dirty = (
        _plain(benign, git_bin, "rev-parse", "HEAD").stdout.strip(),
        _plain(benign, git_bin, "symbolic-ref", "--short", "HEAD").stdout.strip(),
        bool(_plain(benign, git_bin, "status", "--porcelain=v1", "-z",
                    "--untracked-files=all", "--", ".").stdout),
    )
    captured = _captured(hostile, git_bin)

    assert captured == _captured(benign, git_bin)
    provenance, commit_count, churn, security = captured
    assert provenance == {"head": head, "branch": branch, "dirty": dirty}
    assert dirty is False
    # `--all` still reaches the feature branch.
    assert commit_count == int(_plain(benign, git_bin, "rev-list", "--count", "--all").stdout)
    assert security == {"src/app.py", "src/feature.py"}
    assert churn["docs/readme.txt"] == 3  # one line added, then one changed


@pytest.mark.parametrize(
    "change",
    [
        lambda repo: (repo / "src" / "app.py").write_text("changed\n", encoding="utf-8"),
        lambda repo: (repo / "notes.md").write_text("untracked\n", encoding="utf-8"),
        lambda repo: (repo / "docs" / "readme.txt").unlink(),
    ],
    ids=["modified", "untracked", "deleted"],
)
def test_a_dirty_worktree_is_still_dirty(tmp_path, git_bin, change):
    benign = _benign_repo(tmp_path / "benign")
    hostile, markers = _hostile_twin(benign, tmp_path / "hostile")
    change(benign)
    change(hostile)

    assert code_ingest._git_provenance(str(hostile), git_bin)["dirty"] is True
    assert code_ingest._git_provenance(str(benign), git_bin)["dirty"] is True
    assert sorted(path.name for path in markers.iterdir()) == []


def test_inert_repository_settings_still_shape_the_dirty_bit(tmp_path, git_bin):
    """Settings Git probes at init or that only filter paths stay in force."""
    repo = _benign_repo(tmp_path / "benign")
    _git(repo, "config", "core.fileMode", "false")
    _git(repo, "config", "core.excludesFile", str(tmp_path / "acme-ignore"))
    (tmp_path / "acme-ignore").write_text("*.tmp\n", encoding="utf-8")
    (repo / "src" / "app.py").chmod(0o755)
    (repo / "scratch.tmp").write_text("ignored\n", encoding="utf-8")

    plain = _plain(repo, git_bin, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", ".")
    assert plain.stdout == ""
    assert code_ingest._git_provenance(str(repo), git_bin)["dirty"] is False


def test_a_partial_clone_never_fetches_through_repository_transport(tmp_path, git_bin):
    repo = _benign_repo(tmp_path / "benign")
    markers = tmp_path / "markers"
    markers.mkdir()
    blob = _git(repo, "rev-parse", "HEAD~1:docs/readme.txt")
    (repo / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
    _git(repo, "config", "core.repositoryFormatVersion", "1")
    _git(repo, "config", "extensions.partialClone", "origin")
    _git(repo, "config", "remote.origin.url", "ssh://git@acme.example/acme-app.git")
    _git(repo, "config", "remote.origin.promisor", "true")
    _git(repo, "config", "core.sshCommand", _marker_script(tmp_path / "bin", markers, "ssh-command"))

    assert _plain(repo, git_bin, "log", "--numstat", "--format=%H").returncode != 0
    assert (markers / "ssh-command").exists(), "positive control: lazy fetch ran the transport"
    (markers / "ssh-command").unlink()

    code_ingest._git_churn_scores(str(repo), since="10years")

    assert sorted(path.name for path in markers.iterdir()) == []


# --- submodules ----------------------------------------------------------------


def _with_submodule(root: Path) -> Path:
    library = root / "acme-lib"
    library.mkdir(parents=True)
    _git(library, "init", "-q", "-b", "main")
    _write(library, ".gitattributes", "*.txt filter=acme\n")
    _write(library, "lib.txt", "library\n")
    _commit(library, "Initial library", "2026-05-01T09:00:00Z")
    parent = _benign_repo(root / "parent")
    _git(parent, "submodule", "--quiet", "add", str(library), "vendor-lib")
    _commit(parent, "Add library", "2026-05-05T09:00:00Z")
    return parent


def test_a_submodules_own_configuration_never_runs(tmp_path, git_bin):
    parent = _with_submodule(tmp_path)
    markers = tmp_path / "markers"
    markers.mkdir()
    _arm(parent / ".git" / "modules" / "vendor-lib", tmp_path / "bin", markers)
    _touch_index_stat(parent / "vendor-lib")

    _plain(parent, git_bin, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", ".")
    assert "include-clean" in {path.name for path in markers.iterdir()}, "positive control"
    for path in markers.iterdir():
        path.unlink()

    assert code_ingest._git_provenance(str(parent), git_bin)["dirty"] is False
    assert sorted(path.name for path in markers.iterdir()) == []


@pytest.mark.parametrize(
    "change",
    [
        lambda sub: (sub / "lib.txt").write_text("patched\n", encoding="utf-8"),
        lambda sub: (sub / "local.txt").write_text("untracked\n", encoding="utf-8"),
        lambda sub: _commit_in(sub),
    ],
    ids=["modified-content", "untracked-content", "new-commit"],
)
def test_a_dirty_submodule_still_makes_the_worktree_dirty(tmp_path, git_bin, change):
    parent = _with_submodule(tmp_path)
    change(parent / "vendor-lib")

    plain = _plain(parent, git_bin, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", ".")
    assert plain.stdout
    assert code_ingest._git_provenance(str(parent), git_bin)["dirty"] is True


def _commit_in(repo: Path) -> None:
    _write(repo, "next.txt", "next\n")
    _commit(repo, "Next library change", "2026-05-06T09:00:00Z")


# --- repository layouts --------------------------------------------------------


def test_a_linked_worktree_keeps_head_branch_and_all_reach(tmp_path, git_bin):
    main = _benign_repo(tmp_path / "benign")
    linked = tmp_path / "acme-app-review"
    _git(main, "worktree", "add", "-q", "--detach", str(linked), "feature")
    _write(linked, "src/review.py", "REVIEW = 1\n")
    _commit(linked, "security review notes", "2026-05-07T09:00:00Z")
    markers = tmp_path / "markers"
    markers.mkdir()
    _arm(main / ".git", tmp_path / "bin", markers)
    _touch_index_stat(linked)

    for worktree in (main, linked):
        provenance = code_ingest._git_provenance(str(worktree), git_bin)
        assert provenance["head"] == _plain(worktree, git_bin, "rev-parse", "HEAD").stdout.strip()
        assert provenance["dirty"] is False
        # The linked worktree's detached commit is reachable only from its HEAD.
        assert code_ingest._git_commit_count(str(worktree)) == int(
            _plain(main, git_bin, "rev-list", "--count", "--all").stdout
        )
    assert code_ingest._git_provenance(str(linked), git_bin)["branch"] == ""
    assert "src/review.py" in code_ingest._git_security_files(str(main), ["--all"])
    assert sorted(path.name for path in markers.iterdir()) == []


def test_a_linked_worktrees_own_refs_stay_in_all_reach(tmp_path, git_bin):
    main = _benign_repo(tmp_path / "benign")
    linked = tmp_path / "acme-app-review"
    _git(main, "worktree", "add", "-q", "--detach", str(linked), "feature")
    _write(linked, "src/review.py", "REVIEW = 1\n")
    review = _commit(linked, "security review notes", "2026-05-07T09:00:00Z")
    # Reachable only from this worktree's private ref namespace.
    _git(linked, "update-ref", "refs/worktree/review", review)
    _git(linked, "checkout", "-q", "--detach", "feature")

    expected = int(_plain(linked, git_bin, "rev-list", "--count", "--all").stdout)
    assert expected == int(_plain(main, git_bin, "rev-list", "--count", "--all").stdout) + 1
    assert code_ingest._git_commit_count(str(linked)) == expected


def test_a_split_index_is_read_with_its_shared_part(tmp_path, git_bin):
    repo = _benign_repo(tmp_path / "benign")
    _git(repo, "update-index", "--split-index")
    assert list((repo / ".git").glob("sharedindex.*"))
    _touch_index_stat(repo)

    assert code_ingest._git_provenance(str(repo), git_bin)["dirty"] is False


def test_a_shallow_clone_reads_its_history_boundary(tmp_path, git_bin):
    benign = _benign_repo(tmp_path / "benign")
    shallow = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth", "2", f"file://{benign}", str(shallow))

    assert code_ingest._git_commit_count(str(shallow)) == int(
        _plain(shallow, git_bin, "rev-list", "--count", "--all").stdout
    )
    assert code_ingest._git_provenance(str(shallow), git_bin)["dirty"] is False


@pytest.mark.parametrize(
    "init_args",
    [["--object-format=sha256"], ["--ref-format=reftable"]],
    ids=["sha256", "reftable"],
)
def test_repository_formats_are_read_as_the_repository_declares(tmp_path, git_bin, init_args):
    repo = tmp_path / "acme-format"
    repo.mkdir()
    try:
        _git(repo, "init", "-q", "-b", "main", *init_args)
    except subprocess.CalledProcessError:
        pytest.skip(f"this Git does not support {init_args}")
    _write(repo, "src/app.py", "print('acme')\n")
    head = _commit(repo, "fix security bug", "2026-05-01T09:00:00Z")

    assert code_ingest._git_provenance(str(repo), git_bin) == {
        "head": head,
        "branch": "main",
        "dirty": False,
    }
    assert code_ingest._git_security_files(str(repo), ["--all"]) == {"src/app.py"}


# --- the helper's boundary -------------------------------------------------------


def test_target_git_ignores_inherited_git_environment(tmp_path, git_bin, monkeypatch):
    repo = _benign_repo(tmp_path / "benign")
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    monkeypatch.setenv("GIT_DIR", str(attacker))
    monkeypatch.setenv("git_work_tree", str(attacker))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor'='/bin/false'")

    with TargetGit(git_bin, repo) as git:
        head = git.run(["rev-parse", "HEAD"], capture_output=True, text=True)
        environment = dict(git.environment)

    assert head.stdout.strip() == _plain(repo, git_bin, "rev-parse", "HEAD").stdout.strip()
    assert not any(key.upper() == "GIT_CONFIG_PARAMETERS" for key in environment)
    assert environment["GIT_WORK_TREE"] == str(repo.resolve())
    assert not environment["GIT_DIR"].startswith(str(repo))
    assert environment["GIT_OBJECT_DIRECTORY"] == str((repo / ".git" / "objects").resolve())


def test_target_git_refuses_a_worktree_without_git_metadata(tmp_path, git_bin):
    plain_directory = tmp_path / "acme-export"
    plain_directory.mkdir()

    with pytest.raises(ValueError, match="Git"):
        with TargetGit(git_bin, plain_directory):
            pass


# --- security-history matching -------------------------------------------------


@pytest.mark.parametrize(
    "message",
    [
        "Patch Security hole in uploads",
        "cve-2026-4242 backport",
        "Use-After-Free in the image parser",
        "Fix XSS VULNERABILITY in search",
    ],
)
def test_security_history_matches_commit_messages_in_any_letter_case(tmp_path, git_bin, message):
    repo = tmp_path / "acme-history"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _write(repo, "src/app.py", "print('acme')\n")
    _commit(repo, "Initial import", "2026-05-01T09:00:00Z")
    _write(repo, "src/upload.py", "def upload():\n    pass\n")
    _commit(repo, message, "2026-05-02T09:00:00Z")

    assert code_ingest._git_security_files(str(repo), ["--all"]) == {"src/upload.py"}
