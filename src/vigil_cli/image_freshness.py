"""Docker image build-input digest, freshness and drift checks.

Freshness here is a **content manifest, not a timestamp**: a sha256 over
``(relative path, content)`` for every declared build input, stamped onto the
image at build time as ``IMAGE_INPUTS_LABEL`` and re-derived on every check.

An mtime high-water mark could express neither of the two failures that
actually happened:

1. It rglobbed ``agent/scripts/assess`` including ``__pycache__/*.pyc``, which
   every ordinary ``vigil assess`` run rewrites — so ``vigil up`` rebuilt
   ``vigil-proxy`` forever. Hence the central ``EXCLUDED_INPUT_NAMES`` /
   ``is_excluded_input`` cache-and-build-artifact exclusion set, which
   ``install_manifest`` also consumes so the install copier's skip rule and the
   content digest cannot disagree.
2. It stat'd only files that still exist, so an upgrade that DELETED an input
   left the stale image reading as current. ``input_entries`` yields a ``None``
   file for a declared-but-absent path, which is what makes a deletion move the
   digest.

``image_inputs_state`` returns ``missing`` / ``unknown`` / ``stale`` /
``current``. ``unknown`` (an image built before stamping) reads as outdated so a
caller rebuilds once and moves on rather than erroring: an unstamped image
cannot be *proven* current.

The label KEY still says "runtime" because already-built ``vigil:latest`` images
carry it; labels are per-image, so one key serves both the runtime and proxy
images. The proxy manifest additionally covers the installed canonical
``vigil_cli/scope_entries.py``, so changing authored-scope parsing invalidates
the proxy image that imports it.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import docker

_PROXY_CONTAINER_NAME = "vigil-proxy"
_PROXY_IMAGE = "vigil-proxy:latest"

# Sha256 of an image's exact build inputs (see module docstring), stamped at
# build time and re-derived on every check.
#
# The label KEY still reads "runtime" because that is what already-built
# `vigil:latest` images carry; renaming it would make every existing image read
# `unknown` and force a needless full Kali rebuild. Labels are per-image, so one
# key serves the runtime and proxy images without ambiguity.
IMAGE_INPUTS_LABEL = "com.vigil.runtime-inputs-sha256"

# Build artifacts and caches that live INSIDE a source tree but are NOT build
# inputs (see module docstring for the `__pycache__` rebuild-loop history).
#
# This set is shared with `install.py`, which must make the same source-vs-junk
# call when it syncs a tree; the two cannot be allowed to disagree about what
# counts as a source file.
EXCLUDED_INPUT_NAMES = frozenset(
    {
        "__pycache__",
        ".DS_Store",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        "dist",
        ".venv",
        "*.egg-info",
    }
)


def is_excluded_input(name: str) -> bool:
    """True for a path component that is a build artifact/cache, not an input."""
    return name in EXCLUDED_INPUT_NAMES or name.endswith(".egg-info") or name.endswith(".pyc")


def _label_for(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _walk_input_files(directory: Path):
    """Every non-excluded file under ``directory``, pruning excluded subtrees."""
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = sorted(name for name in dirnames if not is_excluded_input(name))
        base = Path(dirpath)
        for name in sorted(filenames):
            if is_excluded_input(name):
                continue
            yield base / name


def input_entries(inputs: list[Path], *, root: Path) -> list[tuple[str, Path | None]]:
    """(label, file) for every build input, in a deterministic order.

    Declared order is preserved for the listed paths; a listed DIRECTORY expands
    to its files in sorted relative-path order. A listed path that does not exist
    (or a directory with no files) yields ``None`` so the digest still records it
    — this is what makes a deletion move the digest (see module docstring).
    """
    entries: list[tuple[str, Path | None]] = []
    for path in inputs:
        if path.is_dir():
            children = sorted(_walk_input_files(path), key=lambda child: _label_for(child, root))
            if not children:
                entries.append((_label_for(path, root), None))
            entries.extend((_label_for(child, root), child) for child in children)
        else:
            entries.append((_label_for(path, root), path if path.is_file() else None))
    return entries


def inputs_digest(inputs: list[Path], *, root: Path) -> str:
    """Stable sha256 over (relative path, content) for every build input."""
    digest = hashlib.sha256()
    for label, path in input_entries(inputs, root=root):
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes() if path is not None else b"<absent>")
        digest.update(b"\0")
    return digest.hexdigest()


def inputs_label_arg(inputs: list[Path], *, root: Path) -> str:
    """The ``--label`` value stamping the current input digest onto an image."""
    return f"{IMAGE_INPUTS_LABEL}={inputs_digest(inputs, root=root)}"


def image_inputs_state(
    image: str, inputs: list[Path], *, root: Path, runner: docker.Runner = docker.run_command
) -> str:
    """``missing`` | ``unknown`` | ``stale`` | ``current`` for an image's inputs.

    Compares the digest stamped on the image at build time against the digest of
    the inputs on disk right now. ``unknown`` means the image predates digest
    stamping, so nothing can be proven about it. Content-based, so neither
    ``vigil install`` rewriting mtimes nor `.pyc` churn can fake staleness, and a
    deleted input cannot hide.
    """
    if not docker.image_exists(image, runner=runner):
        return "missing"
    result = runner(
        [
            "docker",
            "image",
            "inspect",
            "-f",
            '{{ index .Config.Labels "' + IMAGE_INPUTS_LABEL + '" }}',
            image,
        ]
    )
    baked = (result.stdout or "").strip() if result.returncode == 0 else ""
    if not baked or baked == "<no value>":
        return "unknown"
    return "current" if baked == inputs_digest(inputs, root=root) else "stale"


def image_outdated(
    image: str, inputs: list[Path], *, root: Path, runner: docker.Runner = docker.run_command
) -> bool:
    """True unless the image is provably built from exactly the current inputs.

    A missing image, and an image built before digest stamping, both read as
    outdated: callers rebuild once and the rebuilt image is stamped.
    """
    return image_inputs_state(image, inputs, root=root, runner=runner) != "current"


def proxy_image_drift(*, runner: docker.Runner = docker.run_command) -> bool:
    """True when the running ``vigil-proxy`` container predates the current image.

    Compares the container's image id against the ``vigil-proxy:latest`` tag id;
    a mismatch means the tag was rebuilt after the container started, so a
    restart is needed to pick it up. Returns False when either id is unavailable
    (no container / no image), mirroring the runtime's drift check in ``up.py``.
    """
    container_id = docker.container_image_id(_PROXY_CONTAINER_NAME, runner=runner)
    configured_id = docker.image_id(_PROXY_IMAGE, runner=runner)
    return bool(container_id and configured_id and container_id != configured_id)
