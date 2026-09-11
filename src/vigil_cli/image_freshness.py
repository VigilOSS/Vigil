from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import docker

_PROXY_CONTAINER_NAME = "vigil-proxy"
_PROXY_IMAGE = "vigil-proxy:latest"

# Docker label carrying the sha256 of the exact inputs an image was built from.
# Stamped at build time, re-derived and compared on every freshness check, so a
# rebuild is triggered by CONTENT, never by a timestamp.
#
# The label KEY still reads "runtime" because that is what already-built
# `vigil:latest` images carry; renaming it would make every existing image read
# `unknown` and force a needless full Kali rebuild. Labels are per-image, so one
# key serves the runtime and proxy images without ambiguity.
IMAGE_INPUTS_LABEL = "com.vigil.runtime-inputs-sha256"

# Build artifacts and caches that live INSIDE a source tree but are NOT build
# inputs. `__pycache__`/`*.pyc` are the load-bearing entries: every ordinary
# `vigil assess` run rewrites bytecode under the install root, so the previous
# mtime high-water mark over `agent/scripts/assess` was newer than the proxy
# image within minutes of every build and `vigil up` rebuilt it forever.
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
    — that is what makes a DELETION change the digest instead of silently
    vanishing from an mtime high-water mark.
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
