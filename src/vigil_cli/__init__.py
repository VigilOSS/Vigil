"""Universal CLI for Vigil."""

import json
from pathlib import Path

__all__ = ["__version__"]

# Session helpers load the retained CLI snapshot, whose release may outlive the
# installed distribution. Its bundled version is the canonical version there.
_module_path = Path(__file__).resolve()
if _module_path.parent.parent.name == "cli":
    _manifest = _module_path.parents[2] / "bundle.json"
    if _manifest.is_file():
        __version__ = json.loads(_manifest.read_text(encoding="utf-8"))["version"]


def __getattr__(name: str) -> str:
    """Read the version from the installed distribution when it is first asked for.

    A literal here is a second copy of `pyproject.toml`'s `version`, and it
    silently rotted through a release: the 0.2.0 cut left this at "0.1.0". The
    distribution metadata lookup is deferred because every helper imports this
    package and almost none of them reads the version.
    """
    global __version__
    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib.metadata import PackageNotFoundError, version as _dist_version

    try:
        __version__ = _dist_version("vigil")
    except PackageNotFoundError:  # running straight from a source checkout
        __version__ = "0.0.0+unknown"
    return __version__
