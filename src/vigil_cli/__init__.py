"""Universal CLI for Vigil."""

from importlib.metadata import PackageNotFoundError, version as _dist_version

__all__ = ["__version__"]

try:
    # Read the version from the installed distribution rather than restating it.
    # A literal here is a second copy of `pyproject.toml`'s `version`, and it
    # silently rotted through a release: the 0.2.0 cut left this at "0.1.0".
    __version__ = _dist_version("vigil")
except PackageNotFoundError:  # running straight from a source checkout
    __version__ = "0.0.0+unknown"
