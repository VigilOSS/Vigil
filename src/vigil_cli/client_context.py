"""Read project session identity, independently of application/code resolution."""
from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
import os
from pathlib import Path
import re

from .assessment_clients import CONTEXT_FILE
from .client_checks import _manifest_check, _object, _read_regular, validate_context_binding
from .paths import engagements_root


def _project_context() -> Path | None:
    for directory in (Path.cwd(), *Path.cwd().parents):
        context = directory / CONTEXT_FILE
        if context.exists() or context.is_symlink():
            return context
    return None


@contextmanager
def project_identity(*, install_root: str | None = None) -> Iterator[None]:
    """Supply verified GUI project identity for scoped CLI operations.

    Read only canonical install-owned projects. Never run their helper or select
    application code, executable search paths, or backend endpoints from metadata.
    Inherited bindings remain authoritative; a disagreement needs operator review.
    """
    discovered = _project_context()
    explicit = os.environ.get("VIGIL_CLIENT_CONTEXT")
    context = Path(explicit).expanduser() if explicit else discovered
    if context is None:
        yield
        return
    try:
        if not context.is_absolute() or context.name != CONTEXT_FILE:
            raise ValueError("Expected an absolute project context path")
        workspace = context.parent
        if (workspace.name not in {"zcode", "opencode"}
                or not re.fullmatch(r"[0-9a-f]{24}", workspace.parent.name)
                or workspace.parent.parent.name != "client-context"):
            raise ValueError("Expected a generated client project folder")
        if discovered is not None and context != discovered:
            raise ValueError("Inherited context and current project identify different sessions")
        engagement = workspace.parent.parent.parent
        raw = _read_regular(context)
        binding = _object(raw)
        owner = binding.get("install_root")
        if not isinstance(owner, str) or not Path(owner).is_absolute():
            raise ValueError("Expected an absolute private workspace root")
        root = Path(owner)
        if engagements_root(root).resolve() != engagement.parent:
            raise ValueError("Project engagement is outside its private workspace")
        validate_context_binding(binding, workspace, engagement, root, workspace.name)
        check = _manifest_check(workspace, raw, required_files=(CONTEXT_FILE, "bin/vigil", "AGENTS.md"))
        if check.status != "OK":
            raise ValueError(check.detail)
    except (OSError, ValueError, AssertionError) as exc:
        raise SystemExit(
            f"Cannot verify project context {context}: {exc}. "
            "From a terminal outside this project, run `vigil engagement start --client "
            "zcode` (or opencode) and open its printed Project folder."
        ) from exc

    identity = {
        "VIGIL_CLIENT_CONTEXT": str(context),
        "VIGIL_CLIENT_NAME": binding["client"],
        "VIGIL_REQUESTED_CLIENT": binding["client"],
        "VIGIL_INSTALL_DIR": str(root),
        "ENGAGEMENT_DIR": str(engagement),
        "VIGIL_SESSION_ENGAGEMENT_DIR": str(engagement),
        "ENGAGEMENT_KEY": engagement.name,
        "VIGIL_OPERATOR_MODE": binding["mode"],
    }
    paths = {"VIGIL_INSTALL_DIR", "VIGIL_DIR", "ENGAGEMENT_DIR", "VIGIL_SESSION_ENGAGEMENT_DIR"}
    comparisons = {**identity, "VIGIL_DIR": str(root)}
    for name, expected in comparisons.items():
        actual = os.environ.get(name)
        if actual and (str(Path(actual).expanduser().resolve()) if name in paths else actual) != expected:
            raise SystemExit(f"Project identity conflicts with ${name}. Use a terminal for this project with matching session settings.")
    if install_root and Path(install_root).expanduser().resolve() != root:
        raise SystemExit("Project identity conflicts with --root. Use the project's private workspace or inspect the other workspace from a separate terminal.")
    previous = {name: os.environ.get(name) for name in identity}
    try:
        os.environ.update(identity)
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
