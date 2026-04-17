#!/usr/bin/env python3
"""MCP stdio bridge with Kali audit-context injection.

Loads the upstream ``/usr/share/mcp-kali-server/client.py`` module, then
patches the HTTP helpers it uses to talk to the local Kali API server so
every call carries audit context headers (``X-Engagement-Key``,
``X-Agent-Name``, ``X-Phase``, ``X-Engagement-Artifact-Dir``).

Audit values can come from two sources, checked in this order:

1. A thread-local ``_AUDIT_CONTEXT`` set per MCP tool invocation. Once the
   upstream MCP tool signatures are extended with ``engagement_key``,
   ``agent_name``, and ``phase`` parameters, a thin wrapper can populate the
   context before calling the original handler. That extension lives in
   the upstream project; until it lands, the session-level defaults below
   are used.
2. Environment variables set at MCP session start: ``KALI_MCP_DEFAULT_*``
   (same names the patched Kali server reads). The wrapper script sets
   these before exec'ing this bridge.

The patched Kali server is the source of truth for recording; this module
exists so the audit headers actually travel on the wire when the upstream
client makes its HTTP calls.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
from pathlib import Path
from typing import Any


UPSTREAM_CLIENT_PATH = Path(
    os.environ.get("KALI_MCP_CLIENT_PATH", "/usr/share/mcp-kali-server/client.py")
)


_AUDIT_CONTEXT = threading.local()


def _current_audit_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    ctx: dict[str, str] | None = getattr(_AUDIT_CONTEXT, "headers", None)
    if ctx:
        headers.update(ctx)
    # Environment-variable defaults kick in when per-call context isn't set.
    env_map = {
        "X-Engagement-Key": "KALI_MCP_DEFAULT_ENGAGEMENT_KEY",
        "X-Agent-Name": "KALI_MCP_DEFAULT_AGENT_NAME",
        "X-Phase": "KALI_MCP_DEFAULT_PHASE",
        "X-Engagement-Artifact-Dir": "KALI_MCP_DEFAULT_ARTIFACT_DIR",
    }
    for header, env_var in env_map.items():
        if headers.get(header):
            continue
        value = os.environ.get(env_var, "").strip()
        if value:
            headers[header] = value
    return headers


def set_audit_context(
    *,
    engagement_key: str | None = None,
    agent_name: str | None = None,
    phase: str | None = None,
    engagement_artifact_dir: str | None = None,
) -> None:
    """Set per-call audit headers. Call this from a tool-wrapper shim."""
    headers: dict[str, str] = {}
    if engagement_key:
        headers["X-Engagement-Key"] = engagement_key
    if agent_name:
        headers["X-Agent-Name"] = agent_name
    if phase:
        headers["X-Phase"] = phase
    if engagement_artifact_dir:
        headers["X-Engagement-Artifact-Dir"] = engagement_artifact_dir
    _AUDIT_CONTEXT.headers = headers


def clear_audit_context() -> None:
    _AUDIT_CONTEXT.headers = {}


def _patch_requests_module(requests_module) -> None:
    """Merge audit headers into every outbound request made via ``requests``."""
    original_request = requests_module.Session.request

    def audited_request(self, method, url, *args, **kwargs):
        headers = dict(kwargs.get("headers") or {})
        for name, value in _current_audit_headers().items():
            headers.setdefault(name, value)
        kwargs["headers"] = headers
        return original_request(self, method, url, *args, **kwargs)

    requests_module.Session.request = audited_request

    # Functional shorthand helpers also go through the session, but the
    # top-level api module uses a per-call session so patching Session.request
    # covers them too.


def _load_upstream_client():
    spec = importlib.util.spec_from_file_location(
        "kali_upstream_client", UPSTREAM_CLIENT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load upstream client from {UPSTREAM_CLIENT_PATH}")
    module = importlib.util.module_from_spec(spec)
    # Patch `requests` in upstream's import chain so any Session/session-less
    # call picks up audit headers automatically.
    try:
        import requests  # type: ignore

        _patch_requests_module(requests)
    except ImportError:
        pass
    spec.loader.exec_module(module)
    return module


def main() -> None:
    module = _load_upstream_client()
    main_fn = getattr(module, "main", None)
    if callable(main_fn):
        main_fn()
    else:
        # Upstream client exposes itself as a script; running the module is
        # enough because __main__ logic will have executed in exec_module.
        sys.exit(0)


if __name__ == "__main__":
    main()
