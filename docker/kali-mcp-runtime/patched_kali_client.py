#!/usr/bin/env python3
"""MCP stdio bridge with Kali audit-context injection.

Loads the upstream ``/usr/share/mcp-kali-server/client.py`` module after
applying two patches so every Kali MCP tool call carries audit context:

1. ``requests.get``, ``requests.post``, and ``requests.request`` (module-
   level shortcuts — upstream does NOT use ``requests.Session``) are
   wrapped so every outbound HTTP call to the local Kali API server
   includes the audit headers (``X-Engagement-Key``, ``X-Agent-Name``,
   ``X-Phase``, ``X-Engagement-Artifact-Dir``).

2. ``fastmcp.FastMCP.tool`` is wrapped so every ``@mcp.tool(name=...)``
   decorator the upstream applies extends the handler signature with
   three required keyword-only string parameters: ``engagement_key``,
   ``agent_name``, and ``phase``. The LLM sees these in the tool schema
   and must pass them per call; the wrapper captures them into a thread-
   local that the HTTP patch reads when it assembles headers, then
   invokes the original handler with only the fields upstream defined.

If either patch fails, the module falls back to the unpatched upstream
so the MCP bridge at least keeps working — warnings go to stderr.
"""
from __future__ import annotations

import functools
import importlib.util
import inspect
import logging
import os
import sys
import threading
from pathlib import Path


UPSTREAM_CLIENT_PATH = Path(
    os.environ.get("KALI_MCP_CLIENT_PATH", "/usr/share/mcp-kali-server/client.py")
)


_AUDIT_CONTEXT = threading.local()
logger = logging.getLogger("patched_kali_client")


def _current_audit_headers() -> dict[str, str]:
    """Assemble outbound headers. Per-call context (set by the MCP tool
    wrapper) wins over env fallback. Env fallback is allowed only for
    install-scoped fields (engagement_key, artifact_dir) — per-dispatch
    attribution (agent_name, phase) must come from per-call args or the
    header simply won't travel (and the server will 400 when
    KALI_MCP_AUDIT_REQUIRED=1)."""
    headers: dict[str, str] = {}
    ctx: dict[str, str] | None = getattr(_AUDIT_CONTEXT, "headers", None)
    if ctx:
        headers.update(ctx)
    for header, env_var in (
        ("X-Engagement-Key", "KALI_MCP_DEFAULT_ENGAGEMENT_KEY"),
        ("X-Engagement-Artifact-Dir", "KALI_MCP_DEFAULT_ARTIFACT_DIR"),
    ):
        if headers.get(header):
            continue
        value = os.environ.get(env_var, "").strip()
        if value:
            headers[header] = value
    return headers


def _set_audit_context(engagement_key: str, agent_name: str, phase: str) -> None:
    _AUDIT_CONTEXT.headers = {
        "X-Engagement-Key": engagement_key,
        "X-Agent-Name": agent_name,
        "X-Phase": phase,
    }


def _clear_audit_context() -> None:
    _AUDIT_CONTEXT.headers = {}


def _patch_requests_functions() -> None:
    """Wrap module-level ``requests.get/post/request`` so every outbound
    call picks up audit headers from the current thread's context.
    Upstream client.py uses these shortcuts (not ``Session``), so
    patching ``Session.request`` alone would be a silent no-op."""
    import requests  # type: ignore

    def _inject(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            headers = dict(kwargs.get("headers") or {})
            for name, value in _current_audit_headers().items():
                headers.setdefault(name, value)
            kwargs["headers"] = headers
            return method(*args, **kwargs)

        return wrapper

    requests.get = _inject(requests.get)
    requests.post = _inject(requests.post)
    requests.request = _inject(requests.request)


def _wrap_fastmcp_tool_decorator() -> None:
    """Extend FastMCP's ``@tool()`` decorator so every registered MCP
    tool gains three required keyword-only parameters
    (``engagement_key``, ``agent_name``, ``phase``). FastMCP generates
    the tool's JSON schema from the function signature, so extending
    the signature means the LLM sees the audit fields and cannot call a
    Kali tool without supplying them."""
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore
    except ImportError:  # pragma: no cover — defensive
        logger.warning("mcp.server.fastmcp not importable; MCP schema audit patch skipped")
        return

    original_tool = FastMCP.tool

    def audited_tool(self, *tool_args, **tool_kwargs):
        inner_decorator = original_tool(self, *tool_args, **tool_kwargs)

        def wrapper(fn):
            original_sig = inspect.signature(fn)
            original_params = list(original_sig.parameters.values())

            audit_params = [
                inspect.Parameter(
                    name,
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=str,
                )
                for name in ("engagement_key", "agent_name", "phase")
            ]
            new_sig = original_sig.replace(parameters=original_params + audit_params)

            @functools.wraps(fn)
            def shim(*args, **kwargs):
                engagement_key = kwargs.pop("engagement_key", "") or ""
                agent_name = kwargs.pop("agent_name", "") or ""
                phase = kwargs.pop("phase", "") or ""
                _set_audit_context(engagement_key, agent_name, phase)
                try:
                    return fn(*args, **kwargs)
                finally:
                    _clear_audit_context()

            shim.__signature__ = new_sig  # type: ignore[attr-defined]
            shim.__doc__ = (fn.__doc__ or "") + (
                "\n\nAudit: every call MUST pass engagement_key, agent_name, "
                "and phase. These attribute the command to the dispatching "
                "agent so `assess.py list-command-runs --agent-name <self>` "
                "returns only this agent's prior work."
            )
            return inner_decorator(shim)

        return wrapper

    FastMCP.tool = audited_tool


def _load_upstream_client():
    spec = importlib.util.spec_from_file_location(
        "kali_upstream_client", UPSTREAM_CLIENT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load upstream client from {UPSTREAM_CLIENT_PATH}")
    module = importlib.util.module_from_spec(spec)
    try:
        _patch_requests_functions()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("requests HTTP patch failed, audit headers will not travel: %s", exc)
    try:
        _wrap_fastmcp_tool_decorator()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("FastMCP.tool patch failed, MCP schema will not include audit fields: %s", exc)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )
    module = _load_upstream_client()
    main_fn = getattr(module, "main", None)
    if callable(main_fn):
        main_fn()


if __name__ == "__main__":
    main()
