#!/usr/bin/env python3
"""MCP stdio bridge with Kali audit-context injection.

Loads the upstream ``/usr/share/mcp-kali-server/client.py`` module after
applying two patches so every Kali MCP tool call carries audit context:

1. ``requests.get``, ``requests.post``, ``requests.request``, and
   ``requests.Session.request`` are wrapped so every outbound HTTP call to
   the local Kali API server includes the audit headers
   (``X-Engagement-Key``, ``X-Agent-Name``, ``X-Phase``,
   ``X-Engagement-Artifact-Dir``).

2. ``fastmcp.FastMCP.tool`` is wrapped so every ``@mcp.tool(name=...)``
   decorator the upstream applies extends the handler signature with
   three required keyword-only string parameters: ``engagement_key``,
   ``agent_name``, and ``phase``, plus four optional keyword-only
   command-metadata parameters: ``technique`` (enum), ``probe_kind``
   (enum), ``intent`` (≤200 chars), and ``destructive`` (bool). The
   LLM sees all seven in the tool schema; the wrapper captures them
   into a context-local variable that the HTTP patch reads when it
   assembles headers, then invokes the original handler with only the
   fields upstream defined. Unset optional fields produce no header —
   backend stores NULL.

If either patch fails, the module falls back to the unpatched upstream
so the MCP bridge at least keeps working — warnings go to stderr.
"""
from __future__ import annotations

import contextvars
import functools
import importlib.util
import inspect
import logging
import os
import sys
from pathlib import Path
from typing import Annotated, Literal, Optional

# Load the shared enum constants module that lives beside this file in
# the container. Single source of truth shared with patched_kali_server.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_enums import PROBE_KIND_ENUM, TECHNIQUE_ENUM  # noqa: E402

try:
    from pydantic import Field  # type: ignore
except Exception:  # pragma: no cover — defensive; FastMCP always pulls pydantic
    Field = None  # type: ignore[assignment]


# Literal aliases built from the shared tuples so the JSON Schema the
# FastMCP decorator emits advertises the same valid values the server
# soft-validates against. ``Literal[some_tuple]`` unpacks the tuple into
# the Literal args at class-getitem time on Python 3.11+ (see PEP 646 /
# typing module). Fallback below catches the ancient case.
try:
    TechniqueLiteral = Literal[TECHNIQUE_ENUM]  # type: ignore[valid-type]
    ProbeKindLiteral = Literal[PROBE_KIND_ENUM]  # type: ignore[valid-type]
except TypeError:  # pragma: no cover — extremely old Python
    # Manual spelling kept in lock-step with audit_enums.TECHNIQUE_ENUM /
    # PROBE_KIND_ENUM. The assertion right below catches drift at import.
    TechniqueLiteral = Literal[  # type: ignore[misc]
        "SSRF", "XSS", "XXE", "SQLI", "NOSQLI", "SSTI", "RCE", "CMDI",
        "IDOR", "LFI", "RFI", "OPEN-REDIRECT", "AUTH", "JWT", "CSRF",
        "CORS", "REQUEST-SMUGGLING", "RATE-LIMIT", "INFO-DISCLOSURE",
        "RECON", "DISCOVERY", "FUZZ", "OSINT", "CVE-VALIDATION",
        "EXPLOIT-CHAIN", "OTHER",
    ]
    ProbeKindLiteral = Literal[  # type: ignore[misc]
        "fingerprint", "baseline", "payload", "exploit", "replay", "cleanup",
    ]

assert tuple(TechniqueLiteral.__args__) == TECHNIQUE_ENUM, (  # type: ignore[attr-defined]
    "TechniqueLiteral drifted from TECHNIQUE_ENUM — audit_enums.py is the "
    "single source of truth; update both or neither."
)
assert tuple(ProbeKindLiteral.__args__) == PROBE_KIND_ENUM, (  # type: ignore[attr-defined]
    "ProbeKindLiteral drifted from PROBE_KIND_ENUM — audit_enums.py is the "
    "single source of truth; update both or neither."
)


UPSTREAM_CLIENT_PATH = Path(
    os.environ.get("KALI_MCP_CLIENT_PATH", "/usr/share/mcp-kali-server/client.py")
)


_AUDIT_CONTEXT: contextvars.ContextVar[dict[str, str]] = contextvars.ContextVar(
    "kali_audit_context",
    default={},
)
logger = logging.getLogger("patched_kali_client")


def _current_audit_headers() -> dict[str, str]:
    """Assemble outbound headers. Per-call context (set by the MCP tool
    wrapper) wins over env fallback. Env fallback is allowed only for
    install-scoped fields (engagement_key, artifact_dir) — per-dispatch
    attribution (agent_name, phase) must come from per-call args or the
    header simply won't travel (and the server will 400 when
    KALI_MCP_AUDIT_REQUIRED=1)."""
    headers: dict[str, str] = {}
    ctx = _AUDIT_CONTEXT.get()
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


def _set_audit_context(
    engagement_key: str,
    agent_name: str,
    phase: str,
    *,
    technique: Optional[str] = None,
    intent: Optional[str] = None,
    probe_kind: Optional[str] = None,
    destructive: Optional[bool] = None,
) -> contextvars.Token[dict[str, str]]:
    """Stash the per-call audit context so the requests HTTP patch can
    pick it up on outbound calls. Core identity fields are always set
    (empty string means the upstream server will 400). Command-metadata
    fields are omitted from the header dict when None so the runtime
    distinguishes 'not declared' from 'declared as empty'."""
    ctx: dict[str, str] = {
        "X-Engagement-Key": engagement_key,
        "X-Agent-Name": agent_name,
        "X-Phase": phase,
    }
    if technique is not None and technique != "":
        ctx["X-Technique"] = str(technique)
    if intent is not None and intent != "":
        ctx["X-Intent"] = str(intent)[:200]
    if probe_kind is not None and probe_kind != "":
        ctx["X-Probe-Kind"] = str(probe_kind)
    if destructive is not None:
        ctx["X-Destructive"] = "1" if bool(destructive) else "0"
    return _AUDIT_CONTEXT.set(ctx)


def _clear_audit_context(token: contextvars.Token[dict[str, str]]) -> None:
    _AUDIT_CONTEXT.reset(token)


def _patch_requests_functions() -> None:
    """Wrap requests entrypoints so every outbound call picks up audit
    headers from the current call context. Upstream client.py currently uses
    module-level shortcuts, but Session.request is covered too so an
    upstream requests refactor does not silently drop audit metadata."""
    import requests  # type: ignore

    def _inject_headers(kwargs):
        headers = dict(kwargs.get("headers") or {})
        for name, value in _current_audit_headers().items():
            headers.setdefault(name, value)
        kwargs["headers"] = headers

    def _inject(method):
        @functools.wraps(method)
        def wrapper(*args, **kwargs):
            _inject_headers(kwargs)
            return method(*args, **kwargs)

        return wrapper

    requests.get = _inject(requests.get)
    requests.post = _inject(requests.post)
    requests.request = _inject(requests.request)
    requests.sessions.Session.request = _inject(requests.sessions.Session.request)


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

    # Annotated-with-Field annotations for the optional command-metadata
    # kwargs. FastMCP generates JSON Schema from these, so LLM clients
    # see: enum list (technique/probe_kind), maxLength=200 (intent),
    # and the description strings. Built once at import, reused across
    # every decorated tool.
    if Field is not None:
        _intent_annotation = Annotated[
            Optional[str],
            Field(
                default=None,
                max_length=200,
                description=(
                    "One-line purpose of this command. Replaces echo "
                    "breadcrumbs. FTS5-indexed — phrase-match via "
                    "`intent:\"...\"` scope."
                ),
            ),
        ]
        _destructive_annotation = Annotated[
            Optional[bool],
            Field(
                default=None,
                description=(
                    "True when this command attempts a write/edit/delete "
                    "on the target (POST/PUT/PATCH/DELETE, file upload, "
                    "account creation, config change, state-modifying "
                    "shell exec). False for read-only probes. Omit when "
                    "unknown."
                ),
            ),
        ]
        _technique_annotation = Annotated[
            Optional[TechniqueLiteral],
            Field(
                default=None,
                description=(
                    "Vulnerability class this command is testing. Use the "
                    "value from the skill you loaded (e.g. SSRF, SQLI, "
                    "RECON)."
                ),
            ),
        ]
        _probe_kind_annotation = Annotated[
            Optional[ProbeKindLiteral],
            Field(
                default=None,
                description=(
                    "Kind of work this command represents: fingerprint "
                    "(learn target, no payload) / baseline (vanilla "
                    "control) / payload (crafted attack) / exploit "
                    "(attacker-outcome proof) / replay (reused primitive) "
                    "/ cleanup (undo target changes)."
                ),
            ),
        ]
    else:  # pragma: no cover — pydantic absent, degrade gracefully
        _intent_annotation = Optional[str]  # type: ignore[misc]
        _destructive_annotation = Optional[bool]  # type: ignore[misc]
        _technique_annotation = Optional[TechniqueLiteral]  # type: ignore[misc]
        _probe_kind_annotation = Optional[ProbeKindLiteral]  # type: ignore[misc]

    def audited_tool(self, *tool_args, **tool_kwargs):
        inner_decorator = original_tool(self, *tool_args, **tool_kwargs)

        def wrapper(fn):
            original_sig = inspect.signature(fn)
            original_params = list(original_sig.parameters.values())

            # Core attribution kwargs — required at the schema level
            # (default=inspect.Parameter.empty) because the server 400s
            # without them.
            audit_params = [
                inspect.Parameter(
                    name,
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=str,
                )
                for name in ("engagement_key", "agent_name", "phase")
            ]
            # Optional command-metadata kwargs — default=None so LLMs
            # can omit them. Annotations carry the enum / maxLength /
            # description metadata that FastMCP lifts into JSON Schema.
            metadata_params = [
                inspect.Parameter(
                    "technique",
                    inspect.Parameter.KEYWORD_ONLY,
                    default=None,
                    annotation=_technique_annotation,
                ),
                inspect.Parameter(
                    "probe_kind",
                    inspect.Parameter.KEYWORD_ONLY,
                    default=None,
                    annotation=_probe_kind_annotation,
                ),
                inspect.Parameter(
                    "intent",
                    inspect.Parameter.KEYWORD_ONLY,
                    default=None,
                    annotation=_intent_annotation,
                ),
                inspect.Parameter(
                    "destructive",
                    inspect.Parameter.KEYWORD_ONLY,
                    default=None,
                    annotation=_destructive_annotation,
                ),
            ]
            new_sig = original_sig.replace(
                parameters=original_params + audit_params + metadata_params
            )

            def _pop_audit_kwargs(kwargs):
                engagement_key = kwargs.pop("engagement_key", "") or ""
                agent_name = kwargs.pop("agent_name", "") or ""
                phase = kwargs.pop("phase", "") or ""
                # Metadata kwargs: pop unconditionally so they never leak
                # into the upstream handler (which doesn't know them).
                # None → don't emit the header at all.
                technique = kwargs.pop("technique", None)
                probe_kind = kwargs.pop("probe_kind", None)
                intent = kwargs.pop("intent", None)
                destructive = kwargs.pop("destructive", None)
                return (
                    engagement_key,
                    agent_name,
                    phase,
                    technique,
                    probe_kind,
                    intent,
                    destructive,
                )

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def shim(*args, **kwargs):
                    (
                        engagement_key,
                        agent_name,
                        phase,
                        technique,
                        probe_kind,
                        intent,
                        destructive,
                    ) = _pop_audit_kwargs(kwargs)
                    token = _set_audit_context(
                        engagement_key,
                        agent_name,
                        phase,
                        technique=technique,
                        intent=intent,
                        probe_kind=probe_kind,
                        destructive=destructive,
                    )
                    try:
                        return await fn(*args, **kwargs)
                    finally:
                        _clear_audit_context(token)

            else:

                @functools.wraps(fn)
                def shim(*args, **kwargs):
                    (
                        engagement_key,
                        agent_name,
                        phase,
                        technique,
                        probe_kind,
                        intent,
                        destructive,
                    ) = _pop_audit_kwargs(kwargs)
                    token = _set_audit_context(
                        engagement_key,
                        agent_name,
                        phase,
                        technique=technique,
                        intent=intent,
                        probe_kind=probe_kind,
                        destructive=destructive,
                    )
                    try:
                        return fn(*args, **kwargs)
                    finally:
                        _clear_audit_context(token)

            shim.__signature__ = new_sig  # type: ignore[attr-defined]
            shim.__doc__ = (fn.__doc__ or "") + (
                "\n\nAudit: every call MUST pass engagement_key, agent_name, "
                "and phase. These attribute the command to the dispatching "
                "agent so `aith assess list-command-runs --agent-name <self>` "
                "returns only this agent's prior work."
                "\n\nOptional command-metadata kwargs — set them when they "
                "apply and they become filterable in the Commands tab and "
                "`list-command-runs`:\n"
                "  technique: vulnerability class (SSRF, SQLI, RCE, ...)\n"
                "  probe_kind: fingerprint / baseline / payload / exploit / "
                "replay / cleanup\n"
                "  intent: ≤200-char one-liner describing this command\n"
                "  destructive: True for write/edit/delete attempts, False "
                "for read-only, omit when unknown"
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
