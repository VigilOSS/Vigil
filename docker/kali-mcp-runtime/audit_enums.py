"""Shared enums for the Kali MCP command-audit metadata fields.

Single source of truth for ``technique`` and ``probe_kind`` valid values.
Imported by both the server-side header capture (for soft validation +
warning logs) and the client-side FastMCP decorator (for ``Literal`` type
hints so the emitted JSON Schema advertises the valid values to MCP
clients / LLM callers).

Enum values are **additive**. Both the backend API and the server-side
capture use soft validation (log warning, store verbatim) so adding a
new technique does not require a runtime redeploy to stop rejecting
rows. The only place these tuples are a hard contract is the
``Literal`` type hint on the ``@mcp.tool`` decorator — adding a value
there changes the schema surface and therefore needs a client rebuild.
"""
from __future__ import annotations


# 26-value curated enum of vulnerability classes (25 specific classes plus
# the `OTHER` escape hatch). See plan file for rationale on each value.
# Ordering is stable so the emitted JSON Schema and CLI help text are
# deterministic across builds.
TECHNIQUE_ENUM: tuple[str, ...] = (
    "SSRF",
    "XSS",
    "XXE",
    "SQLI",
    "NOSQLI",
    "SSTI",
    "RCE",
    "CMDI",
    "IDOR",
    "LFI",
    "RFI",
    "OPEN-REDIRECT",
    "AUTH",
    "JWT",
    "CSRF",
    "CORS",
    "REQUEST-SMUGGLING",
    "RATE-LIMIT",
    "INFO-DISCLOSURE",
    "RECON",
    "DISCOVERY",
    "FUZZ",
    "OSINT",
    "CVE-VALIDATION",
    "EXPLOIT-CHAIN",
    "OTHER",
)


# 6-value probe_kind enum.
#
# - fingerprint: learning the target (versions, headers, tech stack) — no payload
# - baseline:    vanilla control request against the target surface, for diff
# - payload:     crafted attack payload testing a hypothesis
# - exploit:     attacker-outcome proof (extract token, read a file, dump DB)
# - replay:      captured primitive used against a new surface (lateral)
# - cleanup:     undoing target-side changes
PROBE_KIND_ENUM: tuple[str, ...] = (
    "fingerprint",
    "baseline",
    "payload",
    "exploit",
    "replay",
    "cleanup",
)


__all__ = ["TECHNIQUE_ENUM", "PROBE_KIND_ENUM"]
