"""Shared enums for `vigil assess kali` command-audit metadata fields.

Single source of truth for ``technique`` and ``probe_kind`` valid values.
Consumed by:

- ``agent/scripts/assess/lib/kali.py`` for host-side CLI flag validation.
- ``agent/scripts/assess/commands/list_command_runs.py`` for the
  ``--technique`` / ``--probe-kind`` argparse choices.
- The runtime container image (copied to ``/opt/mcp-tools/audit_enums.py``
  for legacy in-container scripts that still import it).

Enum values are **additive**. The host-side CLI fails closed when a caller
uses an out-of-enum value so prompt drift is caught before an audit row is
written. The backend stores plain TEXT for forward compatibility with older
or externally-written rows.
"""
from __future__ import annotations


TECHNIQUE_ENUM: tuple[str, ...] = (
    "SSRF",
    "XSS",
    "XXE",
    "SQLI",
    "NOSQLI",
    "SSTI",
    "RCE",
    "CMDI",
    "LFI",
    "RFI",
    "PATH-TRAVERSAL",
    "CRLF",
    "DESERIALIZATION",
    "PROTOTYPE-POLLUTION",
    "MASS-ASSIGNMENT",
    "IDOR",
    "BOLA",
    "BFLA",
    "AUTH",
    "JWT",
    "OAUTH",
    "SAML",
    "SESSION",
    "USER-ENUMERATION",
    "OPEN-REDIRECT",
    "CSRF",
    "CORS",
    "REQUEST-SMUGGLING",
    "HOST-HEADER",
    "CACHE-POISONING",
    "WEBSOCKET",
    "GRAPHQL",
    "FILE-UPLOAD",
    "BUSINESS-LOGIC",
    "RACE-CONDITION",
    "RATE-LIMIT",
    "INFO-DISCLOSURE",
    "RECON",
    "DISCOVERY",
    "PARAM-DISCOVERY",
    "FUZZ",
    "OSINT",
    "CVE-VALIDATION",
    "EXPLOIT-CHAIN",
    "META",
    "HEALTH",
    "LOG-READ",
    "OTHER",
)


def normalize_technique(value: str) -> str:
    """Canonicalize a ``--technique`` tag to its ``TECHNIQUE_ENUM`` spelling.

    Case- and separator-insensitive: ``ssrf`` / ``Ssrf`` / ``SSRF`` and
    ``open_redirect`` / ``open-redirect`` all resolve to the canonical enum
    value, so a cosmetic mismatch never forces the LLM into a retry (L3-2). A
    value that does not resolve is returned upper/hyphen-normalized so the
    caller still raises a clear out-of-enum error — never a silent coercion to
    ``OTHER``.
    """
    if not value:
        return value
    return value.strip().upper().replace("_", "-")


def normalize_probe_kind(value: str) -> str:
    """Canonicalize a ``--probe-kind`` to its ``PROBE_KIND_ENUM`` (lowercase) form."""
    if not value:
        return value
    return value.strip().lower()


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


__all__ = [
    "TECHNIQUE_ENUM",
    "PROBE_KIND_ENUM",
    "normalize_technique",
    "normalize_probe_kind",
]
