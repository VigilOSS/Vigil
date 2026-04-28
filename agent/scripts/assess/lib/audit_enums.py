"""Shared enums for `aith assess kali` command-audit metadata fields.

Single source of truth for ``technique`` and ``probe_kind`` valid values.
Consumed by:

- ``agent/scripts/assess/lib/kali.py`` for host-side CLI flag validation.
- ``agent/scripts/assess/commands/list_command_runs.py`` for the
  ``--technique`` / ``--probe-kind`` argparse choices.
- The runtime container image (copied to ``/opt/mcp-tools/audit_enums.py``
  for legacy in-container scripts that still import it).

Enum values are **additive**. Both the backend API and the host-side CLI
use soft validation (warn-and-continue when a row carries an out-of-enum
value) so adding a new technique does not require a runtime redeploy.
"""
from __future__ import annotations


# 29-value curated enum of vulnerability classes (28 specific classes plus
# the ``OTHER`` escape hatch). Ordering is stable so the emitted CLI help
# text is deterministic across builds.
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
    "META",
    "HEALTH",
    "LOG-READ",
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
