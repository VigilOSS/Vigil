"""Shared intel type metadata for record-intel and contract helpers."""
from __future__ import annotations


# Mapping: CLI type -> (schema file, endpoint-plural segment).
# Endpoint-plural is appended to ``/engagements/{key}/intel/``.
INTEL_TYPES: dict[str, tuple[str, str]] = {
    "tech-component": ("intel-tech-component.schema.json", "tech-components"),
    "person": ("intel-person.schema.json", "people"),
    "email": ("intel-email.schema.json", "emails"),
    "domain": ("intel-domain.schema.json", "domains"),
    "cve": ("intel-cve.schema.json", "cves"),
    "dns-record": ("intel-dns-record.schema.json", "dns-records"),
    "social-profile": ("intel-social-profile.schema.json", "social-profiles"),
    "breach-record": ("intel-breach-record.schema.json", "breach-records"),
    "org-fact": ("intel-org-fact.schema.json", "org-facts"),
    "note": ("intel-note.schema.json", "notes"),
}


__all__ = ["INTEL_TYPES"]
