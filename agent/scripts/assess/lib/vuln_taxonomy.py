"""Canonical vuln-class taxonomy — the single cross-track vocabulary.

This module is the ONE source of truth for vulnerability classes across the
web, code, and (eventually) blue tracks. It replaces four disjoint taxonomies
that drifted independently:

  * gf-buckets (``classify_buckets._BUCKETS``)        — web recon signal
  * the hand-maintained ``BUCKET_SKILLS`` dict        — bucket -> skill
  * ``surface_type`` (``surfaces.VALID_SURFACE_TYPES``) — web depth semantics
  * the code track's family lists (``code_analysis.SLOT_VULN_CLASSES`` /
    ``ROLE_CONTEXT_VULN_CLASSES``)                     — CWE / memory-safety

``vuln_class`` is the single canonical term. The
canonical class set below is the UNION of the web attack classes and the code
families, so the code track aligns BY INCLUSION — every string the code track
already validates against (``buffer-overflow``, ``web-app-auth``, …) is a
canonical class here, namespaced into a code-oriented family (``memory-safety``,
``crypto``, …). A drift test asserts ``code families ⊆ canonical classes`` so the
code track never has to fork the term and never false-fails.

Everything downstream DERIVES from this module:
  * ``classify_buckets.BUCKET_SKILLS`` is computed from skill frontmatter +
    ``GF_BUCKET_TO_CLASS`` (no more hand-edited dict).
  * the depth gate translates surfaces / techniques / gf signals
    into expected canonical classes via the maps below.
  * skills declare ``vuln_class:`` frontmatter drawn from ``VULN_CLASSES``.

Anti-staleness: this list is DATA, additive without touching
control flow — adding a framework/class is a one-line edit here. Drift tests in
``test_vuln_taxonomy.py`` fail CI when a skill, gf-bucket, surface_type, code
family, or technique references a class that is not declared here, so the rubric
cannot rot silently. The technique guard runs BOTH ways: a class that is neither
``--technique``-taggable nor listed in ``TECHNIQUE_EXEMPT_CLASSES`` fails CI, so
"record it as an attack_family" and "run it as a technique" cannot diverge.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

LAST_REVIEWED = "2026-09-17"


FAMILIES: dict[str, str] = {
    "access-control": "Authorization defects: object/function/tenant access not enforced.",
    "auth": "Authentication & session: bypass, token, federation, session, enumeration.",
    "injection": "Untrusted input reaches an interpreter/parser/sink.",
    "ssrf": "Server-side request forgery and forced redirects/fetches.",
    "file": "File handling: upload, inclusion, traversal.",
    "disclosure": "Information / secret / source / debug exposure.",
    "business-logic": "Workflow, state, race, and rate-limit abuse.",
    "client-side": "Browser-trust defects: XSS, CSRF, CORS, pollution.",
    "protocol": "HTTP/transport-layer defects: smuggling, headers, cache, ws.",
    "crypto": "Cryptographic misuse.",
    "memory-safety": "Native memory-safety (code track): overflow, UAF, type confusion.",
    "error-handling": "Robustness / fault handling (code track).",
    "ai-ml": "AI/ML-specific security (prompt injection, model abuse).",
    "infrastructure": "Build, container and deployment posture: runtime privilege, exposed services, build supply chain.",
}


VULN_CLASSES: dict[str, tuple[str, str]] = {
    "idor": ("access-control", "Insecure direct object reference (object-level authz)."),
    "bola": ("access-control", "Broken object-level authorization (API)."),
    "bfla": ("access-control", "Broken function-level authorization."),
    "path-authz": ("access-control", "Path/route-level authorization gaps."),
    "auth-bypass": ("auth", "Authentication bypass."),
    "jwt": ("auth", "JWT/token forgery, confusion, weak verification."),
    "oauth": ("auth", "OAuth/OIDC flow and grant abuse."),
    "saml": ("auth", "SAML assertion/signature abuse."),
    "session": ("auth", "Session fixation/management defects."),
    "user-enumeration": ("auth", "Account/user enumeration."),
    "web-app-auth": ("auth", "Web-app authentication weakness (code track)."),
    "sqli": ("injection", "SQL injection."),
    "nosqli": ("injection", "NoSQL injection."),
    "cmdi": ("injection", "OS command / code execution injection."),
    "ssti": ("injection", "Server-side template injection."),
    "xxe": ("injection", "XML external entity / XML injection."),
    "ssi-injection": ("injection", "Server-Side Includes (SSI) directive injection."),
    "ldap-injection": ("injection", "LDAP injection."),
    "xpath-injection": ("injection", "XPath injection."),
    "graphql-injection": ("injection", "GraphQL query/mutation abuse & injection."),
    "elasticsearch-injection": ("injection", "Elasticsearch/search-DSL injection."),
    "mass-assignment": ("injection", "Mass assignment / over-posting."),
    "crlf": ("injection", "CRLF / header injection."),
    "deserialization": ("injection", "Unsafe deserialization."),
    "csv-injection": ("injection", "CSV/spreadsheet formula (DDE) injection via exported data."),
    "injection": ("injection", "Generic injection (code-track coarse family)."),
    "web-app-injection": ("injection", "Web-app injection (code track)."),
    "ssrf": ("ssrf", "Server-side request forgery."),
    "open-redirect": ("ssrf", "Open redirect / forced navigation."),
    "file-upload": ("file", "Unrestricted/abusable file upload."),
    "lfi": ("file", "Local file inclusion."),
    "rfi": ("file", "Remote file inclusion."),
    "path-traversal": ("file", "Path/directory traversal."),
    "img-traversal": ("file", "Image/asset path traversal variant."),
    "info-disclosure": ("disclosure", "Sensitive information disclosure."),
    "secrets-exposure": ("disclosure", "Exposed secrets/keys/credentials."),
    "debug-exposure": ("disclosure", "Debug/admin/internal endpoint exposure."),
    "source-disclosure": ("disclosure", "Source/sourcemap/backup exposure."),
    "web-app-data-exposure": ("disclosure", "Web-app data over-exposure (code track)."),
    "business-logic": ("business-logic", "Business-logic / workflow abuse."),
    "race-condition": ("business-logic", "Race condition / TOCTOU."),
    "rate-limit": ("business-logic", "Missing/weak rate limiting."),
    "algorithmic-dos": ("business-logic", "Algorithmic complexity DoS (code track)."),
    "xss": ("client-side", "Cross-site scripting."),
    "csrf": ("client-side", "Cross-site request forgery."),
    "cors": ("client-side", "CORS misconfiguration."),
    "prototype-pollution": ("client-side", "Prototype pollution."),
    "clickjacking": ("client-side", "Clickjacking / UI redress via frame embedding."),
    "request-smuggling": ("protocol", "HTTP request smuggling/desync."),
    "host-header-injection": ("protocol", "Host-header injection."),
    "cache-poisoning": ("protocol", "Web cache poisoning/deception."),
    "websocket": ("protocol", "WebSocket security defects."),
    "crypto-misuse": ("crypto", "Cryptographic misuse (code track)."),
    "buffer-overflow": ("memory-safety", "Stack/heap buffer overflow."),
    "integer-overflow": ("memory-safety", "Integer overflow/underflow."),
    "format-string": ("memory-safety", "Format-string vulnerability."),
    "null-dereference": ("memory-safety", "Null-pointer dereference."),
    "use-after-free": ("memory-safety", "Use-after-free."),
    "uninitialized-memory": ("memory-safety", "Uninitialized memory use."),
    "type-confusion": ("memory-safety", "Type confusion."),
    "error-handling": ("error-handling", "Error/exception handling defects (code track)."),
    "ai-ml-security": ("ai-ml", "AI/ML security (model/data/inference abuse, code track)."),
    "prompt-injection": ("ai-ml", "LLM prompt injection."),
    # infrastructure (2026-09): the three classes `treesitter_index.py`'s
    # Dockerfile / shell / HTML / CSS extractors emit. They had no canonical home
    # because no family was about infrastructure, and every candidate remap
    # misroutes on the FAMILIES definitions above: `injection` requires untrusted
    # input reaching an interpreter (an `ADD https://…` has none), `rfi` means
    # request-time remote inclusion (a build-time fetch has no request),
    # `access-control` presumes a principal and a routed function (a Dockerfile
    # with no `USER` has neither), and `debug-exposure`/`info-disclosure` mean an
    # HTTP endpoint (`EXPOSE 5432` is a declared port). The FAMILY is the fix; a
    # bare class forced into `injection` or `disclosure` would reproduce the
    # misroute one level up.
    "privilege-escalation": ("infrastructure", "Container/host privilege escalation: root runtime, over-permissive modes, build-time sudo."),
    "network-exposure": ("infrastructure", "Service/port exposed beyond its intended network boundary."),
    "supply-chain": ("infrastructure", "Build/deploy supply chain: remote or unpinned code and assets executed as trusted."),
}


GF_BUCKET_TO_CLASS: dict[str, str | None] = {
    "rce": "cmdi",
    "graphql": "graphql-injection",
    "llm_api": "prompt-injection",
    "ssrf": "ssrf",
    "cloud_metadata": "ssrf",
    "sqli": "sqli",
    "nosqli": "nosqli",
    "prototype-pollution": "prototype-pollution",
    "lfi": "lfi",
    "auth": "auth-bypass",
    "deserialization": "deserialization",
    "dotnet_handler": "deserialization",
    "xxe": "xxe",
    "secret_vault": "secrets-exposure",
    "img_traversal": "img-traversal",
    "idp_admin": "auth-bypass",
    "wordpress": "user-enumeration",
    "cms_db_admin": "auth-bypass",
    "trust_surface": None,
    "idor": "idor",
    "servicenow": "idor",
    "privileged_action": "bfla",
    "mass-assignment": "mass-assignment",
    "devops_console": "debug-exposure",
    "ssi": "ssi-injection",
    "oauth-oidc": "oauth",
    "sso": "saml",
    "upload_fields": "file-upload",
    "debug_logic": "debug-exposure",
    "websocket": "websocket",
    "webhook": "ssrf",
    "jwt": "jwt",
    "redirect": "open-redirect",
    "ssti": "ssti",
    "cors": "cors",
    # `api` / `api-versioning` are family-level path/enumeration signals with no
    # single attack class (like `trust_surface`); the `api_spec` floor label has
    # no _BUCKETS entry and is mapped only so any floor-label drift check passes.
    "api-versioning": None,
    "object-storage": "info-disclosure",
    "api": None,
    "api_spec": None,
    "xss": "xss",
    "interestingparams": None,
    "interestingext": "secrets-exposure",
}


SURFACE_TYPE_TO_CLASSES: dict[str, tuple[str, ...]] = {
    "auth_entry": ("auth-bypass", "jwt", "oauth", "saml", "session"),
    "account_recovery": ("auth-bypass", "user-enumeration", "session"),
    "object_reference": ("idor", "bola", "bfla"),
    "privileged_write": ("bfla", "path-authz", "mass-assignment"),
    "file_handling": ("file-upload", "lfi", "path-traversal"),
    "dynamic_render": ("xss", "ssti", "ssi-injection"),
    "api_documentation": ("bola", "bfla", "mass-assignment", "graphql-injection"),
    "workflow_token": ("business-logic", "race-condition"),
    "misconfiguration": ("info-disclosure", "debug-exposure"),
    "informational": ("info-disclosure",),
}


TECHNIQUE_TO_CLASS: dict[str, str | None] = {
    "SSRF": "ssrf",
    "XSS": "xss",
    "XXE": "xxe",
    "SQLI": "sqli",
    "NOSQLI": "nosqli",
    "LDAP-INJECTION": "ldap-injection",
    "XPATH-INJECTION": "xpath-injection",
    "ELASTICSEARCH-INJECTION": "elasticsearch-injection",
    "SSTI": "ssti",
    "SSI-INJECTION": "ssi-injection",
    "RCE": "cmdi",
    "CMDI": "cmdi",
    "LFI": "lfi",
    "RFI": "rfi",
    "PATH-TRAVERSAL": "path-traversal",
    "CRLF": "crlf",
    "CSV-INJECTION": "csv-injection",
    "DESERIALIZATION": "deserialization",
    "PROTOTYPE-POLLUTION": "prototype-pollution",
    "MASS-ASSIGNMENT": "mass-assignment",
    "IDOR": "idor",
    "BOLA": "bola",
    "BFLA": "bfla",
    "PATH-AUTHZ": "path-authz",
    "AUTH": "auth-bypass",
    "JWT": "jwt",
    "OAUTH": "oauth",
    "SAML": "saml",
    "SESSION": "session",
    "USER-ENUMERATION": "user-enumeration",
    "OPEN-REDIRECT": "open-redirect",
    "CSRF": "csrf",
    "CORS": "cors",
    "CLICKJACKING": "clickjacking",
    "REQUEST-SMUGGLING": "request-smuggling",
    "HOST-HEADER": "host-header-injection",
    "CACHE-POISONING": "cache-poisoning",
    "WEBSOCKET": "websocket",
    "GRAPHQL": "graphql-injection",
    "FILE-UPLOAD": "file-upload",
    "BUSINESS-LOGIC": "business-logic",
    "RACE-CONDITION": "race-condition",
    "RATE-LIMIT": "rate-limit",
    "ALGORITHMIC-DOS": "algorithmic-dos",
    "CRYPTO-MISUSE": "crypto-misuse",
    "INFO-DISCLOSURE": "info-disclosure",
    "SECRETS-EXPOSURE": "secrets-exposure",
    "SOURCE-DISCLOSURE": "source-disclosure",
    "DEBUG-EXPOSURE": "debug-exposure",
    "PROMPT-INJECTION": "prompt-injection",
    "AI-ML-SECURITY": "ai-ml-security",
    "NETWORK-EXPOSURE": "network-exposure",
    "RECON": None,
    "DISCOVERY": None,
    "PARAM-DISCOVERY": None,
    "FUZZ": None,
    "OSINT": None,
    "CVE-VALIDATION": None,
    "EXPLOIT-CHAIN": None,
    "META": None,
    "HEALTH": None,
    "LOG-READ": None,
    "OTHER": None,
}

# Canonical classes that intentionally have NO ``kali exec --technique`` tag.
#
# The reverse drift guard in ``test_vuln_taxonomy.py`` requires every OTHER
# class in ``VULN_CLASSES`` to be reachable as a ``TECHNIQUE_ENUM`` value, so a
# newly-added class cannot become a legal ``record-probe --attack-family`` while
# ``kali exec --technique <X>`` still hard-fails on it — the two surfaces
# silently disagreeing is the drift this set exists to prevent. An entry here is
# a DECISION with a stated reason, never silence: if a specialist CAN run a
# network probe for the class, it belongs in ``TECHNIQUE_ENUM`` instead.
TECHNIQUE_EXEMPT_CLASSES: frozenset[str] = frozenset(
    {
        "buffer-overflow",  # memory safety: proven by a crashing input in code/fuzz, not by a network probe
        "integer-overflow",  # memory safety: an arithmetic defect read out of source, not probed over HTTP
        "format-string",  # memory safety: a format-specifier sink found in source, not a network technique
        "null-dereference",  # memory safety: a robustness/crash defect with no attacker-input probe to tag
        "use-after-free",  # memory safety: an object-lifetime defect proven in code or under a fuzz harness
        "uninitialized-memory",  # memory safety: needs instrumented (ASan/MSan) execution, not a remote probe
        "type-confusion",  # memory safety: a type-punning defect found in source, not a network technique
        "injection",  # coarse code-track rollup (code_analysis slot families); probe the specific class
        "web-app-injection",  # coarse code-track rollup of the injection classes; tag the specific one
        "web-app-auth",  # coarse code-track rollup of the auth classes; tag AUTH/JWT/OAUTH/SAML/SESSION
        "web-app-data-exposure",  # coarse code-track rollup; tag INFO-DISCLOSURE/SECRETS-EXPOSURE instead
        "error-handling",  # code-track robustness; a black-box error page is INFO-DISCLOSURE/DEBUG-EXPOSURE
        "img-traversal",  # gf-bucket refinement of path-traversal; the probe technique IS PATH-TRAVERSAL
        "privilege-escalation",  # container/build hardening read out of a Dockerfile or shell script; a real breakout is tagged EXPLOIT-CHAIN
        "supply-chain",  # build-time provenance read out of a Dockerfile/CI config; no request-time probe carries it
    }
)


def all_classes() -> frozenset[str]:
    """The canonical vuln-class vocabulary."""
    return frozenset(VULN_CLASSES)


def is_valid_class(name: str) -> bool:
    return name in VULN_CLASSES


def family_of(name: str) -> str | None:
    entry = VULN_CLASSES.get(name)
    return entry[0] if entry else None


def normalize_class(name: str) -> str:
    """Canonicalize a class token (lowercase, hyphen-separated)."""
    if not name:
        return name
    return name.strip().lower().replace("_", "-").replace(" ", "-")


def parse_vuln_class_field(value: Any) -> list[str]:
    """Parse a skill/reference ``vuln_class`` frontmatter value into a list.

    Accepts a comma-separated string or a YAML list; normalizes each entry.
    Unknown entries are returned as-is (the drift test flags them) — never
    silently dropped.
    """
    items: list[str] = []
    if isinstance(value, str):
        items = [v for v in (s.strip() for s in value.split(",")) if v]
    elif isinstance(value, (list, tuple)):
        items = [str(v).strip() for v in value if str(v).strip()]
    return [normalize_class(v) for v in items]


def _default_skills_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "skills"


def load_skill_vuln_classes(skills_dir: Path | None = None) -> dict[str, list[str]]:
    """Map skill name -> declared canonical vuln classes, read from frontmatter.

    Only skills that declare a ``vuln_class:`` field are included (supporting /
    procedural skills omit it). The frontmatter is flat (a comma-separated
    string); parsing is tolerant and the drift test enforces that every declared
    class is canonical.
    """
    from . import frontmatter

    root = skills_dir or _default_skills_dir()
    result: dict[str, list[str]] = {}
    if not root.is_dir():
        return result
    for skill_md in sorted(root.glob("*/SKILL.md")):
        meta = frontmatter.parse(skill_md)
        raw = meta.get("vuln_class")
        if not raw:
            continue
        classes = parse_vuln_class_field(raw)
        if classes:
            result[skill_md.parent.name] = classes
    return result


def build_class_to_skills(skills_dir: Path | None = None) -> dict[str, tuple[str, ...]]:
    """Inverse index: canonical class -> skills that declare it (sorted)."""
    skill_classes = load_skill_vuln_classes(skills_dir)
    index: dict[str, list[str]] = {}
    for skill, classes in skill_classes.items():
        for cls in classes:
            index.setdefault(cls, []).append(skill)
    return {cls: tuple(sorted(set(skills))) for cls, skills in index.items()}


def derive_bucket_skills(skills_dir: Path | None = None) -> dict[str, tuple[str, ...]]:
    """Derive the gf-bucket -> skills mapping from the taxonomy + frontmatter.

    Replaces the hand-maintained ``classify_buckets.BUCKET_SKILLS``. A bucket
    maps to the skills that declare the bucket's canonical class. Generic
    buckets (``GF_BUCKET_TO_CLASS[bucket] is None``) map to no single skill, by
    design — they are family-level signals, not a one-skill dispatch.
    """
    class_to_skills = build_class_to_skills(skills_dir)
    result: dict[str, tuple[str, ...]] = {}
    for bucket, cls in GF_BUCKET_TO_CLASS.items():
        if cls is None:
            continue
        skills = class_to_skills.get(cls, ())
        if skills:
            result[bucket] = skills
    return result


__all__ = [
    "LAST_REVIEWED",
    "FAMILIES",
    "VULN_CLASSES",
    "GF_BUCKET_TO_CLASS",
    "SURFACE_TYPE_TO_CLASSES",
    "TECHNIQUE_TO_CLASS",
    "TECHNIQUE_EXEMPT_CLASSES",
    "all_classes",
    "is_valid_class",
    "family_of",
    "normalize_class",
    "parse_vuln_class_field",
    "load_skill_vuln_classes",
    "build_class_to_skills",
    "derive_bucket_skills",
]
