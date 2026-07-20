"""Drift tests for the canonical vulnerability-class taxonomy.

`agent/scripts/assess/lib/vuln_taxonomy.py` is the ONE source of truth for the
cross-track vuln vocabulary. Everything else — skill `vuln_class:` frontmatter,
the gf-bucket signal table, `surface_type`, the `--technique` enum, and the code
track's family lists — must reference only canonical classes, and every canonical
class must reach a real skill (modulo a tiny, justified allowlist). These tests
fail CI the moment any side drifts (a typo'd class, an unmapped bucket, a new
skill that forgot its `vuln_class:`), which is exactly what keeps the original
24-skill blind spot from silently reopening.

Host-side modules (`assess.lib.*`) are imported by inserting the agent scripts
root on `sys.path`, mirroring `test_check_scope_coverage.py`. The code track
lives in the backend (`app.services.code_analysis`), imported normally.
"""
from __future__ import annotations

import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS_ROOT = _REPO_ROOT / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from assess.lib import audit_enums, classify_buckets, surfaces, vuln_taxonomy  # noqa: E402
from app.services import code_analysis  # noqa: E402


KNOWN_SKILLLESS_CLASSES: frozenset[str] = frozenset(
    {
        "ldap-injection",
        "path-authz",
        # Added (vuln-taxonomy-audit 2026-07): real, WSTG-documented classes
        # with no reliable gf-style URL/param signal (so no bucket) and no
        # existing skill whose scope honestly covers them yet — allowlisted
        # rather than forcing an unbacked skill mapping, mirroring
        # `ldap-injection`/`path-authz` above. `ssi-injection` DOES have a
        # bucket (`ssi`, extension-based) but still has no dedicated skill.
        "xpath-injection",
        "ssi-injection",
        "clickjacking",
        "csv-injection",
    }
)


def test_every_skill_vuln_class_is_canonical():
    """Forward consistency: a typo'd or un-canonical class in any skill's
    `vuln_class:` frontmatter FAILS CI."""
    canonical = vuln_taxonomy.all_classes()
    skill_classes = vuln_taxonomy.load_skill_vuln_classes()
    assert skill_classes, "no skill declares vuln_class — frontmatter loader is broken"
    offenders: list[str] = []
    for skill, classes in sorted(skill_classes.items()):
        for cls in classes:
            if cls not in canonical:
                offenders.append(f"{skill} -> {cls}")
    assert not offenders, (
        "Skills declare non-canonical vuln_class values (add them to "
        "VULN_CLASSES or fix the frontmatter):\n  " + "\n  ".join(offenders)
    )


def test_code_families_subset_of_canonical():
    """Code alignment-by-inclusion: every class the code track validates against
    (`SLOT_VULN_CLASSES` + `ROLE_CONTEXT_VULN_CLASSES`) is canonical."""
    canonical = vuln_taxonomy.all_classes()
    code_classes: set[str] = set()
    for groups in code_analysis.SLOT_VULN_CLASSES.values():
        for families in groups.values():
            code_classes.update(families)
    for _keywords, groups in code_analysis.ROLE_CONTEXT_VULN_CLASSES:
        for families in groups.values():
            code_classes.update(families)
    assert code_classes, "code track family lists are empty — wrong module?"
    non_canonical = sorted(code_classes - canonical)
    assert not non_canonical, (
        "code_analysis declares classes not in VULN_CLASSES (the code track "
        "must align by inclusion):\n  " + "\n  ".join(non_canonical)
    )


def test_every_technique_enum_value_is_mapped_and_canonical():
    """Every TECHNIQUE_ENUM value is a key in TECHNIQUE_TO_CLASS; every mapped
    (non-None) class is canonical."""
    canonical = vuln_taxonomy.all_classes()
    mapping = vuln_taxonomy.TECHNIQUE_TO_CLASS
    unmapped = [t for t in audit_enums.TECHNIQUE_ENUM if t not in mapping]
    assert not unmapped, (
        "TECHNIQUE_ENUM values missing from TECHNIQUE_TO_CLASS:\n  "
        + "\n  ".join(unmapped)
    )
    bad_class = sorted(
        cls for cls in mapping.values() if cls is not None and cls not in canonical
    )
    assert not bad_class, (
        "TECHNIQUE_TO_CLASS maps to non-canonical classes:\n  " + "\n  ".join(bad_class)
    )


def test_every_surface_type_is_mapped_and_canonical():
    """Every surface_type is a key in SURFACE_TYPE_TO_CLASSES; every mapped class
    is canonical."""
    canonical = vuln_taxonomy.all_classes()
    mapping = vuln_taxonomy.SURFACE_TYPE_TO_CLASSES
    unmapped = sorted(st for st in surfaces.VALID_SURFACE_TYPES if st not in mapping)
    assert not unmapped, (
        "surface_types missing from SURFACE_TYPE_TO_CLASSES:\n  " + "\n  ".join(unmapped)
    )
    bad: list[str] = []
    for st, classes in mapping.items():
        for cls in classes:
            if cls not in canonical:
                bad.append(f"{st} -> {cls}")
    assert not bad, (
        "SURFACE_TYPE_TO_CLASSES maps to non-canonical classes:\n  " + "\n  ".join(bad)
    )


def test_every_gf_bucket_is_mapped_and_canonical():
    """Every gf-bucket in classify_buckets._BUCKETS is a key in
    GF_BUCKET_TO_CLASS; every non-None mapped class is canonical."""
    canonical = vuln_taxonomy.all_classes()
    mapping = vuln_taxonomy.GF_BUCKET_TO_CLASS
    bucket_names = [name for name, _w, _k, _p in classify_buckets._BUCKETS]
    unmapped = sorted(b for b in bucket_names if b not in mapping)
    assert not unmapped, (
        "gf-buckets missing from GF_BUCKET_TO_CLASS:\n  " + "\n  ".join(unmapped)
    )
    bad = sorted(
        cls for cls in mapping.values() if cls is not None and cls not in canonical
    )
    assert not bad, (
        "GF_BUCKET_TO_CLASS maps to non-canonical classes:\n  " + "\n  ".join(bad)
    )


def test_derive_bucket_skills_reproduces_legacy_eleven():
    """`derive_bucket_skills()` reproduces the legacy hand-maintained
    BUCKET_SKILLS for the 11 previously-mapped buckets EXACTLY (no regression).
    Tuples are sorted by `build_class_to_skills`."""
    expected = {
        "idor": ("idor-testing", "split-brain-idor"),
        "sqli": ("sqli-testing",),
        "ssrf": ("ssrf-testing",),
        "xss": ("xss-testing",),
        "ssti": ("ssti-testing",),
        "lfi": ("file-inclusion",),
        "img_traversal": ("file-inclusion",),
        "rce": ("command-injection",),
        "redirect": ("open-redirect-testing",),
        "cors": ("cors-testing",),
        "upload_fields": ("file-upload-testing",),
    }
    derived = vuln_taxonomy.derive_bucket_skills()
    for bucket, skills in expected.items():
        assert derived.get(bucket) == skills, (
            f"derive_bucket_skills()[{bucket!r}] = {derived.get(bucket)!r}, "
            f"expected {skills!r}"
        )


def test_eleven_web_exclusive_classes_stay_web_skill_only():
    """The 11 classes that reproduce the legacy gf-buckets must be declared
    ONLY by their canonical web skills — never by a code skill (so the code
    track aligns by inclusion without claiming a web-exclusive class)."""
    class_to_skills = vuln_taxonomy.build_class_to_skills()
    expected = {
        "idor": ("idor-testing", "split-brain-idor"),
        "sqli": ("sqli-testing",),
        "ssrf": ("ssrf-testing",),
        "xss": ("xss-testing",),
        "ssti": ("ssti-testing",),
        "lfi": ("file-inclusion",),
        "img-traversal": ("file-inclusion",),
        "cmdi": ("command-injection",),
        "open-redirect": ("open-redirect-testing",),
        "cors": ("cors-testing",),
        "file-upload": ("file-upload-testing",),
    }
    for cls, skills in expected.items():
        assert class_to_skills.get(cls) == skills, (
            f"web-exclusive class {cls!r} is declared by {class_to_skills.get(cls)!r}, "
            f"expected exactly {skills!r}"
        )


def test_every_canonical_class_maps_to_a_skill_or_is_allowlisted():
    """Completeness: every canonical class reaches ≥1 skill via
    `build_class_to_skills()`, except classes in the documented
    KNOWN_SKILLLESS_CLASSES allowlist. A new canonical class that wires to no
    skill (and isn't allowlisted) FAILS — closing the blind spot for good."""
    canonical = vuln_taxonomy.all_classes()
    covered = set(vuln_taxonomy.build_class_to_skills())
    uncovered = sorted((canonical - covered) - KNOWN_SKILLLESS_CLASSES)
    assert not uncovered, (
        "Canonical classes with no declaring skill and no allowlist entry "
        "(map one to a skill, or add it to KNOWN_SKILLLESS_CLASSES with a "
        "justification):\n  " + "\n  ".join(uncovered)
    )


def test_skilless_allowlist_has_no_stale_entries():
    """The allowlist must not rot: every entry must be (1) a real canonical
    class and (2) genuinely skill-less. If a class in the allowlist later gains
    a declaring skill, it must leave the allowlist so it stays an honest ledger."""
    canonical = vuln_taxonomy.all_classes()
    covered = set(vuln_taxonomy.build_class_to_skills())
    stale: list[str] = []
    for cls in sorted(KNOWN_SKILLLESS_CLASSES):
        if cls not in canonical:
            stale.append(f"{cls} (not a canonical class)")
        elif cls in covered:
            stale.append(f"{cls} (now has a skill — drop from allowlist)")
    assert not stale, "Stale KNOWN_SKILLLESS_CLASSES entries:\n  " + "\n  ".join(stale)
