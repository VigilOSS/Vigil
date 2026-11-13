"""Drift guard: references must carry the frontmatter the discovery pipeline keys on.

`vigil assess list-references` (agent/scripts/assess/commands/list_references.py)
finds and pairs references by parsing each file's YAML frontmatter — a `description`
and a `skill:` key. A reference that omits `skill:` is "orphaned": it never
appears under `vigil assess list-references --skill <name>`, so a threat hunter
who navigates by skill never discovers it. This test fails loudly when a new
reference ships without the keys (or with a `skill:` that does not resolve
to a real skill directory), so the orphaned-arjun.md class of bug cannot recur.

Scope: the WHOLE `agent/references/` tree, not just `tools/` — the same discovery
mechanism serves every subdirectory identically, so a reference orphaned in
`gf-patterns/` or `payloads/` is exactly as invisible as one orphaned in `tools/`.

See the "Add a reference" recipe in the root AGENTS.md.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
_SCRIPTS = _REPO / "agent" / "scripts"
_REFERENCES = _REPO / "agent" / "references"
_SKILLS = _REPO / "agent" / "skills"

# References with no matching skill pairing — either no skill in the current roster
# covers the content yet, or the reference is genuinely cross-cutting (operator-owned
# mechanics, or N-to-N across multiple roles/tracks by design) rather than owned by
# one skill. REMOVE an entry the moment a real pairing exists — this allowlist is a
# ledger of deliberate gaps, not a place to silently park new orphans.
_KNOWN_UNPAIRED = {
    # tools/ — no skill covers hash-cracking / hydra / mitmproxy-as-a-technique yet.
    "tools/cracking/hashcat.md",
    "tools/cracking/john.md",
    "tools/exploitation/hydra.md",
    "tools/proxy/mitmproxy.md",

    # gf-patterns/ — generic/meta buckets with no single owning skill: either
    # GF_BUCKET_TO_CLASS maps the bucket to None by design (a cross-cutting baseline
    # signal, not one class), or the file isn't a real classifier bucket at all.
    "gf-patterns/DRIFT.md",  # maintenance/decision-log doc about the classifier itself
    "gf-patterns/api.md",  # generic API-path baseline triage signal (bucket -> None)
    "gf-patterns/api-versioning.md",  # generic version-path signal (bucket -> None)
    "gf-patterns/interestingparams.md",  # generic credential/session-param signal (bucket -> None)
    "gf-patterns/interestingsubs.md",  # bucket=conceptual, a naming-convention doc, not a classifier bucket
    "gf-patterns/trust_surface.md",  # generic sensitive-lifecycle-path signal (bucket -> None)
    "gf-patterns/ssi.md",  # class ssi-injection has no skill declaring it yet

    # Root-level — genuinely N-to-N cross-cutting docs, not owned by one skill.
    "_template-engagement.md",  # per-engagement ROE template, operator-authored not skill-discovered
    "finding-fp-and-severity-gate.md",  # shared web+code verification gate, cited by 5+ skills
    "handoff-protocols.md",  # cross-role handoff mechanics, referenced only from operator docs

    # recon/ — shared calibration table across every recon-class skill, not one skill's.
    "recon/rate-calibration.md",

    # runtime-guides/ — operator-owned cross-phase/cross-track mechanics, not one
    # skill's procedure (dispatch templates, handoff schema, resource policy, etc.).
    "runtime-guides/auth-recovery.md",
    "runtime-guides/cdn-ip-blocking.md",
    "runtime-guides/code-runtime-proof.md",  # code operator trigger-loaded proof-work and web-integration mechanics
    "runtime-guides/command-history-auditing.md",
    "runtime-guides/dispatch-resource-policy.md",
    "runtime-guides/dispatch-template.md",
    "runtime-guides/handoff-schema.md",
    "runtime-guides/phase-verify-exploit.md",
    "runtime-guides/subagent-registry.md",
    "runtime-guides/va-root-cause-review.md",  # owner is a role file (vulnerability-analyst.md), not an agent/skills/ dir
    "runtime-guides/vuln-taxonomy.md",  # canonical cross-track vocabulary, N-to-N by design

    # tenants/ — the generic fallback scaffold has no single owning investigation
    # skill by design (unlike its AWS/GWS/M365/Okta/EDR/Network siblings).
    "tenants/_template-generic.md",
}


def _reference_files() -> list[Path]:
    return sorted(_REFERENCES.rglob("*.md"))


def _known_skill_names() -> set[str]:
    return {d.name for d in _SKILLS.iterdir() if (d / "SKILL.md").is_file()}


def test_reference_files_exist():
    assert _reference_files(), "no references found — path wrong?"


def test_every_reference_has_description():
    from assess.lib import frontmatter

    missing = [
        str(p.relative_to(_REFERENCES))
        for p in _reference_files()
        if not (frontmatter.parse(p).get("description") or "").strip()
    ]
    assert not missing, f"references missing a `description:` frontmatter key: {missing}"


def test_every_reference_is_skill_paired():
    from assess.lib import frontmatter

    orphans = []
    for p in _reference_files():
        rel = str(p.relative_to(_REFERENCES))
        if rel in _KNOWN_UNPAIRED:
            continue
        if not (frontmatter.parse(p).get("skill") or "").strip():
            orphans.append(rel)
    assert not orphans, (
        "references missing a `skill:` frontmatter key (so `list-references --skill` "
        f"never surfaces them): {orphans}. Add `skill: <name>`, or add to "
        "_KNOWN_UNPAIRED with a reason."
    )


def test_paired_skill_names_resolve_to_a_real_skill():
    from assess.lib import frontmatter

    known = _known_skill_names()
    bad: list[str] = []
    for p in _reference_files():
        skills = (frontmatter.parse(p).get("skill") or "").strip()
        for name in (s.strip() for s in skills.split(",") if s.strip()):
            if name not in known:
                bad.append(f"{p.relative_to(_REFERENCES)} -> '{name}'")
    assert not bad, f"references cite a non-existent skill: {bad}"


def test_known_unpaired_allowlist_is_not_stale():
    # If an allowlisted ref has since been paired, drop it from _KNOWN_UNPAIRED.
    from assess.lib import frontmatter

    stale = []
    for rel in _KNOWN_UNPAIRED:
        p = _REFERENCES / rel
        if p.is_file() and (frontmatter.parse(p).get("skill") or "").strip():
            stale.append(rel)
    assert not stale, f"these are paired now — remove from _KNOWN_UNPAIRED: {stale}"


def test_known_unpaired_allowlist_entries_exist():
    # Catch a typo'd/renamed path in the allowlist that no longer matches a real file
    # (silently making that entry meaningless while masking a real orphan elsewhere).
    missing = [rel for rel in _KNOWN_UNPAIRED if not (_REFERENCES / rel).is_file()]
    assert not missing, f"_KNOWN_UNPAIRED entries with no matching file: {missing}"
