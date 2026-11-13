---
description: "Bugcrowd VRT offline lookup: name the exact VRT leaf + its default P1-P5 priority and suggested CVSS (data in bugcrowd-vrt.tsv). Holds the leaf-selection judgment: IDOR Iterable-vs-Complex fork, harvestable-identifier exception, BFLA->privilege-escalation, priority-vs-CVSS reconciliation."
skill: report-generation
category: Disclosure & Reporting Formats
---

# Bugcrowd VRT — offline lookup

Companion to `agent/references/reporting/bugcrowd-vrt.tsv`, the leaves of the official
[vulnerability-rating-taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy) flattened
by `tools/flatten_vrt.py` (its header line names the VRT release). Columns:
`priority⇥vrt_path⇥cvss_v3` — the leaf's default Bugcrowd priority (`P1`–`P5`), the full category path
down to the leaf, and the suggested base vector where the taxonomy ships one (many leaves are
priority-only).

```bash
grep -i idor agent/references/reporting/bugcrowd-vrt.tsv
grep -i "privilege escalation" agent/references/reporting/bugcrowd-vrt.tsv
```

The table gives candidates, not the decision. The leaf is what sets severity, so name the leaf, never
the category or subcategory above it; stopping at "IDOR" lets the triager pick the variant.

## The IDOR fork — Iterable vs Complex identifier

Broken Access Control (BAC) → Insecure Direct Object References (IDOR) has five leaves, and the
priority swings four steps on two axes:

| Leaf | Priority |
|---|---|
| Modify/View Sensitive Information (**Iterable** Object Identifiers) | **P1** |
| Modify Sensitive Information (**Iterable** Object Identifiers) | **P2** |
| View Sensitive Information (**Iterable** Object Identifiers) | **P3** |
| Modify/View Sensitive Information (**Complex** Object Identifiers GUID/UUID) | **P4** |
| View Non-Sensitive Information | **P5** |

Action: Modify+View (P1) > Modify (P2) > View-Sensitive (P3) > View-Non-Sensitive (P5). Identifier: an
iterable ID (integer, username, sequential) is the high branch; a random GUID/UUID collapses to P4
because it cannot be mass-enumerated.

**The harvest exception.** A GUID/UUID is effectively iterable when another primitive hands it to the
attacker — a by-username lookup that returns the target's UUID, or an ordinary-use URL that exposes
it. With that harvest chain demonstrated, claim the Iterable leaf and state the chain in the report,
or the triager defaults to P4 on "it's a UUID". Without a demonstrated harvest path, a UUID-keyed IDOR
stays P4; "UUIDs are enumerable in theory" is not an argument.

## Privilege Escalation for function-level access (BFLA)

BAC → Privilege Escalation is `varies` in the VRT: no fixed baseline, so the CVSS you supply carries
the severity. There is no dedicated BFLA leaf; when a caller reaches a *function* they are not
entitled to (not merely a foreign object), Privilege Escalation is the honest home. Choosing it for
one finding in an IDOR cluster also avoids the reflexive "merge all these IDORs" close (the
cross-finding pass at the start of `agent/phases/phase-8-report.md` step 8).

## CVSS vs VRT priority

The leaf default and your CVSS can disagree, in either direction. Claiming above a leaf's default is
allowed when the CVSS justifies it (an `S:C` scope change pushing a P3 View-IDOR to P2); a leaf whose
default sits above the computed band (access control at P2 with a Medium vector) is justified by
naming the leaf, never by inflating the vector. Either way, state the reconciliation in one sentence
in the body ("I rate this above the VRT default because <CVSS driver>"), typically in Evidence or
Impact. The `VRT:` line itself carries only the taxonomy path, because it is pasted verbatim into the
selector. An unexplained gap reads as an error and invites a downgrade to the leaf default.
