---
description: "Bugcrowd VRT offline lookup: name the exact VRT leaf + its default P1-P5 priority and suggested CVSS (data in bugcrowd-vrt.tsv). Holds the leaf-selection judgment: IDOR Iterable-vs-Complex fork, harvestable-identifier exception, BFLA->privilege-escalation, priority-vs-CVSS reconciliation."
skill: report-generation
category: Disclosure & Reporting Formats
---

# Bugcrowd VRT — offline lookup

Companion to `agent/references/reporting/bugcrowd-vrt.tsv` — 438 leaves flattened from the
official [vulnerability-rating-taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy).
The TSV columns are:

`priority⇥vrt_path⇥cvss_v3`

- **priority** — the VRT's *default* Bugcrowd priority (`P1`–`P5`).
- **vrt_path** — the full category path down to the leaf (e.g. `Broken Access Control (BAC) >
  Insecure Direct Object References (IDOR) > View Sensitive Information(Iterable Object
  Identifiers)`).
- **cvss_v3** — the VRT's suggested base vector where the taxonomy ships one; many leaves ship
  none and are priority-only.

## How to grep it

```bash
grep -i idor agent/references/reporting/bugcrowd-vrt.tsv
grep -i "privilege escalation" agent/references/reporting/bugcrowd-vrt.tsv
```

Grep the bug class or the category head, then read down the matched leaves before picking one —
the table gives you the candidates, not the decision.

## How to pick the *exact* leaf — this is what actually sets severity

The single biggest severity mistake is stopping at the subcategory (e.g. "IDOR") and letting the
triager pick the variant. **Always name the leaf**, not the category or subcategory it lives
under.

### The IDOR severity fork — Iterable vs Complex identifier

Broken Access Control (BAC) → Insecure Direct Object References (IDOR) has **five** leaves, and
the priority swings 4 whole steps on two axes:

| Leaf | Priority |
|---|---|
| Modify/View Sensitive Information (**Iterable** Object Identifiers) | **P1** |
| Modify Sensitive Information (**Iterable** Object Identifiers) | **P2** |
| View Sensitive Information (**Iterable** Object Identifiers) | **P3** |
| Modify/View Sensitive Information (**Complex** Object Identifiers GUID/UUID) | **P4** |
| View Non-Sensitive Information | **P5** |

Axis 1 — **action**: Modify+View (P1) > Modify (P2) > View-Sensitive (P3) > View-Non-Sensitive
(P5).
Axis 2 — **identifier type**: an **iterable** ID (integer, username, sequential) is the
high-severity branch; a **complex GUID/UUID** collapses the whole thing to **P4** — because a
random UUID can't be mass-enumerated.

> **The harvest exception.** A GUID/UUID that looks "complex/P4" is effectively **iterable** if
> another primitive *hands it to you* — e.g. a by-username lookup that returns the target's UUID.
> When you have that harvest chain, argue the identifier is enumerable-in-practice and claim the
> Iterable leaf (P1/P2/P3), not the P4 GUID leaf. State the chain explicitly in the report or the
> triager will default to P4 on "it's a UUID."

A UUID-keyed IDOR defaults **P4** unless you make and state that harvest argument — do not claim
P1–P3 on a bare "UUIDs are technically enumerable in theory" without a demonstrated harvest path.

### Privilege Escalation / function-level (BFLA)

BAC → **Privilege Escalation** is `varies` in the VRT — no fixed baseline; the CVSS you supply
carries the severity. The VRT has **no dedicated BFLA leaf** — when a caller reaches a *function*
they're not entitled to (not merely a foreign *object*), Privilege Escalation is the honest home,
not a forced fit into IDOR. Bonus: choosing it (over IDOR) for one finding in an IDOR cluster
avoids the reflexive "merge all these IDORs into one" triage close (see
`agent/rules/reporting.md` Rule 18's cross-finding dedup pass).

### CVSS vs VRT priority — reconcile before you submit

The VRT default and your CVSS-derived priority can disagree. That's allowed — you can claim
**above** a leaf's default when your CVSS justifies it (e.g. an `S:C` scope-change pushing a P3
View-IDOR up to P2). But do it **knowingly**: name the leaf, then say "I rate this above the VRT
default because \<CVSS driver\>" in one line. An unexplained gap reads as an error and invites a
downgrade to the leaf default — the reconciliation line is what separates a deliberate override
from a mistake.

## The rule in one sentence

Grep the TSV for candidate leaves, read the full leaf name (not just the category), pick the one
whose action + identifier-type actually matches the proof, and if your claimed priority exceeds
that leaf's default, say why in the submission's VRT line or a one-line note.
