# Bugcrowd VRT — quick lookup

Companion to `bugcrowd-vrt-lookup.csv` (flattened from the official
[vulnerability-rating-taxonomy](https://github.com/bugcrowd/vulnerability-rating-taxonomy),
release **2026-06-24**, 438 leaves). The CSV columns are:

`priority | category | subcategory | variant | vrt_path | id_path | cvss_v3`

- **priority** — the VRT *default* Bugcrowd priority (`P1`–`P5`, or `varies` when the
  leaf has no fixed baseline and the triager sets it from your CVSS).
- **cvss_v3** — the VRT's suggested base vector where the taxonomy ships one (many
  leaves ship none; those are priority-only).

Regenerate: `python3 tools/flatten_vrt.py` after re-pulling the two upstream JSON files
(`vulnerability-rating-taxonomy.json` + `mappings/cvss_v3/cvss_v3.json`).

## How to pick the *exact* leaf (this is what actually sets severity)

The single biggest severity mistake is stopping at the subcategory
(e.g. "IDOR") and letting the triager pick the variant. **Always name the leaf.**

### The IDOR severity fork — Iterable vs Complex identifier

Broken Access Control (BAC) → Insecure Direct Object References (IDOR) has **five**
leaves, and the priority swings 4 whole steps on two axes:

| Leaf | Priority |
|---|---|
| Modify/View Sensitive Information (**Iterable** Object Identifiers) | **P1** |
| Modify Sensitive Information (**Iterable** Object Identifiers) | **P2** |
| View Sensitive Information (**Iterable** Object Identifiers) | **P3** |
| Modify/View Sensitive Information (**Complex** Object Identifiers GUID/UUID) | **P4** |
| View Non-Sensitive Information | **P5** |

Axis 1 — **action**: Modify+View (P1) > Modify (P2) > View-Sensitive (P3) > View-Non-Sensitive (P5).
Axis 2 — **identifier type**: an **iterable** ID (integer, username, sequential) is the
high-severity branch; a **complex GUID/UUID** collapses the whole thing to **P4** — because a
random UUID can't be mass-enumerated.

> **The harvest exception.** A GUID/UUID that looks "complex/P4" is effectively **iterable**
> if another primitive *hands it to you* — e.g. a by-username lookup that returns the target's
> UUID. When you have that harvest chain, argue the identifier is enumerable-in-practice and
> claim the Iterable leaf (P1/P2/P3), not the P4 GUID leaf. State the chain explicitly in the
> report or the triager will default to P4 on "it's a UUID."

### Privilege Escalation / function-level (BFLA)

BAC → **Privilege Escalation** is **`varies`** — no fixed baseline; the CVSS you supply
carries the severity. The VRT has **no dedicated BFLA leaf**; when a caller reaches a
*function* they're not entitled to (not merely a foreign *object*), Privilege Escalation is
the honest home. Bonus: choosing it (over IDOR) for one finding in an IDOR cluster avoids the
reflexive "merge all these IDORs into one" triage close.

### CVSS vs VRT priority — reconcile before you submit

The VRT default and your CVSS-derived priority can disagree. That's allowed — you can claim
**above** a leaf's default when your CVSS justifies it (e.g. an `S:C` scope-change pushing a
P3 View-IDOR up to P2). But do it **knowingly**: name the leaf, then say "I rate this above the
VRT default because <CVSS driver>." An unexplained gap reads as an error and invites a downgrade
to the leaf default.
