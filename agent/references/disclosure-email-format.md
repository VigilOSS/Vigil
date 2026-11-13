---
description: "Email disclosure format for vendor security teams: structure, rules, anti-patterns"
skill: report-generation
category: Disclosure & Reporting Formats
---

# Security Disclosure Email Format

The plaintext format for an email disclosure to a project or vendor security contact
(`security@project.example`, a project security mailing list), written to
`$ENGAGEMENT_DIR/submissions/<slug>/disclosure.txt`. Use it when the operator requests an email
disclosure for a confirmed finding with end-to-end proof; a standalone writeup uses
`export submission --platform direct` instead.

## Structure

These sections, in this order. The bracketed counts are ceilings, not targets.

```
Subject: <one-line technical summary — no severity, no CVE, no hype>

Hi <security-team>,

<2-4 sentence summary. What the bug is, where it is, what an attacker gets.
No preamble, no "I discovered...".>


AFFECTED CODE
=============

  <file>:<line> — quote the vulnerable code or describe the operation.
  2-space indentation for code excerpts; number multiple locations.


ROOT CAUSE
==========

  <Why the bug exists, not what it does: missing check, unsigned
  arithmetic, omitted guard, incomplete fix for a prior CVE.
  1 paragraph, 3-6 sentences max.>


IMPACT
======

  <What the attacker gains, the attack vector (remote clone, local
  repo, CI pipeline), and prerequisites stated honestly. Multiple
  impact contexts (local vs CI/CD vs hosted platform) get one line each.>


REPRODUCTION
============

  <Numbered steps: the PoC command, what the victim does, what to
  observe, with exact output where it proves the finding. With a
  control test, show it first to prove the boundary exists, then the
  bypass.>


SUGGESTED FIX
=============

  <Concrete fix with code, referencing existing patterns where they
  apply ("apply the same check from file.c:123 to file.c:456").>


CVSS
====

  <Complete CVSS v3.1 or v4.0 base vector — score (SEVERITY)
  - AV:X  -- reason, one line per factor that is not obvious>

AFFECTED VERSIONS
=================

  <"all versions with feature X", "since commit abc123", or
  "version 2.30+".>

PoC attached (<filename>).

Credit: <name> - <email>
```

## Rules

All writing rules from `agent/rules/reporting.md` apply. Leave out ruled-out attack variants, probe
counts, and telemetry, and do not tell the recipient how to interpret the finding; a control test that
establishes causality is proof and stays (Rule 20).

1. **Subject:** technical summary under 80 characters; no severity, CVE number, or "URGENT".
2. **Honest scoping up front:** say so when the attack needs non-default config, a local filesystem,
   or 32-bit only. An overstated vector damages credibility and delays triage.
3. **Control test:** when the finding bypasses a security gate, show the gate working first, then the
   bypass, so the omission is self-evident.
4. **One finding per email** unless findings share a root cause. Related bugs (the same bug in two
   files, a delivery chain plus the corruption it enables) share one email as numbered sub-issues: a
   "TWO SUB-ISSUES" / "THREE SUB-ISSUES" section after the summary, each sub-issue headed with its
   file:line and carrying its own affected code and root cause; IMPACT, REPRODUCTION, and SUGGESTED
   FIX then cover them together.
5. **CVSS justification per factor**, so the triage team cannot silently rescore without engaging
   with the reasoning.
6. **Plaintext:** 2-space indented code, no markdown fences or formatting; these go to mailing lists.
7. **Length:** under 120 lines for one finding, 150 for multi-issue. The body is self-contained and
   the PoC supplementary.
8. **Credit line always:** `Credit: Full Name - email@domain`.

## Example

- `agent/references/examples/disclosure-email-fast-import.txt` — multi-sub-issue security gate bypass
  with a control test and CI/CD attack-vector framing
