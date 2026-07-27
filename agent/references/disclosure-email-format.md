---
description: "Email disclosure format for vendor security teams: structure, rules, anti-patterns"
skill: report-generation
category: Disclosure & Reporting Formats
---

# Security Disclosure Email Format

Reference format for email-based vulnerability disclosures to security teams
(e.g., security@project.example, git-security@googlegroups.com).

This format is for **external disclosure emails**, not for internal engagement
reports (report.md). Use the standard report-generation skill for internal reports.

## When to Use

- Operator requests an email disclosure report for a confirmed finding
- Finding has a working PoC with end-to-end proof
- Target is an open-source project or vendor with a security contact

## Structure

Every disclosure email has these sections in this order. No extras. No reordering. The sentence/line
counts bracketed below are ceilings, not targets — a ROOT CAUSE paragraph that takes two sentences
because two sentences carry the fact is better than one padded to six.

```
Subject: <one-line technical summary — no severity, no CVE, no hype>

Hi <security-team>,

<2-4 sentence summary. What the bug is, where it is, what an attacker gets.
No preamble. No "I discovered..." Just the technical facts.>


AFFECTED CODE
=============

  <file>:<line> — quote the vulnerable code or describe the operation.
  Use 2-space indentation for code excerpts. Show the specific function
  and line numbers. If multiple locations, number them.


ROOT CAUSE
==========

  <Why the bug exists. Not what it does — why. Missing check, unsigned
  arithmetic, omitted guard, incomplete fix for a prior CVE, etc.
  1 paragraph, 3-6 sentences max.>


IMPACT
======

  <What the attacker gains. Be specific: file read, credential theft,
  heap corruption, DoS. State the attack vector (remote clone, local
  repo, CI pipeline, etc.) and any prerequisites honestly.

  If the finding has multiple impact contexts (e.g., local vs CI/CD vs
  hosted platform), list them with one line each. No speculation.>


REPRODUCTION
============

  <Numbered steps. Start with the PoC command. Then what the victim does.
  Then what to observe. Include exact output where it proves the finding.

  If the PoC has multiple tests (e.g., control test + exploit), number
  them all. Show the control test first to prove the security boundary
  exists, then the bypass.>


SUGGESTED FIX
=============

  <Concrete fix with code. Show the patch or describe the specific check
  to add. Reference existing patterns in the codebase where applicable
  (e.g., "apply the same check from file.c:123 to file.c:456").>


CVSS
====

  <CVSS:3.1 vector string — score (SEVERITY)

  Justify each factor on a separate line:
  - AV:X  -- reason
  - AC:X  -- reason
  - etc.

  Only justify factors that aren't obvious. Skip the boilerplate for
  standard values.>

AFFECTED VERSIONS
=================

  <Which versions are affected. Be specific: "all versions with feature X"
  or "since commit abc123" or "version 2.30+".>

PoC attached (<filename>).

Credit: <name> - <email>
```

## Rules

All writing rules from `agent/rules/reporting.md` apply (banned language, active voice,
no class definitions, evidence truncation, sentence efficiency). Rule 20 applies in full:
do not document ruled-out attack variants, do not include probe counts or telemetry,
do not instruct the recipient on how to interpret the finding.

Format-specific:

1. **Subject line:** Technical summary only. No severity rating, no CVE number
   (you don't have one yet), no "URGENT" or "CRITICAL". Under 80 characters.

2. **Honest scoping:** If the attack requires non-default config, a local
   filesystem, or 32-bit only, say so upfront. Overstating the vector damages
   credibility and delays triage.

3. **Control test when applicable:** If the finding bypasses a security gate,
   show the gate working first (control test), then the bypass. This makes the
   omission self-evident.

4. **One finding per email** unless findings share a root cause. Related
   findings (e.g., same bug in two files, or a delivery chain + the corruption
   it enables) can share an email with numbered sub-issues.

5. **Sub-issues format:** When an email covers multiple related bugs, use a
   numbered "TWO SUB-ISSUES" / "THREE SUB-ISSUES" section after the summary
   paragraph. Each sub-issue gets its own heading with file:line reference.
   IMPACT, REPRODUCTION, and SUGGESTED FIX then cover all sub-issues together.

6. **CVSS justification:** Include per-factor justification. This prevents the
   triage team from silently rescoring without engaging with your reasoning.

7. **Code indentation:** 2-space indent for code in the email body. No markdown
   fences — these are plaintext emails.

8. **Length:** Under 120 lines for a single finding. Under 150 for multi-issue.
   Shorter is better. If the triage team needs to scroll more than twice,
   the email is too long.

9. **Credit line:** Always include. Format: `Credit: Full Name - email@domain`

## Example

- `references/examples/disclosure-email-fast-import.txt` — multi-sub-issue
  security gate bypass with control test and CI/CD attack vector framing

## Anti-Patterns

- Starting with "I am a security researcher..." — skip, go straight to the bug
- Attaching a 500-line PoC without a summary — the email body should be
  self-contained; the PoC is supplementary
- Using markdown formatting — these are plaintext emails to mailing lists
