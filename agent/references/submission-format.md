---
description: "Submission format selector + shared authoring rules (voice, PII redaction, PoC authoring) and ONE consolidated pre-submission / report QA checklist; platform-neutral across Bugcrowd, HackerOne, and direct-to-company. Per-platform scaffolds live in templates/{bugcrowd,hackerone,direct}.md"
skill: report-generation
category: Disclosure & Reporting Formats
---

# Submission Format

Use this when the operator closes a finding out as a standalone submission — a Bugcrowd or HackerOne
report, or a direct-to-company / vendor writeup. The structure and rules here are identical across all
three targets; each finding is a standalone submission.

## Platform selector

`vigil assess export submission <slug> --platform <p> --draft` generates the per-finding draft; once it is authored, QA'd, and blind-triaged, `vigil assess export submission <slug> --platform <p> --overwrite` (no `--draft`) publishes it — see "Finding is the source of truth" below for the `--overwrite` rule. Pick the platform below and use its scaffold for the platform-specific fields. This doc holds the cross-platform authoring rules all three share (voice, section budgets, PII redaction, PoC authoring, de-harnessing, and one consolidated pre-submission / report QA checklist) — the templates link back here rather than repeating them.

| Target | Scaffold | Platform-specific field | Taxonomy lookup |
|---|---|---|---|
| Bugcrowd | `agent/skills/report-generation/templates/bugcrowd.md` | VRT category + P1–P4 priority | `agent/references/reporting/bugcrowd-vrt.md` (leaf table in `bugcrowd-vrt.tsv`) |
| HackerOne | `agent/skills/report-generation/templates/hackerone.md` | CWE weakness | `agent/references/reporting/hackerone-weaknesses.md` (leaf table in `hackerone-weaknesses.tsv`) |
| Direct (company / vendor) | `agent/skills/report-generation/templates/direct.md` | none (VRT / H1 fields dropped) | n/a |

For a vendor/CERT disclosure *email* rather than a platform submission, use `agent/references/disclosure-email-format.md` instead. For a REPLY to a program/company on an already-submitted finding (a Bugcrowd comment, a HackerOne activity reply, a direct follow-up), use `agent/references/reply-format.md` and `vigil assess export reply`/`record-reply` instead — a reply is not a resubmission and does not follow the structure below.

## Finding is the source of truth

`submission.md` is a RENDER of the finding, not the durable copy. `export submission --draft`
renders each section FROM the finding's own fields — `summary` (Summary), `details.steps_to_reproduce`
(Steps to Reproduce), `details.evidence` (Evidence), `details.attack_scenario` (Attack Scenario),
`details.impact` (Impact), `remediation`/`details.remediation` (Remediation) — and consolidates the
finding metadata, any hygiene warnings, the structured proof, and every linked command run into ONE
"OPERATOR DETAILS — NOT FOR SUBMISSION" reference section below the second `---` (present in both
draft and final, always below the never-paste line). That reference section also carries
**Reproduction runs** — the real argv of the command runs named in `details.repro_runs`, in step
order — which is what you check Steps to Reproduce against. The full edit-authority rule (what you
may change and what you may never invent) is stated once in `agent/agents/report-writer.md`
Mandatory Closing Sequence step 1; in short, every command, argv, and response value must trace to
one of those runs, and outside that boundary you author nothing, because you cannot run probes and
an assembled reproduction is a narrative rather than a transcript. You AUTHOR each section, then write it back to
the finding with `vigil assess finding update <slug> --payload-file <path.json>` (the default write
path — see `agent/skills/report-generation/SKILL.md` "Submission-First Closeout" step 3 for the
payload shape; reserve `--details-inline` for a short value with nothing a shell would mangle), and
re-render.

**Re-rendering is the normal, expected operation** — the loop is author → write to the finding →
re-render, repeatedly. `--overwrite` is what makes that loop work, not a hazard to avoid:
- The first render (`--draft`, before `submission.md` exists) omits `--overwrite`; every render
  after that needs it, because the CLI refuses to clobber an existing `submission.md` without it.
- It rewrites only `submission.md` and `submission-context.json` — it never touches the finding
  record.
- Because every rendered field is read back from the finding, a re-render reproduces your authored
  content exactly. A hand edit made only in `submission.md` does not survive it; a write to the
  finding does.

Because the MASKED evidence lives in the finding (raw tool output stays in `scans/` and is only
referenced), a re-render never re-leaks PII. Publish once QA and blind triage clear the finding:
`vigil assess export submission <slug> --platform <same platform> --overwrite` (no `--draft`)
re-renders the same authored content through the final gate — it exits non-zero before writing if a
required field or hygiene check fails — and registers `submission.md` as a finding-linked artifact.
Full procedure: "Submission-First Closeout" in `agent/skills/report-generation/SKILL.md`.

## Staging Convention

Each submission is staged in its own directory under the engagement root before the operator submits it to the platform:

```
$ENGAGEMENT_DIR/submissions/<slug>/
    submission.md       # this file — the drafted submission text
    poc.<ext>           # any PoC script or artifact referenced in the submission
```

The directory name is the finding's backend slug (e.g., `submissions/VA-003/`). The slug stays in the directory name only — it must not appear inside `submission.md` (see "No internal identifiers" below).

PoC artifacts live here alongside `submission.md`. Do NOT place them under `tools/exploit-state/pocs/` — that is the exploitation artifact store, not the submission staging area.

After staging `submission.md` and submitting to the platform, set the finding's submission status:

```bash
vigil assess finding update <slug> --submission-status submitted --reason "Submitted to <program>"
```

Update `submission_status` as the program responds (`accepted` / `needs_info` / `rejected` / `duplicate`). This field is orthogonal to `workflow_status` — it tracks program-facing state only and never changes whether the finding is included in the internal report. See "Submission Status Lifecycle" in `agent/skills/report-generation/SKILL.md` for the full sequence.

## Copy-paste workflow

The output is designed to map cleanly onto the platform's submission form. The operator takes the produced file and copies each block into the matching platform field:

- **`VRT:` line** (or `Weakness:` on HackerOne) → platform's VRT / Vulnerability Category (or Weakness) field
- **`Title:` line** → platform's Submission Title field
- **PoC attachment** (operator-side, NOT a rendered body line) → attach the staged `poc.<ext>` file(s) in the platform's attachment / PoC area and record the run command + pass criterion there; the `**Run:**` step also belongs inside Steps to Reproduce. See "PoC block" below. Omit entirely for inline-only reproductions.
- **Everything from `### Summary` down to (but not including) the second `---`** → platform's Description / Body field

The first `---` separator exists so the operator can select the entire body block in one contiguous paste without stripping the `Title:`/`VRT:`/`Severity:`/`CVSS` metadata lines. Do not put anything between that separator and `### Summary` that the operator should not paste into the platform. The second `---` closes the pasteable body — everything below it is the OPERATOR DETAILS reference section, never pasted.

**The "OPERATOR DETAILS — NOT FOR SUBMISSION" section is never pasted.** It sits below the second `---` (the never-paste line) in both the draft and the final render, and consolidates everything you author the body FROM: the finding metadata to weave in, any internal-identifier hygiene warnings to strip, any advisories to weigh, the structured proof (poc_* / evidence_ref) to mask and weave into Evidence, and the explicitly linked command runs. The pasteable body always ends at that second `---` — select from `### Summary` down to it.

**Hygiene warnings block; advisories do not.** A `hygiene_warnings` entry is a fact about the document — a leaked internal UUID, an absolute engagement path, a `cases.db` reference — so an unresolved one fails the publish render closed; fix it at the finding. An `advisories` entry (title length, for example) is an editorial opinion the command surfaces without gating on: weigh it against the checklist row it names below and fix it at the finding when you agree. Both appear in `submission-context.json`, in the `--json` summary, and as their own OPERATOR DETAILS sub-block; only the first one can stop a publish.

## Structure

`export submission` renders the layout below FROM the finding's fields. The PoC *attachment* is NOT
a body slot — it is the file the operator adds in the platform's attachment area (see "PoC block");
the renderer emits no attachment block into the pasteable body. The proof pointer itself
(`evidence_ref` / `poc_code`) stays under OPERATOR DETAILS, below the second `---` — it is an
internal reference (often a `scans/…` path) with no business above the paste boundary, so the
pasteable header carries no POC line at all.

The operational header (`Asset` / `Run` / `Pass if` / `Deconfliction`, below) is rendered FROM the
finding, not hand-typed, so a re-render/`--overwrite` reproduces it instead of wiping an operator's
hand-applied overlay. Sourcing: **Asset** ← finding `canonical_location`, rendered verbatim — if the
request method matters, put it in `canonical_location` itself, since the renderer composes nothing
onto it. **Run** ← `details.run`; **Pass if** ← `details.pass_if`; **Deconfliction** ← the
engagement's required attribution header (`scope.json:required_headers`) — this is the header value
itself (e.g. `X-HackerOne: <id>`), distinct from the 3-line researcher/IP/window Deconfliction block
in "Section budgets" below. Omit any line with no backing data — an empty field renders as nothing,
not a placeholder.

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**VRT:** [Platform taxonomy category path]   (HackerOne: **Weakness:** CWE-[nnn]; omitted for direct)

**Severity:** [the finding's severity word — CRITICAL / HIGH / MEDIUM / LOW / INFO, matched to the
CVSS band. The renderer emits this from the finding on every platform. A Bugcrowd P1-P4 priority
appears nowhere in this document: the operator sets it in Bugcrowd's own priority field, the VRT
leaf you name already carries its default, and appending it to the `VRT:` line breaks that line's
verbatim paste into the platform's VRT selector — see `templates/bugcrowd.md`]

**CVSS:** CVSS:3.1/[vector] ([score])

**Asset:** [finding canonical_location, verbatim]
**Run:** [details.run]
**Pass if:** [details.pass_if]
**Deconfliction:** [required attribution header, e.g. X-HackerOne, if the program requires one]

---

### Summary
[2-4 sentences. First sentence = attacker outcome. Then the code fault. Then what the POC proves.
Optionally followed by a bold `**Exploit flow**` marker and an ordered list of 3-5 plain sentences,
no commands, giving a triager the mechanism before Steps' commands start — inside this same
`summary` string, no separate field.]

### Steps to Reproduce
[One authored block, numbered by you (`1.`, `2.`, …) and rendered exactly as written — the renderer
adds no numbering or marker of its own, so your numbers are what a triager reads and what any later
cross-reference in the submission ("follow the redirect from step 4") resolves against. Prefix each
step with the acting identity (`[attacker]` / `[administrator]` / `[server]` / `[both]`, or
the finding's own role names; compound form like `[administrator, browser]` for a context switch,
or `[attacker, concurrent]` for a step whose requests fire in parallel).
Read the identity off the step's own request — which session, token, or header the argv carries — and
run `vigil assess command-run get <id>` for a step whose actor the argv does not make obvious.
One action per step, no narrative between
steps. Controls, edge cases, alternate endpoints, and source-code analysis do not appear here;
cleanup does, but only when the reproduction mutates state the triager will also mutate (revert plus
read-back is credibility evidence on a live target) — it is noise when the reproduction is read-only.
A step's expected result is a `**Expect:**` line belonging to that step — at column 0 on the line
after the step's closing fence, matching the fence itself, since platform markdown renderers vary in
how they treat a fence indented inside a list item. Step-local, and distinct from `details.pass_if` (the
one-line criterion for the whole reproduction, rendered in the operational header). Include the run command or inline requests
— whichever form the PoC takes.]

### Evidence
[AUTHORED proof, not a raw command dump — proof the steps cannot show. Six categories, the first
mandatory and the rest as the finding warrants: the decisive artifact (the bytes proving what a
step's `**Expect:**` line can only assert — the leaked record, the crash report, the returned
credential); root cause (source, config, or bundle excerpt); negative controls that prove the causal
claim; post-exploitation boundaries (what the attacker still could not do); minimum privilege
required to reach the sink; and environment facts load-bearing for Impact or Remediation.
**The shape follows the number of proof obligations, not a template** — one fenced block for a
finding with one thing to prove, a labelled block per category when there are several
(`**Cross-tenant read.**` … or `#### ` sub-headings once the blocks run long). Author it from the OPERATOR DETAILS
section's structured proof and linked command runs plus a targeted `vigil assess command-run list
--q <finding's url/param/header/uri>` for reproducing runs the linked set missed. Annotate the
critical lines with <-- proof markers.
Truncated to only the lines that matter. No full tool dumps.
Genuine third-party PII must be partial-masked; self-owned/synthetic data is shown in full — see "PII redaction" below.
This is stored back on the finding as `details.evidence`; the raw output stays in `scans/`.]

(### Attack Scenario)
[2-3 sentences. Realistic adversary class + the access they start with + the action, ending at the
moment of compromise. Stops there — no scope counts or blast-radius quantification (those are Impact).
No theory.]

### Impact
[1-2 sentences. The consequence + how far it reaches (blast radius), quantified by shape/count without
exposing raw PII. Never re-describes the actor or the reproduction steps — this is the severity/CVSS
justification, not a retelling of the scenario.]

### Remediation
[1-3 items. Primary fix first. One defense-in-depth item at most. No "validate the fix" step.]

---

## OPERATOR DETAILS — NOT FOR SUBMISSION
[Reference section — present in both draft and final, ALWAYS below this second `---`, NEVER pasted.
Consolidates everything you author the body FROM: the finding metadata to weave in, any
internal-identifier hygiene warnings to strip, the structured proof (`poc_*` / `evidence_ref`) to
mask and author Evidence from, and every linked command run. The pasteable body is everything from
`### Summary` down to this second `---`.]
```

## Steps to Reproduce vs Evidence

**A step's verification outcome is inline in the step** — a short `**Expect:**` line right after
the request (`grant -> 200`, a required marker), not a separate section. **Evidence carries only
proof the steps cannot show**: the six-category taxonomy under "Evidence" in "Structure" above —
never a request or result a step's `**Expect:**` line already carries (reporting.md Rule 21). The
decisive artifact is the exception that proves the rule: a step asserts what its response showed,
and Evidence carries the bytes that prove the assertion.

## Attack Scenario vs Impact

**Attack Scenario owns plausibility** — adversary class, starting access, the action, ending at
compromise; never quantifies scope. **Impact owns severity** — consequence and blast radius,
quantified by shape/count; never re-describes the actor or the steps. The scope/"how many" sentence
lives only in Impact. Attack Scenario is optional — drop it whenever Steps to Reproduce plus Impact
already make reachability obvious (reporting.md Rule 15), and omit it outright whenever the Summary
carries an Exploit flow, since the two would carry the same sequence twice.

## PoC block

The PoC block is **operator-side attachment guidance, not a `submission.md` body slot.**
`export submission` renders no attachment block into the pasteable body (see "Structure") — but the
**Run:** and **Pass if:** values it documents ARE rendered into the operational header from
`details.run` and `details.pass_if`, so write them there rather than typing them only into this
block; a value typed only here does not survive the next `--overwrite`. Use it when the finding's
proof is an attached script rather than inline requests: stage the file as
`submissions/<slug>/poc.<ext>` and, when the operator submits, attach it in the platform's
attachment / PoC area with the run command and pass criterion below. The `**Run:**` command also
belongs inside Steps to Reproduce (which the renderer DOES emit, from
`details.steps_to_reproduce`), so a triager sees it in the pasteable body too. Omit
the whole block when every reproduction step is an inline request or command in Steps to Reproduce.

Choose the form that fits the reproduction:

**Inline only — no attachment:**
Omit the block. Steps to Reproduce contains everything the triager needs to run.

**Single file:**

```
Attach: `<filename>`
**Run:** `<runtime> <filename>`
**Pass if:** <one-line observable success criterion>
```

**Multiple files:**

```
Attach (all): `<main>`, `<file2>`, `<file3>`
**Run:** `<runtime> <main>`
**Pass if:** <one-line observable success criterion>
```

Rules for the PoC block:
- The attached filename(s) are operator-side attachment notes, not a rendered field — no header
  line reproduces them, so name them plainly for whoever is doing the attaching.
- `**Run:**` is the exact command the triager copies and pastes. Include environment setup (e.g., `source env.sh && python3 poc.py`) in the command, not in a separate step.
- `**Pass if:**` is one observable line — what the triager sees in output that confirms the finding. Not a paragraph, not a list.
- Use the actual file extension. Do not normalize everything to `.sh`.
- If setup requires manual prerequisites (running a server, creating a test account), document them with `# SETUP:` comments inside the script, not in the PoC block.

## PoC Script Authoring

The attached PoC is a standalone artifact a stranger reads cold. It is **not** the internal
exploit playbook (`tools/exploit-state/playbook-<slug>.sh`, `agent/skills/exploit-playbook-authoring/SKILL.md`)
copied verbatim — that playbook is written for the operator to replay inside the engagement and is
allowed to be verbose, annotated, and full of engagement-specific plumbing. The submission PoC is
written for a triager who has none of that context and is actively looking for reasons to distrust
it. Write it separately, minimal, and clean, even when it reproduces the same steps.

**Minimal by default.** Fewest lines that still produce the decisive observable — a busy triager
runs a 25-line script and is suspicious of a 90-line one. Scale to what the vulnerability actually
needs: a single injected payload needs a handful of lines; a race condition, a multi-step auth
chain, or a blind OOB confirmation legitimately needs more. Match the length to the proof, not to
how thorough the investigation felt while building it — cut every step, retry loop, or diagnostic
that does not change what the triager sees at the end.

**No decorative harness.** No ANSI color codes, no `hdr()`/`pass()`/`fail()`/`note()`-style banner
helper functions, no boxed section dividers, no emoji status markers. A plain `print`/`echo` of the
observed value is enough — the narration belongs in the submission's Evidence section, not in the
script's own stdout theater. Colorized, banner-heavy output is a CTF-harness convention; a human
proving a bug to a stranger does not build a test framework first.

**No docstring or self-summary.** Do not open the script with a multi-paragraph comment block
restating the vulnerability class, the CWE, the attack flow design rationale, or a copy of the
submission's own Summary section. One line naming what the script does is enough — the submission
body already carries the narrative; repeating it in the script reads as a template being filled in,
not a script someone wrote to check something.

**De-harness: strip anything that reveals the PoC was authored or run inside an AI-agent sandbox.**
This is the single most damaging provenance leak, because it directly answers "who/what produced
this" rather than merely reading as stylistically odd:
- No code that inspects, unsets, or branches on agent-identifying environment variables
  (`CLAUDECODE`, `CURSOR_AGENT`, `CURSOR_TRACE_ID`, `GEMINI_CLI`, `CODEX_SANDBOX`, `CODEX_CI`,
  `COPILOT_*`, `OPENCODE_CLIENT`, `REPL_ID`, or equivalents from any harness). A human running this
  from their own terminal has none of these set and no reason to ever reference them — a script that
  strips them proves someone anticipated an agent-detection check, which itself proves an agent wrote
  it.
- No tool-hint comments, plugin banners, or references to the harness that built or ran it (agent
  names, dispatch IDs, "MANUAL:" operator-handoff annotations, container/runtime paths specific to
  this engagement).
- If the target's own agent-detection logic is genuinely part of the mechanism (e.g., the app
  branches on an `isAgent` signal and the PoC must reach the human-path branch to trigger), name that
  **once**, as a single mechanism sentence in the submission body ("run outside an agent harness to
  reach the default interactive code path") — do not leave the strip-list itself inside the shipped
  script.

**Default to one file.** Don't split into a script plus `README.md` plus `REPRODUCE.md` plus
`OPERATOR-INSTRUCTIONS.md` — that bundling belongs in the internal report, not the submission. Use a
second file only when the exploit genuinely requires a second running component (a callback stub
server, a payload the target must fetch) — never to hold instructions or narrative that the PoC block's
`**Run:**` line and the submission body already carry.

**Prove it in a clean environment — at exploit time, not report time.** The clean-env run (fresh
shell/clone/account, outside any agent session) belongs to whoever BUILDS the PoC during
exploitation, so the captured evidence already carries that provenance. The report-writer does NOT
re-run it — it works from the captured evidence and confirms the PoC is agent-independent by READING
it against the de-harness rules above. A script that only works inside the sandbox that wrote it
leaks its own origin and fails those static checks. Empirical clean-environment
reproduction is a hunt-time responsibility; the report-writer never re-runs
target-facing proof.

## Section budgets

These are ceilings, not targets. A one-sentence Summary that lands the attacker outcome is a complete
Summary — using the full ceiling on every finding is a sign the prose is padded to look thorough, not
that it is thorough. Write the fact in as little space as it needs, then stop; only cut when a section
runs past its ceiling below. The sentence-length row follows ASD-STE100 (Simplified Technical
English), the maintenance-documentation standard that caps prose at similar lengths for the same
followability reason.

| Section | Ceiling |
|---|---|
| Title | 12 words, single clause |
| Any single sentence | 25 words (20 in Steps to Reproduce) |
| Summary | ≤4 sentences + optional 3-5 step Exploit flow |
| Steps to Reproduce | One sentence per step, no narrative between steps; ≤10 steps for most findings, one action per step |
| Evidence | ≤15 lines of content per fenced block; annotate the proof line, and carry only proof the steps cannot show |
| Attack Scenario | 3 sentences |
| Impact | 2 sentences |
| Remediation | 3 items |
| Deconfliction (if required by program) | 3 lines: researcher ID, source IP, UTC time window |

Sections not in this table (Chain Potential, Defender-positive, Probe Coverage, Architectural Analysis, Fix Validation steps) do not exist in external submissions. If content belongs in one of those categories, it belongs in the internal `report.md`, not the submission.

A chain genuinely requiring more identities or stages may exceed the 10-step guideline — see the
`[long]` exemplar in "Examples" below, where every one of 16 steps is load-bearing. That is the
exception, not permission to pad: a finding that needs more space because it restates controls,
narrates methodology, or re-proves an already-established fact is still over budget, per reporting.md
Rule 21.

**This table is the sole owner of external-submission section length.** `agent/rules/reporting.md`
Rule 10 owns the internal `report.md`'s separate, non-conflicting ceilings for
`Description`/`Steps to Reproduce`/`Impact`/`Remediation` — the two tables use different section
names for a reason (this one is the submission's rendered fields, that one is `report.md`'s), and
neither number cross-applies to the other artifact.

## Rules

All writing rules from `agent/rules/reporting.md` apply (banned language, active voice, no class definitions, every sentence load-bearing).

### Mandatory fields

- **VRT is mandatory.** Every submission must carry a VRT category path from the platform's taxonomy. An unknown VRT is not an excuse — look it up before submitting. Never leave it blank, "TBD", or "N/A". Bugcrowd uses the VRT at https://bugcrowd.com/vulnerability-rating-taxonomy; HackerOne uses CWE. Pick the most specific category that matches the proved attack.
- **Title must be a single line.** No markdown, no backticks, no internal finding IDs. Use the pattern: `[Bug Class] in [exact component] allows [attacker role] to [impact]`. The title is pasted directly into the platform's title field — anything that looks wrong there is wrong here too.

### PII redaction

**Precedence gate — decide this before masking anything:**
- Self-owned or synthetic — your own test tenant/account, a seeded demo, data in an org you control? **Show it in full.** Do not mask self-owned or synthetic test data; masking it buys zero privacy and destroys the proof.
- Genuine third-party customer PII? **Partial-mask only**, at the character level (`v****@real-domain.com`) — never substitute a generic placeholder (`example.org`, `respondent@example.org`); a placeholder proves nothing and fails blind triage. The identifying structure must survive: distinct IDs, timestamps, real domains, the actual output line.

A bug bounty submission creates a second copy of the evidence on the platform's infrastructure. Pasting genuine third-party customer PII exposes those customers a second time without their consent. GDPR/CCPA exposure is non-trivial for the target organization even if the platform is "trusted". Partial-mask third-party PII before submitting; self-owned and synthetic data needs no redaction.

- **Never paste unmasked genuine third-party PII** into the submission body, evidence blocks, or screenshots. This covers: full email addresses, phone numbers, case/account/order numbers tied to real (non-test) users, full names, government IDs, SSNs, addresses, DOBs, payment details, session tokens belonging to real users.
- **Partial masking**, character-level, is the only acceptable treatment for third-party PII: `j***@example.com`, `+1-555-***-4421`, `CASE-12******`. Show enough structure to prove the data is real, not enough to re-identify the customer.
- **Prefer synthetic data.** If the target has a staging tenant, test accounts, or a seed/demo dataset, reproduce the finding against those and show the synthetic PII in full — a clean PoC against a test account beats a masked PoC against a real one.
- **Internal report vs external submission.** The internal `report.md` may include unredacted evidence under the engagement's authorized scope. External bug bounty submissions must partial-mask genuine third-party PII only — self-owned and synthetic data is shown in full in both.

### No internal identifiers

Bug bounty submissions are standalone deliverables — nothing inside them should reference this engagement's internal state.

- **No finding slugs** (`VA-003`, `NNN`, any prefix) in the submission body.
- **No engagement keys, engagement directory paths, `$DIR/`, `$ENGAGEMENT_KEY/`, or backend URLs.**
- **No cross-references to other findings in the same engagement** — each submission stands alone. If two findings share a root cause, file two submissions; if one finding genuinely depends on another, describe the dependency in plain English, not via a finding ID.
- **No operator/tool metadata breadcrumbs** — tool run IDs, MCP command IDs, activity log references, `vigil assess` invocations.
- **No internal tooling breadcrumbs** — references to alternate reproducers, operator convenience wrappers, or internal `tools/` paths belong in the internal report. "Also available at…" creates ambiguity and exposes research-time scaffolding the platform does not need.

### Format-specific

- Each finding is one submission. Do not bundle.
- **Choose the right PoC form.** Inline requests (curl, HTTP) pasted into Steps to Reproduce need no attachment. A script that must be run gets the PoC block with `**Run:**` and `**Pass if:**`. Multiple supporting files (payload file, env config, helper module) are listed in the PoC block and all attached — do not artificially collapse them into one file.
- Attach only what the triager needs to reproduce the finding. Internal scaffolding, bundled all-in-one scripts, and alternate reproducers stay in the internal report.
- The PoC must exercise the vendor's code, not reimplemented logic. Import and call their functions. Run their binary. Show their output.
- Evidence must come from running the PoC, not from reading the source. Code analysis supports the description but does not replace proof.
- Credentials and secrets go in environment variables, never in submission text or script source.

## Pre-submission checklist

**One checklist for both closeout paths.** It is the primary gate before handing a **submission**
file to the operator, and it is also the internal-report QA checklist that
`agent/skills/report-generation/SKILL.md` "Post-Generation Self-Review" and "Review-and-Fix QA Mode"
run against `report.md`. Verify every applicable row; any failing row blocks delivery. Fix failures
at the SOURCE: write the correction to the finding (`vigil assess finding update` /
`finding link`) and re-render — that is the only fix that survives, since a correction made only in
`submission.md` / `report.md` is lost on the next render.

Each row is tagged for where it applies:
- **[both]** — a submission AND the internal report
- **[submission]** — external submissions only (bug bounty / direct-to-company writeup), not the internal report
- **[report]** — internal `report.md` only

Where a row's rationale is a reporting rule it cites the rule (`agent/rules/reporting.md`) instead of restating it.

### Structure & mandatory fields

- [ ] **[both]** `Title:` is a single line, ≤12 words, one clause, follows the title formula (`[bug class] in [exact component] allows [attacker role] to [impact]`); no markdown/backticks, no finding-IDs, no parenthetical product aliases, and no severity label inside the title — count the words before checking this box; over 12 fails this row outright, no exceptions (reporting.md Rules 8, 16)
- [ ] **[submission]** Platform taxonomy field is populated with a specific path — Bugcrowd `VRT:` (most specific leaf) or HackerOne `Weakness:` CWE; never blank, "TBD", or "N/A"; omitted only for `direct`
- [ ] **[both]** `Severity:` and CVSS vector match the proved impact — if write operations were rejected by application-layer validation with nothing mutated, `I` is not `H` (reporting.md Rules 3, 20)
- [ ] **[submission]** First `---` separator is present so the operator can paste `Title:`/`VRT:`/`Severity:` plus the body in one block; a second `---` closes the body with `## OPERATOR DETAILS — NOT FOR SUBMISSION` beneath it (never pasted)
- [ ] **[both]** Body starts with `### Summary` and the summary leads with the attacker outcome in sentence 1 (reporting.md Rule 6)
- [ ] **[both]** Steps to Reproduce is a single authored block, numbered by you (`1.`, `2.`, …) and rendered exactly as written — the renderer imposes no numbering or marker, so any step cross-reference elsewhere in the submission only resolves because you wrote the number; one action per step, copy-pasteable, no narrative between steps (reporting.md Rule 10)
- [ ] **[both]** Remediation names a specific technology and control, not generic advice — ≤3 items, primary fix first, ≤1 defense-in-depth, no "validate the fix" item (reporting.md Rule 14)
- [ ] **[both]** Findings that share one vulnerable component or configuration are consolidated — one root cause, one submission, with siblings only as downstream outcomes (reporting.md Rule 18)
- [ ] **[submission]** No section exists outside the defined structure — no Chain Potential, Architectural Analysis, Fix Validation, Probe Coverage, or Defender-positive block (reporting.md Rule 15; "Section budgets" above)
- [ ] **[report]** Executive summary is ≤ one page (reporting.md Rule 10)
- [ ] **[report]** Severity counts in the executive summary match the actual finding list
- [ ] **[report]** No Coverage Summary and no Finding Cross-Reference section (reporting.md Rule 19)

### Proof & evidence

- [ ] **[both]** Evidence is authored, annotated proof — not a raw tool dump; each fenced block is truncated to only the lines that prove the finding (≤15 lines of content per block in a submission; reporting.md Rule 10 owns the internal report's own ceiling), with the critical line bolded or `<-- proof`-annotated so a reviewer finds it in seconds (reporting.md Rule 13)
- [ ] **[both]** Title and summary claim no reach, read, or impact beyond what the Evidence block literally shows — fix any claim the Evidence does not literally support
- [ ] **[both]** A reachable-but-not-fully-exploited finding scores CVSS on the demonstrated outcome only — there is a single `cvss_vector` field, not a separate score for the further reach a defender should still fix; name that further reach in `remediation` or one caveat sentence in `impact`, never as a second CVSS vector, and never in the title or summary
- [ ] **[submission]** For any finding with claimed CVSS ≥ 8.0 (upper-High into Critical — the platform's own "critical" label starts at 9.0), `agent/skills/disclosure-deployment-shape-check/SKILL.md`'s eight-category audit ran and passed before send — it catches the deployment-shape overstatement class (allocator dependence, build-flag gates, claim-vs-evidence fidelity, vendor-distro variation) that source-only verification does not, because those facts live in the runtime deployment, not the code. The audit memo lives at `tools/analysis-state/disclosure-shape-check-<slug>.md`.
- [ ] **[submission]** PoC form matches the reproduction: inline-only → no attachment; a script → staged `poc.<ext>` with the correct extension, its run command, and a one-line pass criterion; multi-file → every file staged and attached
- [ ] **[submission]** The attached PoC is agent-independent by inspection (de-harness rules above) and its clean-environment reproduction was established at exploit time — the report-writer does not re-run it here
- [ ] **[submission]** The PoC script is minimal — no line that does not contribute to the decisive observable; a reviewer unfamiliar with the finding could read it end to end in under a minute
- [ ] **[submission]** No ANSI colors, banner/box-drawing output, or `hdr()`/`pass()`/`fail()`-style status-helper functions in the PoC script
- [ ] **[submission]** No docstring-style header block restating the vulnerability class, CWE, or Summary at the top of the PoC script
- [ ] **[submission]** No code in the PoC inspects, unsets, or branches on agent-identifying environment variables (`CLAUDECODE`, `CURSOR_AGENT`, `GEMINI_CLI`, `CODEX_SANDBOX`, `COPILOT_*`, or equivalent), and nothing references the harness/agent that produced it (reporting.md Rule 20)
- [ ] **[submission]** If the program requires a deconfliction/attribution header (e.g. `X-HackerOne`), every attached PoC script sends it UNCONDITIONALLY on every request — not behind an env var, flag, or conditional — so the documented `**Run:**` command cannot violate program ROE
- [ ] **[submission]** The submission is one script by default; a second file exists only if the exploit requires a second running component, never to hold instructions or narrative
- [ ] **[submission]** Safety framing ("offline", "FAKE token", "localhost-only") appears once, in the setup, kept separate from any sentence explaining the vulnerability's mechanism (reporting.md Rule 20)
- [ ] **[submission]** If evidence, PoC, or claimed severity changed after the finding's last recorded blind-triage verdict, that verdict is STALE — re-run blind triage (`agent/skills/blind-triage/SKILL.md` Pass 2) before publish; do not ship on an outdated `Accept`

### PII & internal identifiers

- [ ] **[submission]** Self-owned/synthetic data (own test tenant/account, seeded demo, data in an org you control) is shown in full, unmasked; genuine third-party PII (emails, phone numbers, case/account/SSN values, real names, real session tokens) is partial-masked at the character level with structure intact (distinct IDs, timestamps, real domains) — never a generic placeholder. (The internal `report.md` may keep unredacted evidence under the engagement's authorized scope — this row is submission-only)
- [ ] **[both]** No internal identifiers anywhere in the body — finding slugs (`VA-003`), engagement keys/paths (`$ENGAGEMENT_DIR`, `$DIR/`), backend URLs, tool/command run IDs, `vigil assess` breadcrumbs, `cases.db` references, or "also available at…" alternate-reproducer pointers (reporting.md Rule 17)

### Human voice / AI-tell elimination

- [ ] **[both]** The opening does not echo the title — sentence 1 adds the proof, victim scope, or attacker outcome the title does not carry (reporting.md Rule 11)
- [ ] **[both]** No vulnerability-class definitions — the audience knows XSS/SQLi/IDOR/SSRF; jump to the specifics (reporting.md Rule 11)
- [ ] **[both]** No banned filler phrases (`Furthermore`, `It is worth noting`, `During the course of our assessment`, `robust`, `comprehensive`, …) (reporting.md Rule 11)
- [ ] **[both]** No given-property qualifier — an adjective the reader already assumes (`disposable`/`throwaway` organization, `malicious` attacker, `unsuspecting` victim, `carefully crafted` payload, `vulnerable` endpoint); a qualifier stays only when dropping it would let the reader assume something false (`attacker-controlled`, `you control`, `pre-auth`) (reporting.md Rule 11)
- [ ] **[both]** No narration of the report's own revision history or an earlier investigative pass being wrong (`Earlier revisions of this report carried...`, `An earlier pass... wrongly concluded...`) — state the current, correct fact only (reporting.md Rule 11)
- [ ] **[both]** Active voice throughout — the subject acts (reporting.md Rule 12)
- [ ] **[both]** Every sentence is load-bearing — if removing it does not reduce the reader's understanding, cut it (reporting.md Rule 15)
- [ ] **[submission]** No "Defender-positive", "Dead ends", "Negative findings", or "What was ruled out" section or sub-section anywhere in the submission — a control that proves the causal claim (a safe branch escaping the same bytes, a pre-exploitation capability baseline) is corroborating proof in Evidence, not a dead end (reporting.md Rule 20)
- [ ] **[submission]** No probe counts, request volumes, or percentile latencies appear anywhere in the submission body (reporting.md Rule 20)
- [ ] **[submission]** Deconfliction (if present) is ≤3 lines — researcher ID, source IP, UTC time window — no per-phase breakdowns, marker-string lists, or rate pledges (reporting.md Rule 20)
- [ ] **[submission]** Attack scenario uses a realistic adversary class, not a cartoonish persona ("student in a dorm room", "script kiddie") — 3 sentences maximum (reporting.md Rule 20)
- [ ] **[submission]** No sentence instructs the reviewer how to interpret, score, or act on the finding (`"please do not treat"`, `"recorded so triage does not re-investigate"`, `"triage can prioritize"`) (reporting.md Rule 20)
- [ ] **[submission]** The word "submission" does not appear in the body prose — use "finding" or "report" (reporting.md Rule 20)
- [ ] **[submission]** CWE, CVSS, or VRT that appear in header fields are not restated or justified inside body prose (reporting.md Rule 20)
- [ ] **[submission]** No em-dash appears more than once per paragraph; replace surplus em-dashes with a period, comma, or parentheses
- [ ] **[submission]** Contractions appear where natural (doesn't, it's, I've, won't) — the prose is not uniformly formal
- [ ] **[submission]** If a genuine first-person observation, hunch, or unresolved gap exists, it is stated in your own voice ("I traced the failure to…") rather than flattened into third-person narration — one is usually there on a real finding, but do not manufacture one to fill this row (reporting.md Rules 15, 20). External submissions only; the internal `report.md` stays impersonal
- [ ] **[both]** No load-bearing fact (the actor's access level, the auth-bypass claim, a specific field value) is stated or proven more than once across Summary, a step preamble, Attack Scenario, and Evidence — each fact has exactly one home, and every other mention references it instead of re-asserting it (reporting.md Rule 21)
- [ ] **[submission]** Actions the operator personally performed are narrated in first person ("I submitted…", "I filed…"), not third-person/passive ("a human filed…", "it was observed…") (reporting.md Rule 20)
- [ ] **[submission]** A genuine gap or unresolved edge case, if one exists, is named plainly in the operator's own voice rather than omitted or hedged into a fully-solved matrix — and stays accurate about what still holds (reporting.md Rule 20)

## Examples

Each entry is tagged **[short/medium/long]** by complexity — pick the tier that matches the finding
you're writing, not just the vuln class. A short reference miscalibrates a report-writer facing a
genuinely multi-step chain: it has no model for how many steps or Evidence blocks are legitimate, and
tends to either under-write (missing proof) or over-write (padding). Reach for **[medium]** or
**[long]** whenever Steps to Reproduce needs more than 3-4 steps or Evidence needs more than one block.

- `agent/references/examples/submission-bugcrowd-idor-invoice-access.md` — **[short]** Bugcrowd IDOR (VRT category, inline request/response proof)
- `agent/references/examples/submission-hackerone-ssrf-webhook.md` — **[short]** HackerOne SSRF (CWE weakness, `poc_code` proof)
- `agent/references/examples/submission-direct-sql-injection-login.md` — **[short]** Direct disclosure SQL injection (no platform-specific fields)
- `agent/references/examples/bugbounty-submission-ldap-injection.md` — **[short]** LDAP injection with a working PoC
- `agent/references/examples/submission-direct-buffer-overflow-fuzz.md` — **[short]** Direct disclosure memory-safety/buffer-overflow from a fuzzing campaign (reachable from `agent/phases/code-phase-4-fuzz.md`)
- `agent/references/examples/submission-hackerone-race-wallet-withdrawal.md` — **[short]** HackerOne race condition (CWE-362, impossible end-state proof, compound `[attacker, concurrent]` actor label)
- `agent/references/examples/submission-bugcrowd-missing-auth-shared-report-bucket.md` — **[medium]** Bugcrowd missing authentication (VRT category, 9 steps, cross-account read of a shared storage bucket via an unauthenticated render endpoint)
- `agent/references/examples/submission-hackerone-authz-shared-widget-query-override.md` — **[long]** HackerOne incorrect authorization (CWE-863, 16 steps, 5-block Evidence section, a shared-dashboard-widget query override that runs under the creator's permission instead of the requester's)
