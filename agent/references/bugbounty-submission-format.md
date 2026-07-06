---
description: "Bug bounty submission selector + shared authoring rules (voice, PII redaction, PoC authoring, pre-submission checklist); per-platform scaffolds live in templates/{bugcrowd,hackerone,direct}.md"
skill: report-generation
category: Disclosure & Reporting Formats
---

# Bug Bounty Submission Format

Use this when the operator requests a bug bounty submission (Bugcrowd, HackerOne, or similar platform). Each finding is a standalone submission.

## Platform selector

`vigil assess export-submission <slug> --platform <p> --draft` generates the per-finding draft; pick the platform below and use its scaffold for the platform-specific fields. This doc holds the cross-platform authoring rules all three share (voice, section budgets, PII redaction, PoC authoring, de-harnessing, and the pre-submission checklist) — the templates link back here rather than repeating them.

| Target | Scaffold | Platform-specific field |
|---|---|---|
| Bugcrowd | `agent/skills/report-generation/templates/bugcrowd.md` | VRT category + P1–P4 priority |
| HackerOne | `agent/skills/report-generation/templates/hackerone.md` | CWE weakness |
| Direct (company / vendor) | `agent/skills/report-generation/templates/direct.md` | none (VRT / H1 fields dropped) |

For a vendor/CERT disclosure *email* rather than a platform submission, use `agent/references/disclosure-email-format.md` instead.

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
vigil assess update-finding <slug> --submission-status submitted --reason "Submitted to <program>"
```

Update `submission_status` as the program responds (`accepted` / `needs_info` / `rejected` / `duplicate`). This field is orthogonal to `workflow_status` — it tracks program-facing state only and never changes whether the finding is included in the internal report. See "Submission Status Lifecycle" in `agent/skills/report-generation/SKILL.md` for the full sequence.

## Copy-paste workflow

The output is designed to map cleanly onto the platform's submission form. The operator takes the produced file and copies each block into the matching platform field:

- **`VRT:` line** → platform's VRT / Vulnerability Category field
- **`Title:` line** → platform's Submission Title field
- **`POC:` block** → identifies what to attach; omit entirely for inline-only reproductions
- **Everything from `### Summary` down to the end of the file** → platform's Description / Body field

The `---` separator exists so the operator can select the entire body block in one contiguous paste without stripping metadata lines. Do not put anything between the separator and `### Summary` that the operator should not paste into the platform.

## Structure

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**VRT:** [Platform taxonomy category path]

**Severity:** [P1-P4]

[PoC block — see "PoC block" below. Omit entirely for inline-only reproductions.]

---

### Summary
[2-4 sentences. First sentence = attacker outcome. Then the code fault. Then what the POC proves.]

### Steps to Reproduce
[Numbered steps. One action per step. No narrative between steps. Include the run command or
inline requests — whichever form the PoC takes.]

### Evidence
[Key PoC output proving the finding. Annotated with <-- proof markers on critical lines.
Truncated to only the lines that matter. No full tool dumps.
Real customer PII must be redacted — see "PII redaction" below.]

### Attack Scenario
[2-3 sentences. Concrete attacker persona + action + outcome. No theory.]

### Impact
[1-2 sentences. Proven impact only. Quantify by shape/count without exposing raw PII.]

### Remediation
[1-3 items. Primary fix first. One defense-in-depth item at most. No "validate the fix" step.]
```

## PoC block

Choose the form that fits the reproduction. Place the block between `**Severity:**` and the `---` separator. Omit entirely when all reproduction steps are inline requests or commands pasted directly into Steps to Reproduce.

**Inline only — no attachment:**
Omit the block. Steps to Reproduce contains everything the triager needs to run.

**Single file:**
```
**POC:** `<filename>` — attach
**Run:** `<runtime> <filename>`
**Pass if:** <one-line observable success criterion>
```

**Multiple files:**
```
**POC:** `<main>`, `<file2>`, `<file3>` — attach all
**Run:** `<runtime> <main>`
**Pass if:** <one-line observable success criterion>
```

Rules for the PoC block:
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

**Prove it in a clean environment.** Before attaching, re-run the PoC in a fresh shell/clone/account
outside of any agent session, and confirm the submission's output matches that run rather than a
cached one (see the pre-submission checklist below). This is both a correctness check — it proves the
PoC does not silently depend on agent-harness state — and a provenance check: a script that only
works inside the sandbox that wrote it is a script that leaks its own origin.

## Section budgets

These are hard ceilings. A section that exceeds its budget needs to be cut, not wrapped.

| Section | Budget |
|---|---|
| Title | 12 words, single clause |
| Summary | 4 sentences |
| Steps to Reproduce | One sentence per step, no narrative between steps |
| Attack Scenario | 3 sentences |
| Impact | 2 sentences |
| Remediation | 3 items |
| Related Findings (if present) | 1 sentence per cross-reference |
| Deconfliction (if required by program) | 3 lines: researcher ID, source IP, UTC time window |

Sections not in this table (Chain Potential, Defender-positive, Probe Coverage, Architectural Analysis, Fix Validation steps) do not exist in external submissions. If content belongs in one of those categories, it belongs in the internal `report.md`, not the submission.

## Rules

All writing rules from `agent/rules/reporting.md` apply (banned language, active voice, no class definitions, every sentence load-bearing).

### Mandatory fields

- **VRT is mandatory.** Every submission must carry a VRT category path from the platform's taxonomy. An unknown VRT is not an excuse — look it up before submitting. Never leave it blank, "TBD", or "N/A". Bugcrowd uses the VRT at https://bugcrowd.com/vulnerability-rating-taxonomy; HackerOne uses CWE. Pick the most specific category that matches the proved attack.
- **Title must be a single line.** No markdown, no backticks, no internal finding IDs. Use the pattern: `[Bug Class] in [exact component] allows [attacker role] to [impact]`. The title is pasted directly into the platform's title field — anything that looks wrong there is wrong here too.

### PII redaction

A bug bounty submission creates a second copy of the evidence on the platform's infrastructure. Pasting real customer PII exposes those customers a second time without their consent. GDPR/CCPA exposure is non-trivial for the target organization even if the platform is "trusted". Redact before submitting.

- **Never paste raw customer PII** into the submission body, evidence blocks, or screenshots. This covers: full email addresses, phone numbers, case/account/order numbers tied to real users, full names, government IDs, SSNs, addresses, DOBs, payment details, session tokens belonging to real users.
- **Partial masking** is acceptable when shape alone is not convincing: `j***@example.com`, `+1-555-***-4421`, `CASE-12******`. Show enough structure to prove the data is real, not enough to re-identify the customer.
- **Prefer synthetic data.** If the target has a staging tenant, test accounts, or a seed/demo dataset, reproduce the finding against those and use the synthetic PII directly. A clean PoC against a test account beats a redacted PoC against a real account.
- **Internal report vs external submission.** The internal `report.md` may include unredacted evidence under the engagement's authorized scope. External bug bounty submissions must be redacted, because the platform is a third party and the customers whose data is leaked are not parties to the engagement.

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

Verify every item before handing the submission file to the operator. Any failing item blocks the submission.

**Structure and content**
- [ ] `Title:` is a single line, ≤12 words, no markdown/backticks/finding-IDs, follows the title formula — no sub-clauses, no parenthetical product aliases
- [ ] `VRT:` is populated with a specific platform-taxonomy path (not blank, not "TBD", not "N/A")
- [ ] `Severity:` and CVSS score match proved impact — if write operations were rejected by application-layer validation, `I` is not `H`
- [ ] `---` separator is present so the operator can paste the body in one block
- [ ] Body starts with `### Summary` and the summary leads with attacker outcome in sentence 1
- [ ] Evidence contains no raw customer PII (emails, phone numbers, case/account/SSN values, real names). Exposure is proved by shape and count, with partial masking where needed
- [ ] No internal finding slugs, engagement paths, or tool run IDs anywhere in the body
- [ ] Remediation names a specific technology and control, not generic advice — ≤3 items, no "validate the fix" item
- [ ] PoC form matches the reproduction: inline-only → no block; script → PoC block with correct extension, `**Run:**` command, and one-line `**Pass if:**`; multi-file → all files listed in the block
- [ ] The PoC was re-run in a clean environment (fresh clone or fresh account, outside any agent session) and the submission's output matches that run, not a cached result
- [ ] PoC script is minimal — no line exists that does not contribute to the decisive observable; a reviewer unfamiliar with the finding could read it end to end in under a minute
- [ ] No ANSI colors, banner/box-drawing output, or `hdr()`/`pass()`/`fail()`-style status helper functions in the PoC script
- [ ] No docstring-style header block restating the vulnerability class, CWE, or summary at the top of the PoC script
- [ ] No code in the PoC script inspects, unsets, or branches on agent-identifying environment variables (`CLAUDECODE`, `CURSOR_AGENT`, `GEMINI_CLI`, `CODEX_SANDBOX`, `COPILOT_*`, or equivalent) or references the harness/agent that produced it
- [ ] The submission is one script by default; a second file exists only if the exploit requires a second running component, never to hold instructions or narrative
- [ ] Safety framing ("offline", "FAKE token", "localhost-only") appears once, in the setup — not restated at every step; it is kept separate from sentences explaining the vulnerability's mechanism

**Human voice — AI tell elimination (Rule 20)**
- [ ] No "Defender-positive", "Dead ends", "Negative findings", or "What was ruled out" section or sub-section exists anywhere in the submission
- [ ] No probe counts, request volumes, or percentile latencies appear anywhere in the submission body
- [ ] Deconfliction (if present) is ≤3 lines: researcher ID, source IP, UTC time window — no per-phase breakdowns, no marker string lists, no rate pledges
- [ ] Attack scenario uses a realistic adversary class, not a cartoonish persona ("student in a dorm room", "script kiddie") — 3 sentences maximum
- [ ] No sentence instructs the reviewer how to interpret, score, or act on the finding (`"please do not treat"`, `"recorded so triage does not re-investigate"`, `"triage can prioritize"`)
- [ ] No section exists outside the defined structure (no Chain Potential, Architectural Analysis, Fix Validation, Related Findings as multi-paragraph blocks)
- [ ] The word "submission" does not appear in the body prose — use "finding" or "report"
- [ ] CWE, CVSS, or VRT that appear in header fields are not restated or justified inside body prose
- [ ] Related findings (if present) are one sentence each at the end of the submission, not multi-paragraph cross-references
- [ ] No em-dash appears more than once per paragraph; replace surplus em-dashes with a period, comma, or parentheses (em-dash density is a top statistical AI tell)
- [ ] Contractions appear where natural (doesn't, it's, I've, won't) — the prose is not uniformly formal
- [ ] At least one sentence carries a first-person observation or hunch (e.g. "I traced the failure to…") — not uniform third-person narration. (External submissions only; the internal report.md stays impersonal.)

## Examples

- `agent/references/examples/submission-bugcrowd-idor-invoice-access.md` — Bugcrowd IDOR (VRT category, inline request/response proof)
- `agent/references/examples/submission-hackerone-ssrf-webhook.md` — HackerOne SSRF (CWE weakness, `poc_code` proof)
- `agent/references/examples/submission-direct-sql-injection-login.md` — Direct disclosure SQL injection (no platform-specific fields)
- `agent/references/examples/bugbounty-submission-ldap-injection.md` — LDAP injection with a working PoC
