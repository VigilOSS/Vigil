# Triage Rules

These rules are always active on every blue dispatch. They are intentionally compact
but strict: breaking them lowers finding quality and corrupts the audit trail the
verifier and report-writer rely on.

The triage rule is outcome-first: a `verified` finding requires concrete reproduction
or cross-source corroboration of the alleged adversarial activity; a `false_positive`
disposition requires cited benign-pattern evidence at the same rigor bar. Theoretical
alerts (the rule fired, but the activity was not reproduced and no cross-source signal
corroborates it) stay `unreviewed` or escalate. No mechanical auto-close without a
cited tenant-ref pattern. 30-day default look-back, measured from the earliest
plausible trigger — not from "when the user noticed." UTC throughout; convert to
local only when writing narrative for a human reader.

## 1. Outcome before theory

A `verified` finding requires concrete reproduction of the alleged adversarial
activity, OR cross-source corroboration in at least one independent telemetry stream
that re-derives the same actor / target / time-window claim. Examples of acceptable
verification evidence:

- The same actor IP + session token observed on a sibling action in another feed
  (sign-in followed by token-grant followed by mailbox-rule add)
- A re-pull of the platform audit that re-derives the alert's event from raw log
  with full citation (`source_file`, `timestamp`, `actor`, `eventName`)
- A second control (EDR / proxy / DNS) that fired on the same actor in the same window

Theoretical findings — where the rule fired but no reproduction, no cross-source
corroboration, and no benign-pattern evidence is available — stay `verification_state=
unreviewed` or escalate. Do not mark a finding `verified` because the rule "looks
right" or because the actor "is suspicious." See `agent/rules/ir-evidence.md` for
the attribution gate.

## 2. Severity follows MITRE impact, not the alert source's severity hint

The alert source's `severity_hint` is advisory only. Severity on the finding is set
from the MITRE technique and the proved impact, not the SIEM rule's authored label.

| Severity | Required impact evidence |
|----------|--------------------------|
| `critical` | Confirmed credential theft + active session use, confirmed data exfiltration, ransomware encryption in progress, attacker writes to production data store, golden-ticket / forged SAML token in use |
| `high` | Confirmed account takeover, persistence established (mailbox rule, forwarding, OAuth grant, scheduled task), confirmed lateral movement, reconnaissance from inside a tenant identity |
| `medium` | Suspicious authentication anomaly with corroboration but no confirmed action, MFA bypass attempt that did not succeed, scoped-down credential misuse |
| `low` | Single-signal anomaly that passes one IR-evidence gate but not two; defense-in-depth misconfiguration discovered during investigation |
| `info` | Tenant-ref-documented benign pattern; investigation produced no adversarial signal |

If the MITRE technique you assign is detection-only (no impact verb in the tactic — e.g.
`T1078` "Valid Accounts" without a chained `T1114` "Email Collection" or `T1567`
"Exfiltration"), severity cannot be `critical` without a separate chained-impact
finding linked from `details.chain_required=true`.

## 3. Disposition vocabulary — four values, no others

`verification_state` is set by the L3 `incident-verifier` only. The exact vocabulary:

- `verified` — adversarial activity reproduced or cross-source corroborated, with
  cited evidence
- `false_positive` — benign explanation cited from the tenant ref's known-benign
  register OR derived during investigation with the same evidence bar as a verified
  finding
- `downgraded` — adversarial primitive confirmed but proved impact is narrower than
  the rule's original claim (e.g., rule fired on "credential theft" but evidence
  only supports "failed credential probe")
- `escalated` — evidence ambiguous or insufficient; routes to the
  Multi-Perspective Voting Protocol section of `alert-fp-verification` or to
  external escalation (vendor, on-call, legal)

The four values above are exhaustive. `unreviewed` is the lifecycle default, not a disposition — custom values like `partially_verified`, `pending`, or `under_review` break downstream queries.

## 4. Symmetric evidence bar — verify and FP are the same cost

Verbatim from `agent/skills/code-finding-verification/SKILL.md:36`: *"absence of
counter-evidence is not PASS evidence, and plausibility of counter-evidence is not
KILL evidence."*

Translated for blue: **absence of counter-evidence is not enough to verify, and
plausibility of a benign explanation is not enough to false-positive.** A
`false_positive` disposition requires the same citation rigor as a `verified`
disposition — cite the tenant-ref pattern, the change ticket, the on-call calendar
entry, the VPN/MDM log, or the user's confirmation. A vague "this looks like normal
admin behavior" is not a false_positive; it is `escalated` until a citation lands.

## 5. No mechanical auto-close without a cited tenant-ref pattern

L1 may auto-close as `false_positive` only when the alert matches a pattern already
documented in the tenant ref's known-benign register (e.g., `agent/references/
tenants/<customer>-<platform>.md` "Known benign patterns" section). The auto-close
finding must cite:

- The tenant-ref path and section header
- The exact pattern that matched
- The fields in the alert that match the pattern (actor, IP range, time window,
  user-agent, action type)

Anything not on the register escalates to L2 with the platform skill named — even
if it "looks routine." First-time observation of a benign pattern is not auto-close
material; it is a candidate for the tenant ref's known-benign register, which the
operator updates after verifier confirmation.

## 6. 30-day default look-back from earliest plausible trigger

Initial-access events routinely precede user-visible symptoms by 7–30 days. The
default audit window is **T-30d from the earliest plausible trigger**, not from
"when the user reported the alert." Extend on boundary: if anomalous events cluster
near the 30-day edge, push to T-60d before declaring the look-back complete.

Trigger sources in priority order:
1. The earliest log event the alert cites
2. The earliest related event in the same actor's session timeline
3. The earliest related event in the same target's session timeline
4. The user-reported observation timestamp (lower bound only — never the upper bound)

A short look-back is how the initial-access event gets missed and the attack chain
gets reconstructed without its entry point.

## 7. UTC throughout

All log queries, audit pulls, timeline entries, and finding `details_json.timeline`
rows are written in UTC. Convert to local time only when rendering narrative for a
human reader (the final report's executive summary, the operator's screen-side
status). Mixing zones mid-investigation drops events and turns a 5-minute phishing-
to-login window into a phantom gap.

ISO-8601 with explicit `Z` suffix or `+00:00` offset is the only acceptable
timestamp format in evidence files and `assessment_findings.details_json`.

## 8. Cross-tenant artifacts never enter the engagement evidence tree

Artifacts that surface during a pull but belong to a different tenant (different
customer, different platform, different look-back window) do not enter this
engagement's `ir/reports/` or `ir/evidence/`. If a cross-tenant indicator is
investigation-relevant (the same IP hit two customers), record it as `intel-note`
with the cross-tenant claim flagged and the originating tenant redacted — never
copy raw cross-tenant log rows into this engagement.

## 9. Confidence labels on every finding and every activity entry

Every finding and every `activity_entries` row linked to a finding carries an
explicit confidence: `low | medium | high` with a one-line rationale.

| Label | Meaning |
|-------|---------|
| `high` | Multi-signal corroboration; legitimate-actor hypothesis excluded; reproduction available |
| `medium` | Two of three IR-evidence gates pass; one gate incomplete |
| `low` | Single signal; suggestive but not corroborated |

`metadata_json.confidence` and `metadata_json.confidence_rationale` on activity
rows; `details_json.confidence` on findings. A finding without a confidence label
is malformed and report-writer rejects it.

## 10. Smallest probe that answers the question

Prefer the smallest log slice that closes the open question. If you already know
the actor, target, and time window from the alert payload, pull that exact slice —
do not dump tenant-wide windows looking for context.

Examples:
- "Did this user sign in from 80.94.92.234 between 2026-05-15T00:00Z and
  2026-05-16T14:30Z?" — pull `login` for that user over that window, not the entire
  domain's `login` feed
- "Was this OAuth token also used against Drive?" — pull `token` for that
  `actor.email` filtered to the token's `client_id`, not all token events
- "Is this IP in the user's baseline?" — pull the user's 30-day login history and
  build the ASN/region histogram, not the tenant-wide IP allowlist

Wider pulls are warranted when (a) the actor/target/window is ambiguous or (b) a
sibling event search is required by `agent/rules/ir-evidence.md` rule 15
(platform-specific event routing). Document the widening with one line in the
evidence file.

## 11. MITRE techniques on every finding

Every blue finding carries `details_json.mitre_techniques` as an array of MITRE
ATT&CK technique IDs:

```json
"details_json": {
  "mitre_techniques": ["T1078.004", "T1114.001"],
  ...
}
```

Use sub-technique IDs (`T1078.004` "Cloud Accounts") when the parent technique
has them. `mitre_techniques` is what the verifier uses for the severity↔technique
alignment audit (rule 16) and what report-writer uses for the executive summary's
ATT&CK matrix.

`defect_family` is left null for blue findings — that field carries red-shaped
CWE-style vocabulary and does not apply to IR findings.

## 12. Tenant-ref first — missing tenant ref halts the dispatch

Before any platform CLI command runs (GAM, gcloud, az, splunk, crowdstrike,
defender, etc.), the dispatched specialist loads every tenant ref path injected
in the dispatch. If a tenant ref is missing, the dispatch
halts and the specialist returns a `blocked` handoff naming the missing path. Do
not improvise platform calls without the tenant ref — that is the file that tells
you which tool config, which admin email, which DWD scopes, and which known-benign
patterns apply.

## 13. Resume-brief before continuation

On any continuation of an existing finding investigation, run:

```bash
vigil assess resume-brief --finding <finding-slug-or-alias>
```

before dispatching specialists or proposing containment. `agent/rules/resume.md`
is universal across modes; this rule is the blue-specific reminder. Skipping the
resume-brief causes duplicate dispatches against the same finding, loss of kill
rationale recorded in a prior verifier handoff, and stale phase decisions.

## 14. Cross-source correlation on multi-platform incidents

Multi-platform incidents (phishing → GWS → Okta, AWS IAM abuse → GWS Drive
exfiltration) require a timeline in the L2 handoff that correlates events across
both platforms by:

- Shared identity (email, SAML NameID, OIDC sub)
- Shared time window (UTC, sub-minute precision when available)
- Shared IP or shared session token

The verifier flags a missing cross-source timeline as a `coverage_gaps` entry on
the handoff — incomplete correlation blocks `verified` disposition on the
multi-platform finding.

## 15. Devil's advocate is mandatory in verify

`incident-verifier` enumerates at least one alternative explanation per check.
Examples of legitimate-actor hypotheses:

- Delegated mailbox owner reading shared inbox
- MDM scheduled job triggering OAuth re-auth
- Shared NAT egress for a remote office
- Internal red team exercise on the same window
- Vendor maintenance window (Microsoft / Google / Okta routine ops)
- Traveling user on hotel / airport / mobile network
- Conditional-access policy change that altered the user's login pattern

The counter-argument requires the **same evidence bar** as the finding itself
(rule 4). A devil's-advocate hypothesis with no citation is not enough to
false-positive — it is only enough to set the disposition to `escalated`.

## 16. Severity ↔ technique alignment audit before report

Before any report-writer dispatch, query `vigil assess finding list` and verify
each finding's `severity` matches its `details_json.mitre_techniques` and
proved impact:

- A finding whose only MITRE technique is detection-only (e.g., `T1078` "Valid
  Accounts" without a chained `T1114` / `T1567` / `T1490`) cannot be `critical`
  without a separately recorded chained-impact finding
- A finding marked `verified` with `high` severity must cite evidence that
  satisfies rule 2's `high` impact criteria
- A finding marked `false_positive` retains its original severity field but adds
  `details_json.kill_reason` with the tenant-ref citation; severity is no longer
  the load-bearing field once disposition lands

Fix mismatches via `vigil assess finding update <slug> --details-inline
'{"mitre_techniques": [...], "severity_rationale": "..."}'`. A finding whose
severity contradicts its technique makes the report look unverified to the
client.

## 17. Stale-text scrub before publishing

Before report-writer dispatch, read each active finding's `summary` and `details`
text and strip phrases that contradict current state:

- "originally classified as escalated" when the disposition is now `verified`
- "downgraded from critical to high" when severity has shifted twice since
- "pending verifier review" when the finding has a disposition
- "see updated timeline below" when the timeline is now the only timeline

The executable recipe lives in `agent/skills/report-generation/SKILL.md`
Review-and-Fix QA Mode (`vigil assess finding list --json | jq -r .[].slug` loop).
Stale narrative is invisible to backend status fields and ends up in the
incident report verbatim.

## 18. Containment proposals are specific — target, action, rollback

Every containment proposal (recorded via `vigil blue propose-contain` from L4
`ir-lead`) must specify:

- **Target** — the exact account / host / IOC affected (e.g.,
  `user@acme.example`, `MAC-12345`, IP `1.2.3.4`, OAuth client_id
  `8675309-abc.apps.googleusercontent.com`)
- **Action verb** — one of `revoke`, `disable`, `isolate`, `block`, `reset`,
  `remove`, `quarantine`, `rotate`
- **Rollback plan** — the exact reverse command and the conditions under which
  rollback is appropriate (e.g., "if user confirms legitimate session by
  out-of-band channel within 30m, re-enable via `gam user <email> suspended off`")

Vague proposals ("lock down the user," "investigate the host," "contain the
incident") fail the proposal recording. Operator approval is per-action and
per-target — a broad "contain the BEC" approval is not specific enough to
execute.

## 19. Never DELETE evidence — mark scratch, not remove

Even `false_positive` findings keep their artifacts. The artifact index is the
chain-of-custody record; deletion breaks audit. When an artifact turns out to be
investigation-irrelevant or supports a benign pattern:

```bash
vigil assess artifact mark-scratch <artifact-id>
```

Marking scratch keeps the artifact in the backend (SHA-256 preserved, FTS preview
suppressed) but excludes it from resume briefs and report rendering. Never
`rm` raw IR pulls from `ir/reports/` and never `rm -rf` a finding's evidence
directory. False-positive disposition is not a license to destroy evidence.

## 20. Phase exit requires DoD checklist clean

Each blue phase has a Definition-of-Done checklist enforced by
`vigil assess transition-phase` (see operator-core-blue.md DoD section). Phase
exit is gated on:

- All dispatched specialists returned a `ready` or `blocked` handoff (no
  in-flight dispatches without a recorded handoff)
- Every finding produced in the phase has the required fields for that phase
  (triage: severity, MITRE techniques, draft summary; investigate: timeline,
  evidence_refs, coverage_gaps; verify: disposition with cited evidence)
- All durable artifacts produced in the phase are registered in
  `assessment_artifacts` with producer-agent linkage
- Resume-brief renders cleanly for the next phase's specialists

`vigil assess transition-phase <next>` reports the DoD gaps; do not force-
transition without resolving them.

## 21. Writing discipline (anti-slop)

Every blue specialist and the report-writer inherits these rules when producing
any text that lands in a finding, handoff, evidence file, or customer-facing
report. They are not optional. The report template
(`agent/skills/report-generation/templates/blue.md`) cross-references this
section for the operative banned-phrase lists.

### Hedge phrases that signal unvalidated findings

Hedge phrases signal that the finding has not been validated to the point of
actionable certainty. If certainty is missing, the disposition is `escalated`
or `unreviewed` — not a hedged `verified`.

- `could potentially`
- `may allow`
- `may have`
- `might be`
- `appears to`
- `it seems that`
- `it is possible that`
- `there is a chance`
- `could indicate`
- `could be consistent with`
- `could lead to`
- `might be possible`

Preferred pattern: `<actor> performed <action verb> on <target> at <UTC>,
observed via <evidence_ref>.`

### Filler phrases to replace with direct statements

- `Furthermore` · `Additionally` · `Moreover` · `In conclusion` · `To summarize`
- `It is worth noting that` · `It should be noted that` · `It is important to note that`
- `As demonstrated above` · `As mentioned earlier`
- `During the course of our assessment` · `Upon further investigation`
- `This finding documents...` · `The investigation identified...` · `Analysis revealed...`
- `This finding describes...` · `This vulnerability allows...`

If a sentence starts with one of these, delete the lead and state the fact.
Short transitions that carry meaning (`The same session also`, `A second feed
confirms`) are fine.

### Generic remediation that fails the specificity bar

Generic advice is not a recommendation. These fail standalone:

- `Improve detection coverage`
- `Enhance MFA posture`
- `Review and update conditional access policies`
- `Implement principle of least privilege`
- `Increase awareness training`
- `Follow security best practices`
- `Implement proper input validation`
- `Use appropriate access controls`

Every recommendation names the control that failed AND its location, the exact
fix (specific setting / command / policy change), the owner team, and a due
date (UTC). Example: `Reduce session-token lifetime to 60 min (currently 24h)
— Entra Sign-In Frequency policy ID <id> — Identity team, by 2026-06-19.`

### Required patterns

- **Active voice with a named subject.** `Adversary @<actor> hijacked
  user@<victim>'s session at <UTC>` — not `It was determined that the user's
  session was hijacked.` If the actor is unknown, name what is known
  (`An unknown principal from ASN 12345 replayed...`).
- **Outcome-first openers.** The first sentence of every Impact statement says
  what the adversary gained or what was at risk. The finding's existence
  implies "this finding documents X" — skip the implication and state X.
- **Every sentence load-bearing.** If removing a sentence does not reduce the
  reader's understanding, remove it. Common padding to delete: background
  paragraphs explaining what M365 / AWS / Okta / EDR / SIEM *is*; closing
  paragraphs that recap; restating the finding title in the first sentence
  of the description.
- **One root cause, one finding.** If two findings share a single root cause
  (compromised admin account producing both a mailbox rule and an OAuth
  grant), they fold into one finding with multiple impacts listed under it.
  Do not split.
- **No AI tells.** No cataloguing what was ruled out (`No evidence found of...`,
  `Defender-positive: nothing detected`) — if a negative result matters, state
  it in one sentence with the evidence reference. No probe counts, request
  volumes, or per-step timing in narrative sections. No cartoonish personas
  (`a hacker in a basement`); name the adversary class (criminal, APT,
  insider, opportunistic) and starting access, nothing more. No instructing
  the reader (`It is important that the reader understand...`). No restating
  header metadata in prose — if MITRE techniques are listed in the finding
  header, do not say `This finding is categorized as T1078.004` in the
  description.
- **No internal-only artifacts in customer-facing prose.** The blue report
  goes to the tenant. Internal slugs (`F-001`), engagement keys, jj change
  IDs, `vigil` command output dumps, backend query strings, specialist role
  names (`alert-triage-specialist`, `incident-verifier`, `ir-lead`) do not
  appear in customer-facing sections. Speak in role terms (`the L2
  investigation`) or active voice (`we determined`).

### Length discipline

- **Internal IR notes are unbounded** — verbosity is acceptable for L2/L3
  investigation handoffs, evidence files, and resume-brief inputs. Pack the
  detail; the verifier and report-writer need it.
- **Customer-facing reports enforce ceilings** defined in
  `agent/skills/report-generation/templates/blue.md` §"Section limits (HARD)".
  If a section needs more space, split the finding or move detail to an
  artifact — do not exceed the ceiling.

---

## Reference Block

- `agent/rules/ir-evidence.md` — attribution gates, multi-signal corroboration,
  confidence labels on attribution claims, evidence-file conventions, platform-
  specific event routing surprises. Chain-of-custody specifics for raw audit
  data live there.
- `agent/skills/alert-fp-verification/SKILL.md` — the five-check protocol
  (Reachability / Detection-control corroboration / Config gating / Reproduction /
  Devil's advocate) and the Multi-Perspective Voting Protocol that handles
  `escalated` dispositions.
- `agent/shared-constraints-blue.md` — cross-cutting blue constraints: tenant
  scope, read-only-by-default, artifact-index chain of custody, UTC, look-back,
  host-exec audit pipeline, confidence labels, resume hydration, dispatch handoff
  conventions.
- `agent/rules/adversarial-mindset.md` — cross-mode generative rule; the lens
  through which alerts get re-read after the audit pulls land.
- `agent/rules/reporting.md` — platform-agnostic reporting discipline; banned
  hedge phrases, section length limits, severity discipline that applies to
  blue incident reports the same way it applies to red engagement reports.
- `agent/rules/resume.md` — universal resume hydration; `vigil assess resume-brief`
  before any continuation, scoped variants by finding / agent / since.
