---
name: alert-fp-verification
description: L3 five-check verification protocol for blue alerts — symmetric evidence bar, devil's advocate, multi-perspective voting, and the strict four-value disposition vocabulary
origin: Vigil
---

# Alert FP Verification (L3)

This is the production-critical skill for blue mode. It owns the disposition
decision for every alert the L2 investigator hands up. The five checks here
are the blue translation of `agent/skills/code-finding-verification/SKILL.md`
(red mode's five-check); the symmetry rule is identical, the disposition
vocabulary is different (blue uses `verified | false_positive | downgraded |
escalated`), and the evidence sources are telemetry instead of source code.

## When to Activate

- Verifier dispatch on a finding with `verification_state=unreviewed` that
  the L2 platform investigator has populated with `evidence_refs`,
  `details_json.timeline`, and a coverage-gaps list.
- Pre-containment gate — every finding `≥ high` that the L4 ir-lead is
  about to propose containment on must be `verified` first. The verifier
  is the only role that can write a disposition.
- Reopening of a previously dispositioned finding when new evidence
  contradicts the prior verdict (the `finding update --status draft` lifecycle transition
  routes through this skill again).

This skill is for L3 verification only. Initial triage belongs to L1's
`alert-triage`; investigation belongs to L2's platform skill (e.g.,
`google-workspaces`). The verifier is independent of both — the
investigator's annotations are inputs, never trusted on their own.

## Always-active references

- `agent/rules/triage.md` — disposition vocabulary (rule 3), symmetric
  evidence bar (rule 4), devil's advocate mandate (rule 15), severity ↔
  technique alignment (rule 16).
- `agent/shared-constraints-blue.md` — tenant scope, read-only by default,
  artifact chain of custody, UTC, dispatch handoff conventions,
  resume-brief hydration.
- `agent/rules/ir-evidence.md` — attribution gates (named explicitly in
  Checks 1 and 4), multi-signal corroboration definitions, confidence
  labels.
- The tenant ref(s) named in `scope.json:tenant_reference_paths[]` — the
  customer's documented identities, schedules, change tickets, on-call
  calendar, vendor maintenance windows, and known-benign register that
  Check 5's devil's advocate searches against.
- `agent/skills/code-finding-verification/SKILL.md` — the red-mode origin
  of the five-check protocol. Skim it when in doubt about the rigor of a
  Check 1 or Check 4 evidence citation — the standard is identical, only
  the data source differs.

## Tools

- `vigil assess resume-brief --finding <slug>` — hydrate the finding's full
  history before the first check runs. The verifier never re-pulls
  evidence the investigator already registered; it cross-reads the
  registered artifacts.
- `vigil assess artifact get <id>` — pull the registered artifact by ID and
  read its content (raw log JSON, timeline markdown, IOC dump). Always
  resolve evidence by artifact ID; never by local path. A local path is
  not citable across dispatches.
- `vigil assess artifact search "<query>"` — locate corroborating
  artifacts in the engagement's artifact index — sibling pulls in the
  same actor's session, prior verifications of the same actor, change
  tickets, on-call calendar exports.
- `vigil assess host-exec --tool <gam|gcloud|az|splunk|jq|python3|...>` —
  when the verifier needs to **cross-source pull** an additional
  telemetry stream the investigator did not (e.g., the investigator
  pulled `login` audit but did not pull `token` audit, and Check 4
  reproduction needs the token feed). Every cross-source pull lands in
  the audit pipeline with the same envelope as the investigator's pulls:
  `--technique`, `--intent`, `--phase verify`, `--scope-host <tenant>`.
- `vigil assess finding verify <slug>` — record `verified`, `downgraded`,
  or `escalated` disposition with cited evidence. (Note: the CLI's
  `--disposition` flag uses `confirmed | downgraded | false_positive |
  disputed`; the blue vocabulary maps `verified` → `confirmed` and
  `escalated` → `disputed` at the storage layer. Use the
  `--details-inline` object's `disposition` field to record the blue
  vocabulary verbatim for the report-writer.)
- `vigil assess finding verify <slug> --disposition false_positive` — record `false_positive` disposition
  with cited counter-evidence. Enforces required fields
  (`kill_check`, `kill_reason`) before the request leaves the CLI.
- `vigil assess log` — every check outcome is recorded as an
  activity entry with `metadata_json.check_number`,
  `metadata_json.outcome`, `metadata_json.evidence_refs`, and
  `metadata_json.confidence`. The activity log is the verifier's audit
  trail; FTS over `metadata_json` is what the report-writer queries to
  produce the per-finding verification narrative.
- `vigil assess artifact register` — register devil's-advocate research
  notes, voting-request artifacts, and any new evidence the verifier
  pulled with `kind=ir_evidence`.
- `vigil assess agent handoff --from-json <path>` — close the verifier
  dispatch with `disposition`, `evidence_refs`, `coverage_gaps`, and the
  voting outcome (if any).

## Methodology — Five-Check Protocol

### Preamble (verbatim from red-mode origin + blue translation)

Verbatim from `agent/skills/code-finding-verification/SKILL.md:36`:

> *"absence of counter-evidence is not PASS evidence, and plausibility of
> counter-evidence is not KILL evidence."*

Blue translation (PASS → `verified`, KILL → `false_positive`): absence of
counter-evidence is not enough to verify, and plausibility of a benign
explanation is not enough to false-positive. The two dispositions carry
identical evidence cost — a `verified` finding must cite supporting
telemetry at the same rigor a `false_positive` finding cites the
tenant-ref benign pattern or the change ticket. A vague "looks like normal
admin behavior" is not `false_positive`; it is `escalated` until a
citation lands. A vague "the actor seems suspicious" is not `verified`;
it is also `escalated`.

Each of the five checks below produces one outcome:

- **PASS** — supporting evidence at the rigor bar (cited artifact IDs,
  cited tenant-ref entries, cited log slices); the check confirms the
  finding for this dimension.
- **KILL** — counter-evidence at the same rigor bar; the check refutes the
  finding for this dimension.
- **DOWNGRADE** — counter-evidence reduces the alleged impact but does
  not eliminate the adversarial primitive (e.g., the rule fired on
  "credential theft + active use" but evidence only supports "failed
  credential probe").
- **ESCALATE** — evidence fits neither PASS nor KILL at the rigor bar;
  route to the Multi-Perspective Voting Protocol section.

Disposition synthesis after all five checks:

- All five PASS (or PASS-equivalent with cited DOWNGRADE rationale) →
  `verified` (`downgraded` if any DOWNGRADE landed).
- Any one check produces a KILL with same-bar counter-evidence and the
  remaining checks do not contradict the kill → `false_positive`.
- Mixed evidence with at least one ESCALATE that voting did not resolve
  → `escalated` (handoff to operator with FOR/AGAINST summary).
- Symmetric outcomes that cannot be reconciled → ESCALATE (do not
  default to either disposition).

### Check 1: Reachability from external entry

Was the actor on a network/identity path that could reach the alleged
target at the alleged time?

**Process:**

1. Read the finding's `details_json.actor` and `time_window_utc`.
2. From the investigator's registered artifacts, locate the sign-in
   evidence for that actor during that window. Standard sources:
   - GWS Admin Reports `login` feed
   - M365 Entra `signinLogs`
   - Okta System Log `user.session.start`
   - AWS CloudTrail `ConsoleLogin` / `AssumeRole` / token-issued events
   - VPN concentrator / Zero-Trust gateway logs
   - Conditional Access / device-trust gate logs
3. Cross-reference the sign-in IP against:
   - The user's 30-day ASN baseline (the L2 investigator should have
     pulled this; if missing, flag as a coverage gap and ESCALATE — do
     not assume).
   - The customer's documented egress IP ranges in the tenant ref.
   - Threat-intel IP reputation (lazy — confirm via
     `ioc-enrichment` skill if the IP is fresh).
4. Verify the session continuity — did the same session token that
   produced the alleged action also produce a sign-in? Or did the
   action ride a stolen refresh token whose origin session is missing
   from the feed?

**Decision:**

- **PASS (verified-direction):** cite the sign-in artifact ID, the
  session token used, the source IP, and a one-sentence statement
  positioning the IP relative to the user's baseline ("outside 30-day
  ASN baseline; user's prior 90 days are all AS-15169 / US-CA"). Naming
  the sign-in alone is insufficient — the IP/baseline relationship is
  the load-bearing field.
- **KILL (FP-direction):** cite the sign-in artifact ID AND a
  citation that explains the IP as legitimate — VPN exit node listed
  in tenant ref's allowlist, customer's documented satellite office
  in same time window, conditional-access policy that exempts the
  IP range with the named admin justification. The counter-evidence
  must be at the same rigor as the original alert: an artifact ID
  and a tenant-ref section, not a hunch.
- **DOWNGRADE:** sign-in is from an unfamiliar IP but corroborating
  evidence narrows the adversarial primitive (e.g., the user was
  traveling, but the action still used a session not tied to the
  travel device). Severity drops; finding remains `unreviewed`-shaped
  until Checks 2-5 land.
- **ESCALATE:** the sign-in evidence is incomplete or contradictory —
  the investigator pulled `login` but not `token`, the IP geo is
  ambiguous (commercial VPN exit serving both legitimate and abusive
  traffic), the session continuity question cannot be answered from
  the registered artifacts alone. Record the specific ambiguity in
  the check's activity entry and route to voting.

**Activity log entry shape:**

```bash
vigil assess log <agent-id> \
  "Check 1: Reachability for <finding-slug>" \
  "Read artifact <id>; matched actor <email> sign-in at <UTC>; IP <a.b.c.d> outside 30d ASN baseline" \
  "Outcome: PASS — supporting evidence cited" \
  --actor-kind agent
```

`metadata_json` carries `check_number: 1`, `outcome: PASS|KILL|DOWNGRADE|ESCALATE`,
`evidence_refs: [<artifact-ids>]`, `confidence: low|medium|high`.

### Check 2: Detection-control corroboration (upstream guards)

Would another detection control have also fired for the same actor /
target / time window? Silence here is informative but not determinative.

**Process:**

1. Enumerate the customer's deployed detection-control stack from the
   tenant ref. Typical layers:
   - SIEM rules (the originating control)
   - EDR (CrowdStrike Falcon, Defender for Endpoint, SentinelOne)
   - Proxy / SWG (Zscaler, Netskope, Umbrella)
   - DNS (Umbrella DNS, internal RPZ)
   - IdP risk engine (Entra Identity Protection, Okta ThreatInsight)
   - DLP (Microsoft Purview, Google DLP, Symantec)
   - CASB (MCAS / Defender for Cloud Apps, Netskope CASB)
2. For each layer, check whether a corroborating event exists in the
   investigator's registered artifacts. If not registered, run a
   targeted cross-source pull via `vigil assess host-exec` and register
   the new artifact.
3. Specifically ask:
   - Did the IdP risk engine flag the same sign-in as anomalous?
   - Did the EDR see process activity from the same user at the same
     time (a localhost click on a phishing link should produce both
     browser process telemetry and the IdP sign-in)?
   - Did the proxy see DNS / HTTP egress to the IOC the SIEM alerted
     on?

**Decision:**

- **PASS:** cite at least one independent detection control that fired
  on the same actor / target / window with its artifact ID. The
  corroborating event need not be the same severity — a `low` IdP
  risk signal corroborates the SIEM `high` cleanly. Independence
  matters: two SIEM rules feeding off the same audit feed are NOT
  independent corroboration; SIEM + EDR on the same actor IS.
- **KILL:** cite **explicit absence** in a control that *would have*
  fired had the activity been adversarial — e.g., the EDR is deployed
  on the user's only device and would log any browser-initiated
  cookie theft, the EDR was healthy during the window, and the EDR
  produced no events for that user. The kill citation includes:
  artifact ID showing the EDR was healthy (heartbeat / sensor-status
  artifact), the windowed query against the EDR feed, and a
  tenant-ref note documenting the deployment coverage. Silence in a
  control that does NOT cover the relevant surface (e.g., EDR not
  installed on mobile devices, action came from mobile) is not KILL
  evidence.
- **DOWNGRADE:** corroborating signals exist but at narrower scope
  than the original alert claimed.
- **ESCALATE:** the corroborating control's coverage is contested
  (was the EDR truly healthy for that window? was the proxy in
  monitor-only mode for that user?). Route to voting.

**Silence-is-evidence rule:** silence in a control is only KILL
evidence when the verifier can cite the control's coverage of the
specific surface AND its health during the window. Bare "the EDR was
quiet" is not KILL; "the EDR sensor on host MAC-12345 reported
heartbeat every 60s during the alleged window and produced zero
process or network events for user joe.smith — coverage attested by
tenant ref §3.2" IS.

### Check 3: Build configuration / tenant config gating

Is the alleged technique enabled in the deployed baseline? Many alleged
techniques are infeasible because the customer's tenant config gates them
off (no public OAuth grants, no external forwarding, no IAM key creation
outside a privileged role, conditional access blocks all non-corporate
devices).

**Process:**

1. Read the tenant ref's "Tenant config baseline" section for the
   platform in question.
2. Look up the specific config that governs the alleged technique:
   - GWS: OAuth client allowlist, external forwarding policy,
     workspace-wide trust settings, DWD-authorized SAs.
   - M365 / Entra: Conditional Access policies, application
     consent settings, External ID guest settings, mailbox external
     forwarding policy, role assignments.
   - AWS: SCPs, IAM permission boundaries, organization-level
     trust policies, key creation guardrails.
   - Okta: Authentication policies, App-level enrollment, sign-on
     factor requirements, network zones.
3. Pull a fresh dump of the relevant config via
   `vigil assess host-exec` if the tenant ref is older than 7 days OR
   if the alert is `critical`.
4. Verify whether the alleged technique would succeed given the
   current config. Three categories:
   - **Enabled by default + deployed in this tenant** → technique is
     feasible at the tenant-config layer.
   - **Disabled or gated** → technique is infeasible at the
     tenant-config layer; alert evidence must explain how the gate
     was bypassed (or the alert is misclassified).
   - **Conditional** (e.g., gated for most users, exempted for a
     named admin group) → check whether the alert's actor is in the
     exempt group.

**Decision:**

- **PASS:** cite the config dump (artifact ID) showing the technique
  is feasible for this actor on this tenant, OR the tenant ref's
  "baseline" section attesting the same. The verifier-side rigor
  bar is: a config line + a date the config was last verified +
  the actor's relationship to the gating policy.
- **KILL:** cite the config that gates the technique off AND the
  verification that the gate covers this actor. E.g., "Conditional
  Access policy `CA-021` (artifact <id>) requires compliant device
  for all SharePoint sessions; the alerted sign-in used a session
  on a managed device confirmed by Intune (artifact <id>) — the
  external-cookie-theft technique the rule fired on is gated off
  for this actor."
- **DOWNGRADE:** the gate exists but is partial — applies to some
  paths and not others (e.g., CA gates browser sessions but not
  legacy authentication). Severity drops by one tier; finding
  remains live for Checks 4 and 5.
- **ESCALATE:** the config's coverage of the alleged technique is
  contested (vendor docs disagree with tenant config, the policy was
  changed mid-window, the actor was moved between groups during the
  alleged session). Route to voting.

### Check 4: Exploitation feasibility — Reproduce-or-Constraint

The most evidentially demanding check. Two acceptable PASS-direction
outcomes; one acceptable KILL-direction outcome.

**Process — choose A or B:**

**(A) Reproduce the alert pattern in another evidence source.** The
investigator's primary feed showed the event; reproduction means a
sibling feed re-derives the same actor / target / time-window claim
independently.

Standard reproduction shapes:

- The sign-in in `login` is followed within the same session by a
  token-grant in `token`, a mailbox-rule add in `gmail`, or an
  admin-action in `admin` (GWS).
- The Entra `signinLogs` event lines up with a Defender for Cloud
  Apps activity for the same user in the same window (M365).
- The CloudTrail `ConsoleLogin` lines up with a subsequent `iam:CreateAccessKey`
  by the same principal session (AWS).
- A SIEM correlation rule fired across two independent feeds for the
  same actor in the same window.

The reproduction is registered as a new artifact (`kind=evidence`,
`finding=<slug>`) with the cross-source query embedded.

**(B) Prove a specific constraint prevents the alleged exploit
trajectory.** Symmetric to red-mode Check 4's "specific blocking
constraint" — name the constraint and demonstrate the attacker
cannot route around it.

Standard constraint shapes:

- The alleged token-grant required user-consent-prompt visibility on
  a device the user did not have access to during the window
  (registered Intune device list + sign-in device fingerprint
  artifact).
- The alleged data-exfiltration required a Drive scope the user's
  OAuth grants did not include (registered token-feed dump).
- The alleged IAM access-key creation required a role assumption
  the user's permission boundary blocked (registered IAM policy
  dump + simulate-principal-policy artifact).

For constraints, the verifier must enumerate and rule out at least
two bypass routes:

- Encoding / canonicalization mismatches (different audit feeds may
  log different field representations of the same event).
- Pre-condition mutation (TOCTOU on the checked policy state — was
  the policy in effect at the alleged moment, or was it changed
  shortly before).
- Alternative input channels (legacy authentication path, mobile
  app, API token path the gating policy does not cover).
- Chained primitives that satisfy the constraint's precondition
  under attacker control.

**Decision:**

- **PASS (reproduce):** cite the reproduction artifact ID, the
  cross-source query, the matched fields (actor, time, session
  token or IP), and a one-sentence reproduction statement.
- **PASS (constraint absent):** cite that no constraint blocks
  the alleged trajectory AND list the specific constraints you
  considered and excluded (so the next reader knows the check
  was discharged, not skipped).
- **KILL:** cite the constraint AND the two enumerated bypass
  routes that are each closed by specific evidence. "Mitigation
  exists" is not KILL; "mitigation exists AND these N routes
  around it are each closed by [specific evidence]" is.
- **DOWNGRADE:** reproduction is partial (the sibling feed shows
  related but narrower activity — e.g., the sign-in is corroborated
  but the alleged exfil action is not). Severity drops.
- **ESCALATE:** reproduction attempted but the cross-source pull
  returned ambiguous data (e.g., the `token` feed has a 4-minute
  delay against `login`, and the alleged action straddles the
  edge). Route to voting.

### Check 5: Devil's advocate (Trail of Bits FP-check methodology, mandatory)

**ASSUME THE FINDING IS WRONG.** Enumerate at least one legitimate
explanation per the `triage.md` rule 15 list, then attempt to
support it with same-bar evidence.

**Standard legitimate-actor hypotheses (from triage.md rule 15):**

- **Delegated mailbox owner** — the alleged actor is the mailbox
  delegate, reading a shared inbox from their own device. Search:
  Gmail delegate-list pull for the target mailbox; cross-reference
  to actor.
- **MDM scheduled job** — the alleged OAuth re-auth was driven by
  the device's MDM enforcement. Search: Intune / Jamf /
  Workspace MDM policy pull for the device; check whether the
  policy schedules re-auth during the window.
- **Shared NAT / remote office** — the alleged unfamiliar IP is a
  shared egress for a satellite location. Search: tenant ref's
  documented egress IP ranges; corporate IT's network inventory.
- **Internal red team exercise** — the alleged adversarial activity
  is an authorized purple-team or red-team test. Search: the
  customer's red-team calendar (on-call / change-ticket system);
  out-of-band confirm with the security manager.
- **Vendor maintenance window** — Microsoft, Google, or Okta ran
  routine ops that produced telemetry resembling adversarial
  activity. Search: vendor status pages, customer comms with
  vendor support, the vendor's documented maintenance schedule.
- **Traveling user** — the alleged unfamiliar IP is the user's
  hotel, airport, or mobile network. Search: HR travel-approval
  records; user's calendar; out-of-band confirm with the user.
- **Conditional access policy change** — a recent CA / Okta sign-on
  policy edit altered the user's login pattern, and the SIEM rule
  is still calibrated to the prior baseline. Search: tenant config
  change history; CA policy version artifact.

**Rigor requirement (verbatim from red-mode Check 5):** A DA
counter-argument must meet the same evidence bar as the original
finding. The investigator provided MITRE technique, actor + target +
time, evidence_refs from registered artifacts, and a confidence
rationale. Your counter-argument must be equally specific: the exact
register entry, the exact change ticket, the exact maintenance
window URL, the exact delegate-list entry, the exact travel-approval
record. Circumstantial evidence — "this looks like routine vendor
activity" — is not sufficient to false-positive.

**Outcome:**

- **PASS (survives):** cite what you tried to disprove across the
  legitimate-actor hypotheses, the evidence you inspected for each,
  and why each hypothesis fails. Silence across the hypotheses is
  not survival — silence is undischarged. The verifier states
  explicitly "considered delegated-mailbox: ruled out per Gmail
  delegate list artifact <id>; considered MDM-scheduled: ruled out
  per Intune policy artifact <id>; considered red-team: ruled out
  per change-ticket artifact <id>" etc.
- **KILL (DA succeeds with same-bar evidence):** record the
  hypothesis, the cited evidence (artifact IDs + tenant-ref sections
  + change-ticket numbers), and the explanation of why this
  legitimate-actor explanation accounts for every piece of the
  alert's evidence.
- **DOWNGRADE:** a partial hypothesis explains part of the alert's
  evidence (the unfamiliar IP is the user's travel network) but
  not all (the post-sign-in mailbox-rule add is not explained).
  Severity drops; finding remains live.
- **ESCALATE:** counter-argument is plausible but rests on
  assumptions — the user has not yet confirmed travel, the change
  ticket exists but for a different scope. Route to voting.

## Symmetric Evidence Rule (callout)

> A finding survives only if Checks 1-4 each produce PASS or DOWNGRADE
> evidence and Check 5's counter-arguments are rebutted with
> same-bar counter-evidence.
>
> A finding flips to `false_positive` only if at least one check produces
> KILL evidence at the original-finding rigor bar, AND no other check
> contradicts the kill with comparable evidence.
>
> Disposition by elimination is forbidden. "I could not find evidence to
> support the finding" is not KILL; it is ESCALATE pending the missing
> evidence pull. "I could not find a benign explanation" is not PASS; it
> is ESCALATE pending the devil's-advocate work.

The rule is symmetric: PASS evidence and KILL evidence have the same
rigor bar. The verifier does NOT get to discharge a check by inertia in
either direction.

## Disposition Vocabulary — four values, no others

Verbatim from `agent/rules/triage.md:53-70`:

| Disposition | Meaning | Evidence required |
|-------------|---------|-------------------|
| `verified` | Adversarial activity reproduced or cross-source corroborated | Check 1-4 PASS (or PASS-with-DOWNGRADE); Check 5 survives with cited disproof attempts |
| `false_positive` | Benign explanation cited at finding's rigor bar | At least one check KILL with same-bar counter-evidence; no contradicting evidence in other checks; `kill_reason` + `kill_check` populated |
| `downgraded` | Adversarial primitive confirmed but narrower impact than rule's claim | At least one check DOWNGRADE; remaining checks PASS or DOWNGRADE; severity reduced; `details_json.severity_rationale` updated |
| `escalated` | Evidence ambiguous; routes to multi-perspective voting OR external escalation (vendor, on-call, legal) | At least one check ESCALATE that voting did not resolve; FOR / AGAINST summary in handoff |

Forbidden vocabulary: `partially_verified`, `pending`, `unknown`,
`under_review`, `confirmed-but`, anything not in the four-value list.
`unreviewed` is the lifecycle default and is never a disposition.

The CLI's `finding verify --disposition` flag uses the legacy
red-mode vocabulary (`confirmed | downgraded | false_positive |
disputed`). The blue mapping is:

- `verified` → `--disposition confirmed` + `--details-inline '{"disposition": "verified", ...}'`
- `false_positive` → `vigil assess finding verify --disposition false_positive` (preferred — enforces
  required fields)
- `downgraded` → `--disposition downgraded` + `--new-severity <new>`
- `escalated` → `--disposition disputed` + `--details-inline '{"disposition": "escalated", "voting_summary": "..."}'`

The report-writer reads `details.disposition` (blue vocabulary) for
narrative, not the CLI's storage field. Keep both in sync.

### Recording dispositions — CLI templates

`verified`:

```bash
vigil assess finding verify <slug> \
  --disposition confirmed \
  --reason "Five-check complete: Checks 1-4 PASS, Check 5 survives" \
  --evidence-ref <artifact-id-1>,<artifact-id-2>,<artifact-id-3> \
  --details-inline '{
    "disposition": "verified",
    "five_check": {
      "check_1": "PASS",
      "check_2": "PASS",
      "check_3": "PASS",
      "check_4": "PASS",
      "check_5": "PASS"
    },
    "evidence_refs": [<id-1>, <id-2>, <id-3>],
    "confidence": "high",
    "confidence_rationale": "Three independent telemetry streams corroborate; legitimate-actor hypotheses ruled out per artifact <id-3>"
  }'
```

`false_positive`:

```bash
vigil assess finding verify <slug> --disposition false_positive \
  --kill-reason "Mailbox rule add was the delegate's routine — Gmail delegate-list confirms" \
  --kill-check 5 \
  --reason "DA hypothesis confirmed: delegated mailbox owner" \
  --evidence-ref <artifact-id-delegate-list>,<artifact-id-tenant-ref> \
  --details-inline '{
    "disposition": "false_positive",
    "kill_check": 5,
    "kill_reason": "Mailbox rule add was the delegate user@acme.example; delegate-list artifact <id> attests; tenant ref §4.1 documents this delegation pattern as benign",
    "evidence_refs": [<id-delegate-list>, <id-tenant-ref>],
    "da_hypothesis_confirmed": "delegated_mailbox_owner"
  }'
```

`downgraded`:

```bash
vigil assess finding verify <slug> \
  --disposition downgraded \
  --new-severity medium \
  --reason "Check 4 DOWNGRADE: reproduction confirms sign-in anomaly but not exfil action" \
  --evidence-ref <artifact-id-1>,<artifact-id-2> \
  --details-inline '{
    "disposition": "downgraded",
    "original_severity": "high",
    "new_severity": "medium",
    "severity_rationale": "Sign-in from unfamiliar IP confirmed (Check 1 PASS) but no subsequent OAuth grant or mailbox-rule activity in session (Check 4 DOWNGRADE)",
    "five_check": { ... }
  }'
```

`escalated`:

```bash
vigil assess finding verify <slug> \
  --disposition disputed \
  --reason "Check 5 ESCALATE: travel-approval ticket exists but covers different window" \
  --details-inline '{
    "disposition": "escalated",
    "voting_summary": {
      "FOR": "Sign-in IP outside ASN baseline; post-signin mailbox-rule unexplained",
      "AGAINST": "Travel-approval ticket #4521 covers 2026-05-15 to 2026-05-22; sign-in IP geo-resolves to listed destination city",
      "BLOCKER": "Travel-approval window ends 2026-05-22T17:00Z; alert sign-in at 2026-05-22T22:14Z — 5h after ticket end. Need user confirmation of late return."
    },
    "next_action": "Out-of-band user confirmation of travel return time"
  }'
```

## Multi-Perspective Voting Protocol

Entered when any of Checks 1-5 returns ESCALATE. The voting protocol is
intentionally identical in shape to red-mode's: a second verifier
dispatch with explicit disagreement scope, then operator decision.

**When to invoke voting:**

- Reachability evidence is incomplete (the L2 investigator did not pull
  a sibling feed, and the cross-source pull the verifier ran returned
  ambiguous data).
- A detection control's coverage of the relevant surface is contested.
- A tenant config gate's effective state during the alleged window
  cannot be re-derived from the artifacts.
- A reproduction attempt landed partial cross-source evidence.
- A devil's-advocate hypothesis is plausible but rests on assumptions
  (e.g., user travel not yet confirmed out-of-band).
- The legitimate-actor explanation requires implicit invariants the
  tenant ref does not document.
- Two reasonable IR analysts could disagree on the disposition.

**Voting procedure:**

1. **Document FOR the finding:**
   - Investigator's evidence_refs and timeline
   - Verifier's Check 1-4 PASS outcomes (or PASS-with-DOWNGRADE)
   - Why the devil's advocate counter-argument is incomplete
2. **Document AGAINST the finding:**
   - DA hypothesis from Check 5
   - Specific artifact IDs supporting the counter-argument
   - The assumption(s) the counter-argument depends on
3. **Present both perspectives to the operator** with the verifier's
   recommendation and confidence level.
4. **Operator may dispatch a second verifier** with both perspectives
   and the named ESCALATE'd check. The second verifier reads the same
   artifacts independently and produces its own PASS/KILL/DOWNGRADE
   on the contested check.
5. **Majority of two-of-three decides** (original verifier + second
   verifier + operator). Record the vote in the activity log and the
   handoff.

**Voting request format:**

```
VOTING REQUEST: <finding-slug>
ESCALATED CHECK: <1-5>
FOR:    <one-paragraph: evidence supporting verified>
AGAINST: <one-paragraph: evidence supporting false_positive>
RECOMMENDATION: <verifier's lean — verified | downgraded | false_positive — with confidence label>
BLOCKER: <what specific evidence would resolve the ambiguity>
RECOMMENDED NEXT PULL: <the cross-source query that would close the gap>
```

The voting request lands as a registered artifact (`kind=ir_evidence`,
`finding=<slug>`) so the operator and the second verifier can read it
without re-deriving the framing.

## Activity Log Convention

Every check outcome produces one `activity_entries` row with the
following `metadata_json` shape:

```json
{
  "check_number": 4,
  "outcome": "PASS",
  "outcome_subtype": "reproduce",
  "evidence_refs": [<artifact-ids>],
  "confidence": "high",
  "confidence_rationale": "<one sentence>",
  "tier": "L3",
  "finding_slug": "<slug>",
  "alert_external_id": "<id>",
  "mitre_techniques": ["T1078.004", "T1098.001"]
}
```

The FTS index on `activity_entries` searches the structured metadata
fields. The report-writer queries
`metadata_json.check_number` and `metadata_json.outcome` to render the
per-finding verification narrative section. Skipping the check-level
activity entries makes the verifier's work invisible to the report;
include them for every check, including ones that PASS quickly.

## Closing Sequence

The verifier's dispatch closes with the following steps in order. Skipping
any step breaks resume-brief, the artifact chain of custody, or the
handoff schema.

1. **Record the disposition** via `finding verify` — `--disposition confirmed|downgraded|disputed`
   (verified, downgraded, escalated) or `--disposition false_positive` (false_positive). The `--details-inline` object
   carries the blue vocabulary in `details.disposition` even when the
   CLI's `--disposition` flag uses the legacy red vocabulary.
2. **Register devil's-advocate research notes** if Check 5 produced
   substantive notes (delegate-list dump, change-ticket export,
   on-call-calendar slice). Register as
   `kind=ir_evidence`, `--finding <slug>`.
3. **Register the voting-request artifact** if a check ESCALATEd. The
   artifact is the durable record of the FOR/AGAINST framing.
4. **Run severity ↔ MITRE alignment** per `triage.md` rule 16. If
   `severity` no longer aligns with `details.mitre_techniques` (e.g.,
   downgraded from `critical` to `medium` but the technique list still
   reads `T1486` ransomware), update the finding via
   `finding update <slug> --details-inline '{"mitre_techniques": [...],
   "severity_rationale": "..."}'`.
5. **Record the closing activity entry:**

   ```bash
   vigil assess log <agent-id> \
     "Verification closed: <finding-slug> → <disposition>" \
     "Five-check complete; <N> PASS, <M> KILL, <K> DOWNGRADE, <L> ESCALATE" \
     "Disposition: <verified|false_positive|downgraded|escalated>" \
     --actor-kind agent
   ```

6. **Emit the handoff JSON** with `disposition`, `evidence_refs`
   (artifact IDs, NEVER local paths), `coverage_gaps` (open items the
   verifier could not close), `mitre_techniques`,
   `tenant_ref_paths_consulted`, and a one-paragraph
   `cross_platform_correlation_notes` if `scope.json.platforms` has
   more than one entry.
7. **Self-check** with `vigil assess agent render-handoff <agent-id>`.
   A 404 means the `agent_id` did not match the dispatch row; fix and
   re-handoff before returning.

## Common Failure Modes

- **Skipping the activity-entry-per-check.** The verifier's work is
  invisible to FTS and the report-writer if every check outcome is not
  logged. One activity entry per check is the floor, not the ceiling.
- **Letting CLI's `--disposition` storage vocab leak into the report
  narrative.** Storage uses `confirmed | disputed`; narrative uses
  `verified | escalated`. Always carry the blue vocab in
  `details.disposition`.
- **`kill_check=0` on a verifier disposition.** That value is reserved
  for L1 mechanical FPs. Verifier KILLs use `kill_check` ∈ {1..5}
  naming the check whose KILL evidence drove the disposition.
- **Citing local file paths in `evidence_refs`.** Always artifact IDs.
  A local path cannot survive resume hydration in the next dispatch.
- **Disposing by elimination.** "Couldn't find evidence" is not KILL.
  "Couldn't find a benign explanation" is not PASS. Both are ESCALATE
  pending the missing pull.
- **Skipping voting on a real ESCALATE.** The verifier does not have
  unilateral authority to disposition an ambiguous finding; the
  voting protocol is the discipline that keeps disposition decisions
  honest under pressure.

## Reference Block

- `agent/skills/code-finding-verification/SKILL.md` — red-mode origin of
  the five-check; the symmetric evidence rule (line 36) is verbatim
  the same in blue.
- `agent/rules/triage.md` — disposition vocabulary (rule 3), symmetric
  evidence bar (rule 4), devil's advocate mandate (rule 15), severity
  ↔ technique alignment (rule 16).
- `agent/shared-constraints-blue.md` — dispatch handoff conventions,
  resume hydration, artifact chain of custody, audit pipeline.
- `agent/rules/ir-evidence.md` — attribution gates, multi-signal
  corroboration definitions, confidence labels on attribution claims.
- `agent/skills/alert-triage/SKILL.md` — the L1 skill that produced
  the draft finding; the verifier reads the L1 handoff's mechanical-FP
  outcome and L2 handoff's evidence_refs as inputs.
- `agent/skills/ioc-enrichment/SKILL.md` — support skill the verifier
  invokes when an IP, hash, or domain in the evidence needs
  reputation lookup before Check 1 or Check 2 lands.
- `agent/skills/incident-containment/SKILL.md` — downstream L4 skill
  that activates only on `verified` ≥ `high` (or operator-forced
  containment on `downgraded`).
- `agent/references/tenants/<customer>-<platform>.md` — the tenant
  ref whose Known-benign register, documented egress, and configured
  policies the five checks read against.
