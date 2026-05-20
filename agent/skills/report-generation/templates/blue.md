<!--
Blue incident report template. Loaded by `report-writer` when
`engagement_type=blue`. Readers: tenant exec stakeholder (§1-3, 9, 10), tenant
security team (all), counsel/compliance (§3, 7, 11). PII ships in Appendix B
out-of-band.

Full anti-slop rule set: `agent/rules/triage.md` §21. The operative banned
blocks are reproduced below. Run the one-screen self-check at the bottom of
this file before delivering.

Do NOT import from red: no CVSS, no PoC / exploit-chain / weaponized vocabulary,
no "Steps to Reproduce" framing (blue cites artifact IDs, not inline payloads),
no red disposition vocabulary leak (`confirmed`/`disputed` stay in the
database).

Tone: §1-3 + §9 plain English for the exec; §4-7 + Appendix A MITRE-cited and
UTC-cited; §8 + §9 imperative with owner + tracker + due date on every line.

================================================================================
SECTION LIMITS (HARD) — referenced from every section header
================================================================================

| Section | Maximum |
|---|---|
| Executive Summary | 200 words, ONE PAGE |
| Incident Overview | 150 words |
| Scope & Authorization | 150 words + tables |
| Timeline | Unbounded, strictly tabular |
| Technical Findings (per finding) | 400 words |
| Attack Reconstruction | 500 words |
| Containment & Eradication Actions | 300 words + table |
| Posture Observations | 300 words |
| Recommendations | 300 words (table preferred) |
| Coverage Gaps & Limitations | 300 words |
| Appendix A (Evidence Index) | Unbounded, strictly tabular |
| Appendix B (Sensitive Annex) | One paragraph in the main report |

If a section needs more space, split the finding or move detail to an artifact.

================================================================================
FORBIDDEN VOCABULARY — operator-readable in 30 seconds
================================================================================

Hedge phrases (signal unverified findings):
  could potentially · may allow · may have · might be · appears to ·
  it seems that · it is possible that · there is a chance · could indicate ·
  could be consistent with · could lead to · might be possible

Filler / transitions:
  Furthermore · Additionally · Moreover · In conclusion · To summarize ·
  It is worth noting that · It should be noted that · It is important to note that ·
  As demonstrated above · As mentioned earlier ·
  During the course of our assessment · Upon further investigation ·
  This finding documents... · The investigation identified... · Analysis revealed... ·
  This finding describes... · This vulnerability allows...

Remediation:
  Improve detection coverage · Enhance MFA posture ·
  Review and update conditional access policies ·
  Implement principle of least privilege · Increase awareness training ·
  Follow security best practices · Implement proper input validation ·
  Use appropriate access controls

Full list + rationale: `agent/rules/triage.md` §21.

AI-tell elimination — do NOT write:
- Rule-out catalogs ("No evidence found of...", "Defender-positive: nothing detected"). State a material negative in one sentence with the evidence ref.
- Probe counts, request volumes, per-step timing outside Technical Findings.
- Cartoonish personas ("a hacker in a basement", "Phantom"). Name the adversary class (criminal, APT, insider, opportunistic) + starting access — stop there.
- Reader instructions ("It is important that the reader understand..."). State the fact.
- Restated header metadata. If MITRE is in the finding header, do not repeat "This finding is categorized as T1078.004" in the description.
- Internal slugs (`F-001`), engagement keys, jj change IDs, raw `aith` output, backend query strings, specialist role names (`alert-triage-specialist`, `incident-verifier`). Use role terms (`the L2 investigation`) or active voice.

Write active voice, named subject. Lead with what the adversary gained. If a sentence can be deleted without losing information, delete it.
-->

# Incident Report — <ENGAGEMENT_TITLE>

> Tenant: `<tenant-slug>` · Platforms: `<gws|m365|aws|okta|edr|network>` · Issued: `<UTC-date>` · Status: `<contained|ongoing|resolved>`

---

## Executive Summary

<!--
LIMIT: 200 words, ONE PAGE. Reader: exec (CISO, GC, director). Plain English.
No MITRE codes. No artifact IDs. No log fragments. Write this LAST.
-->

**Outcome.** <ONE_SENTENCE in business terms. Example: "An external attacker took over the AP manager's M365 mailbox and modified payment-routing replies on an active wire-transfer thread.">

**Scope.** <ONE_SENTENCE — tenant + platforms.>

**Blast radius.** <ONE_SENTENCE — how many users / systems / records / dollars affected.>

**Current status.** <ONE_SENTENCE — contained / ongoing / resolved + the gate that defines the state.>

### Top recommendations

1. <ONE_LINE — short-term action, imperative, named owner.>
2. <ONE_LINE — medium-term hardening, imperative, named owner.>
3. <ONE_LINE — long-term posture shift, imperative, named owner.>

---

## Incident Overview

<!-- LIMIT: 150 words. -->

### What happened
<2-4 sentences. Attacker outcome first; mechanism second. Active voice, named actor. Example: "An attacker authenticated to <user>'s mailbox from a non-baseline IP at 2026-05-15T03:14Z and held the session ~72h. The attacker created a forwarding rule, modified an in-flight wire-transfer reply, and deleted the Sent Items entries.">

### Who detected it
<1-2 sentences. Name the detection control. If multiple controls fired, list them with the lag between fires.>

### When
- Earliest plausible trigger (UTC): `<UTC>`
- Detection fire (UTC): `<UTC>`
- Engagement opened (UTC): `<UTC>`
- Containment complete (UTC): `<UTC or "in progress">`
- Report issued (UTC): `<UTC>`

### Current state
<2-3 sentences. Where the response is right now. What is still open.>

---

## Scope & Authorization

<!-- LIMIT: 150 words + tables. Counsel reads this carefully. -->

| Field | Value |
|-------|-------|
| Tenant / Reference | `<customer-slug>` / `agent/references/tenants/<customer>-<platform>.md` |
| Platforms | `<gws | m365 | aws | okta | edr | network>` |
| Identities / Assets | `<user@tenant>`, ... / `<MAC-12345>`, `<arn:aws:iam::...:user/...>`, ... |
| Authorization (UTC) / By | `<UTC>` / `<title — name → Appendix B if PII>` |

### Out-of-scope exclusions
<Copy verbatim from `agent/references/tenants/<customer>-<platform>.md` § "Out-of-Scope Artifacts". Do not paraphrase.>

### Recent authorized activity windows
<List entries from the tenant ref's "Recent red team / authorized testing windows" so the reader can match adversary-looking telemetry against authorized activity.>

---

## Timeline

<!--
LIMIT: Unbounded but TABULAR ONLY — no narrative between rows.
Chronological oldest-first. UTC with `Z` or `+00:00`. One row per load-bearing
event (drop keep-alives, heartbeats, routine refreshes unless they bracket the
attacker session). Cite an artifact_id under "Evidence ref" — never inline log
lines. Pull from `activity_entries` (`metadata.kind='timeline'`) plus
L2-handoff rows via `assessment_findings.details_json.timeline`.
-->

| UTC timestamp | Observed-via | Evidence ref | MITRE | Event description | Confidence |
|---------------|--------------|--------------|-------|-------------------|------------|
| `<2026-05-15T03:14:22Z>` | m365/signinLogs | `art_<id>` | `T1078.004` | Sign-in to `<user>@<tenant>` from `<IP>` (outside 30d ASN baseline; ASN `<AS#>`) | HIGH |
| `<2026-05-15T03:15:08Z>` | m365/auditLogs/MailboxAudit | `art_<id>` | `T1098.002` | Inbox rule `<rule-name>` forwards `<thread-subject>` to `<external-address>` (recipient → Appendix B) | HIGH |
| `<2026-05-15T03:42:11Z>` | m365/auditLogs/MailItemsAccessed | `art_<id>` | `T1114.002` | Bulk read of folder `<folder>` from same session token | HIGH |
| `<2026-05-17T22:00:14Z>` | operator/respond | `art_<id>` (containment_proof) | — | Session revoked + credential rotated via `Revoke-AzureADUserAllRefreshToken` (proposal `<id>`) | HIGH |

<!-- Shape example. Real timelines run 10-60 rows. -->

---

## Technical Findings

<!--
LIMIT: 400 words PER finding. Split if longer.
- One subsection per finding, severity descending. `false_positive` EXCLUDED
  (their artifacts stay in the index marked scratch).
- One root cause = one finding (see `agent/rules/triage.md` §21). Multiple
  impacts list under one root cause; do not split by impact.
- Render all subfields. Empty field → `[EVIDENCE MISSING]`. Never fabricate.
-->

### Finding — <SHORT_TITLE>

<!-- Human-readable short title. No internal slugs (e.g., `F-001`) in customer-facing prose. -->

| Field | Value |
|-------|-------|
| Disposition / Severity / Confidence | `<verified | downgraded | escalated>` / `<critical | high | medium | low>` / `HIGH | MEDIUM | LOW` |
| MITRE techniques | `<T1078.004>`, `<T1098.002>`, ... |
| Actor / Target | `<identity>@<tenant>` (human owner → Appendix B) / `<mailbox | host | principal | resource>` |
| Time window (UTC) | `<UTC-start> — <UTC-end>` |

#### Plain-English impact
<1-3 sentences. Lead with what the adversary gained, quantified where possible. Active voice. Named actor. No log lines. No artifact IDs in this block. Do not restate the title. Do not restate the MITRE technique that is already in the header.>

#### Evidence reproduction
<Cite the artifact IDs that substantiate the finding. Never paste raw log content here — PII goes to Appendix B; primary logs are referenced by ID.>

- Artifact `<art_id_1>` — `<kind>` — `<one-line description>`
- Artifact `<art_id_2>` — `<kind>` — `<one-line description>`

**Reproduction command** (so the tenant team can re-derive the central evidence from raw audit):

```text
<EXACT command-run that re-derives the central event. Examples:
  Search-UnifiedAuditLog -StartDate "<UTC>" -EndDate "<UTC>" -UserIds "<user>" -RecordType ExchangeItem
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<arn> --start-time <UTC> --end-time <UTC>
  gcloud logging read 'resource.type="gce_instance" AND timestamp>="<UTC>" AND ...' --project <proj>
  okta /api/v1/logs?since=<UTC>&until=<UTC>&filter=actor.id+eq+"<id>"
Cite the `command-run-id` if the original investigator pull is in `assessment_command_runs`.>
```

#### Adversary capability demonstrated
<1-3 sentences. What the adversary proved they could do in this tenant. Example: "The adversary held a valid OAuth refresh token for ≥72h, used it to read mail, create rules, and send replies; the refresh path did not re-evaluate device compliance.">

#### Verification trail (five-check)

| Check | Outcome | Evidence ref | Devil's-advocate rebuttal |
|-------|---------|--------------|---------------------------|
| 1. Reachability | `PASS` | `<art_id>` | <legitimate-actor hypothesis considered + ruled-out evidence> |
| 2. Detection-control corroboration | `PASS` | `<art_id>` | <hypothesis + ruled-out evidence> |
| 3. Config gating | `PASS` | `<art_id>` | <hypothesis + ruled-out evidence> |
| 4. Reproduction or constraint | `PASS (reproduce)` | `<art_id>` | <hypothesis + ruled-out evidence> |
| 5. Devil's advocate | `PASS (survives)` | `<art_id>` | <hypotheses inspected; ruled-out evidence for each> |

<!--
`verified`: every check has cited PASS evidence + a non-empty rebuttal.
`downgraded`: at least one check is DOWNGRADE; name which and what narrowed it.
`escalated`: render the FOR / AGAINST voting summary from the verifier handoff.
-->

#### Cross-platform correlation (when applicable)
<Present only if `scope.json:platforms` > 1. Name the clock-sync assumption (authoritative time field) + the identity-mapping assumption (bridging field: `actor.email`, SAML NameID, OIDC `sub`, AWS principal ARN). Cite the bridging artifact IDs.>

---

<!-- Repeat the per-finding block for each finding. `false_positive` excluded. -->

<...>

---

## Attack Reconstruction

<!--
LIMIT: 500 words. Kill-chain narrative. Use only stages the evidence supports
— do not stub stages without evidence. Cite MITRE per stage and artifact IDs
by ID (not path).

Stages (in order, omit if no evidence): Initial Access · Persistence · Discovery
· Privilege Escalation · Lateral Movement · Collection · Command and Control ·
Exfiltration · Impact.

Cross-platform reconstructions MUST name the clock-sync field and the
identity-bridge field. "The attacker pivoted from M365 to Okta" has no meaning
without both.
-->

### Kill-chain summary
<One paragraph. Named techniques + UTC time markers. Example: "Initial access at 2026-05-15T03:14Z via OAuth refresh-token reuse on a non-baseline IP (T1078.004); within 90s mail forwarding was established (T1098.002), within an hour the folder was bulk-read (T1114.002), and within 36h an attacker-modified reply was sent (T1534). The attacker stayed in-mailbox until session revoke at 2026-05-17T22:00Z.">

### Stage-by-stage
<One `#### <Stage> — <T-id> (<Stage label>)` block per stage with evidence. 2-4 sentences each. Cite artifact IDs. Name the platform feed. Omit stages with no evidence — do not stub.>

#### Initial Access — T1078.004 (Valid Accounts: Cloud Accounts)
<2-4 sentences. Cite artifact IDs.>

#### Persistence — T1098.002 (Account Manipulation: Additional Email Delegate Permissions)
<2-4 sentences. Cite artifact IDs.>

#### Collection — T1114.002 (Email Collection: Remote Email Collection)
<2-4 sentences. Cite artifact IDs.>

#### Exfiltration — T1567 (Exfiltration Over Web Service)
<2-4 sentences. Cite artifact IDs.>

#### Impact — T1657 (Financial Theft) / T1534 (Internal Spearphishing) / etc.
<2-4 sentences. Cite artifact IDs.>

### Cross-platform correlation (when applicable)
<Present only if `scope.json:platforms` has more than one entry.

- **Clock-sync assumption:** <"M365 audit timestamps lead Okta System Log timestamps by ~30s; correlation tolerance set at ±90s."> — from verifier `cross_platform_correlation_notes`.
- **Identity-mapping assumption:** <"`actor.email` in M365 audit maps 1:1 to `outcome.target.alternateId` in Okta System Log; corroborated by artifact <id>."> — from L2/L3 handoff.
- **Bridge gaps:** <users with multiple emails, SP-initiated SAML logins that lost the original session ID, service accounts whose principal does not resolve cross-platform.>>

---

## Containment & Eradication Actions

<!--
LIMIT: 300 words + table. One block per approved action. Pull from
`assessment_command_runs WHERE phase='respond'` and `activity_entries WHERE
metadata.containment_action IS NOT NULL`. Cross-reference proposal +
approval IDs.
-->

### Action — <ACTION_VERB> on <TARGET>

| Field | Value |
|-------|-------|
| Action | `<revoke_session | reset_credential | disable_account | isolate_host | block_ioc | remove_oauth_grant | quarantine_mailbox | rotate_key>` |
| Target | `<user@tenant | host-id | IOC | OAuth client_id | principal-ARN>` |
| Proposal ID / Approval row | `<proposal-id>` / `<activity_entries.id>` |
| Executed (UTC) / by | `<UTC>` / `<operator>` |
| Command-run ID | `<command-run-id>` |

#### Exact command
```text
<COPY VERBATIM from `assessment_command_runs.command`. Examples:
  Revoke-AzureADUserAllRefreshToken -ObjectId <user-objectid>
  aws iam delete-access-key --user-name <user> --access-key-id <id>
  gam user <user@tenant> deprovision noactionifalias
  okta /api/v1/users/<id>/lifecycle/suspend
Read it back from host-exec; do NOT compose or author the command here.>
```

#### Authorization reference
<`activity_entries` row ID + proposal ID + tenant authorization (UTC). Example: "Approved by `<operator>` at 2026-05-17T21:55Z via numbered-choice acknowledgement of proposal `<id>`; approval row `<activity_entries.id>`.">

#### Pre/post artifact diff
- **Pre** — `<art_id>` — `<e.g., "refresh tokens active = 4 for <user> at 2026-05-17T21:54Z">`
- **Post** — `<art_id>` — `<e.g., "refresh tokens active = 0 for <user> at 2026-05-17T22:01Z">`

#### Reversibility note
<1-2 sentences. Reversible? Under what conditions? What reverse command?>

<!-- Repeat one block per approved containment / eradication action. -->

---

## Posture Observations

<!--
LIMIT: 300 words. Root-cause categories: identity / network / endpoint /
process. Cite tenant ref paths + sections. Flag known-benign register entries
that need updating.
-->

### Root-cause categories observed

| Category | Observation | Tenant-ref section |
|----------|-------------|---------------------|
| Identity | <one-line observation, e.g., "OAuth refresh tokens are not re-evaluated against device-trust on refresh; stolen token bypassed CA for session lifetime."> | `agent/references/tenants/<customer>-<platform>.md` §<n> |
| Network | <one-line observation> | `<tenant-ref-section>` |
| Endpoint | <one-line observation> | `<tenant-ref-section>` |
| Process | <one-line observation> | `<tenant-ref-section or "(not in tenant ref)">` |

### Tenant-ref drift to file
- <Pattern observed that the known-benign register does NOT yet document. Cite tenant ref path + proposed section.>
- <Config drift between tenant ref's "Tenant config baseline" and deployed config. Cite the config dump artifact ID.>

---

## Recommendations

<!--
LIMIT: 300 words. Table preferred. Short ≤ 7d / medium ≤ 30d / long ≤ 90d.
Imperative voice. Every recommendation names control + exact fix + owner team
+ tracker + due date (UTC).

Good: "Reduce session-token lifetime to 60 min (currently 24h) — Entra Sign-In
Frequency policy ID <id> — Identity team, by 2026-06-19."

Banned standalone remediation patterns: see `agent/rules/triage.md` §21 (and
the FORBIDDEN VOCABULARY block at the top of this file).
-->

| Horizon | Recommendation | Owner | Tracker | Due (UTC) |
|---------|----------------|-------|---------|-----------|
| Short (≤ 7d) | **<Imperative: control that failed + exact fix.>** | `<team>` | `<project>` | `<UTC>` |
| Short (≤ 7d) | **<Imperative.>** | `<team>` | `<project>` | `<UTC>` |
| Medium (≤ 30d) | **<Imperative.>** | `<team>` | `<project>` | `<UTC>` |
| Long (≤ 90d) | **<Imperative.>** | `<team>` | `<project>` | `<UTC>` |

---

## Coverage Gaps & Limitations

<!--
LIMIT: 300 words. Known unknowns: what evidence could not be pulled, what
would change the verdict if it landed. Cite `coverage_deferral` activity
entries and the L3 handoff's `coverage_gaps` array.
-->

### Telemetry gaps

| Gap | What is missing | What would change | Source |
|-----|-----------------|-------------------|--------|
| <one-line, e.g., "M365 MailItemsAccessed unavailable for first 12h of attacker session — Purview retention lapsed."> | <feed + window> | <verdict that would shift> | `<coverage_deferral activity_entries.id>` |
| <one-line> | <one-line> | <one-line> | `<source>` |

### Log retention boundaries
<One paragraph naming each platform's retention floor and whether the look-back falls inside it. Example: "M365 audit retention for non-E5 caps at 90 days; the 30d look-back is inside retention. Events older than 2026-02-15Z require Purview Premium.">

### Cross-platform correlation limits
<Present only if `scope.json:platforms` has more than one entry. One paragraph naming the clock-sync gap, the identity-bridge gap, and any unresolved bridging questions.>

### Out-of-scope adjacent findings
<One paragraph naming adjacent telemetry that surfaced indicators outside this engagement's scope. These are NOT investigated here. Cross-tenant indicators are recorded as `intel-note` claims; no cross-tenant evidence is imported.>

---

## Appendix A — Evidence Index

<!--
LIMIT: Unbounded, STRICTLY TABULAR. Pull from `assessment_artifacts WHERE
engagement_id=<current> AND scratch=0`. Sort by `kind`, then `relative_path`.
Exclude `false_positive`-only artifacts (they are marked scratch). SHA-256 is
the backend-computed value — do NOT recompute. `--sensitive` rows show kind +
sha + link but suppress the FTS preview; body lives in Appendix B.
-->

| Artifact ID | Relative path | Producer (agent / cmd-run) | SHA-256 | Size | Kind | Linked finding |
|-------------|---------------|----------------------------|---------|------|------|----------------|
| `<art_id>` | `ir/reports/<feed>_<target>_<window>.json` | `<role>` / `<cmd-run-id>` | `<sha256>` | `<bytes>` | `<alert_intake | ir_log | ir_evidence | timeline | ioc_dump | containment_proof | ir_closeout>` | `<finding-slug>` |
| `<art_id>` | `ir/evidence/<topic>.md` | `<role>` / `<cmd-run-id>` | `<sha256>` | `<bytes>` | `<kind>` | `<finding-slug>` |
| `<art_id>` | `ir/reports/<sensitive_export>.csv` | `<role>` | `<sha256>` | `<bytes>` | `<kind>` `--sensitive` | `<finding-slug>` — preview suppressed (see Appendix B) |

<!-- Shape example. Real engagements carry 20-200 rows. -->

---

## Appendix B — Sensitive Annex (separate delivery)

<!-- LIMIT: One paragraph here. The annex itself ships separately. -->

Delivered separately on encrypted channel to `<contact-role-or-name>`. Contents: PII (mapping `actor.email` to human owners), attacker-modified message bodies, credential fragments observed in audit, IP/UPN combinations, and any other PII surfaced during investigation. Distribution list: `<named-recipients>`. Encrypted-channel reference: `<channel-id or PGP-key-fingerprint>`. The main report names the Annex but does not reproduce its contents.

---

<!--
================================================================================
ONE-SCREEN SELF-CHECK — run before delivering
================================================================================

- [ ] Every sentence load-bearing? Delete the ones that aren't.
- [ ] Every finding ≤ 400 words? Split if not.
- [ ] No banned hedge phrases? (grep "could potentially", "may allow", "appears to", "it seems that")
- [ ] No filler transitions? (grep "Furthermore", "Additionally", "Moreover", "In conclusion", "It is worth noting")
- [ ] No AI tells? (no probe counts, no rule-out catalogs, no cartoonish personas, no reader-instructions)
- [ ] No internal slugs / engagement keys / specialist role names in customer-facing prose?
- [ ] Every recommendation has control + fix + owner + due date?
- [ ] Active voice with named subject in every Impact statement?
- [ ] Executive Summary ≤ 200 words, one page?
- [ ] Timeline strictly tabular?

================================================================================
BACKEND QUERIES (run from the engagement directory)
================================================================================

Findings (§5 + §6):   aith assess list-report-findings --mode final --json
                      aith assess fetch findings/<finding-slug>
Timeline (§4):        aith assess fetch 'activity-entries?limit=1000'
                        # filter by metadata.kind / check_number post-pull
Artifacts (App. A):   aith assess artifact search --finding <finding-slug>
                      aith assess artifact get <artifact-id>
Containment (§7):     aith assess list-command-runs --phase respond
                      aith assess get-command-run <command-run-id>
Verification (§5):    aith assess agent list
                      aith assess agent render-handoff <agent-id>
Readiness gate:       operator ran `aith assess transition-phase report`

================================================================================
CLOSING SEQUENCE (blue)
================================================================================

After QA pass (`agent/skills/report-generation/SKILL.md` § Post-Generation
Self-Review), register the rendered file and publish.

False-positive, benign, no-impact, or inconclusive outcomes (closeout path):

    aith assess artifact register closeout.md --kind ir_closeout \
      --agent-id <report-writer-agent-id>

Verified incident outcomes (full report path):

    aith assess artifact register report.md --kind ir_evidence \
      --finding <slug-list-or-engagement-ref> --agent-id <report-writer-agent-id>

Then run § "Publish After QA Pass" — emit `closeout.generated` (closeout path)
or `report.generated` (report path), mark findings `reported`, transition the
engagement to `complete`.
-->
