---
name: alert-triage
description: L1 alert normalization, MITRE-aligned severity recompute, mechanical-FP screening against the tenant ref's known-benign register, and dispatch handoff drafting for the L2 platform specialist
origin: Vigil
---

# Alert Triage (L1)

## When to Activate

- First contact with a pasted alert body that the operator has just landed in
  `scope.json:alert_metadata`.
- A SIEM / SOAR rule fired and you are deciding whether the alert dispatches
  to an L2 platform investigator or auto-closes against the tenant ref's
  known-benign register.
- The operator asks "what is this alert, who is it about, what severity, what
  platform, what does L2 need to know?" — that is the L1 question this skill
  answers in one cycle without running any platform CLI.

L1 does NOT run platform CLIs (no GAM, no gcloud, no Splunk pull). L1 reads
`scope.json`, the alert body, and the named tenant refs; drafts a finding;
and emits a dispatch handoff. Audit pulls, log slices, and reproduction work
belong to the L2 platform specialist this skill hands off to.

## Always-active references

Every L1 dispatch loads these before the first command runs. Skipping any of
them produces malformed handoffs and severity hints that downstream
specialists have to correct under stress.

- `agent/rules/triage.md` — disposition vocabulary, severity ↔ MITRE
  alignment, look-back window, symmetric evidence bar, mandatory mechanical-
  FP citation form.
- `agent/shared-constraints-blue.md` — authorization scope, read-only by
  default, artifact chain of custody, UTC discipline, dispatch handoff
  schema, resume hydration, echo-banner prohibition.
- `agent/rules/ir-evidence.md` — attribution gate; what counts as a
  cross-source corroborating signal for severity rationale.
- The tenant ref(s) named in `scope.json:tenant_reference_paths[]` — the
  customer-specific "known benign patterns" register, the documented admin
  identities, the expected schedules, and the platform-specific common
  patterns. If the tenant ref is missing, halt and return a `blocked`
  handoff naming the missing path (`triage.md` rule 12).

## Tools

L1 is `vigil assess`-only. The platform CLIs (GAM, gcloud, Splunk, Defender)
are off-limits — those are L2 verbs.

- `vigil assess resume-brief` — hydrate engagement state before the first
  classification. Always run this first on continuation; on a fresh
  engagement it returns an empty brief but still records the dispatch
  intent.
- `vigil assess finding record <agent-name> <finding-json>` — draft the
  finding skeleton with severity, MITRE techniques, actor, target, time
  window, platform.
- `vigil assess finding verify <slug> --disposition false_positive` — only on a mechanical-FP match against
  the tenant ref's known-benign register; never on operator hunch.
- `vigil assess artifact search --kind alert_intake` — confirm the operator
  registered the raw alert intake artifact so the chain of custody survives audit.
- `vigil assess log` — record the triage decision (dispatched or
  auto-closed) in `activity_entries` with the actor/target/platform fields
  pulled out so FTS can find them later.
- `vigil assess agent handoff --from-json <path>` — close the L1 dispatch
  with a handoff JSON that names the downstream skill, tenant refs
  consulted, mechanical-FP screen result, and confidence on the
  classification.

Forbidden from L1: `vigil assess host-exec` (that is L2 territory),
`vigil assess kali` (red-only), any direct platform CLI invocation, any
`vigil blue propose-contain` / containment proposal.

## Methodology

### Step 1 — Read the alert from `scope.json`

The alert body lands in `scope.json:alert_metadata` as either:

- `alert_metadata.raw_body` — the pasted text exactly as the SIEM emitted it
- `alert_metadata.parsed` — the operator's pre-parsed fields (rule name,
  actor, target, time, source-signal hint, severity hint)

If both are present, treat `parsed` as the convenience extract and
`raw_body` as the source of truth. If only `raw_body` is present, parse the
fields yourself before the classification step. Do NOT modify
`alert_metadata` in place — it is a read-only record of what the operator
received.

A copy of the raw alert text is written to
`$ENGAGEMENT_DIR/ir/alerts/<external_id>.txt` (where `<external_id>` is the
SIEM rule ID, alert UUID, or a short slug the operator assigned), and
registered as an artifact in Step 7's closing sequence.

### Step 2 — Normalize the alert fields

Pull these out of the alert body into a small JSON the rest of the steps
consume:

| Field | Example | Notes |
|-------|---------|-------|
| `actor` | `user@acme.example`, `okta-user-00uabc`, `arn:aws:iam::123456:user/joe`, `MAC-12345` | Email address OR identity provider ID. If both are present, prefer the canonical IdP identifier and keep the email in `actor_aliases[]`. |
| `target` | account email, host ID, IOC (IP, domain, hash), AWS resource ARN | What the actor allegedly acted against. May be the same as `actor` (e.g., self-grant of OAuth scope). |
| `action` | `signin_anomaly`, `oauth_grant`, `mailbox_rule_add`, `iam_access_key_create`, `host_isolation_triggered` | The verb that fired the rule. Use the platform's native event name when available; otherwise normalize to one of the IR-tag verbs. |
| `time_window_utc` | `["2026-05-17T03:22:14Z", "2026-05-17T03:24:58Z"]` | UTC ISO-8601, ALWAYS. Convert from any timezone the SIEM emitted before storing. The earliest plausible trigger anchors the look-back window (rule 6). |
| `source_signal` | rule name + rule ID + severity hint + detection control name | Whatever the alert source emitted as its rule identity. Preserves provenance for the verifier's Check 2. |

Write this normalization into the finding's `details_json` as a top-level
`alert_normalized` object so downstream agents (verifier, report-writer)
read the same parse you did.

### Step 3 — Classify

Three classifications happen in this step. They feed the dispatch decision
and the severity field on the draft finding.

**Platform classification** — one of:

| Tag | Examples |
|-----|----------|
| `gws` | Google Workspace Admin Reports, Alert Center, Gmail audit, OAuth grants on Workspace tenant |
| `m365` | Microsoft 365 / Entra ID sign-in logs, Defender for O365, Exchange transport rules, SharePoint audit |
| `aws` | CloudTrail, GuardDuty, IAM, Macie, Security Hub |
| `okta` | Okta System Log, MFA factor changes, session events |
| `edr` | CrowdStrike / Defender for Endpoint / SentinelOne / Carbon Black host telemetry |
| `network` | Firewall / proxy / IDS / DNS / VPN telemetry |
| `other` | Anything not in the above set — set `confidence=low` and route to operator for manual L2 selection |

The dispatch decision in Step 6 reads this tag. If the platform is `other`,
the dispatch handoff is `blocked` with `next_steps` naming the platform the
operator needs to add.

**Severity classification** — recomputed from MITRE impact, NOT from the
SIEM's authored `severity_hint`. The mapping is `triage.md` rule 2:

| Severity | Required impact evidence |
|----------|--------------------------|
| `critical` | Confirmed credential theft + active session use, confirmed exfiltration, ransomware encryption in progress, production data store write, golden-ticket / forged SAML in use |
| `high` | Confirmed account takeover, persistence established (mailbox rule, forwarding, OAuth grant, scheduled task), confirmed lateral movement, reconnaissance from inside the tenant |
| `medium` | Suspicious auth anomaly with corroboration but no confirmed action; MFA bypass attempt that did not succeed; scoped-down credential misuse |
| `low` | Single-signal anomaly that passes one IR-evidence gate but not two |
| `info` | Tenant-ref-documented benign pattern; no adversarial signal |

L1 rarely has reproduction evidence yet, so the recomputed severity is the
**ceiling** the L2 investigator will refine. Record it with a rationale
sentence in `details_json.severity_rationale`.

**MITRE techniques** — best-effort list of MITRE ATT&CK technique IDs the
alert pattern suggests. Use sub-technique IDs (`T1078.004` "Cloud
Accounts") when the parent technique has them. The verifier confirms the
list during the five-check; L1's job is to seed it well.

Common starter mappings (not exhaustive — load the relevant tenant ref for
platform-specific defaults):

| Alert pattern | Likely techniques |
|---------------|-------------------|
| Anomalous sign-in from unfamiliar IP | `T1078.004` (Cloud Accounts), possibly `T1110.001` (Password Guessing) |
| New OAuth grant on user account | `T1098.001` (Additional Cloud Credentials), `T1078.004` |
| New mailbox forwarding rule | `T1114.003` (Email Forwarding Rule), `T1098.001` |
| Suspicious AWS IAM access-key creation | `T1098.001`, `T1078.004` |
| EDR detected suspicious PowerShell parent chain | `T1059.001` (PowerShell), `T1086` (deprecated, use sub-ID) |
| Impossible travel | `T1078.004` |
| DLP exfiltration alert (file shared externally) | `T1567.002` (Exfiltration to Cloud Storage) |

`triage.md` rule 11 forbids leaving `details_json.mitre_techniques` empty;
"unclassified" is `T1078` (Valid Accounts) as a fallback, never the empty
array.

### Step 4 — Mechanical-FP screen

Walk the tenant ref's "Known benign patterns" section and look for an
**exact-match** pattern against the alert. The bar is intentionally narrow
— the operator builds the register from prior verifier confirmations, so a
register entry already carries the rigor of a previous five-check pass.

**A match counts only when ALL of these hold:**

1. The register entry is tagged `mechanical: true`. Register entries
   tagged `manual_review: true` (or any tag other than `mechanical`) escalate
   to L2 even if the pattern matches — they exist precisely because a human
   needs to confirm them each time.
2. The actor in the alert matches an **explicit identity** named in the
   register (e.g., `user@acme.example`). Wildcard identities
   (`*@tenant.acme.example`) in the register do NOT satisfy the match
   condition — the register author flagged them with a wildcard because the
   pattern is too broad for auto-close.
3. The action verb in the alert matches the register entry's `action_verb`
   exactly. "Similar" actions (e.g., `oauth_grant` vs `oauth_token_refresh`)
   do not match.
4. The time pattern in the alert matches the register entry's documented
   schedule. "Approximately during business hours" is NOT a documented
   schedule; "every Tuesday 02:00 UTC ± 5 minutes" IS. Mismatched-by-day,
   mismatched-by-hour-of-day, or mismatched-by-month-end-vs-mid-month all
   escalate.
5. The alert's severity hint did not escalate since the register entry was
   last updated. If the SIEM bumped the rule severity from `medium` to
   `high` after the register entry landed, treat the register entry as
   stale and escalate — the verifier needs to refresh it.

If all five hold, auto-close as `false_positive`:

```bash
vigil assess finding verify <draft-slug> --disposition false_positive \
  --kill-reason "Mechanical FP — matches tenant-ref pattern <pattern-id>" \
  --kill-check 0 \
  --inline '{"evidence_refs": [<alert-intake-artifact-id>], "tenant_ref_path": "<path>", "tenant_ref_section": "Known benign patterns / <pattern-id>", "matched_fields": {"actor": "...", "action_verb": "...", "time_pattern": "...", "source_signal": "..."}}'
```

`kill_check=0` is reserved for L1 mechanical FPs (five-check uses 1-5).
The verifier never overwrites a `kill_check=0` row without re-running
its five-check — the convention preserves provenance.

Anything not satisfying all five conditions proceeds to Step 5 — **even if
it looks routine**. First-time observation of a benign pattern is NOT
auto-close material; it is a candidate for the operator to add to the
register after the verifier confirms it.

### Step 5 — Draft the finding skeleton

```bash
vigil assess finding record alert-triage-specialist /tmp/finding.json
```

With `/tmp/finding.json` shaped:

```json
{
  "title": "<one-line headline derived from rule name + actor>",
  "summary": "<two-sentence description: what fired, against whom, when>",
  "severity": "<recomputed from Step 3>",
  "workflow_status": "active",
  "verification_state": "unreviewed",
  "details_json": {
    "platform": "gws|m365|aws|okta|edr|network|other",
    "actor": "<from Step 2>",
    "target": "<from Step 2>",
    "time_window_utc": ["<start>", "<end>"],
    "alert_normalized": { ... full Step 2 normalization ... },
    "mitre_techniques": ["T1078.004", "T1098.001"],
    "severity_rationale": "<one sentence: why this severity, not the SIEM's>",
    "confidence": "low|medium|high",
    "confidence_rationale": "<one sentence>",
    "source_signal": {
      "rule_name": "...",
      "rule_id": "...",
      "detection_control": "...",
      "severity_hint": "..."
    },
    "alert_external_id": "<SIEM alert UUID or operator-assigned slug>",
    "tenant_ref_paths_consulted": ["agent/references/tenants/<customer>-<platform>.md"]
  }
}
```

Capture the returned finding slug for the handoff (Step 6) and the activity
entry (Step 7).

Confidence at L1 is almost always `low` — L1 has not pulled audit data,
has not corroborated cross-source, and has not reproduced the alert. The
exceptions are: (a) the alert payload itself contains corroboration (e.g., the
SIEM bundled two independent rule fires), in which case `medium` is
defensible; (b) the alert's actor or target is already named in a prior
`verified` finding on this engagement, in which case `medium` is again
defensible with a citation. `high` confidence at L1 is never correct —
that label is the verifier's to grant.

### Step 6 — Pick the downstream skill

Map the platform tag from Step 3 to a skill name:

| Platform tag | Skill (status) |
|--------------|----------------|
| `gws` | `google-workspaces` (dispatchable; reference tenant: `acme-workspace.md`) |
| `m365` | `m365-signin-investigation` (dispatchable; requires tenant ref with conditional-access / sign-in policy snapshot) |
| `aws` | `aws-cloudtrail-investigation` (dispatchable; requires tenant ref with account inventory + privileged-role list) |
| `okta` | `okta-investigation` (dispatchable; requires tenant ref with policy / factor enrollment snapshot) |
| `edr` | `edr-alert-triage` (dispatchable; requires tenant ref with EDR product fingerprint + known-quiet host register) |
| `network` | `network-threat-hunt` (dispatchable; requires tenant ref with netflow source inventory + egress allowlist) |
| phishing pattern observed in alert body | `phishing-triage` (dispatchable; requires tenant ref with mail-gateway product + DMARC/SPF/DKIM posture) |
| `other` | no skill — dispatch is `blocked` |

All platform investigation skills are now built and dispatchable. The hard
prerequisite for L2 is a populated tenant ref at
`agent/references/tenants/<customer>-<suffix>.md` — without it, the L2
specialist has no policy / inventory / known-quiet baseline to read against
and degrades to a blind pull. If the tenant ref is missing or stale, L1's
handoff should still name the target skill so the operator's queue records
the gap; bootstrap the ref via `vigil blue tenant init --platform <tag>`
before re-dispatching.

### Step 7 — Closing sequence

Run all four in order:

1. **Confirm the raw alert intake artifact exists:**

   ```bash
   vigil assess artifact search --kind alert_intake --limit 10
   ```

   Raw alert recording is operator-owned and happens before L1 dispatch via
   `vigil blue alert record --body-file <path>`. If no `alert_intake` artifact
   exists, return a `blocked` handoff naming the missing intake record instead
   of re-registering the raw alert yourself.

2. **Record the triage activity entry:**

   ```bash
   vigil assess log \
     <runtime-agent-id> \
     "Triaged alert <alert_external_id> as <platform>/<severity>" \
     "Read alert body; normalized fields; classified platform=<x> severity=<y> mitre=<list>; mechanical-FP screen: <hit|miss>" \
     "Dispatched to <downstream-skill>" \
     --actor-kind agent
   ```

   `metadata_json` on the activity row (set via the backend client wrapper
   or the next iteration of `log`) carries:

   - `tier: L1`
   - `alert_external_id: <id>`
   - `platform: <tag>`
   - `disposition: dispatched | auto-closed`
   - `mechanical_fp_checked: true | false`
   - `confidence: low | medium | high`
   - `mitre_techniques: [...]`

3. **Emit the dispatch handoff JSON** (see Handoff Template below) and
   record it:

   ```bash
   vigil assess agent handoff --from-json /tmp/handoff.json
   ```

4. **One-screen TSV summary** to stdout for the operator (see Output
   Format below).

## Mechanical-FP Bar (decision card)

The screen is intentionally narrow because false auto-close is how a real
incident gets swept under "vendor sync ran again." All five conditions
must hold:

- [ ] Register entry tagged `mechanical: true`
- [ ] Actor in alert matches explicit identity in register (NOT wildcard)
- [ ] Action verb matches register's `action_verb` exactly
- [ ] Time pattern matches documented schedule (NOT "approximately
      business hours")
- [ ] Alert severity hint has not escalated since register entry's
      `last_updated_utc`

Any unchecked box → escalate to L2 with the alert intake artifact registered and the
finding draft recorded `unreviewed`. The operator can promote the alert to
the register later, after the verifier confirms the benign pattern.

The register entry citation in the kill_reason field must include:

- `tenant_ref_path` — full repo path
- `tenant_ref_section` — exact section header
- `pattern_id` — the register's per-entry slug (if the register has slugs;
  otherwise the section header)
- `matched_fields` — actor/action_verb/time_pattern/source_signal that the
  alert produced and the register expected

A vague kill_reason like "matches vendor sync pattern" is not citation. The
verifier rejects it on intake and reopens the finding.

## Handoff Template

```json
{
  "agent_id": "<runtime-agent-id from dispatch banner>",
  "agent_role": "alert-triage-specialist",
  "phase": "triage",
  "handoff_status": "ready",
  "finding_slug": "<from Step 5>",
  "skill_to_load": "google-workspaces",
  "platform": "gws",
  "alert_external_id": "<from Step 2>",
  "actor": "<from Step 2>",
  "target": "<from Step 2>",
  "time_window_utc": ["<start>", "<end>"],
  "mitre_techniques": ["T1078.004", "T1098.001"],
  "severity": "high",
  "confidence": "low",
  "confidence_rationale": "Single-signal; L1 has no audit pull yet.",
  "mechanical_fp_checked": true,
  "mechanical_fp_outcome": "miss",
  "tenant_ref_paths_consulted": [
    "agent/references/tenants/acme-workspace.md"
  ],
  "evidence_refs": [<artifact-id-of-alert-intake>],
  "next_specialist": "investigator",
  "next_steps": [
    "Pull Admin Reports login feed for actor over time_window_utc ± 30d",
    "Cross-check IP against user's 30-day ASN baseline",
    "Search for sibling OAuth grant / mailbox-rule events in same actor session"
  ],
  "coverage_gaps": [],
  "cross_platform_correlation_notes": "",
  "rationale": "<one paragraph: why dispatch to this skill, what L2 should look for first>"
}
```

For a mechanical auto-close, the handoff still goes out — but the shape
changes:

```json
{
  "handoff_status": "ready",
  "finding_slug": "<auto-closed slug>",
  "skill_to_load": null,
  "next_specialist": null,
  "disposition": "false_positive",
  "kill_reason": "Mechanical FP — matches tenant-ref pattern <pattern-id>",
  "mechanical_fp_checked": true,
  "mechanical_fp_outcome": "hit",
  "tenant_ref_paths_consulted": ["..."],
  "evidence_refs": [<artifact-id>],
  "rationale": "Auto-closed at L1 per tenant ref register; no L2 needed."
}
```

`handoff_status` is `blocked` when:

- The tenant ref for the classified platform is missing from
  `scope.json:tenant_reference_paths[]`
- The platform tag is `other` and no skill mapping exists
- The alert body is malformed beyond Step 2's ability to normalize
  (missing actor, missing target, missing timestamp)

A `blocked` handoff names the exact blocker in `next_steps` and does NOT
draft a finding skeleton — the operator resolves the block first.

## Output Format

One-screen TSV summary printed to stdout after the handoff lands. The
operator skims this between dispatches; everything below the TSV is the
durable backend record.

```
alert_id        actor                       target                      severity  platform  mitre               downstream_skill        disposition
ALERT-12345     user@acme.example  user@acme.example  high      gws       T1078.004,T1098.001 google-workspaces       dispatched
ALERT-12346     vendor-sync@acme...  drive.googleapis.com        info      gws       T1078.004           -                       auto-closed
```

Columns:

- `alert_id` — `alert_external_id` from Step 2
- `actor` — Step 2 actor field (truncate to 28 chars + `...`)
- `target` — Step 2 target field (truncate to 28 chars + `...`)
- `severity` — Step 3 recomputed severity
- `platform` — Step 3 platform tag
- `mitre` — comma-separated MITRE technique IDs
- `downstream_skill` — Step 6 skill name (or `-` for auto-closed)
- `disposition` — `dispatched | auto-closed | blocked`

Do NOT echo the Runtime Identity banner above this TSV. The banner is
already at the top of the dispatch prompt; re-emitting it wastes context.

## Common Failure Modes

- **Severity inherited from SIEM hint.** Recompute every time. The SIEM's
  `severity_hint` is advisory only (`triage.md` rule 2). A SIEM marked
  `high` does not mean the L1 finding is `high`.
- **Auto-close on a `manual_review: true` register entry.** Read the
  register tag, not just the section header. Many "Known benign patterns"
  sections mix mechanical and manual-review entries; the tag is the
  discriminator.
- **Wildcard identity passed as mechanical match.** A register entry with
  `actor: "*@tenant.acme.example"` is NOT mechanical-eligible — it is a
  pattern the operator wrote for L2 to filter against, not for L1 to
  auto-close on.
- **`mitre_techniques: []`** on the draft finding. Empty is forbidden by
  `triage.md` rule 11. Use `T1078` as the unclassified fallback.
- **Skipping the alert-intake artifact check.** Without the registered
  artifact, the L2 verifier cannot cite "the alert as originally pasted"
  in its five-check. Block and ask the operator to record intake before L1 proceeds.
- **Echoing the runtime identity banner in the response.** Forbidden by
  `shared-constraints-blue.md`. The handoff JSON carries identity; the
  markdown response is reflection.

## Reference Block

- `agent/rules/triage.md` — disposition vocabulary (rule 3), severity
  recompute (rule 2), mechanical-FP citation (rule 5), 30-day look-back
  (rule 6), MITRE on every finding (rule 11), tenant-ref-first (rule 12).
- `agent/shared-constraints-blue.md` — authorization, read-only,
  artifact chain of custody, UTC, dispatch handoff schema.
- `agent/skills/alert-fp-verification/SKILL.md` — what the L3 verifier
  expects to see in the L2 handoff that the L1 handoff hands forward.
- `agent/skills/case-dispatching/SKILL.md` — coordination patterns this
  skill mirrors (signal → skill trigger, batch routing, completion).
- `agent/skills/google-workspaces/SKILL.md` — the P0 downstream skill in
  v1; the L2 specialist's playbook for `platform=gws` dispatches.
- `agent/references/tenants/<customer>-<platform>.md` — the tenant ref
  whose "Known benign patterns" register the mechanical-FP screen reads.
