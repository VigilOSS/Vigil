# IR Evidence & Attribution Rules

These rules are always active during blue-team IR engagements. They govern how agents
interpret audit telemetry, attribute actions to actors, and write evidence claims.
They apply regardless of which platform-specific skill is loaded (Google Workspace,
M365, AWS, endpoint).

## 1. Attribution requires multi-signal corroboration — IP alone is not enough

An unfamiliar IP in an audit log is a lead, not a conclusion. Before classifying an
event as adversarial, the agent must satisfy at least two of the following three gates:

| Gate | What it proves | How to check |
|---|---|---|
| **IP is not in the user's baseline** | The session did not originate from the user's normal network | Compare against the user's ASN/region history across the full look-back window. Check for VPN, travel, tethering, shared-mailbox delegates, and corporate egress. |
| **Corroborating anomaly exists** | Something else about the session is wrong, not just the source | A second independent signal: unusual user-agent, impossible-travel timing, action type the user has never performed, `is_suspicious=true` flag, concurrent session from a known-good IP doing different work. |
| **Legitimate-actor hypothesis tested and excluded** | The event is not the user on an unexpected network | Ask the user or a colleague out-of-band whether they recognize the IP, device, or action. Check whether the ASN belongs to a known VPN provider, mobile carrier, or corporate proxy the organization uses. |

Passing one gate raises suspicion. Passing two gates supports an attribution claim.
Failing to check any gate before asserting "attacker did X" is a methodology failure
that produces findings the client has to correct under stress.

**The cost asymmetry matters.** Misattributing a legitimate user's action as adversarial
causes unnecessary panic, credential rotations, and loss of investigator credibility.
Misattributing an attacker's action as legitimate causes a missed detection. Both are
bad, but only multi-signal corroboration defends against both failure modes — single-
signal attribution defends against neither.

## 2. Distinguish what an event proves from what you infer

Audit events are facts about system state transitions. They are not narratives. An
agent must separate the three layers cleanly:

| Layer | Example | Allowed in |
|---|---|---|
| **Fact** | `2026-04-22T06:02:22Z delivery from IP 80.94.92.234, subject "Re: Commercial Deposit Rates", destinations payments@bank.example` | Evidence files, timelines, raw citations |
| **Attribution** | "The attacker sent this email" — supported by: IP matches the persistent attacker node across 15 days, IP is not in the user's baseline, action occurred during an active attacker session window | Evidence files with explicit reasoning |
| **Interpretation** | "The attacker was attempting bank account manipulation" — supported by: subject is a reply into a financial thread, content unknown without body inspection, classification is SUSPICIOUS until body/recipient confirmation | Report sections, clearly marked as inference |

Never collapse these layers. "The attacker sent a fraudulent email to CFG Bank" packs
a fact, an attribution, and an interpretation into one sentence — and the interpretation
(fraudulent) is unverified. Write: "IP 80.94.92.234 sent a reply on the existing
'Commercial Deposit Rates' thread to payments@bank.example at 06:02:22Z. Content
classification requires body inspection and recipient confirmation."

## 3. Every claim cites source file, timestamp, IP, actor, and eventName

A claim without a citation is an opinion. Every factual assertion in an evidence file
or timeline must include:

- **Source file** — the raw JSON/CSV in `ir/reports/` that contains the event
- **Timestamp** — UTC, to sub-second precision when the source provides it
- **IP address** — the `ipAddress` field from the audit event
- **Actor** — the `actor.email` from the audit event (this is the authenticated session, not necessarily the human)
- **Event name** — the `eventName` or `type/name` pair from the audit event

If any of these five fields is missing from the source event, note the absence
explicitly rather than omitting the citation. Some platforms suppress IP on server-side
actions (`ip=null` in Google Drive backend events) — document this rather than
guessing.

## 4. Temporal proximity is evidence, not proof

Two events close in time may be causally related or coincidental. Temporal proximity
strengthens an attribution when combined with other signals (same IP, same session,
same actor) but does not establish causation alone.

Use temporal proximity correctly:
- "The blocked_sender_change at 08:40:10Z from 80.94.92.234 preceded the first Stripe
  outbound by ~22 hours, consistent with notification suppression before fraud" — good,
  states the timing relationship and the hypothesis it supports
- "The attacker blocked Stripe notifications to prepare for the fraud email" — bad,
  asserts causation without marking it as inference

## 5. Session continuity is stronger evidence than IP matching

A sequence of events from the same IP within a continuous session window (no login
event between them, consistent timing cadence) is stronger attribution evidence than
isolated events from the same IP separated by hours or days. The reason: an IP can be
reassigned, shared, or NAT'd, but a continuous session implies a single authenticated
context.

When building timelines, identify session boundaries:
- Login events (`login_success`, `authorize`) open a session
- Logout events, `login_failure` after a password reset, or `signOut` close one
- Long gaps (>4 hours of silence) between events from the same IP suggest a session
  boundary even without an explicit logout

## 6. Classify events before attributing them

Before asking "who did this?", ask "what does this event actually represent?"

| Event characteristic | What it tells you | Common misread |
|---|---|---|
| `mail_event_type=28` (outbound delivery) | A message was sent from this mailbox | Does not reveal whether content was composed by the session holder or sent from a pre-existing draft |
| `mail_event_type=31` (inbound delivery) | A message arrived in the mailbox | Does not mean the user read it; it means the MTA delivered it |
| `mail_event_type=7` (sent-message copy) | Gmail stored a copy in Sent | Does not prove the user composed the message — auto-forwards and delegated sends also produce sent copies |
| `blocked_sender_change` | A sender was blocked or unblocked | Event lives in `applicationName=login`, not `gmail` — searching only `gmail` misses it |
| `authorize` on a token | An OAuth token was granted | Does not mean a new device — Chrome re-authorizes on session refresh |
| `view` on a Drive file | The file metadata was accessed | Does not prove the content was read — preview pane triggers `view` |
| `download` on a Drive file | The file was downloaded to the session's device | This is the exfiltration signal, not `view` |

This list is not exhaustive. The principle is: read the event specification for the
platform before writing what the event "means."

## 7. IP reputation is context, not verdict

An IP belonging to a hosting provider, VPN, or foreign ASN is suspicious context. It
is not proof of adversarial origin. Many organizations have:
- Remote workers on residential ISPs in unexpected countries
- Contractors on cloud-hosted VDI (AWS, Azure, GCP IPs)
- Executives on hotel/airport/mobile networks with unfamiliar ASNs
- Shared mailboxes with delegates across multiple offices

Before writing "attacker IP," verify the IP is not in the organization's normal
operating set. The check is: pull the user's login history for the full look-back
window and build their ASN/region baseline. An IP that appears once, from a hosting
ASN, during the incident window, performing actions the user does not normally perform,
with no legitimate explanation after out-of-band verification — that is an attacker IP.

## 8. Distinguish "sent from attacker session" from "attacker-composed content"

When an attacker holds a stolen session, they can:
- Compose and send new messages (attacker content)
- Open and send pre-existing drafts the user had staged (user content, attacker-dispatched)
- Reply to existing threads with attacker-modified content (mixed attribution)
- Forward existing messages to external addresses (exfiltration)

The Gmail audit log records that a delivery event occurred from an IP. It does not
record whether the message body was typed by the session holder or was a pre-existing
draft. Before classifying outbound email as "attacker-composed," verify:
- The message was not a draft the user had pending (ask the user)
- The subject or recipients are inconsistent with the user's normal workflow
- The content (if recoverable via DWD/Vault) contains attacker-specific artifacts

Until body/content verification is complete, classify as "attacker-dispatched from
stolen session" rather than "attacker-composed fraud email."

## 9. Confidence labels are mandatory on attribution claims

Every attribution claim in evidence files and reports must carry a confidence tag:

| Label | Meaning | When to use |
|---|---|---|
| **CONFIRMED** | Multi-signal attribution verified; legitimate-actor hypothesis excluded | IP outside baseline + corroborating anomaly + user confirmed not them |
| **HIGH CONFIDENCE** | Strong signals but one gate incomplete | IP outside baseline + corroborating anomaly, user not yet asked |
| **SUSPICIOUS** | Single signal or ambiguous corroboration | Unfamiliar IP but no corroborating anomaly yet, or timing is suggestive but not conclusive |
| **UNCLASSIFIED** | Insufficient evidence to attribute | IP is null, event lacks context, or the actor could plausibly be legitimate |

An agent that writes "the attacker did X" without a confidence label has skipped the
attribution protocol. Rework the claim.

## 10. Absence of evidence is not evidence of absence

The audit log has coverage gaps. Common ones:

- **Google Workspace Gmail feed** records ML-flagged deliveries and policy events, not
  every normal send/receive. A message the attacker sent may not appear in `gmail`
  audit if Gmail's ML engine did not flag it.
- **Drive audit** does not emit per-attachment open events. "No Drive access from
  attacker IP" means no Drive API call was logged, not that the attacker did not read
  attachments inline in Gmail.
- **Token audit** does not record every token refresh. An attacker who holds a valid
  refresh token operates silently between authorize/revoke events.
- **Endpoint logs** (Chrome History, Unified Log) have retention windows. Events older
  than the ring buffer's capacity are gone, not "didn't happen."

When evidence for a hypothesis is absent, state: "No evidence of X in the available
telemetry" — not "X did not happen."

## 11. Correct errors in place with correction banners

When a prior claim is found to be wrong during the investigation, do not delete the
original claim. Add a correction banner at the top of the evidence file:

```
> ⚠️ **CORRECTION [date]** — [original claim] was [incorrect because]. Corrected to [new claim].
```

Corrections preserve the investigation's chain of reasoning. Silently editing prior
analysis destroys the audit trail and makes it impossible to understand why a
conclusion changed.

## 12. Do not conflate the authenticated actor with the human operator

The `actor.email` field in an audit event identifies the authenticated session, not the
person at the keyboard. In a BEC investigation, the attacker operates as the victim's
authenticated identity. The entire point of the investigation is to separate "financegg@
performed action X" (system fact) from "the attacker performed action X using
financegg@'s stolen session" (attributed conclusion).

Never write "financegg@ sent the fraud email" as though the mailbox owner sent it.
Write "a delivery event from financegg@'s session, IP 80.94.92.234 (attacker node),
sent [subject] to [recipients]."

## 13. Evidence files are derived analysis, not raw data

Raw audit JSON and CSV live in `ir/reports/` and are never edited. Evidence files in
`ir/evidence/` are derived analysis that must:

- Cite the source file for every claim
- Embed the jq/sqlite/python command used to extract the data so another investigator
  can reproduce it
- Distinguish facts (from the log) from attribution (agent's analysis) from
  interpretation (what it means for the investigation)

An evidence file that contains conclusions without reproducible extraction commands is
a liability, not an asset.

## 14. Look-back window starts at 30 days minimum

User-reported compromise dates are lower bounds. Initial access routinely precedes
visible symptoms by 7–30 days. Set the initial audit pull window to T-30d from the
reported date; extend if anomalous events cluster near the boundary.

A short look-back window is how initial-access events get missed entirely. The
downstream cost — reconstructing the attack chain without the entry point — is far
higher than the cost of pulling 30 days of audit data upfront.

## 15. Platform-specific event routing is treacherous

Audit events do not always live where their name suggests. Agents must not assume
an event's location from its name — grep across all feeds before concluding an event
did not occur.

Known routing surprises (not exhaustive):

| Event | Expected location | Actual location |
|---|---|---|
| `blocked_sender_change` | `gmail` | `login` |
| `forwarding_edit` | `gmail` | `user_accounts` |
| `recovery_email_edit` | `admin` | `user_accounts` |
| `2sv_enroll` | `admin` | `user_accounts` |
| OAuth `authorize`/`revoke` | `login` | `token` |

When an event is not found in the expected feed, the correct response is to search
every feed — not to conclude the event did not happen.
