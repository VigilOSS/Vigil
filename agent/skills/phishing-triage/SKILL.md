---
name: phishing-triage
description: L2 email-content forensics. Header chain, sender authentication state, URL+attachment detonation, BEC pattern detection. Use after L1 dispatches a phishing-class alert.
origin: AI Threat Hunting
---

# Phishing Triage (L2)

L2 email-content forensics — the playbook the investigator loads when
`alert-triage` dispatches a phishing-class alert. Primary platform is
Microsoft 365 / Exchange Online; the Google Workspace analog lives in
`agent/skills/google-workspaces/SKILL.md` §Gmail content. Same evidence
shape, MITRE mapping, and disposition vocabulary; only the platform CLIs
differ.

L2 pulls audit data, parses raw `.eml`, detonates URLs, hashes
attachments, and writes a `disposition_recommendation`. L2 does NOT
write the final disposition (L3 `alert-fp-verification`) and does NOT
propose containment (L4 `incident-containment`). L2's deliverable is a
registered evidence trail and a handoff JSON shaped for the verifier.

## When to Activate

- L1 `alert-triage` dispatches with platform hint `m365-email` or
  `gws-gmail` and category `phishing`, `bec`, `aitm`, or `oauth-grant`.
- Operator pastes a phish report (end-user report, fraud notification,
  vendor warning) into `scope.json:alert_metadata` and the L1 classifier
  routes it here.
- L2 platform investigator (`google-workspaces` or
  `m365-signin-investigation`) escalates after surfacing an inbox-rule
  artifact or attacker-grafted forwarding rule — the email that grafted
  the rule needs forensic triage before the session-token side of the
  AiTM compromise can be closed.

Does NOT activate on:

- Generic credential-stuffing without an email artifact — those go to
  `m365-signin-investigation` or `google-workspaces` directly.
- DLP exfiltration where the compromise is in the user's outbox —
  `incident-containment` owns outbound purge.
- Quarantined-message release decisions — triage shortcut on the
  tenant's quarantine console, not a full L2 investigation.

## Operating Rules

Load before the first command runs. Do not restate linked content.

- `agent/rules/triage.md` (always-active) — disposition vocabulary
  (`verified | false_positive | downgraded | escalated`), severity ↔
  MITRE alignment, 30-day look-back, symmetric evidence bar,
  mechanical-FP citation.
- `agent/rules/ir-evidence.md` (always-active) — attribution gates on
  header forensics. An `Authentication-Results` verdict is not
  evidence-grade without Step 3's live DNS recheck.
- `agent/shared-constraints-blue.md` — authorization, read-only by
  default, chain of custody, UTC, dispatch schema, host-exec audit
  pipeline.
- Tenant ref(s) from `scope.json:tenant_reference_paths[]` —
  documented sender allowlists, mailflow rules, quarantine-release
  SOPs, known-benign register. Missing tenant ref = `blocked` handoff
  per `triage.md` rule 12.

## Tools

| Task | Tool | Why |
|------|------|-----|
| Pull raw `.eml` from M365 mailbox | `curl` against Graph `users/{id}/messages/{id}/$value` | Graph returns the exact RFC 822 bytes the recipient received; preserves chain of custody. Authenticate via Azure AD app with `Mail.ReadBasic.All` (read) or `Mail.Read` if body access is required. |
| Pull raw `.eml` from GWS mailbox | `gam user <u> show message <gmail-internal-id> format raw` | GAM with DWD; mirror the pattern in `google-workspaces/SKILL.md` §3. |
| Parse RFC 5322 headers (Received chain, Auth-Results, Reply-To, From) | `eml-parser` (pypi) via `aith assess host-exec --tool python3` | Pure-Python parser; deterministic JSON output; handles multipart MIME, attachments, header folding. |
| Office attachment triage (macros, OLE, embedded URLs) | `oletools` (`oleid`, `olevba`, `oledump.py`) via host-exec | Standard malicious-document toolkit; surfaces VBA macros, AutoExec triggers, suspicious URL fragments. |
| PDF action / JS / embedded form triage | `pdfid.py` + `pdf-parser.py` (Didier Stevens) via host-exec | Surfaces `/JS`, `/JavaScript`, `/OpenAction`, `/AcroForm`, `/EmbeddedFile`, `/Launch` — the high-signal phishing-PDF tokens. |
| DNS auth verification (SPF, DKIM selector, DMARC) | `dig +short TXT <name>` via host-exec | Re-resolves live DNS at investigation time; compares against the verdicts the receiving MTA stamped into `Authentication-Results`. |
| Lookalike-domain check (homoglyph, IDN, character swap) | `dnstwist <domain>` via host-exec | Generates and resolves permutations of a target domain; flags the ones that resolve and serve mail (`--mxcheck`). |
| URL sandbox detonation | `curl` POST `https://urlscan.io/api/v1/scan/` then GET `https://urlscan.io/api/v1/result/{uuid}/` | urlscan returns the response chain, screenshot, DOM snapshot, and IOC list. **Always submit with `"visibility": "private"`** — public scans leak the customer's lookalike domains and recipient-tailored URLs to the urlscan public feed. |
| File / URL / domain reputation | `curl` against VirusTotal v3 (`/files/{sha256}`, `/urls/{id}`, `/domains/{d}`) via host-exec | Auth via `x-apikey: $VT_API_KEY`. URL IDs are base64url of the URL (see `ioc-enrichment/SKILL.md` §3). |
| M365 Defender Advanced Hunting (delivery, click-through, post-delivery rules) | `curl` POST `https://api.security.microsoft.com/api/advancedhunting/run` with KQL body | Tables: `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`, `UrlClickEvents`. Auth via Azure AD app with `ThreatHunting.Read.All`. |
| GWS Gmail mailflow pivot | `gam`, `gcloud` Reports API (`gmail`, `rules`) | Cross-link `agent/skills/google-workspaces/SKILL.md` §3 (content search) and §Gmail content for full message access via DWD. |
| Offline JSON / header analysis | `jq`, `python3 -c '...'` | Read-only, no host-exec needed; manipulate already-pulled artifacts. |
| Intel record + linkage | `aith assess record-intel`, `aith assess link-finding --intel <id>` | Records each IOC (sender domain, sender IP, lookalike domain, URL, attachment hash) and links it to the finding. |

### Negative tool list (do NOT invent these)

- No `message-header-analyzer` CLI exists. Microsoft's web tool by
  that name is browser-only. Use `eml-parser` + `python3` over the
  parsed `Authentication-Results` headers.
- No `bec-detector` or `phish-classifier` CLI. Step 5 is rule-based
  pattern matching against parsed headers — not a one-shot tool.
- `file(1)` on a `.eml` says "RFC 822 mail" and nothing else — use
  `eml-parser` for real content.
- Never submit URLs to urlscan without `"visibility": "private"` —
  public submissions leak customer-tailored URLs to the public feed.

## Methodology

Six numbered steps: Purpose / Action / Evidence collected / Common
FPs. Run in order; the verifier's symmetric-evidence bar
(`triage.md` rule 4) needs every step to land — do not skip even
when the disposition feels obvious early.

### Step 1 — Preserve the message

**Purpose.** Chain of custody on the original RFC 822 bytes. A
forwarded screenshot is not evidence — it carries the forwarder's
headers, not the attacker's; the verifier rejects findings backed only
by screenshots.

**Action (M365).** Pull the raw `.eml` from Graph using the recipient's
mailbox ID and the message ID from the alert:

```bash
TENANT=<tenant-slug>
USER_ID=<recipient-upn-or-objectid>
MSG_ID=<message-graph-id-from-alert>
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "client_id=$AAD_CLIENT_ID&client_secret=$AAD_CLIENT_SECRET&grant_type=client_credentials&scope=https://graph.microsoft.com/.default" \
  | jq -r '.access_token')

aith assess host-exec \
  --tool curl \
  --intent "preserve raw RFC 822 for phish triage on <finding-slug>" \
  --technique IR-EVIDENCE \
  --phase investigate \
  --scope-host "$TENANT" \
  --target-host graph.microsoft.com \
  -- curl -s -H "Authorization: Bearer $TOKEN" \
    -o "$ENGAGEMENT_DIR/ir/evidence/email-${MSG_ID:0:12}.eml" \
    "https://graph.microsoft.com/v1.0/users/$USER_ID/messages/$MSG_ID/\$value"

/usr/bin/shasum -a 256 "$ENGAGEMENT_DIR/ir/evidence/email-${MSG_ID:0:12}.eml"
```

**Action (GWS).** GAM with DWD + `gmail.readonly`:

```bash
GMAIL_ID=<gmail-internal-id-from-alert>   # 16-char hex, e.g. 19e1c40646b0e836
aith assess host-exec \
  --tool gam \
  --intent "preserve raw RFC 822 for phish triage on <finding-slug>" \
  --technique IR-EVIDENCE \
  --phase investigate \
  --scope-host "$TENANT" \
  --target-host gmail.googleapis.com \
  -- gam user <recipient@domain> show message "$GMAIL_ID" format raw \
    > "$ENGAGEMENT_DIR/ir/evidence/email-${GMAIL_ID:0:12}.eml"
```

If the alert carries an RFC 2822 `Message-ID` (Alert Center's
`messages[].messageId`) and you do not yet have the Gmail internal ID,
resolve first via `gam user <recipient> print messages query
"rfc822msgid:<rfc2822-id>" max_to_print 1` (see
`google-workspaces/SKILL.md` §3).

**Register the artifact:**

```bash
aith assess artifact register \
  "$ENGAGEMENT_DIR/ir/evidence/email-${MSG_ID:0:12}.eml" \
  --kind ir_evidence \
  --finding <finding-slug> \
  --agent-id <runtime-agent-id> \
  --sensitive
```

`--sensitive` is mandatory — `.eml` carries PII in subjects,
recipients, and embedded reply chains.

**Evidence collected.**

- The raw `.eml` at `$ENGAGEMENT_DIR/ir/evidence/email-<short>.eml`
- SHA-256 in `$ENGAGEMENT_DIR/ir/evidence/SHA256SUMS.txt`
- A registered artifact ID pointing at the file
- The Graph or GAM command in the activity log

**Common false positives.**

- Reporter forwarded a screenshot — refuse to analyze as source of
  truth; screenshot metadata is not RFC 822.
- Message in Trash / Deleted Items — pull explicitly from
  `MailFolders/DeletedItems/messages/{id}` if inbox returns 404.
- Reporter is a delegate, not the original recipient — pull from the
  named recipient's mailbox; headers diverge.

### Step 2 — Parse headers

**Purpose.** Build provenance from alleged sender to recipient MTA.
Load-bearing fields for Steps 3–5: `Received` chain,
`Authentication-Results`, `ARC-Authentication-Results`, `Message-ID`,
`Return-Path`, `Reply-To`, `From`, `X-Originating-IP`.

**Action.** Run `eml-parser` via host-exec
(`--tool python3 --technique IR-EVIDENCE --phase investigate
--target-host -`), invoking
`python3 -c "import eml_parser, json, pathlib; ep = eml_parser.EmlParser(
include_raw_body=False, include_attachment_data=False);
print(json.dumps(ep.decode_email_bytes(pathlib.Path('<eml-path>').
read_bytes()), default=str, indent=2))"`. Save output as
`email-<short>.parsed.json`.

Distill the load-bearing fields into `email-<short>.headers.json` via
a `jq` projection over `.header.header.*`. Required fields:
`message-id`, `from`, `reply-to`, `return-path`, `to`, `subject`,
`date`, `received`, `authentication-results`,
`arc-authentication-results`, `x-originating-ip`, `x-mailer`,
`list-id`, `list-unsubscribe`.

**Reading the Received chain.** Bottom-up: bottom-most was added
first (origin MTA), top-most last (recipient MTA). Reading top-down
gives the wrong origin IP — a common L2 mistake.

**Reading Authentication-Results.** Comma-separated. A typical M365
line:

```
Authentication-Results: spf=fail (sender IP is 198.51.100.10)
  smtp.mailfrom=invoice-vendor.example; dkim=none (message not signed)
  header.d=none; dmarc=fail action=oreject
  header.from=invoice-vendor.example; compauth=fail reason=001
```

The verifier needs `spf=`, `dkim=`, `dmarc=`. M365 also stamps
`compauth=` (Microsoft-specific composite). GWS emits the same shape
via `mx.google.com`.

**Evidence collected.**

- `email-<short>.parsed.json` — full eml-parser output, registered
- `email-<short>.headers.json` — distilled header view, registered
- A note in the timeline citing the Received-chain origin IP, the
  `From:` domain, and the three auth verdicts

**Common false positives.**

- Mailing-list rewriting (`lists.example.com`, IETF, GitHub
  notifications). DMARC fails by design; tag
  `mailflow_rule_matched: list-rewrite` per the tenant ref and
  downgrade.
- ARC-sealed forwarded mail — read `ARC-Authentication-Results`
  alongside the current `Authentication-Results`; the originating hop
  may have passed.
- M365 SafeLinks rewriting wraps URLs in
  `https://*.safelinks.protection.outlook.com/?url=...`. Decode the
  `url=` param to recover the attacker link before submitting to
  urlscan.

### Step 3 — SPF/DKIM/DMARC verification

**Purpose.** Confirm the auth state in `Authentication-Results`
matches live DNS at investigation time. An attacker with sender-side
DNS compromise can manufacture a stamped PASS; a sender rotating DKIM
selectors can report a stale `dkim=fail` while a new selector is valid
in live DNS.

**Action.** Re-resolve all three records against the claimed sender's
domain. Extract the sender domain from `header.from` (left of `@`) and
the DKIM selector from the `Authentication-Results` `header.s=`
sub-field:

```bash
SENDER_DOMAIN=invoice-vendor.example
DKIM_SELECTOR=selector1  # from Authentication-Results header.s=

aith assess host-exec --tool dig \
  --intent "live SPF lookup for <finding-slug>" \
  --technique IR-EVIDENCE --phase investigate \
  --scope-host "$TENANT" --target-host "$SENDER_DOMAIN" \
  -- dig +short TXT "$SENDER_DOMAIN"

aith assess host-exec --tool dig \
  --intent "live DKIM lookup for <finding-slug>" \
  --technique IR-EVIDENCE --phase investigate \
  --scope-host "$TENANT" --target-host "$SENDER_DOMAIN" \
  -- dig +short TXT "$DKIM_SELECTOR._domainkey.$SENDER_DOMAIN"

aith assess host-exec --tool dig \
  --intent "live DMARC lookup for <finding-slug>" \
  --technique IR-EVIDENCE --phase investigate \
  --scope-host "$TENANT" --target-host "$SENDER_DOMAIN" \
  -- dig +short TXT "_dmarc.$SENDER_DOMAIN"
```

Capture into a side-by-side `dns-verify.json` with shape
`{sender_domain, header_verdicts:{spf,dkim,dmarc}, live_dns:{spf,
dkim_selector, dkim_txt, dmarc}, verdict_alignment:{spf_consistent,
dkim_consistent, dmarc_consistent}, notes}`. Register as
`ir_evidence` and link to the finding.

**Evidence collected.**

- `email-<short>.dns-verify.json` — the side-by-side artifact
- The three `dig` outputs (eml-parser does not re-query DNS; the live
  pulls are the verifier's reproduction signal)

**Common false positives.**

- Sender rotated DKIM selector. Header `dkim=fail` with selector A;
  live DNS shows selector A retired and selector B published. Record
  both selectors; recommend `downgraded`, not `verified`.
- SPF macros (`%{i}` / `%{s}`). `dig` returns the macro text, not the
  expansion. Resolve manually if it gates disposition.
- `v=spf1 ?all` (neutral) — non-decision; not phish signal. `v=spf1
  +all` is a sender misconfiguration finding for the tenant ref, not
  a phish indicator on this message.
- DMARC `p=none` (monitoring) — fail does not cause reject; signal
  only. Message may have been delivered legitimately by a
  misconfigured forwarder.

### Step 4 — URL + attachment detonation

**Purpose.** Identify the payload — URL clicked or attachment opened.
The most disposition-driving step: a malicious payload moves the
finding toward `verified`; a known-benign payload moves it toward
`false_positive`.

**Action (URLs).** Extract via `jq -r '((.body[]?.content // "") |
scan("https?://[^\\s\"<>]+")) | unique[]'` over the parsed JSON into
`urls.txt`. Decode M365 SafeLinks (`*.safelinks.protection.outlook.com`)
via `urllib.parse` on the `url=` query parameter; write the result to
`urls.decoded.txt`.

Submit each URL to urlscan with `visibility=private`:

```bash
URL=<one-url-from-the-list>
aith assess host-exec --tool curl \
  --intent "urlscan detonation for <finding-slug>" \
  --technique IOC-ENRICH --phase investigate \
  --scope-host "$TENANT" --target-host urlscan.io \
  -- curl -s -X POST -H "API-Key: $URLSCAN_API_KEY" \
       -H "Content-Type: application/json" \
       -d "{\"url\":\"$URL\",\"visibility\":\"private\"}" \
       "https://urlscan.io/api/v1/scan/"
```

Submission returns a `uuid`. Poll the result (urlscan completes in
10–60s) via host-exec at
`https://urlscan.io/api/v1/result/<uuid>/`, save as
`urlscan-<uuid>.json`. Result JSON carries response chain, verdicts,
IOCs; pull the screenshot from
`https://urlscan.io/screenshots/<uuid>.png`.

**Action (attachments).** Re-run `eml_parser` with
`include_attachment_data=True`, iterate over `parsed['attachment']`,
base64-decode each `raw` field, write to
`$ENGAGEMENT_DIR/ir/evidence/attachments-<short>/<filename>`, then
`shasum -a 256` everything into a SHA256SUMS.txt sibling.

For each Office attachment, run `python3 -m oletools.oleid <f>` and
`python3 -m oletools.olevba --decode <f>` under host-exec
(`--technique IR-EVIDENCE --phase investigate`). For each PDF, run
`pdfid.py <f>` under the same envelope. Then for each hash, query
VirusTotal:

```bash
HASH=<sha256-from-SHA256SUMS>
aith assess host-exec --tool curl \
  --intent "VT file reputation for <finding-slug>" \
  --technique IOC-ENRICH --phase investigate \
  --scope-host "$TENANT" --target-host virustotal.com \
  -- curl -s -H "x-apikey: $VT_API_KEY" \
       "https://www.virustotal.com/api/v3/files/$HASH" \
  > "$ENGAGEMENT_DIR/ir/evidence/vt-file-$HASH.json"
```

Route each URL / hash / domain through
`agent/skills/ioc-enrichment/SKILL.md` for the full reputation pass —
that skill records `intel_*` rows and returns intel IDs for
`link-finding` in the closing sequence.

**Evidence collected.**

- `email-<short>.urls.decoded.txt` — extracted, SafeLinks-decoded URLs
- `urlscan-<uuid>.json` and `urlscan-<uuid>.png` — sandbox detonation
- `attachments-<short>/*` — each attachment + SHA-256
- `vt-file-<hash>.json`, `vt-url-<id>.json`, `vt-domain-<d>.json` — VT
  reputation responses, one per IOC
- Intel IDs from `record-intel` (per IOC, recorded via ioc-enrichment)

**Common false positives.**

- URL shorteners (`t.co`, `bit.ly`, `lnkd.in`) — urlscan follows the
  redirect chain; flag the landing, not the shortener.
- DMARC report aggregators (`postmaster@google.com`,
  `eu.dmarcian.com`, `dmarc@valimail.com`) — reporting infrastructure,
  not phishing.
- Vendor document portals (DocuSign, Adobe Sign, HelloSign) — same
  shape as credential-harvester landing pages. Confirm against tenant
  ref vendor allowlist before flagging.
- Legitimate password reset / 2FA enrollment from a vendor the user
  uses. urlscan flags the login page as "credential prompt" — true
  but not adversarial. Pair with the tenant ref.

### Step 5 — BEC pattern check

**Purpose.** Distinguish credential-harvest phishing (Step 4 finds
the payload) from business email compromise (no payload; the attack
is the message — wire redirect, invoice fraud, CEO impersonation).
BEC routes to a different downstream specialist and containment
playbook.

**Action.** Run a deterministic checklist against parsed headers +
body; each item is binary, captured in JSON.

Write a `python3` snippet that emits a JSON envelope with these
fields (load `headers.json` + `parsed.json`):

```
reply_to_divergent           bool   (Reply-To domain != From domain)
from_domain / reply_to_domain string
subject_has_wire_keywords    bool   (wire|ach|invoice|payment|remittance|urgent)
body_has_wire_keywords       bool   (wire transfer|routing number|bank details|remit to|new account)
thread_hijack_signals:
  subject_starts_with_re_or_fwd  bool
  missing_in_reply_to_header     bool
```

Save to `email-<short>.bec-check.json` and register.

Then check for homoglyph / IDN lookalikes via `dnstwist` against the
impersonated domain (the recipient's own domain or a known vendor):

```bash
aith assess host-exec --tool dnstwist \
  --intent "lookalike domain enumeration for <finding-slug>" \
  --technique IOC-ENRICH --phase investigate \
  --scope-host "$TENANT" --target-host "$TARGET_DOMAIN" \
  -- dnstwist --format json --mxcheck "$TARGET_DOMAIN" \
  > "$ENGAGEMENT_DIR/ir/evidence/dnstwist-$TARGET_DOMAIN.json"
```

Then `jq '[.[] | select(.domain == "<sender_from_bec_check>")]'`
against the dnstwist output.

Non-empty result = sender domain is a registered permutation of the
impersonated domain — strong BEC signal.

**BEC indicators that drive `escalated` disposition:**

| Indicator | Why |
|-----------|-----|
| `Reply-To` domain ≠ `From` domain | Attacker wants the reply on infrastructure they control; legitimate senders rarely diverge |
| Homoglyph match in `dnstwist` output | `invoice-vendor.example` vs `invoíce-vendor.example` (IDN) or `rn`↔`m` substitution |
| Subject Re:/Fwd: prefix without `In-Reply-To` header | Thread-hijack pattern — attacker forges a reply to a thread that never existed in the recipient's mailbox |
| Sender's `From` matches a recipient's prior contact AND `Reply-To` is novel | Display-name spoofing of a known contact |
| Wire / invoice / payment keywords in subject AND body AND no payload URL | Pure-text BEC — Step 4 found nothing because the attack is the text itself |

**Evidence collected.**

- `email-<short>.bec-check.json` — deterministic BEC checklist result
- `dnstwist-<target>.json` — lookalike enumeration when applicable
- A timeline note pairing `From` / `Reply-To` and citing each fired
  BEC indicator

**Common false positives.**

- Legitimate vendor changing payment terms — authenticated sender, on
  tenant allowlist. Still `escalated`; next step is out-of-band voice
  verification on a number from the customer's vendor records (NOT
  from the email).
- Internal `Reply-To` divergence (CEO assistant routing to a
  calendar-management mailbox). Confirm against documented mailflow
  rules.
- Marketing automation that sends from `mail.vendor.com` and replies
  to `vendor.com` — divergence by design, documented in tenant ref.
- Re:/Fwd: subject from a ticketing system that drops `In-Reply-To`
  on outbound (Jira, Zendesk). Confirm against user's ticket-reply
  history before flagging.

### Step 6 — Recipient + tenant impact pivot

**Purpose.** Scope the blast radius. One recipient who deleted it
vs. 200 recipients with 30 clicks and 4 post-delivery inbox rules
are materially different incidents.

**Action (M365 Defender Advanced Hunting).** Query `EmailEvents` for the
sender + subject combination across the tenant in a wide window:

```bash
DEFENDER_TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "client_id=$AAD_CLIENT_ID&client_secret=$AAD_CLIENT_SECRET&grant_type=client_credentials&scope=https://api.security.microsoft.com/.default" \
  | jq -r '.access_token')

KQL='EmailEvents
| where Timestamp between (datetime(2026-05-05T00:00:00Z) .. datetime(2026-05-19T23:59:59Z))
| where SenderFromAddress =~ "no-reply@invoice-vendor.example"
  or Subject =~ "Invoice 2034 - Payment overdue"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods'

aith assess host-exec --tool curl \
  --intent "Defender EmailEvents pivot for <finding-slug>" \
  --technique IR-EVIDENCE --phase investigate \
  --scope-host "$TENANT" --target-host api.security.microsoft.com \
  -- curl -s -X POST -H "Authorization: Bearer $DEFENDER_TOKEN" \
       -H "Content-Type: application/json" \
       -d "$(jq -n --arg q "$KQL" '{Query:$q}')" \
       "https://api.security.microsoft.com/api/advancedhunting/run" \
  > "$ENGAGEMENT_DIR/ir/evidence/defender-emailevents-${MSG_ID:0:12}.json"
```

Pivot on `EmailUrlInfo` joined left-outer to `UrlClickEvents` on
`Url` to capture click-through per `NetworkMessageId` — project
`Timestamp, AccountUpn, ActionType, Url, UrlChain, ThreatTypes`.

Check post-delivery inbox-rule activity in `CloudAppEvents` (Defender
for Cloud Apps) with `ActionType in ("New-InboxRule", "Set-InboxRule",
"UpdateInboxRules", "MailboxRuleCreated")` for the recipient's
`AccountObjectId` in a ±15min window from delivery; or via Graph
`mailFolders/inbox/messageRules`.

**Action (GWS).** Pivot via host-exec on `gmail`, `rules`, `login`
audit feeds — full details in
`agent/skills/google-workspaces/SKILL.md` §3 / §4. Look for:

- `gmail` audit event around delivery time matching recipient +
  subject substring
- `rules` event creating a forwarding rule / filter shortly after
- `login` event from new IP / user-agent within 5–10 minutes (AiTM
  token grab)

**Evidence collected.**

- `defender-emailevents-<short>.json` — full delivery list
- `defender-emailurlinfo-<short>.json` — URLs delivered + click events
- `defender-postdelivery-<short>.json` — inbox-rule changes in ±15min
  window
- For GWS: cross-link to the audit-feed artifacts the
  `google-workspaces` skill already registered

**Common false positives.**

- ML-flagged but never delivered (`DeliveryAction == "Blocked"` /
  `DeliveryLocation == "Quarantine"`) — phish real, blast radius
  zero. Disposition `downgraded`; still record IOCs to intel.
- Quarantine-release / ZAP race: helpdesk released, ZAP
  re-quarantined 10 minutes later. Both events appear in
  `DeliveryAction`; read both.
- Delivery to a shared mailbox / role alias — blast radius depends
  on alias expansion. Pull membership before sizing impact.

## MITRE ATT&CK Technique Mapping

| Technique | When to apply | Evidence shape |
|-----------|---------------|----------------|
| **T1566.001** Spearphishing Attachment | Attachment present (Office macro, PDF JS, zipped exe, ISO) | oletools/pdfid hit, hash on VT, attachment recovered to evidence tree |
| **T1566.002** Spearphishing Link | URL present in body, no attachment; recipient interaction expected | urlscan verdict, URL VT reputation, click-through telemetry from Defender / GWS |
| **T1566.003** Spearphishing via Service | Social-channel message (LinkedIn, WhatsApp, SMS) landed before email; email confirms the lure | Cross-ref `osint-recon` for the prior-channel message; sender's social profile (where consented) |
| **T1566.004** Spearphishing Voice | Call-back number embedded in attachment or body ("vishing"); the email is a pretext to drive the call | Phone number IOC recorded; call carrier reputation if available |
| **T1078.004** Cloud Accounts | Post-credential-entry: attacker uses the stolen credentials in the tenant | Hand off to `m365-signin-investigation` or `google-workspaces` for the sign-in pivot |
| **T1098.001** Additional Cloud Credentials | OAuth-grant phish — recipient grants third-party app access | Captured via OAuth grant event in the platform's audit feed; the email is the lure that drove the consent |
| **T1114.003** Email Forwarding Rule | Attacker grafted forwarding rule post-compromise | Step 6 surfaces the rule; cross-ref to the email that grafted it |
| **T1556.007** Hybrid Identity / AiTM | Attacker proxy-relayed the auth and stole the session cookie | The phish landing page is an Evilginx / Modlishka shape; urlscan screenshot shows the proxied login form |

Cite the MITRE source: <https://attack.mitre.org/techniques/T1566/>.

The finding's `details_json.mitre_techniques` array carries every
applicable technique from this table. Empty is forbidden by
`triage.md` rule 11; the L1 fallback is `T1566` (parent) only if no
sub-technique applies.

## Known-benign Register Additions

When this skill confirms a recurring benign pattern, seed the tenant
ref's known-benign register with:

- `sender_domain_allowlist` — vendor domains that consistently
  DMARC-fail due to mailing-list rewriting or DKIM rotation. Include
  rotation cadence + the verifier pass that promoted the entry.
- `mailflow_rule_matched` — internal transport rules known to fire
  noisily (legal-hold copy-on-send, DLP fingerprint mismatch).
- `sender_authentication_state` — explicit (spf=fail, dkim=pass,
  dmarc=fail) verdict triples for documented cases.
- `quarantine_release_pattern` — known FP-release SOPs (helpdesk
  releases marketing; M&A counterparty allowlist release).

`alert-triage` consumes these entries in its mechanical-FP screen
(`alert-triage/SKILL.md` §Mechanical-FP Bar). Entries must be tagged
`mechanical: true` to be auto-close eligible; otherwise the next fire
escalates here for human-confirmed FP.

## Disposition Heuristics

The L3 verifier owns the final disposition. This skill recommends one
based on the six steps; the verifier confirms or overturns.

| Evidence shape | Recommended disposition | Rationale |
|----------------|-------------------------|-----------|
| DMARC fail (Step 3) + URL flagged adversarial by urlscan (Step 4) + recipient clicked OR inbox-rule created post-delivery (Step 6) | `verified` | Three independent signals corroborate adversarial intent and user impact |
| DMARC fail + URL flagged + no click + no post-delivery rule + delivered to ≥1 user | `verified` (impact `medium`) | Adversarial intent confirmed; impact bounded to delivery without interaction |
| DMARC fail + adversarial URL but `DeliveryAction == "Blocked"` / `Quarantine` (Step 6) | `downgraded` | Threat real, blast radius zero; IOCs still record to intel |
| Sender on tenant allowlist + no malicious URL (Step 4 clean) + no payload + Step 5 BEC checklist all-negative | `false_positive` | Tenant-ref-documented benign pattern with multi-step corroboration |
| Reply-To divergent + homoglyph match in dnstwist + wire/invoice keywords + no payload | `escalated` | Pure BEC pattern; requires out-of-band caller verification — not an automatic verdict |
| Mailing-list rewriting (Step 2 FP) + tenant-ref `sender_domain_allowlist` hit | `false_positive` | Documented benign DMARC-fail pattern |
| Step 1 evidence missing (only screenshot, not raw `.eml`) | (do not dispose; return `blocked`) | Chain of custody cannot be established; the verifier rejects on intake |
| Step 3 verdict misalignment (header says pass, live DNS says fail — or vice versa) | `escalated` | Possible header replay or sender-side DNS compromise; needs verifier judgment |

Record the recommendation in `details_json.disposition_recommendation`
on the finding; the verifier reads it but is not bound by it.

## Activity Log Convention

Every L2 pass writes one activity row per methodology step plus one
closing handoff row. The closing row is the durable record the
verifier and report-writer consume; per-step rows are the audit
trail. Closing-row signature uses `aith assess log`:

```bash
aith assess log \
  <runtime-agent-id> \
  "phishing-triage-handoff for <finding-slug>" \
  handoff \
  "Disposition recommendation=<value>; sender_auth=<spf/dkim/dmarc>; payload=<url|attachment|none>; bec_indicators=<list>; blast_radius=<delivery_count>" \
  --actor-kind agent
```

`metadata_json` on the closing row carries:

```json
{
  "tier": "L2",
  "alert_external_id": "...",
  "platform": "m365|gws",
  "skill_loaded": "phishing-triage",
  "disposition": "verified|false_positive|downgraded|escalated|pending",
  "confidence": "high|medium|low",
  "mitre_techniques": ["T1566.002"],
  "sender_auth_state": {"spf":"fail","dkim":"pass","dmarc":"fail"},
  "bec_indicators": ["reply_to_divergent","homoglyph"],
  "delivery_count": 12,
  "click_count": 0,
  "post_delivery_rule_count": 0,
  "attachment_count": 1,
  "url_count": 3
}
```

Per-step rows use the same verb with step-specific titles
(`phishing-triage-step-1-preserve`,
`phishing-triage-step-3-dns-verify`, …) so FTS can narrow on a
specific step during the verifier's reproduction pass.

## Output Contract

The specialist returns this JSON from the dispatch:

```json
{
  "finding_slug": "...",
  "skill_used": "phishing-triage",
  "disposition_recommendation": "verified|false_positive|downgraded|escalated|pending",
  "evidence_refs": ["<artifact-id-eml>", "<artifact-id-parsed>", "<artifact-id-urlscan>"],
  "intel_ids": [<intel-id-1>, <intel-id-2>],
  "mitre_techniques": ["T1566.002", "T1078.004"],
  "tenant_ref_paths_consulted": ["agent/references/tenants/<slug>-m365.md"],
  "next_specialist": "verifier|m365-signin-investigation|incident-containment",
  "confidence": "high|medium|low",
  "confidence_rationale": "...",
  "rationale": "<one paragraph: what was found, what the recommendation rests on, what the verifier should re-read first>",
  "coverage_gaps": ["VT_API_KEY missing — file hashes not enriched"],
  "containment_hints": [
    {"action": "purge_message", "target": "<message-id>", "blast_radius": "single-user|all-recipients", "rationale": "..."},
    {"action": "block_sender_domain", "target": "<sender-domain>", "rationale": "..."}
  ]
}
```

`containment_hints` is advisory — `incident-containment` (L4) owns
proposal + execution after L3 confirms disposition. This skill does
NOT execute purge or block actions.

## Closing Sequence

Run these four steps in order before returning the handoff JSON:

1. **Register every durable artifact** via
   `aith assess artifact register <path> --kind <ir_evidence|ioc_dump>
   --finding <slug> --agent-id <runtime-agent-id> --sensitive`.
   Durables: raw `.eml`, parsed JSON, headers JSON, DNS-verify JSON,
   urlscan JSON + screenshot, attachments + SHA256SUMS, oletools /
   pdfid outputs, VT responses, BEC-check JSON, dnstwist JSON,
   Defender hunting JSONs.

2. **Mark transient working notes scratch** via
   `aith assess artifact mark-scratch --under
   "$ENGAGEMENT_DIR/notes/scratch/"`. Intermediate jq output, draft
   timelines, paste-buffer screenshots are not chain-of-custody and
   must not appear in `evidence_refs`.

3. **Write the activity-log handoff row** with `aith assess log`
   (positional args: `<agent-id> <title> <action> <result>`). The
   verb is `log` — the `log` + `entry` compound does NOT exist; see
   `src/ai_threat_hunting_cli/blue.py:15`. Signature:

   ```bash
   aith assess log \
     <runtime-agent-id> \
     "phishing-triage-handoff for <finding-slug>" \
     handoff \
     "<one-line disposition + key signals + blast radius>" \
     --actor-kind agent
   ```

   The `metadata_json` shape under Activity Log Convention rides
   alongside this row (via the backend client wrapper or the next CLI
   iteration's `--metadata-json` flag).

4. **Link IOCs to the finding** for the intel rows that
   `ioc-enrichment` created during Step 4:

   ```bash
   aith assess link-finding <finding-slug> --intel <intel-id> \
     --note "URL <url> recorded as adversarial via urlscan + VT"
   ```

   The `--intel` flag is being added to `link-finding` in parallel
   with this skill's v1; if the flag is not yet wired, fall back to
   `aith assess update-finding <slug> --inline
   '{"details": {"related_intel_ids": [<id-1>, <id-2>]}}'` per the
   pattern in `ioc-enrichment/SKILL.md` §6.

5. **Emit the handoff JSON** via `aith assess agent handoff
   --from-json /tmp/phishing-triage-handoff.json`. Shape per Output
   Contract above. `next_specialist` routes to:
   - `verifier` for any disposition recommendation with met
     evidence rigor
   - `m365-signin-investigation` (P1, parallel build) when AiTM
     signals need a credential-entry pivot before the verifier
   - `google-workspaces` for GWS-tenant phish that surfaced a
     sign-in / token event needing the GWS audit pivot
   - `incident-containment` (L4) — only via `verifier`'s
     `verified` disposition; this skill never routes directly to L4

## Common Failure Modes

- **Recording the screenshot, not the raw `.eml`.** Fails chain of
  custody; the verifier rejects on intake.
- **Trusting `Authentication-Results` blindly.** A sophisticated
  adversary can replay the header from a legitimate prior message.
  Step 3's live DNS recheck is the verifier's reproduction signal —
  skipping it leaves `verified` findings that cannot withstand the
  symmetric-evidence bar.
- **urlscan without `"visibility": "private"`.** Leaks lookalike
  domains and recipient-tailored URLs to the public feed —
  containment-relevant data leak.
- **Activating at L1.** Only `alert-triage` dispatches here; loading
  directly skips L1's mechanical-FP screen and the actor/target/time
  normalization this skill assumes is in `alert_normalized`.
- **Writing a final disposition.** This skill emits a
  `disposition_recommendation`; final disposition is L3
  `alert-fp-verification`'s. Calling `verify-finding` /
  `kill-finding` from this skill is out of role.
- **Skipping IOC enrichment for "obvious" cases.** Record IOCs via
  `record-intel` and `link-finding` even when the verdict is
  unambiguous — the tenant intel repo is the cross-engagement signal.
- **Conflating M365 SafeLinks with the attacker URL.** The
  `*.safelinks.protection.outlook.com/?url=` wrapper hides the actual
  link; decode `url=` before urlscan submission.
- **Pulling from the wrong mailbox.** Delegate / forwarder copies
  carry different transport headers; pull from the originally named
  recipient.

## Reference Block

- `agent/rules/triage.md` — disposition vocabulary, severity ↔ MITRE
  alignment, symmetric evidence bar, mechanical-FP citation, 30-day
  look-back.
- `agent/rules/ir-evidence.md` — attribution gates on header
  forensics; multi-signal corroboration shape.
- `agent/shared-constraints-blue.md` — host-exec audit envelope,
  artifact chain of custody, UTC, dispatch handoff schema.
- `agent/skills/alert-triage/SKILL.md` — L1 dispatcher; this skill is
  the L2 target for `phishing` / `bec` / `aitm` / `oauth-grant`.
- `agent/skills/alert-fp-verification/SKILL.md` — L3 next stop; runs
  the five-check against the registered evidence.
- `agent/skills/ioc-enrichment/SKILL.md` — every URL / IP / domain /
  hash from Steps 4–5 routes here.
- `agent/skills/incident-containment/SKILL.md` — L4 next stop (only
  via L3); consumes `containment_hints`.
- `agent/skills/google-workspaces/SKILL.md` §Gmail content — GWS-side
  sister investigation.
- `agent/skills/m365-signin-investigation/SKILL.md` (P1, parallel
  build) — M365 sign-in side of an AiTM compromise.
- `agent/skills/osint-recon/SKILL.md` — cross-channel context for
  T1566.003 multi-channel lures.
- MITRE T1566 tree: <https://attack.mitre.org/techniques/T1566/>
- M365 Defender Advanced Hunting:
  <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview>
- Microsoft Graph mail message GET:
  <https://learn.microsoft.com/en-us/graph/api/message-get>
- urlscan.io API: <https://urlscan.io/docs/api/>
- eml-parser: <https://github.com/GOVCERT-LU/eml_parser>
- oletools: <https://github.com/decalage2/oletools>
- pdfid / pdf-parser: <https://blog.didierstevens.com/programs/pdf-tools/>
- dnstwist: <https://github.com/elceef/dnstwist>
