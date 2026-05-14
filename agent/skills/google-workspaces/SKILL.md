---
name: google-workspaces
description: Blue-team IR for Google Workspace BEC and AiTM compromises — audit log pulls, Alert Center, OAuth token review, session revoke, Gmail content search, browser/endpoint forensics on Windows and macOS. Covers gcloud vs GAM vs raw REST and the scopes each needs.
origin: AI Threat Hunting
---

# Google Workspace Incident Response

## When to Activate

- A tenant user is suspected compromised (BEC, AiTM, token theft, malicious OAuth grant, insider misuse).
- An end-user sees a "new device signed in" alert they do not recognize.
- A vendor or bank reports an invoice redirection or wire fraud traced to a tenant mailbox.
- Admin Reports API audit logs, Alert Center alerts, Gmail filters or forwarding, OAuth grants, or session state need to be pulled.
- Durable admin actions (signOut, password reset, token revoke) need to land with an audit trail.

## Operating Rules

These constrain every action taken under this skill. They apply before any command runs.

**Attribution and evidence discipline.** The always-active rules in `agent/rules/ir-evidence.md` govern how agents attribute actions to actors, interpret audit events, and write evidence claims. Those rules apply here — this section adds platform-specific constraints, not replacements.

**Read-only by default.** Every command in this skill is read-only unless explicitly marked **WRITE**. Read-only pulls produce artifacts the investigator reviews; write actions change tenant state (sessions end, users lose access, filters disappear, passwords rotate). An incident investigation does not become a containment action without an explicit user authorization for the specific target and the specific action.

**WRITE actions require user approval.** Password reset, suspend, unsuspend, signOut, token revoke, OAuth-app removal, filter deletion, role changes, MFA enrollment changes, and any Directory API mutation are WRITE actions. The pattern: surface the evidence, propose the action with the exact command, wait for the user to approve this specific action against this specific target, then run it. A broad "you can contain" authorization is not specific. Silent destructive action during an investigation is how evidence gets lost and users get locked out mid-business-hours.

**Chain of custody.** Every raw pull lands under `$ENGAGEMENT_DIR/ir/reports/` with a predictable filename (`<feed>_<target>_<window>.json|csv`). SHA-256 every artifact immediately: `/usr/bin/shasum -a 256 ir/reports/*.json > ir/reports/SHA256SUMS.txt`. Derived analysis goes in `ir/evidence/` as markdown with the source-file path and the jq/sqlite command embedded in the evidence file. Nothing is edited in place. A timeline without source paths cannot be defended.

**UTC is the working timezone.** Audit logs, Chrome history timestamps, and cloud telemetry are all UTC. Convert to user-local only when writing narrative for a human reader. Mixing zones mid-analysis drops events and turns a 5-minute phishing-to-login window into a phantom gap.

**Timeline reconstruction starts from the earliest plausible trigger, not from "when the user noticed."** User-visible detection lags initial access by days or weeks. A compromise reported today routinely traces back 14–30 days; the starting look-back window is 30 days minimum and extends if anything anomalous sits at the boundary.

**Every sentence must carry new information.** Finding write-ups, reports, and evidence files obey: if removing a sentence does not reduce the reader's understanding, remove it. Restating what the code does is slop; explaining why a field matters is not.

**Verify attribution before asserting attacker action.** An IP you do not recognize inside an audit log may still belong to a user on travel, a VPN, or a shared mailbox with many delegates. Before calling an event adversarial, rule out the legitimate actor by (a) checking the user's normal ASN/region history, (b) asking the user or a teammate out-of-band, or (c) finding a corroborating anomaly (IP + user-agent + action type). Acting on suspicion alone leads to misattributed findings the user has to correct under stress.

**Stay in scope.** Artifacts that look interesting but belong to a different investigation (different tenant, different user, different time window) do not enter this engagement's evidence tree. Scope creep in IR produces reports that the client has to strip.

## Tool Roster — Picking the Right CLI

| Task | Tool | Why |
|---|---|---|
| Pull login / token / admin / user_accounts / drive / gmail / saml / groups_enterprise / mobile / rules / context_aware_access activities | `gcloud` + `curl` (Admin Reports API) | Read-only, no DWD needed, one ADC token |
| Alert Center (`alertcenter.googleapis.com`) | **GAM** | `apps.alerts` requires a DWD-authorized service account |
| Gmail Mailbox Settings (filters, forwarding, vacation, IMAP/POP, S/MIME) per user | **GAM** (DWD) | Per-user impersonation; gcloud ADC cannot impersonate other users |
| Gmail message content (subject, body, headers, attachments) | **GAM** (DWD + `gmail.readonly`) or Google Vault | Admin Reports Gmail feed contains only ML-flagged delivery metadata; full message access requires impersonation or Vault |
| Admin Console → Reporting → Email Log Search | UI only | Envelope-level metadata (sender, recipient, subject, spam verdict), last 30 days; no API equivalent |
| List / revoke a user's OAuth tokens | GAM or `curl` Directory API (`tokens.list`, `tokens.delete`) | Equivalent; GAM is shorter |
| signOut a user (invalidate every refresh token + session cookie) | `curl` Directory API (`/users/{key}/signOut`) | Atomic one-liner with ADC |
| Reset password / suspend / un-suspend / create user | GAM or Admin Console | GAM for scripted / bulk |
| SQL-style queries over pulled JSON | `jq` + `python3` | Read-only, fast, no tenant calls |

Rule of thumb: `gcloud` for read-heavy Reports pulls; **GAM** for anything that touches `apps.alerts`, Gmail mailbox settings, Gmail content, or per-user impersonation; raw `curl` when neither tool has a direct verb.

## Scope Map

Read-only ADC scopes (safe to grant to the investigator's gcloud session):

```
openid, email, profile
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/admin.reports.usage.readonly
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.user.security       # list/delete user tokens + signOut
https://www.googleapis.com/auth/admin.directory.user.alias.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/cloud-platform
```

Scopes that live on a DWD-authorized service account (not on the gcloud ADC client):

```
https://www.googleapis.com/auth/apps.alerts                         # Alert Center
https://www.googleapis.com/auth/gmail.settings.basic                # filters, forwarding, vacation
https://www.googleapis.com/auth/gmail.settings.sharing              # IMAP/POP, sendas, delegation
https://www.googleapis.com/auth/gmail.readonly                      # full message bodies, headers, attachments (READ)
https://www.googleapis.com/auth/gmail.modify                        # delete/label messages (WRITE)
https://www.googleapis.com/auth/admin.directory.user                # create / reset password / signOut via GAM (WRITE)
https://www.googleapis.com/auth/ediscovery                          # Google Vault (if licensed)
```

`apps.alerts` is restricted by Google to allowlisted OAuth clients — it will not authorize against the default gcloud ADC client. That is the architectural reason Alert Center pulls go through GAM.

The signed-in principal must be a **Super Admin** whose admin role has "Services → Admin console → Reports" and "Admin API privileges" turned on.

## Why DWD Is Required

A service account has no Workspace identity of its own. Domain-Wide Delegation lets it impersonate a specific real user to call Workspace APIs (Alert Center, Gmail, Directory, Drive). Without DWD, a service account has zero Workspace access regardless of project-level IAM. The `admin_email` setting in `gam.cfg` controls which user the service account impersonates — set it to a Super Admin whose role includes the API services being called.

## Setup

### Path A — Adopting an existing GAM project

Applies when a GAM GCP project and its service account already exist (`gcloud projects list | grep -i gam` returns a hit). Running `gam create project` again conflicts on the service-account name; the path below adopts the existing infrastructure instead.

Prerequisites: GAM 7 installed, a GCP project with a service account, Super Admin credentials.

```bash
# 1. Domain + admin email (the user the SA will impersonate)
gam config domain <your-domain>.tld save
gam config admin_email <superadmin@your-domain.tld> save

# 2. OAuth client_secrets.json (from GCP Console → APIs & Services → Credentials → OAuth 2.0 Client IDs)
cp ~/Downloads/client_secret_*.json ~/.gam/client_secrets.json

# 3. User-OAuth token — opens browser; sign in as the Super Admin above
gam oauth create

# 4. Service account key JSON (from GCP Console → IAM & Admin → Service Accounts → Keys → Add Key → JSON)
cp ~/Downloads/<project>-<keyid>.json ~/.gam/oauth2service.json

# 5. Service account numeric client ID (needed for DWD)
gam info currentprojectid   # prints GCP project ID
gam info instance           # prints customer ID, primary domain — SA client_id is in oauth2service.json

# 6. Authorize DWD — https://admin.google.com/ac/owl/domainwidedelegation
#    Add new → paste the numeric client ID from step 5 → paste scopes comma-separated, no spaces:
#      https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/apps.alerts,https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/gmail.settings.sharing,https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/cloud-platform

# 7. Trust the GAM OAuth client (once per tenant) — https://admin.google.com/ac/owl/list?tab=configuredApps
#    Configure new app → paste GAM's OAuth client ID → Trusted

# 8. Enable Gmail API + Alert Center API on the GCP project (silent no-op if already enabled)
gcloud services enable gmail.googleapis.com alertcenter.googleapis.com admin.googleapis.com \
  --project=<existing-project-id>

# 9. Verify every scope authorizes end-to-end
gam user <superadmin@your-domain.tld> check serviceaccount

# 10. Smoke test
gam print alerts
```

Propagation for Admin Console changes takes 1–2 minutes.

### Path B — Fresh GAM install (no GAM project in GCP yet)

```bash
# 1. Install GAM 7
bash <(curl -s -S -L https://git.io/install-gam) -l

# 2. gam create project walks through: new GCP project, service account, client secret, user OAuth
gam create project

# 3. Set admin_email
gam config admin_email <superadmin@your-domain.tld> save

# 4. create project prints the GAM OAuth client ID and SA numeric client ID.
#    Authorize both in Admin Console: trust the OAuth client, add DWD entry for the SA.

# 5. Verify
gam user <superadmin@your-domain.tld> check serviceaccount
gam print alerts
```

### Path C — gcloud ADC for Admin Reports only (no GAM)

Sufficient when the engagement only needs the audit feeds. Cannot pull Alert Center or message content.

```bash
SCOPES="openid,email,profile,\
https://www.googleapis.com/auth/admin.reports.audit.readonly,\
https://www.googleapis.com/auth/admin.reports.usage.readonly,\
https://www.googleapis.com/auth/admin.directory.user.readonly,\
https://www.googleapis.com/auth/admin.directory.user.security,\
https://www.googleapis.com/auth/admin.directory.user.alias.readonly,\
https://www.googleapis.com/auth/admin.directory.group.readonly,\
https://www.googleapis.com/auth/cloud-platform"

gcloud auth application-default login --scopes="$SCOPES"

TOKEN=$(gcloud auth application-default print-access-token)
curl -s "https://oauth2.googleapis.com/tokeninfo?access_token=$TOKEN" | python3 -m json.tool
curl -s -o /dev/null -w "Reports probe: HTTP %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" \
  "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?maxResults=1"
```

`apps.alerts` does not belong in this list — the gcloud ADC client is not on Google's allowlist for that scope, and including it causes the interactive login to fail with `Error 400: invalid_scope`.

### Setup troubleshooting

- `oauth2.txt Not Found` → `gam oauth create` has not completed; the flow exits early if the trust step in Admin Console wasn't confirmed.
- `oauth2service.json Not Found` → the service-account key JSON hasn't been placed at `~/.gam/oauth2service.json`.
- `Alerts Service/App not enabled` → `admin_email` impersonates a user who does not have Alert Center access; set it to a Super Admin via `gam config admin_email <superadmin> save`.
- `Gmail API Service/App not enabled` → two independent causes; verify both before acting:
  1. Gmail API actually disabled on the GCP project — `gcloud services list --project=<gam-project-id> --filter="NAME:gmail"`. If absent, `gcloud services enable gmail.googleapis.com --project=<gam-project-id>` and wait 60 seconds.
  2. Gmail API is enabled but GAM's DWD preflight still fails — GAM's `check serviceaccount` (without arguments) probes `gmail.modify` as its Gmail test scope, **not** `gmail.readonly`. A DWD entry that grants only `gmail.readonly` will cause GAM to report this error even though read access works fine. Do not add `gmail.modify` to DWD to silence it — instead bypass GAM's preflight entirely using the Python DWD fallback in §3, which tests `gmail.readonly` directly.
- `check serviceaccount` reports scope failures → the DWD entry is missing those scopes. Append them at `https://admin.google.com/ac/owl/domainwidedelegation` and wait for propagation. **Note:** running `check serviceaccount` without arguments tests a fixed internal list that includes `gmail.modify` but not `gmail.readonly`. To check `gmail.readonly` specifically, use `gam user <target> check serviceaccount scopes "https://www.googleapis.com/auth/gmail.readonly"`, or use the Python DWD test in §3 as the authoritative check.
- After rotating the OAuth client secret in GCP, delete `~/.gam/oauth2.txt` and re-run `gam oauth create` — the old token is bound to the previous secret.

## Investigation Start Protocol

The first 30 minutes of any Workspace IR determine whether the rest of the investigation hits the actual point of entry or chases a red herring. The steps below run sequentially.

**Step 1 — Frame the compromise.** Ask the user three questions: (a) when did you first notice something wrong, (b) which account(s), (c) what did you see that was wrong. Write the answers verbatim into `ir/evidence/initial-report.md`. These are the only statements of fact at this point.

**Step 2 — Set the look-back window to 30 days minimum.** Compromise dates reported by users are lower bounds, not ground truth. Initial-access phishing routinely precedes user-visible symptoms by 7–14 days; one engagement here observed a 9-day gap between the phish and the first fraudulent email. Pull audit data from T-30d → now on the first pass; extend if any event anchors near T-30d.

**Step 3 — Pull the four primary feeds for the affected users and for `all`.** `login`, `token`, `admin`, `user_accounts`. These are always in scope.

**Step 4 — Pull the secondary feeds.** `drive`, `gmail`, `saml`, `groups_enterprise`, `context_aware_access`, `rules`, `mobile`. Skipping any of these means not knowing about the forwarding rule, the mobile device enrollment, the Drive share, or the inbox-rule filter that will turn up later.

**Step 5 — Check the endpoint.** Before assuming cloud-side compromise, check the user's primary device Chrome History (or Safari, Edge, Firefox) around the earliest anomalous event in cloud telemetry. The phishing landing URL that drops the credentials is almost always in browser history within 5 minutes of the attacker's first successful login. Not finding it in History means the click happened in a different browser profile, a different device, or an IMAP-capable mail client — narrow further rather than assuming cloud-side origin.

**Step 6 — Only then form a hypothesis.** The hypothesis the investigator writes down after step 5 has a much better chance of being right than one formed after step 1.

## IR Playbook — Common Tasks

Output convention: raw JSON/CSV in `$ENGAGEMENT_DIR/ir/reports/` named `<feed>_<target>_<date-range>.json`. Dates UTC. All values quoted.

### 1. Pull audit activities (read-only)

Applications worth pulling during BEC or AiTM IR: `login`, `token`, `admin`, `user_accounts`, `drive`, `gmail`, `saml`, `groups_enterprise`, `mobile`, `rules`, `context_aware_access`, `access_transparency`.

```bash
DIR="$ENGAGEMENT_DIR/ir/reports"
TOKEN=$(gcloud auth application-default print-access-token)
APP=login
USER=all
START=2026-04-01T00:00:00Z
END=2026-04-23T23:59:59Z

pageToken=""
OUT="$DIR/activity_${APP}_${USER//[^a-zA-Z0-9]/_}.json"
: > "$OUT"
while :; do
  resp=$(curl -s -G \
    -H "Authorization: Bearer $TOKEN" \
    --data-urlencode "startTime=$START" \
    --data-urlencode "endTime=$END" \
    --data-urlencode "maxResults=1000" \
    ${pageToken:+--data-urlencode "pageToken=$pageToken"} \
    "https://admin.googleapis.com/admin/reports/v1/activity/users/$USER/applications/$APP")
  echo "$resp" >> "$OUT"
  pageToken=$(echo "$resp" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("nextPageToken",""))')
  [ -z "$pageToken" ] && break
done
```

Narrow with `filters` when hunting a specific IP or event name:

```
--data-urlencode "filters=ip_address==<ip>"
--data-urlencode "filters=ip_address==<ip>,event_name==login_success"
```

### 2. Pull Alert Center

```bash
gam print alerts > "$DIR/alerts_all.csv"
# Filter to window offline:
python3 -c "
import csv
from datetime import datetime
rows=list(csv.DictReader(open('$DIR/alerts_all.csv')))
w=[r for r in rows if '2026-04-01' <= r.get('createTime','') <= '2026-04-24']
print(f'{len(w)} alerts in window')
for r in w:
    print(r['createTime'], r['type'], r.get('data.maliciousEntity.fromHeader',''), r.get('data.messages.0.recipient',''))
"
```

`gam print alerts` inline filter syntax is fragile across GAM 7 minor versions. Pulling everything and filtering locally in Python avoids the argument-parsing failure mode and gives the investigator the full corpus for later keyword hunts.

### 3. Search Gmail content across a compromised mailbox (read-only, DWD required)

Three things have to line up before any message-content query works:

1. The DWD entry in Admin Console includes `https://www.googleapis.com/auth/gmail.readonly`. The most reliable confirmation is the Python DWD test at the end of this section — request the scope directly and verify a token is returned. `gam user <target> check serviceaccount` without arguments does **not** test `gmail.readonly` (it probes `gmail.modify`); use `gam user <target> check serviceaccount scopes "https://www.googleapis.com/auth/gmail.readonly"` for a targeted GAM check, but trust the Python test over it if they disagree.
2. The Gmail API is enabled on the GAM GCP project. Workspace Admin SDK (Reports, Directory, Alert Center) is implicitly available on any Cloud Identity tenant; the Gmail API is not. Enable explicitly:
   ```bash
   gcloud services enable gmail.googleapis.com --project=<gam-project-id>
   ```
   Enablement takes ~60 seconds to propagate. Without this, GAM returns `Gmail API Service/App not enabled` even when DWD authentication is perfect — the error describes a missing GCP API enablement, not a Workspace-side problem.
3. The `admin_email` in `gam.cfg` is set to a Super Admin that itself has Gmail service enabled. Some Workspace for Nonprofits tenants have Gmail scoped off certain admin-only OUs; if the admin account you're impersonating doesn't have Gmail, the `/users/me/messages` route 403s through the SA's impersonation — set `admin_email` to a Super Admin whose user has Gmail service on.

Gmail's native search operators live inside the `query "..."` string; GAM's own `after` / `before` keywords do not exist for `print messages` and throw `Invalid argument`. Put the date filter inside the Gmail query:

```bash
# Hunt phishing-lure keywords in a time window via GAM
# Result cap: max_to_print <N>  — NOT maxresults (throws "Invalid argument")
gam user <user@domain> print messages \
  query "(docusign OR dropbox OR sharepoint OR supoena OR \"document access\") after:2026/04/05 before:2026/04/09" \
  headers "Subject,From,To,Date,Message-Id,Authentication-Results,Received" \
  max_to_print 25

# Specific message full content (raw RFC822)
# IMPORTANT: GAM and the Gmail API require the Gmail INTERNAL message ID (16-char hex, e.g. 19e1c40646b0e836).
# Alert Center's messages[].messageId field is the RFC 2822 Message-ID (e.g. message-id@sender.example) — these are NOT the same.
# Resolve an RFC 2822 ID to a Gmail internal ID first:
#   gam user <user@domain> print messages query "rfc822msgid:<rfc2822-id>" max_to_print 1
# then use the id field from the result.
gam user <user@domain> show message <gmail-internal-id> format raw > "$DIR/msg_<user>_<gmail-internal-id>.eml"
```

Gmail search operators that matter for phishing hunts: `from:`, `to:`, `subject:`, `has:attachment`, `filename:.html`, `list:`, `in:anywhere` (includes Spam and Trash), `rfc822msgid:`. Dates in `after:` / `before:` use `YYYY/MM/DD`.

**Direct Gmail API fallback when GAM is uncooperative.** Some GCP project configurations (Gmail API freshly enabled, billing not linked, project ID reused across tools) leave GAM's preflight stuck on `Gmail API Service/App not enabled` even though DWD authenticates and the API itself is reachable. The direct-JWT path sidesteps the preflight and uses the service-account key + `gmail.readonly` DWD scope to talk to `gmail.googleapis.com` end-to-end. It also works identically on any host with `python3` + `openssl`, which is useful for environments where GAM is not installed:

```python
# Requires nothing beyond python3 + openssl. Reuses ~/.gam/oauth2service.json.
import json, base64, time, urllib.request, urllib.parse, subprocess, tempfile, os
SA  = json.load(open(os.path.expanduser('~/.gam/oauth2service.json')))
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def dwd_token(user, scope):
    now = int(time.time())
    claim = {"iss": SA["client_email"], "sub": user, "scope": scope,
             "aud": SA["token_uri"], "iat": now, "exp": now + 3600}
    h = b64u(b'{"alg":"RS256","typ":"JWT"}')
    p = b64u(json.dumps(claim, separators=(',', ':')).encode())
    si = f"{h}.{p}".encode()
    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as f:
        f.write(SA['private_key'].encode()); keyf = f.name
    sig = subprocess.check_output(['/usr/bin/openssl', 'dgst', '-sha256', '-sign', keyf], input=si)
    os.unlink(keyf)
    jwt = f"{si.decode()}.{b64u(sig)}"
    body = urllib.parse.urlencode(
        {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': jwt}).encode()
    req = urllib.request.Request(SA['token_uri'], data=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    return json.loads(urllib.request.urlopen(req, timeout=20).read())['access_token']

USER = 'target@domain.tld'
TOK  = dwd_token(USER, 'https://www.googleapis.com/auth/gmail.readonly')
q    = urllib.parse.quote('docusign OR supoena OR "document access" after:2026/04/05 before:2026/04/09')
hits = json.loads(urllib.request.urlopen(urllib.request.Request(
    f'https://gmail.googleapis.com/gmail/v1/users/me/messages?q={q}&maxResults=25',
    headers={'Authorization': f'Bearer {TOK}'}), timeout=20).read())
for m in hits.get('messages', []):
    meta = json.loads(urllib.request.urlopen(urllib.request.Request(
        f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{m["id"]}'
        '?format=metadata&metadataHeaders=Subject&metadataHeaders=From'
        '&metadataHeaders=Date&metadataHeaders=Authentication-Results'
        '&metadataHeaders=Received&metadataHeaders=Message-Id',
        headers={'Authorization': f'Bearer {TOK}'}), timeout=20).read())
    hdrs = {h['name']: h['value'] for h in meta.get('payload', {}).get('headers', [])}
    print(m['id'], hdrs.get('Date', ''), hdrs.get('From', ''), hdrs.get('Subject', ''))

# Full body of one message (format=full returns base64url-encoded body parts)
MSG = hits['messages'][0]['id']
full = json.loads(urllib.request.urlopen(urllib.request.Request(
    f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{MSG}?format=full',
    headers={'Authorization': f'Bearer {TOK}'}), timeout=20).read())
def walk(part, out):
    if part.get('body', {}).get('data'):
        out.append((part.get('mimeType', '?'),
                    base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', 'replace')))
    for c in part.get('parts', []) or []:
        walk(c, out)
parts = []; walk(full['payload'], parts)
for mt, txt in parts:
    print(f"=== {mt} ===\n{txt[:2000]}")
```

Why the explicit `sub` (subject) in the JWT matters: the `sub` claim is the user whose mailbox the service account impersonates. For the Gmail API, the `users/me` path then resolves to that user. This is the "assume user account" mechanism — Workspace's equivalent of M365's `AppPassword` + impersonation. The impersonated user must exist in the tenant and have a mailbox; the service account itself has no mailbox and cannot be the `sub`.

**Notes specific to Workspace for Nonprofits and Frontline SKUs.**

- Workspace for Nonprofits (free tier) includes the Admin SDK, Directory, Gmail, Alert Center APIs at the same API surface as paid Workspace. DWD impersonation behaves identically. The tier does not change Gmail API availability.
- Cloud Identity Free (no Workspace mailbox) tenants: users have no Gmail mailbox, so `gmail.readonly` impersonation 403s on those users. Verify the target has a Gmail mailbox with `gam info user <target> fields isMailboxSetup` before reaching for Gmail API.
- Workspace Frontline Starter / Frontline Standard: Gmail is available; DWD impersonation works normally. Alert Center is Frontline-Standard-and-up.
- Vault is not available on Workspace for Nonprofits free or Business Starter; eDiscovery fallback for message content on those tiers is the DWD Gmail API path documented above.
- For tenants whose Super Admin OU has Gmail service suspended (common hardening in larger orgs), impersonation fails against those admins specifically. Create or identify a Super Admin in the default OU with Gmail on, set `gam config admin_email <that-admin> save`, and impersonate from there — the `sub` in the JWT is the user whose mailbox is accessed, independent of the admin who owns the DWD grant.

After recovering a lure message, parse the full headers from the `format=raw` or `format=full` output — `Authentication-Results` tells you SPF/DKIM/DMARC outcome, `Received` reveals the originating IP that Google's MTA accepted the message from, and `X-Originating-IP` is occasionally present when upstream clients preserved it. Attacker-owned Google Workspace tenants show a distinctive DKIM selector pattern `<tenant>-<hyphen>.<YYYYMMDD>.gappssmtp.com` — Google's default DKIM for tenants that never configured a custom selector. Legitimate business senders almost always use a custom selector like `s1._domainkey.<their-domain>`.

### 4. List / revoke OAuth tokens for a user

```bash
# READ
gam user <user> show tokens
# equivalent:
curl -sS -H "Authorization: Bearer $(gcloud auth application-default print-access-token)" \
  "https://admin.googleapis.com/admin/directory/v1/users/<user>/tokens" | python3 -m json.tool

# WRITE (requires user approval)
gam user <user> delete tokens clientid <client_id>
gam user <user> delete tokens all
```

The `client_id` values to understand before treating a token as adversarial:
- `77185425430.apps.googleusercontent.com` — Google Chrome (native desktop sync). Legitimate when the user's own browser signed in; adversarial when the IP does not belong to the user.
- `292824132082.apps.googleusercontent.com` — Google iOS / Android apps.
- `764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com` — `gcloud` ADC client.
- Anything else — third-party OAuth app; inspect `displayText` and `scopes` before concluding.

### 5. signOut a user (WRITE — invalidates every refresh token + session cookie)

Password reset does not invalidate existing OAuth refresh tokens. A thief who captured a refresh token or session cookie keeps access after a password change; `signOut` is the endpoint that ends it.

```bash
# WRITE — requires user approval
TOKEN=$(gcloud auth application-default print-access-token)
curl -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-goog-user-project: <gcp-project-id>" \
  "https://admin.googleapis.com/admin/directory/v1/users/<user@domain>/signOut"
```

`x-goog-user-project` is required on user-quota routes; set it to any GCP project the caller has access to.

### 6. Inspect Gmail filters, forwarding, delegates (read-only, DWD)

```bash
gam user <user> show filters
gam user <user> show forwarding
gam user <user> show forwardingaddresses
gam user <user> show vacation
gam user <user> show imap pop
gam user <user> show sendas
gam user <user> show delegate
```

Patterns to pull out: filters that forward or delete based on vendor-name substrings (`bank`, `stripe`, `paypal`, `bill.com`, `ach`, `wire`, `invoice`, `payment`, `remit`); forwarding addresses to external gmail/outlook/protonmail; delegate grants the user didn't request.

### 7. Enumerate admin actions and recent user creations

```bash
gam report admin start 2026-04-01T00:00:00Z end 2026-04-23T23:59:59Z todrive false > "$DIR/admin_report.csv"
gam print users query "orgUnitPath:*" fields primaryEmail,creationTime,suspended,lastLoginTime \
  | awk -F, 'NR==1 || $3 > "2026-04-01"'
```

### 8. MFA and recovery posture per user

```bash
gam info user <user> fields isEnrolledIn2Sv,isEnforcedIn2Sv,recoveryEmail,recoveryPhone,lastLoginTime
```

## Browser and Endpoint Forensics

The Workspace audit log tells you what the attacker did with the account; the endpoint tells you how they got the credentials. Either half alone is misleading. The Chrome History query below resolved the initial-access vector in under 10 seconds on one engagement where 4 days of cloud-side hypothesis had pointed at the wrong browser extension.

### Chrome artifacts on any platform

Profile root:
- macOS: `~/Library/Application Support/Google/Chrome/`
- Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\`
- Linux: `~/.config/google-chrome/`

`Local State` (JSON) lists every profile in `profile.info_cache` with `gaia_id`, `user_name`, `hosted_domain`, `is_managed`. A profile whose `user_name` and `gaia_id` are empty but whose label claims a tenant domain is either dormant or anomalous — read `Preferences`, `Cookies`, and `History` timestamps to decide.

`Default/History` (SQLite). The single highest-value endpoint artifact for AiTM investigations because the phishing landing page, the OAuth redirect chain, and the post-submit bounce all land in `urls` + `visits`:

```sql
SELECT datetime(v.visit_time/1000000 - 11644473600, 'unixepoch') AS t,
       u.url, u.title, v.transition
FROM visits v JOIN urls u ON u.id = v.url
WHERE t BETWEEN '2026-04-07 00:00' AND '2026-04-08 00:00'
ORDER BY v.visit_time;
```

`transition` field decoding (low byte): `0x00` link, `0x01` typed, `0x05` generated, `0x07` form_submit, `0x08` reload. A `form_submit` to an unexpected origin immediately before a `login.microsoftonline.com` or `accounts.google.com` visit is the AiTM fingerprint.

`Default/Cookies` (SQLite, encrypted).
- macOS: encryption key lives in the login keychain under `Chrome Safe Storage`; extraction needs the user's password.
- Windows 11 Chrome 127+: App-Bound Encryption wraps the key via an `IElevator` COM call running as SYSTEM; offline extraction from a mounted image is impossible. Decrypt live on the running host (or in a booted VM clone of the image).

`Default/Login Data` (SQLite) holds saved autofill logins — enumerate `origin_url`, `username_value`, `date_created`, `date_last_used`, `times_used`. Passwords are keychain/DPAPI-encrypted; leave them alone without the user's password. The list of sites a user had autofill for is the shortlist of credentials to rotate as a secondary blast-radius action.

`Default/Preferences` + `Default/Secure Preferences`. Extension install audit: per-extension `install_time`, `from_webstore`, `was_installed_by_default`, `active_permissions`, `granted_permissions`. An extension with `from_webstore=false` + `install_time` inside the incident window is a sideload and gets static-analyzed first. An extension with `<all_urls>` + `webRequest` + `cookies` permissions gets scrutinized regardless of install time.

### Extension static analysis

For a suspect extension under `Default/Extensions/<id>/<version>/`:

```bash
shasum -a 256 "Default/Extensions/<id>/<version>/"{manifest.json,background*,*.js,*.html}
python3 -m json.tool "Default/Extensions/<id>/<version>/manifest.json"
grep -rEo '(fetch\(|XMLHttpRequest|sendBeacon|WebSocket\(|https?://[A-Za-z0-9._~:/?#@!$&+,;=%-]+|chrome\.(cookies|webRequest|tabs|scripting|debugger|identity))' \
  "Default/Extensions/<id>/<version>/"
```

An extension that permits only a specific vendor origin in `host_permissions`, contains zero outbound network primitives, and never touches Google domains is not the attack vector however unfashionable its purpose (adware, search hijacker). Move on and look at History.

---

### Windows Incident Response (Sonoma-Sequoia-Tahoe equivalent follows in the next section)

#### 1. Live-Response Acquisition (Incident Still Active)

Volatile state dies at shutdown and degrades with every minute an attacker stays resident. Capture order follows volatility: RAM, then network and process state, then on-disk transient artifacts, then everything else. Rebooting a live-infected host destroys injected shellcode, unlinked processes, and in-memory-only C2 agents that disk forensics cannot recover.

**Memory acquisition.** Pick by environment, not preference.
- `DumpIt` (Comae/Magnet) — one-file exe, works on Secure Boot / VBS / HVCI hosts, produces `.dmp` or `.raw`. Default when the analyst is at the console with USB.
- `WinPmem` (Velociraptor fork, current build `winpmem_mini_x64_rc2`) — scriptable, right pick when pushing via EDR live-response console or PsExec. Older 3.x builds fail on Win11 22H2+ VBS kernels; the Velociraptor build works.
- `Magnet RAM Capture` — free, GUI, artifact-signed output that plays cleanly with AXIOM downstream.
- `Belkasoft Live RAM Capturer` — fallback when anti-forensics drivers block the others; uses a kernel-mode technique that usually wins against userland tampering.
- `Velociraptor` live memory via `Windows.Memory.Acquisition` artifact — right pick when a Velociraptor agent is already deployed.

On BitLocker-enabled hosts with no suspend-to-disk, grab the BitLocker recovery key from Entra (`Get-BitLockerRecoveryKey`) before any power event.

**Process, network, session snapshot (single PowerShell session so timestamps correlate):**
```powershell
Get-Process -IncludeUserName | Export-Csv proc.csv
Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv net.csv
tasklist /v /fo csv > tasklist.csv
netstat -anob > netstat.txt
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,CommandLine,ExecutablePath | Export-Csv cmdline.csv
query user ; logonsessions.exe -p -c
```

**Persistence triad.**
```powershell
Get-ScheduledTask | Get-ScheduledTaskInfo | Export-Csv tasks.csv
Get-CimInstance Win32_Service | Select Name,State,StartMode,PathName,StartName | Export-Csv svc.csv
Get-CimInstance -Namespace root\subscription -Class __EventFilter
Get-CimInstance -Namespace root\subscription -Class __EventConsumer
Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding
```
WMI event subscriptions are the persistence mechanism attackers most reliably forget to clean, and Autoruns misses filter-to-consumer bindings unless the specific checkbox is ticked.

**Browser state (live).** Chrome/Edge cookies are App-Bound Encrypted — offline copy yields ciphertext. Capture live via Velociraptor's `Windows.Applications.Chrome.Cookies` (IElevator COM call as SYSTEM) or a DPAPI helper attached to the browser process. Also capture `History`, `Login Data`, `Web Data`, `Sessions\*`, `Current Tabs`, `Current Session` per profile.

**KAPE live target.** When dwell time is unknown, multi-host, or repeatable chain-of-custody is required, `kape.exe --target !BasicCollection,!SANS_Triage,RegistryHives,EventLogs,WebBrowsers --tsource C: --tdest \\share\%ComputerName%` captures the artifacts below in 8–15 minutes.

#### 2. Dead-Disk / Image-Based Forensics

Full `dd` images of endpoints are overkill for most intrusions. KAPE or Velociraptor triage collections cover the top-10 artifact list in under 20 minutes over a network share. Reserve full images for destructive malware, insider-threat with civil-litigation exposure, or unallocated-space carving.

| Artifact | Path | What it answers |
|---|---|---|
| Event Logs | `C:\Windows\System32\winevt\Logs\*.evtx` | Logon, process, PowerShell, RDP, WMI, Tasks (see §3) |
| AmCache | `C:\Windows\AppCompat\Programs\Amcache.hve` | First-executed binaries + SHA1 |
| ShimCache | `SYSTEM\ControlSet00x\Control\Session Manager\AppCompatCache` | Executed/stat'd binaries, flushed on clean shutdown |
| Prefetch | `C:\Windows\Prefetch\*.pf` | Last 8 execution times, loaded DLLs, files touched |
| UserAssist | `NTUSER.DAT\...\Explorer\UserAssist` | Explorer-launched executions (ROT13-encoded) |
| ShellBags | `UsrClass.dat\Local Settings\...\Shell\BagMRU` | Folders browsed (including deleted/removable) |
| Jumplists | `%APPDATA%\Microsoft\Windows\Recent\{Automatic,Custom}Destinations` | Recently opened per-app |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | 30-day per-process network bytes, app usage |
| BAM/DAM | `SYSTEM\ControlSet00x\Services\bam\State\UserSettings\<SID>` | Last-run times per exe |
| `$Recycle.Bin` | `C:\$Recycle.Bin\<SID>\` | `$I` metadata + `$R` contents |

**Post-2023 artifacts.**
- **DeliveryOptimization** — `C:\Windows\SoftwareDistribution\DeliveryOptimization\Logs\*.etl`. Peer-to-peer LAN transfers; tool-staging signal.
- **BITS** — `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr.db`. Parse with `BitsParser.py`. `bitsadmin` / `Start-BitsTransfer` remain an active LOLbin download path.
- **Windows Notification Platform** — `%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db` (SQLite). Toast notification history routinely captures Teams/Outlook snippets and MFA push prompts.
- **PowerShell transcripts** — only present if transcription GPO is on: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting=1`. Default output `%USERPROFILE%\Documents\PowerShell_transcript.*.txt`.
- **Scheduled Tasks XML** — `C:\Windows\System32\Tasks\` + registry mirror at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`. Comparing the two reveals tampered entries.

**Chrome/Edge on Windows.** `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\` and `%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\`. The `Local State` `os_crypt.encrypted_key` is ABE-wrapped since Chrome 127 (July 2024); offline cookie decryption from an image is impossible as of 2024. Firefox `%APPDATA%\Mozilla\Firefox\Profiles\<rand>.default-release\` is unchanged — `key4.db` + `logins.json` still decrypt offline.

**Tooling.** Eric Zimmerman's suite (`MFTECmd`, `RECmd`, `AppCompatCacheParser`, `AmcacheParser`, `PECmd`, `SBECmd`, `JLECmd`, `SrumECmd`, `EvtxECmd`, `SQLECmd`); `plaso/log2timeline` for super-timelining; `Hindsight` for browser; Velociraptor's offline collector; Magnet AXIOM and X-Ways when courtroom-defensible parsing is required.

#### 3. Event-Log and ETW Hunting

`Get-WinEvent -FilterHashtable` wins for targeted live queries. `wevtutil epl` exports logs for offline parsing. `EvtxECmd` with community maps wins for offline bulk parsing — fields normalize into CSV/JSON.

**Security.evtx — logon chain.** 4624 `LogonType` matters more than the event itself: **3** network, **9** NewCredentials (runas `/netonly`, PTH signature), **10** RemoteInteractive (RDP), **11** CachedInteractive. Cross-reference `LogonGuid` across 4624 and 4648 (explicit credentials). 4768/4769 Kerberos `TicketEncryptionType 0x17` = RC4 (Kerberoast), `0x12` = AES256. 4740 lockout with empty `Source Workstation` = remote service-account brute force.

**PowerShell/Operational 4104** (script block logging) is the single highest-value log — captures deobfuscated script text even when the attacker used `-enc`. Enable via GPO `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=1`. Search 4104 for `FromBase64String`, `IEX`, `DownloadString`, `Invoke-Expression`, `System.Reflection`, `VirtualAlloc`, `WmiEvent`.

**Sysmon (when deployed).** High-value IDs with the 2024 SwiftOnSecurity/Olaf config: **1** ProcessCreate, **3** NetworkConnect, **7** unsigned DLL ImageLoad, **10** LSASS handle opens with `0x1010`/`0x1410` (Mimikatz), **11** FileCreate in `\Users\Public\` / `\ProgramData\`, **22** DNSQuery, **25** ProcessTampering.

**Other high-value operational logs.** `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational 1149` (pre-logon NLA success). `TerminalServices-LocalSessionManager/Operational 21/24/25` (logon/disconnect/reconnect). `Microsoft-Windows-WMI-Activity/Operational 5861` (CommandLineEventConsumer = WMI persistence). `Microsoft-Windows-TaskScheduler/Operational 106/140/141/200/201`. `Microsoft-Windows-LSA/Operational 3033/3063` (LSA protection). `Microsoft-Windows-AAD/Operational 1006/1098/1100` (Primary Refresh Token — the AiTM-to-Entra bridge). `Microsoft-Windows-WinRM/Operational 91` (WinRM session). `Microsoft-Windows-Windows Defender/Operational 5001/5007` (realtime disabled / config changed — tamper signature).

**Retrospective ETW.** `logman query providers`, then `wpr -start GeneralProfile -filemode` or `xperf -on Base+Network+DiskIO -f trace.etl`. Convert with `tracerpt`. `SilkETW` for lightweight production capture.

#### 4. Browser / AiTM Investigation on Windows

Evilginx2 / EvilProxy / Tycoon-2FA / Storm-1575 leave evidence in four places: `History`, cookie store, `IndexedDB`/Session Storage/Service Workers, and DPAPI ecosystem.

**Profile paths:**
- Chrome `%LOCALAPPDATA%\Google\Chrome\User Data\`
- Edge `%LOCALAPPDATA%\Microsoft\Edge\User Data\`
- Brave `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\`
- Firefox `%APPDATA%\Mozilla\Firefox\Profiles\`

**`Local State` `profile.info_cache`** enumerates per-profile `gaia_id`, `hosted_domain`, signed-in email. A profile with `hosted_domain` set and `is_using_default_avatar=false` whose GAIA ID doesn't match enterprise SSO is a personal-account profile (common exfil channel).

**History AiTM query (see §Browser and Endpoint Forensics above for the same SQL — applies identically on Windows).**

**IndexedDB / Session Storage / Service Workers.** `IndexedDB\`, `Session Storage\`, `Local Storage\leveldb\`, `Service Worker\` per profile. For O365 AiTM, `IndexedDB\https_outlook.office.com_0.indexeddb.leveldb\` contains MSAL token cache (`msal.account.keys`, `msal.token.keys`) — tokens present without a corresponding Entra sign-in = token replay.

**Extensions audit.** `Preferences` + `Secure Preferences` (HMAC'd with profile seed, key in `Local State.protection.macs`). Compute HMAC-SHA256 over `extensions.settings.<id>` with the seed; mismatch = out-of-band modification. Enterprise force-installs: `HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist`, `HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist`. A `Secure Preferences` entry not in the forcelist and not from the Web Store (`update_url` ≠ `clients2.google.com`) = sideload.

**Outlook / Teams caches.**
- `%LOCALAPPDATA%\Microsoft\Outlook\RoamCache\` — Stream_Autocomplete_*.dat (recent recipients / BEC target lists).
- `%LOCALAPPDATA%\Microsoft\Outlook\*.ost` — offline mailbox; items the attacker read via OWA/EAS sit here even after `MailItemsAccessed` noise settles.
- New Teams (v2): `%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\IndexedDB\` — chats, attachments, tenant metadata. Classic `%APPDATA%\Microsoft\Teams\` path is retired.

#### 5. Entra ID / Azure AD / M365 Telemetry

Token-theft leaves minimal endpoint trace beyond a browser cookie DB; the post-compromise story lives in the cloud.

**Sign-in streams (Log Analytics / Sentinel).**
- `SigninLogs` — interactive
- `AADNonInteractiveUserSignInLogs` — token refresh, FOCI, most AiTM replays
- `AADServicePrincipalSignInLogs` — app-as-app
- `AADManagedIdentitySignInLogs` — managed identity

CA risk signals (`riskLevelDuringSignIn`, `riskEventTypes_v2`: `unfamiliarFeatures`, `anonymizedIPAddress`, `tokenIssuerAnomaly`) are advisory. They are not ground truth — an AiTM replay from a residential proxy on the user's home ISP scores "low risk" routinely.

**Audit.** `AuditLogs` — `Consent to application` (illicit-grant phishing signature, especially with `Mail.ReadWrite` + `offline_access` + `Files.Read.All` scope, no admin consent required).

**Microsoft Graph Activity Logs (GA 2024).** `MicrosoftGraphActivityLogs` records every Graph API call with URI, method, response, app ID, user ID. Correlation pattern for token theft: sign-in from suspicious IP → Graph calls to `/me/messages`, `/me/mailFolders/inbox/messageRules`, `/me/drive/root/children` under the same `SignInActivityId`.

**UAL (Purview).** Key ops: `MailItemsAccessed` (per-folder read, BEC anchor), `Send`/`SendAs`/`SendOnBehalf`, `MoveToDeletedItems`/`SoftDelete`/`HardDelete`, `UpdateInboxRules`/`New-InboxRule`, `FileAccessed`/`FileDownloaded`/`FileSyncDownloadedFull`, `Add-MailboxPermission`/`Set-Mailbox ForwardingSmtpAddress`. Retention: Audit Standard 180d, Audit Premium 1y.

**KQL snippets.**
```kusto
// Sign-in IP differs from post-auth action IP
AADSignInEventsBeta
| where Timestamp > ago(7d) and ErrorCode == 0
| where isnotempty(SessionId)
| join kind=inner (
    CloudAppEvents
    | where ActionType in ("MailItemsAccessed","New-InboxRule","Set-Mailbox")
  ) on $left.AccountObjectId == $right.AccountObjectId
| where IPAddress != IPAddress1
| project Timestamp, AccountUpn, IPAddress, IPAddress1, Country, Country1, ActionType, SessionId

// Impossible travel via non-interactive refresh
AADNonInteractiveUserSignInLogs
| summarize Countries = make_set(LocationDetails.countryOrRegion), IPs = make_set(IPAddress)
  by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
```

**Tools.** `AzureHound` (BloodHound-compatible Entra collection); `ROADtools` (`roadrecon`, `roadtx`); `Microsoft-Extractor-Suite` (Invictus-IR, de facto IR collector since 2023); `Hawk` (mailbox-focused O365 triage); Microsoft's own `MIA` / Incident Response module; Defender for Endpoint advanced hunting (`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `IdentityLogonEvents`, `CloudAppEvents`).

#### 6. Windows References and 2024-2025 Breaking Changes

**Tool shortlist.** Velociraptor (open-source DFIR platform); KAPE (triage collection); EZ Tools; plaso/log2timeline (super-timeline); Hindsight (browser); chainsaw/hayabusa (Sigma-based evtx at scale); Magnet AXIOM / X-Ways (commercial); Defender for Endpoint (EDR); Microsoft-Extractor-Suite (M365/Entra); ROADtools; BloodHound CE + AzureHound; CyberChef / DidierStevens suite; Sysmon (SwiftOnSecurity/Olaf config).

**References.** The DFIR Report (`thedfirreport.com`); SANS FOR508 2024 rewrite; Mandiant M-Trends 2025; Microsoft Digital Defense Report 2024; CISA AA-advisories; MITRE ATT&CK v15+; Invictus-IR and Huntress blogs.

**Breaking changes.**
- **Chrome ABE (July 2024)** — offline cookie decryption from an image is dead.
- **Entra named locations** are IP-based only; residential-proxy VPNs defeat them.
- **JA3 → JA4** (Salesforce/FoxIO, 2023-2024) — JA3 gives unstable fingerprints on TLS 1.3; detection content moves to JA4/JA4S/JA4H/JA4X.
- **New Teams (v2)** moved cache to `%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\`. Classic parsers silently return nothing.
- **PowerShell 7** logs to `PowerShellCore/Operational`, not the classic PowerShell log. Both need pulling.
- **ShimCache on Win11** — registry flush behavior changed; AmCache + Prefetch are primary execution artifacts now.

**WSL.**
- WSL1 — Linux syscalls mapped to NT; `%LOCALAPPDATA%\Packages\<distro>\LocalState\rootfs\`, directly collectable.
- WSL2 — real Linux VM, `ext4.vhdx` at `%LOCALAPPDATA%\Packages\<distro>\LocalState\ext4.vhdx`. Standard Windows triage collectors ignore it. Mount the VHDX (`Mount-VHD`, then `wsl --mount`) and run Linux triage (UAC-LR, Velociraptor Linux collector). Bash history at `/home/<user>/.bash_history` is the single most valuable artifact when WSL was used for pivoting.

---

### macOS Incident Response (14 Sonoma / 15 Sequoia / 26 Tahoe)

#### 1. Live-Response Acquisition

**Full-disk preservation.** On Apple Silicon (M1–M4), the SSD is soldered and the Secure Enclave owns volume keys — block-level Target Disk Mode is gone. Three options:
- **Share Disk** (1TR: power → Options → Utilities → Share Disk) — Data volume read-only over Thunderbolt/USB-C SMB.
- **Apple Configurator 2** restore-image of a DFU-placed target — encrypted bundle, needs user password to decrypt later.
- **Logical triage** (Aftermath, mac_apt, custom tar) — typically the fastest and most realistic.

Intel + T2 still supports TDM but FileVault is T2-bound; acquire while unlocked or collect the FV key from MDM escrow.

**Unified Log.**
```
sudo log collect --last 7d --output /tmp/ir_$(hostname -s).logarchive
```
Captures every `os_log` call from launchd, TCC, sandboxd, ES clients, networking, trustd. Ring buffer lasts 7–30 days depending on verbosity. Does not contain file contents, network payloads, keystrokes, or anything an attacker stripped with `log erase --all` (rare — requires root and itself logs to ASL fallback).

**Volatile state.**
```
sudo ps -Aef -o pid,ppid,user,lstart,command
sudo lsof -nP +c 0
sudo lsof -i -nP
netstat -van | grep -E 'ESTAB|LISTEN'
sudo arp -an
sudo fs_usage -w -f filesys                   # firehose; pipe to file, kill quickly
```

**Targeted triage.** Meta's **Aftermath** (active through 2025):
```
sudo aftermath -o /Volumes/EVIDENCE/
sudo aftermath --deep -o /Volumes/EVIDENCE/   # adds browser + mail, slower
```

**Unified-log streaming for a live attacker.**
```
log stream --style ndjson --predicate 'subsystem == "com.apple.TCC" OR eventMessage CONTAINS "tccd"'
log stream --predicate 'process == "osascript" OR process == "curl"' --style syslog
```

**ES telemetry.** Lives inside whichever vendor subscribes — Santa (`/var/db/santa/rules.db`), CrowdStrike Falcon (`falconctl stats`), Jamf Protect (local plan at `/Library/Application Support/JamfProtect/`), Red Canary Mac Monitor (`.rcmmx` trace), Bluelight (`/var/log/bluelight/` JSONL).

**Memory.** `osxpmem` broken since Catalina; no working kernel-memory capture on Apple Silicon (kext path removed, page tables behind SPTM/TXM on M3+). Operational reality: EDR memory YARA (Falcon `runscript`, S1 Deep Visibility). Userspace `lldb -p <pid>; process save-core` where SIP allows and the process isn't hardened-runtime-restricted.

**Keychain.** Decryptable only with user logged in and keychain unlocked. SEP-wrapped items (Passkeys, anything `kSecAttrTokenIDSecureEnclave`) never leave SEP.
```
security dump-keychain -d ~/Library/Keychains/login.keychain-db      # prompts per item
security find-generic-password -a <user> -s "Chrome Safe Storage" -w # Chrome cookie key
```

**Persistence live enumeration.**
```
sudo launchctl list | sort
sfltool dumpbtm                                 # BTM db, macOS 13+
ls -la /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents
profiles show
profiles show -type enrollment
systemextensionsctl list
kmutil showloaded --list-only
```

**Integrity posture.**
```
csrutil status
spctl --status ; spctl --assess -vv /path/to/App.app
nvram -p | grep -E 'boot-args|csr-active-config'    # boot-args set = SIP tampering
bputil -d                                             # Apple Silicon boot policy
```

#### 2. Dead / Offline Forensics

| Path | What it reveals |
|---|---|
| `/var/db/diagnostics/` + `/var/db/uuidtext/` | Unified Log ring on disk |
| `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | Every download with source URL + referrer + UTI |
| `~/.fseventsd/` and `/.fseventsd/` | APFS FSEvents (compressed) |
| `/Library/Application Support/com.apple.TCC/TCC.db` + user copy | Privacy grants: FullDiskAccess, ScreenCapture, Accessibility, Camera, Mic, AppleEvents |
| `~/Library/Application Support/Knowledge/knowledgeC.db` | App focus, device-use bouts, Safari domain visits |
| `~/Library/Biome/` | macOS 13+ activity streams (app launches, notifications) |
| `/private/var/db/BackgroundTaskManagementAgent/BackgroundItems-v*.btm` | BTM persistence store |
| `/var/db/ConfigurationProfiles/Store/` | Installed profiles (MDM + manual) |
| `~/Library/Safari/History.db`, `Downloads.plist`, `CloudTabs.db` | Safari activity |
| `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara` | Signature versions |
| `/Library/Logs/DiagnosticReports/` + `~/Library/Logs/DiagnosticReports/` | Crash logs — malware crashes often |
| `/var/log/install.log` + `.log.*.bz2` | pkg install trail |

**Unified Log offline.**
```
log show --archive /EVIDENCE/system.logarchive \
  --predicate 'process == "tccd" OR subsystem == "com.apple.securityd"' \
  --style ndjson --info --debug > tcc.ndjson
```

**Quarantine SQL.**
```
sqlite3 QuarantineEventsV2 \
  "select datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString from LSQuarantineEvent order by 1 desc;"
```
Apple epoch offset 978307200 = 2001-01-01.

**FSEvents.** Parse `.fseventsd/` binary-compressed logs with **FSEventsParser** (2024+ fork supports APFS compression).

**TCC.**
```
sqlite3 TCC.db "select service, client, auth_value, datetime(last_modified,'unixepoch') from access;"
```
`auth_value` 2 = allowed, 0 = denied. `kTCCServiceAppleEvents` granted to `osascript` or a random binary = AppleScript-driven data theft signature.

**Keychain offline.** `login.keychain-db` on Sonoma+ is SQLite-wrapped; `security dump-keychain -d` still requires the user password. **ChainBreaker 2** for legacy `.keychain` only.

**Browsers.** Canonical paths:
- Safari `~/Library/Safari/`; cookies `~/Library/Cookies/Cookies.binarycookies`
- Chrome `~/Library/Application Support/Google/Chrome/<Profile>/`
- Edge `~/Library/Application Support/Microsoft Edge/<Profile>/`
- Brave `~/Library/Application Support/BraveSoftware/Brave-Browser/<Profile>/`
- Arc `~/Library/Application Support/Arc/User Data/<Profile>/`
- Firefox `~/Library/Application Support/Firefox/Profiles/<rand>.default-release/`

**knowledgeC / biome.** `knowledgeC.db` tables `ZOBJECT` + `ZSTRUCTUREDMETADATA` — `/app/usage`, `/app/inFocus`, `/safari/history`. Parse with **APOLLO**. `~/Library/Biome/streams/` protobuf streams are the 2024+ replacement Apple is migrating records into.

#### 3. Persistence in 2025-2026

**LaunchDaemons / LaunchAgents** remain primary. Sonoma+ requires loading binaries to be notarized or BTM-approved; rogue unsigned daemons surface in `sfltool dumpbtm` as "disabled" or "awaiting approval."

**BTM (Background Task Management).** Central registry since macOS 13. `sfltool dumpbtm` live; offline at `/private/var/db/BackgroundTaskManagementAgent/BackgroundItems-v*.btm`. Unified-log subsystem `com.apple.backgroundtaskmanagement` logs add/remove.

**Configuration Profiles.** `/var/db/ConfigurationProfiles/Store/ConfigProfiles.binary`. Rogue profiles install root certs, proxies, update restrictions. `profiles show -all` for inventory.

**cron.** Still works on Sonoma/Sequoia/Tahoe but requires Full Disk Access TCC grant for most user data. `/var/at/tabs/`, `/var/at/atjobs/`.

**Kernel extensions.** Deprecated 2020. On Apple Silicon, requires 1TR → Security Policy → Reduced + `systemextensionsctl developer on`; loud signal. Intel + T2 with reduced security: possible.

**System Extensions / DriverKit / ES extensions.** `/Library/SystemExtensions/<UUID>/`, enumerate with `systemextensionsctl list`. Abusable via signed-but-malicious NetworkExtension (VPN/proxy exfil) or ES extension (shadow inspection).

**Login-item surface (all land in BTM).** Dock persistent apps (`~/Library/Preferences/com.apple.dock.plist`); QuickLook plugins (`/Library/QuickLook/`, `~/Library/QuickLook/`); Spotlight importers; Finder sync extensions (`pluginkit -m -p com.apple.FinderSync`); screen savers; services; Safari App Extensions (`pluginkit -m -A -v | grep -i safari`).

**Shell init.** zsh: `/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin` system-level; `~/.zshenv`, `~/.zprofile`, `~/.zshrc`, `~/.zlogin` user-level. `/etc/zshenv` fires for every zsh invocation including non-interactive scripts — high-value attacker plant.

**sudoers.** `/etc/sudoers.d/*` — drop-ins granting NOPASSWD to user-writable binaries.

**Network-level.** `~/.ssh/authorized_keys` + `/etc/ssh/sshd_config`; Wi-Fi `com.apple.airport.preferences.plist`; `known_hosts` + `~/.ssh/config` with `ProxyCommand`.

**Supply-chain.** Homebrew taps (`$(brew --repository)/Library/Taps/`), CocoaPods (`Podfile.lock` + `~/.cocoapods/repos/`), MacPorts, `pip --user` installs.

**Dylib hijack / `DYLD_INSERT_LIBRARIES`.** SIP blocks against Apple/hardened-runtime binaries; residual risk on third-party apps shipped with Library Validation disabled and a writable bundle. Audit with `codesign -dv --entitlements - /Applications/<app>.app`.

#### 4. Browser / AiTM Investigation on macOS

**Chrome profile binding.** `Local State` → `profile.info_cache` → per-profile `gaia_id`, `user_name`, `hosted_domain`, `is_managed`. `is_managed=true` with unexpected `hosted_domain` = attacker-enrolled profile.

**Chrome cookie encryption on macOS.** v10 AES-GCM, 16-byte key via PBKDF2 (1003 rounds, salt `saltysalt`) from the keychain entry `Chrome Safe Storage`. No ABE on macOS — decryption needs only the keychain unlock + the `Cookies` file.

**Safari cookies.** `~/Library/Cookies/Cookies.binarycookies` — Apple binary format; parse with **BinaryCookieReader** or `mac_apt`.

**AiTM History query.**
```sql
SELECT datetime(visit_time/1000000 - 11644473600, 'unixepoch') AS t,
       urls.url, urls.title, visits.transition
FROM visits JOIN urls ON urls.id = visits.url
WHERE urls.url LIKE '%login.microsoftonline%' OR urls.url LIKE '%accounts.google%'
   OR urls.url LIKE '%okta%' OR urls.url LIKE '%/oauth2/%' OR urls.url LIKE '%/saml%'
ORDER BY t;
```
Cross-reference with `QuarantineEventsV2` for HTML-smuggled attachments, and with `knowledgeC.db /app/inFocus` for "Mail app was focused at T-30s."

**Extensions audit.** `Preferences` JSON + `Secure Preferences` (HMAC with `Local State.protection.macs`). Per-extension `install_time`, `from_webstore`, `was_installed_by_default`, `path`. `from_webstore=false` + `install_time` inside the incident window = sideloaded.

**Safari Extensions.** Mac App Store only since Safari 13. Enumerate: `pluginkit -m -A -v | grep -i 'com.apple.Safari.extension'`.

**WebKit LocalStorage / IndexedDB.** `~/Library/Safari/LocalStorage/`, `~/Library/Safari/Databases/___IndexedDB/`, `~/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/`. Chrome `~/Library/Application Support/Google/Chrome/<Profile>/Local Storage/leveldb/` + `IndexedDB/`. Grep for `gmail.com`, `outlook.office.com`, `login.live.com` keys.

#### 5. Workspace / M365 Endpoint Telemetry on Mac

- **Chrome saved logins** — `Login Data` SQLite `logins`; passwords encrypted with the Safe Storage key. Enumerate sites to shortlist the rotate-now credentials.
- **Apple Mail** — `~/Library/Containers/com.apple.mail/Data/Library/Mail/V10/` (V10 Sonoma/Sequoia, V11 Tahoe). `.emlx` message store; attacker-read items may linger after server-side deletion.
- **iCloud Mail** — `~/Library/Mail/V10/IMAP-<account>@imap.mail.me.com/`.
- **Google Drive for Desktop** — `~/Library/Application Support/Google/DriveFS/<obfuscated id>/`; identifiers in `experiments.db` and `root_preference_sqlite.db`; logs at `~/Library/Application Support/Google/DriveFS/Logs/drive_fs.txt`.
- **OneDrive** — `~/Library/Application Support/OneDrive/settings/<account>/`; tenant ID in `Business1/global.ini`; logs `~/Library/Logs/OneDrive/`.
- **Slack** — `~/Library/Application Support/Slack/storage/` + `~/Library/Application Support/Slack/Cookies`.
- **New Teams** — `~/Library/Containers/com.microsoft.teams2/Data/Library/Application Support/com.microsoft.teams/` + `~/Library/Group Containers/UBF8T346G9.com.microsoft.teams/`.
- **Outlook for Mac** — `~/Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/<Profile>/Data/Outlook.sqlite`; attacker-added inbox rules visible offline here even after server-side strip.

#### 6. macOS References and 2024-2026 Breaking Changes

**Open-source.** Aftermath (primary triage); mac_apt (offline parser with APFS snapshot/knowledgeC/Spotlight/FSEvents/Safari/Chrome plugins); ChainBreaker 2 (legacy keychain); FSEventsParser; SpotlightParser; APOLLO (knowledgeC/biome/powerlog/Duet).

**EDR / commercial.** Velociraptor (macOS pack refreshed 2024 with Sonoma parsers for BTM/TCC/unified-log); CrowdStrike Falcon Forensics; Jamf Protect offline collector; SentinelOne `sentinelctl`; Mosyle Hardening; Kandji Liftoff; Magnet AXIOM; BlackBag MacQuisition.

**Apple native.** `sysdiagnose` (Ctrl-Opt-Cmd-Shift-. or `sudo sysdiagnose -f /tmp/`) — 2024 builds add taskinfo, richer spindump, full ES subscription dump, MDM profile state.

**MDE on Mac.**
```
mdatp diagnostic create --path /tmp/
mdatp health ; mdatp threat list
```
Logs at `/Library/Logs/Microsoft/mdatp/`.

**Breaking changes 2023→2026.**
- Kexts functionally gone on Apple Silicon.
- TCC tightened — every sensitive path requires explicit grant and the grants are logged.
- Keychain access to a locked keychain is blocked; SEP-bound items never extract.
- `launchctl load/unload` is soft-deprecated since macOS 13 in favor of `bootstrap`/`bootout` with domain targets; BTM gates approval.
- System Extensions fully replaced kexts.
- Biome streams are the new first-class activity source; knowledgeC alone misses 2024+ data.
- Emond removed macOS 14.
- Gatekeeper on Sequoia tightened: right-click-Open bypass for unsigned apps requires System Settings → Privacy & Security.

**References.** SANS FOR518; objective-see.org (Patrick Wardle's tools + Mac Malware annual reports); The Art of Mac Malware vols 1 & 2; Thomas Reed (Malwarebytes) stealer writeups; Objective by the Sea talks; Apple Platform Security Guide.

---

## Codified Lessons (Anti-Pattern List)

Each entry below reflects a specific mistake observed on at least one engagement. The shape: observation → why it is wrong → correct approach. Attribution and evidence discipline rules that generalize across platforms have been extracted to `agent/rules/ir-evidence.md` — the anti-patterns below are Google Workspace-specific or illustrate the general rules with platform-specific detail.

**A1. Look-back window too short.** Setting the initial pull window to match when the user noticed misses the initial-access event by days or weeks. Correct approach: 30-day minimum on the first pass; extend if events cluster near the boundary.

**A2. Assuming the browser extension is the attack vector before checking History.** Browser extensions are visible, suspicious-looking, and have suggestive names — but the attack vector in AiTM compromises is almost always a phishing URL in History. Correct approach: query `History.urls` + `History.visits` for the 10-minute window around the earliest anomalous cloud event, then consider extensions only if History is clean.

**A3. Treating Admin Reports Gmail feed as complete email telemetry.** The Admin Reports `gmail` application only records ML-flagged events (spam/phishing/malware decisions); it does not record normal deliveries. Correct approach: Admin Reports for policy-flagged events, DWD + `gmail.readonly` (or Vault) for message content, Admin Console Email Log Search for envelope metadata in the last 30 days.

**A4. Password reset as containment.** Password reset does not invalidate OAuth refresh tokens or session cookies. An attacker who stole a session via AiTM keeps access after a password change. Correct approach: `signOut` the user, revoke every OAuth token not known to belong to the user, then reset the password.

**A5. Treating the `77185425430` Chrome client_id as an attacker app-registration.** That client ID is Google's built-in Chrome sync client, minted automatically when any Chrome instance signs into a Google account. It becomes adversarial evidence only when the authorizing IP does not belong to the user. Correct approach: `client_id` alone is never the smoking gun; correlate with IP, user-agent, and whether the user has a known Chrome instance there.

**A6. Searching the wrong audit `application` for a Gmail-looking event.** `blocked_sender_change` fires in `applicationName=login`, not `gmail`. `forwarding_edit` fires in `user_accounts`. Correct approach: when a named event doesn't show up where expected, grep the full audit JSON across every feed before concluding the event didn't happen.

**A7. Including `apps.alerts` in the gcloud ADC scope list.** Google restricts `apps.alerts` to allowlisted OAuth clients; the gcloud ADC client is not on that list. Adding it causes the interactive login to fail with `Error 400: invalid_scope`. Correct approach: Alert Center goes through GAM (or a custom OAuth client with the tenant's own consent screen).

**A8. Confusing "session stolen" with "password captured + MFA bypass".** A `login_type: reauth` event with a fresh session cookie = cookie replay (session theft). A `login_type: google_password` followed by phone challenge = AiTM credential capture plus MFA bypass. The distinction determines whether the attack used a proxy kit or opportunistic cookie exfil. Correct approach: read the `login_type` and `login_challenge_method` fields before writing the attack-chain narrative.

**A9. Misattributing user activity to the attacker because an IP is unfamiliar.** Shared mailboxes have many legitimate delegates; users travel, VPN, and tether. An IP that looks wrong may still belong to a legitimate delegate. Correct approach: ask the user or a teammate out-of-band before asserting an event is adversarial.

**A10. Scope creep into artifacts that belong to a different investigation.** Artifacts from another user, tenant, or time window that "look interesting" should stay out of the evidence tree unless the user authorizes inclusion. Correct approach: scope-entries that fall outside the engagement get annotated with a correction banner or dropped entirely, not carried forward "just in case."

**A11. Running destructive containment without specific user approval.** Broad "you have authorization to investigate" is not authorization to signOut, revoke, suspend, or delete. Correct approach: propose the specific action against the specific target, wait for the user to approve, then run it.

**A12. Reporting in AI slop.** Sentences that restate what a command does, preamble ("Here is an analysis of…"), or wrap-up ("In conclusion, the attacker…") add nothing. Correct approach: every sentence either adds a fact the reader did not have or is cut. The reader has the audit log; they do not need the narrative padding.

## Prompting Subordinate Agents Under This Skill

When dispatching a subagent to run a piece of this work, write the prompt so the agent understands the constraint rather than memorizes a rule. Prefer explaining the consequence over issuing an imperative. Two examples of the same instruction:

Weaker (imperative, brittle):
> Do not run `gam user ... delete ...` commands.

Stronger (explanatory, generalizes):
> All `gam user ... delete ...` operations terminate live sessions or remove mailbox configuration; they require the investigator to review evidence first and approve the specific command and target. If you reach a point where deletion appears warranted, produce the exact command and a one-line evidence summary, then stop and wait for approval.

Weaker:
> Do not modify raw audit JSON files.

Stronger:
> Raw audit JSON is the canonical evidence the finding is built on; overwriting it breaks chain of custody and makes the finding unreproducible. Derived analysis lives in markdown under `ir/evidence/` with the source-file path and the jq command embedded.

The pattern is: say *why* once, then the rule follows from it without needing repetition or emphasis formatting.

## Output Conventions

Raw pulls: `$ENGAGEMENT_DIR/ir/reports/<feed>_<target>_<window>.{json,csv}`. SHA-256 into `ir/reports/SHA256SUMS.txt`. Never edit in place.

Derived analysis: `$ENGAGEMENT_DIR/ir/evidence/*.md`. Every claim cites a source file + timestamp + IP + actor + eventName. Derived files embed the jq/sqlite command they used so another investigator can re-run.

Timelines: one `ir/timeline/<topic>.md` per narrative thread (admin-account events, financial-fraud events, endpoint events). Events listed UTC, one per line, with source file reference.

Containment log: `ir/containment.md` — every WRITE action with its timestamp, the command, the approver, and the user-visible outcome.

## Extended Resources

- Admin SDK Reports API: https://developers.google.com/admin-sdk/reports/v1/reference/activities
- Alert Center API: https://developers.google.com/admin-sdk/alertcenter/reference/rest
- GAM 7 wiki: https://github.com/GAM-team/GAM/wiki
- GAMADV-XTD3 project-reuse reference: https://github.com/taers232c/GAMADV-XTD3/wiki/Authorization
- DWD setup: https://support.google.com/a/answer/162106
- Google Vault API: https://developers.google.com/vault/reference/rest
- Admin Console Email Log Search: https://support.google.com/a/answer/2604578
