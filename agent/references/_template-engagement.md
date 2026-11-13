---
description: "Per-engagement program brief template — the canonical home for all engagement-specific ROE (scope, headers, rate cap, no-fire endpoints, side-effect limits, ban-risk rules). Fill in one copy per engagement. Stays OUT of global prompts; loaded by specialists via the engagement's ENGAGEMENT.md or scope.json references."
category: Engagement Setup
---

# Engagement Program Brief — \[ENGAGEMENT NAME / KEY\]

> **Usage:** copy this file to `$ENGAGEMENT_DIR/ENGAGEMENT.md` and fill in every section before
> dispatching specialists, who read it at the start of each dispatch. Update it as the program
> changes (new OOS carve-outs, rate caps, no-fire endpoints). It holds only per-program values; the
> reasoning behind the constraints is in `agent/shared-constraints.md` and `agent/rules/hunting.md`.
>
> **Applicability:** these constraints govern live target-facing testing. A code engagement doing
> pure source review sends no target traffic and isn't bound by the header, rate, no-fire,
> deconfliction or exfiltration rows while it reads source. They apply again as soon as the code
> track runs a live probe, such as a fuzz campaign against a running target
> (`agent/phases/code-phase-4-fuzz.md`) or web testing alongside the review (`operator-core-code.md`
> "Integration with Web Engagement").

---

## 1. Scope

### In-Scope Hosts and Assets

```
# List every in-scope apex domain, wildcard, IP range, or asset class.
# Mirror what is registered in scope.json — this section is human-readable context;
# scope.json is the canonical declaration of what this engagement is authorized to touch.

*.example.com
api.example.com
10.0.0.0/24   # internal range — only when VPN/tunneled access is granted
```

Scope notes (cloud regions, mobile apps, API versions, etc.):

> [FILL: any scope nuances not captured by the host list — e.g., "Android app v3.x+
> only", "EU region only", "does not include payment microservice"]

### Out-of-Scope Hosts and Paths

```
# List every explicit OOS carve-out. These are registered with:
#   vigil engagement add-oos <key> <host-or-path>
# HOST carve-outs shape the surfaces that read scope.json: the recon/ingest host
# filters, work-buffer admission, and proxy capture ownership. PATH carve-outs
# belong in the human-readable Off-Limits Paths section below. Neither host nor
# path metadata is a network-request or specialist-dispatch admission control;
# the canonical engagement-boundary rule is agent/shared-constraints.md §1.

appointments.example.com       # third-party scheduling SaaS
*.cdn-vendor.net               # CDN infrastructure — not in scope
/api/internal/billing          # billing service — separate program
```

OOS notes:

> [FILL: rationale for unusual carve-outs; whether any OOS paths were recently moved in-scope]

---

## 2. Required Request Headers and Deconfliction Marker

> Programs require these headers to attribute and deconflict researcher traffic.
> `vigil engagement set-header` registers each one, and the CLI then injects it into in-scope HTTP
> probes (`agent/skills/kali-exec/SKILL.md` "Required attribution headers" lists which tools).

### Program-Mandated Headers

```bash
# Register these before any probing. set-header takes the engagement key plus a
# single "Name: Value" string (NOT separate name and value arguments):
vigil engagement set-header <engagement-key> "X-Bug-Bounty-Researcher: <handle>"
vigil engagement set-header <engagement-key> "User-Agent: BugBountyResearcher/<handle>"
```

| Header | Value | Injection method |
|--------|-------|-----------------|
| `[FILL: header name]` | `[FILL: value]` | `set-header` (auto-injected) |

### Deconfliction Marker

The program uses `[FILL: header name OR User-Agent OR request body field]` as the
deconfliction marker. Registered value: `[FILL: exact value]`.

Placement decision (fill in one):

- [ ] **Header** — registered via `vigil engagement set-header` and auto-injected
- [ ] **User-Agent** — must be set explicitly on tools that override UA by default (nikto, whatweb, hydra)
- [ ] **Request body field** — inject manually into POST/PUT payloads; note which tools cannot carry it

> [FILL: any tool-specific exceptions where the marker cannot be auto-injected and must be handled manually]

---

## 3. Rate Cap

> Exceeding the program's rate cap risks a ban or invalidation of findings.
> The per-target rate table in `agent/references/recon/rate-calibration.md` provides per-trait
> defaults; the values below OVERRIDE those defaults for this engagement.

| Surface | Max requests/sec | Max concurrency | Notes |
|---------|-----------------|-----------------|-------|
| All in-scope hosts (default) | `[FILL: e.g., 20]` | `[FILL: e.g., 5]` | — |
| API endpoints | `[FILL]` | `[FILL]` | [FILL: e.g., "strict — returns 429 at > 10 req/s"] |
| Authenticated flows | `[FILL]` | `[FILL]` | [FILL: e.g., "session invalidates on rapid reuse"] |

Back-off rule: on a 429, pause `[FILL: e.g., 60]` seconds before retrying, then step down a row
as `agent/references/runtime-guides/dispatch-resource-policy.md` "When to step down a tier"
describes. Stay under the cap rather than working around it, because the program may revoke
scope on violation.

---

## 4. No-Fire Endpoints

> Don't probe these. They reach real end-user inboxes, queues or state, or the program excludes
> them. For a lead that touches one, record a `scope_decision` instead of firing the request to
> see what happens.

```
# Absolute no-fire list for this engagement (add paths or full URLs):
/api/send-email
/api/sms
/api/create-account         # could create real accounts visible to real users
/admin/delete               # destructive operation on production data
[FILL: additional no-fire paths]
```

If the engagement schema mirrors this list into `scope.json.off_limits_paths`
(a JSON array of `/path`, globbed `/path/*`, or absolute URL patterns), treat
that field as descriptive ROE metadata. Kali execution, browser navigation,
Katana defaults, and the shared proxy do not translate it into outbound-request
refusal.

If a test path you want to probe is adjacent to one of the above (e.g., testing
`/api/send-notification` vs. `/api/send-email`), raise a `scope_decision` before proceeding
so the operator can confirm the boundary.

---

## 5. Irreversible and Notifying Flows

> Any flow that on success OR failure could land in a real inbox, create a persistent
> record visible to real users, or send a notification must be characterized statically —
> not proved by triggering it. Run `vigil assess contract agent decision` for the doctrine
> (static-first characterization, the reaches-a-real-third-party test, and the capped
> 1-3 live-fire budget for genuine unknowns).

Known irreversible / notifying flows in this engagement:

| Endpoint / action | Side effect | Real recipient? (yes\|no\|unknown) | Approved for probing? | Condition |
|-------------------|-------------|----------------------------------|----------------------|-----------|
| `[FILL: e.g., POST /api/support/ticket]` | Creates a real support ticket visible to the vendor | Yes | No | Record a `human_reach_decision`; do not fire |
| `[FILL: e.g., POST /api/password-reset]` | Sends a reset email to the account address | Unknown | Conditional | Only with a researcher-owned email address (see Known-Safe Test Destinations below) |
| `[FILL: add rows]` | | | | |

Static characterization procedure: describe the likely behavior from source / spec /
documentation and record a `scope_decision`. Do not trigger to confirm beyond the
capped live-fire budget in `agent/shared-constraints.md` §2d when the recipient is
genuinely unknown.

### Known-Safe Test Destinations

> Pre-declare test identities and destinations here that are proven NEGATIVE under
> the "reaches-a-real-third-party" test in `vigil assess contract agent decision` — a
> researcher-owned mailbox/phone, a documented sandbox with no live inbox, or a
> self-directed test account. A destination listed here is ordinary surface — hunt
> it fully; sending to it does not consume the `agent/shared-constraints.md` §2d live-fire budget and does not
> need a `human_reach_decision` record.

| Destination | Type | Owner / control | Notes |
|-------------|------|-----------------|-------|
| `[FILL: e.g., pentest+vigil@researcher.example]` | Email | Researcher-owned mailbox | Safe for password-reset / notification testing |
| `[FILL: e.g., +1-555-0100]` | Phone / SMS | Researcher-owned test number | Safe for SMS-notification testing |
| `[FILL: e.g., staging.example.com sandbox tenant]` | Sandbox account | Provisioned by the program, no live inbox | Confirmed no delivery to real users |
| `[FILL: add rows]` | | | |

---

## 6. Exfiltration Limits

> Proof of access needs one exact minimal sample. Bulk-pulling real user records adds no evidence
> and only adds harm (`agent/rules/hunting.md` §10).

Per-finding exfiltration limit: **one exact minimal sample** (enough to prove the
record class and access). Specific limits for this engagement:

| Data class | Limit | Notes |
|------------|-------|-------|
| PII / user records | 1 exact row | Preserve the captured row verbatim; do not collect a second row |
| Payment / financial data | 1 exact row | Preserve the captured row verbatim; stop immediately on first confirmed access |
| Credentials / tokens | 1 exact value when it is the proof | Preserve the captured value verbatim; stop after confirmation |
| `[FILL: engagement-specific class]` | `[FILL]` | `[FILL]` |

Evidence-not-collection principle: if a single record proves access, stop. The finding's
`details.evidence` carries that exact minimal sample; it does not carry a downloaded table.

---

## 7. Parked and Non-Submittable Findings

> Some in-scope findings cannot be submitted (duplicate, not-applicable by program policy,
> informational-only, already-known). Park them rather than discarding — they may become
> submittable after a disclosure window or serve as chain primitives.

Known non-submittable classes for this program:

- [ ] Missing security headers (informational per program policy)
- [ ] Self-XSS (requires victim interaction not achievable by attacker)
- [ ] `[FILL: any program-specific not-applicable class]`

Finding lifecycle for parked findings (there is no `parked` status — use the real
holding-area mechanism):
1. Record normally via `vigil assess finding record`. For informational / not-applicable-by-policy
   classes, set `evidence_type=informational`; for a strong-but-unproven finding or chain primitive,
   set `evidence_type=theoretical` and `details.chain_required=true` (with `details.chain_rationale`).
2. Move it into the holding area so it stays OUT of the report until proven, rather than leaving it
   report-ready: `vigil assess finding verify <slug> --status pending_runtime_proof --reason "parked: <why not yet submittable>" --next-test-file <next-test.json>`.
   The next test names what would make it submittable or disprove it (`vigil assess contract finding verify`).
   The park reason lives in that verification reason / `details.chain_rationale`, not a non-existent `parked_reason`.
3. Review the holding area with `vigil assess finding list --holding` and re-evaluate after each
   engagement phase — a chain may promote it to submittable.

---

## 8. Ban-Risk Rules

> Violating these risks account suspension, revocation of scope, or CNA action.

- **Do not bypass the rate cap** (§3 above). The program monitors request volume by IP and
  researcher handle.
- **Do not use destructive operations** (`DELETE`, `PATCH` on production data) without
  explicit written approval from the program.
- **Deconfliction header is mandatory** on all in-scope HTTP traffic (§2 above). Missing
  headers on a probe that triggers an alert is treated as unauthorized access.
- `[FILL: any program-specific ban-risk rule — e.g., "account creation via the standard
  flow is not permitted; researcher accounts are pre-provisioned"]`

If you are unsure whether a probe is in-scope, record a `scope_decision` and surface it
to the operator before probing.

---

## 9. Passive DNS Coverage — Free Key Uplift

> Supply these environment variables before running dns-discovery to unlock free tier
> access to Chaos (ProjectDiscovery) and GitHub subdomain corpora. Missing keys mean
> subfinder silently skips those sources and the recon coverage is lower.

```bash
# Set in the engagement environment or ~/.vigil/.env:
export SUBFINDER_CHAOS_API_KEY="[FILL: get from https://chaos.projectdiscovery.io]"
export SUBFINDER_GITHUB_TOKEN="[FILL: personal token, read:packages scope]"
```

After setting the keys, re-run the dns-discovery stage:

```bash
vigil assess dns-discovery <apex-domain> --engagement-dir <engagement-dir>
# OR if already ran subfinder:
vigil assess kali subfinder -d <apex-domain> -all -recursive \
  -o /engagements/<key>/scans/subs_passive_refresh.txt \
  --technique RECON --intent "subfinder rerun with Chaos+GitHub keys" \
  --probe-kind fingerprint --phase recon --timeout 600
```

A re-run with keys typically surfaces 15–40% more subdomains on enterprise targets versus
the keyless run, which directly affects the attack surface available in Phase 2.
