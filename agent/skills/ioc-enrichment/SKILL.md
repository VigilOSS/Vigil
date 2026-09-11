---
name: ioc-enrichment
description: Support skill for IOC reputation, classification, and cross-referencing against threat-intelligence sources — IPs, domains, URLs, hashes, emails, ASNs
origin: Vigil
---

# IOC Enrichment

## When to Activate

- L2 platform investigator needs reputation on an IP, domain, URL, hash,
  email, or ASN that surfaced during an audit pull — sign-in source IP,
  OAuth redirect URL, attachment hash, sender domain, suspect ASN.
- L3 verifier needs IOC reputation before Check 1 (reachability) or
  Check 2 (detection-control corroboration) lands — e.g., the verifier
  wants to confirm the IP is a known commercial VPN exit before
  accepting the sign-in as anomalous.
- L4 ir-lead needs IOC reputation before authoring a containment
  proposal — confirming the IP is malicious before firewall-blocking
  it, confirming the domain is the actual phish landing page before
  sinkholing it.
- Cross-referencing intel from a prior engagement: an IOC the operator
  recognizes from another customer's investigation, recorded as a
  cross-tenant `intel-note` with no copied cross-tenant evidence per
  `triage.md` rule 8.

This skill is **support-class** — it does not produce findings on its
own. IOC reputation lookups feed the investigator's evidence_refs, the
verifier's check outcomes, and the ir-lead's containment proposals.
Record reputation as intel via `vigil assess intel record`, link intel
to findings via `vigil assess finding link`.

## Always-active references

- `agent/rules/triage.md` — symmetric evidence bar (rule 4) applies to
  IOC reputation citations the same way it applies to alert evidence;
  a vendor's verdict alone is not evidence-grade without a source URL,
  query timestamp, and reproduction details.
- `agent/shared-constraints-blue.md` — read-only by default,
  cross-tenant work forbidden (rule 7 / §1), host-exec audit pipeline
  required for every reputation query (§6).
- `agent/rules/ir-evidence.md` — attribution gate on IOC-to-actor
  claims; a malicious-IP reputation does not by itself attribute
  malicious intent to a user signing in from that IP.
- The tenant ref(s) named in `scope.json:tenant_reference_paths[]` —
  the customer's documented egress IPs, partner-domain allowlists,
  legitimate-vendor IOCs that should NOT be flagged adversarial even
  when public reputation tags them so.

## Tools

All IOC reputation queries run through `vigil assess host-exec` so the
audit pipeline records them. The `host-exec` envelope for IOC
enrichment uses `--technique IOC-ENRICH`.

| Tool | What it covers | Notes |
|------|----------------|-------|
| `whois` | IP / ASN / domain registration | Free; use for ASN ownership and domain age |
| `dig` | DNS A / AAAA / MX / NS / TXT / SOA / CNAME / PTR | Free; resolve domain → IP; PTR resolve IP → hostname |
| `curl` against VirusTotal API | IP / domain / URL / file-hash reputation | Requires `VT_API_KEY` env var; v3 API documented at virustotal.com/reference/files |
| `curl` against AbuseIPDB | IP reputation, abuse confidence score | Requires `ABUSEIPDB_API_KEY` env var |
| `curl` against AlienVault OTX | IP / domain / URL / hash; threat-actor pulse linkage | `OTX_API_KEY` env var |
| `curl` against Shodan | IP service / banner fingerprint | `SHODAN_API_KEY` env var |
| `curl` against urlscan.io | URL screenshot, DOM, response chain | `URLSCAN_API_KEY` for higher rate limits |
| `curl` against MaxMind GeoIP2 | IP → geo + ASN lookup | Local database OR API depending on customer setup |
| `python3 -c 'import ipaddress; ...'` | RFC1918 / cloud-provider CIDR classification | No external calls; pure-stdlib |
| `jq` | Filtering reputation JSON | No external calls |

### API key conventions

The wrapper expects API keys in environment variables, never inline in
commands. Configure per-engagement in the operator's secrets file
(referenced from `scope.json:secrets_path`) and source before any
host-exec:

```
VT_API_KEY=<vt-key>
ABUSEIPDB_API_KEY=<aip-key>
OTX_API_KEY=<otx-key>
SHODAN_API_KEY=<shodan-key>
URLSCAN_API_KEY=<urlscan-key>
MAXMIND_LICENSE_KEY=<maxmind-key>
```

The actual key values do NOT enter the engagement repository, the
`host-exec` `--intent` field, or the `intel record` payload. Missing
API keys for a given source surface as `coverage_gaps` in the dispatch
handoff so the operator can decide whether to re-dispatch with
credentials.

### Backend-only helpers (no host-exec needed)

These touch no external services and do not need the audit envelope:

- `vigil assess intel record <type> <json-file>` — record reputation
  results into the appropriate `intel_*` table
- `vigil assess finding link <finding> --intel <intel-id>` —
  associate enriched IOC with a finding; `--intel` may be repeated to
  attach multiple intel rows in one call (the verb merges with any
  existing `details.related_intel_ids[]` on the finding)
- `vigil assess intel list <type>` — query existing intel records to
  avoid duplicate enrichment
- `vigil assess artifact register` / `artifact search` — register IOC
  dump artifacts

## Methodology

### Step 1 — Collect IOCs from the finding

Pull the IOC list from the finding's `details.indicators[]` —
each entry is `{"kind": "ip|domain|url|hash|email|asn", "value": "..."}`
with an optional `algorithm` field on hashes.

If the finding lacks an explicit `indicators[]` array, parse the
registered artifacts: the L2 investigator's `timeline.md` typically
embeds IOCs inline. Extract with `jq` over the artifact JSON or `rg`
over the markdown — both run host-side without host-exec because they
touch no tenant data.

Before enriching, query existing intel for de-duplication:

```bash
vigil assess intel list domain --q "<domain>" --json | jq '.[]'
vigil assess intel list dns-record --q "<ip>" --json | jq '.[]'
```

An IOC already recorded from a prior dispatch does not need re-enrichment
unless the prior record is older than the engagement's documented
TTL (default 7 days for IP / URL reputation; 30 days for domain WHOIS
and hash reputation). Stale-intel logic: read `intel_*.last_verified_utc`,
re-enrich if older than TTL.

### Step 2 — Classify each IOC

Classification runs offline (`python3 -c`, `jq`); no host-exec needed.
Per-kind classifier dimensions: `ip` (v4/v6; RFC1918/loopback/public;
cloud-provider CIDR; VPN/Tor exit); `domain` (TLD tier; registrar;
WHOIS age); `url` (protocol; path depth; URL-shortener flag); `hash`
(algorithm; length; known-good DB miss); `email` (domain reputation;
SPF/DKIM/DMARC alignment from the artifact's header dump); `asn`
(registrar; residential vs hosting vs corporate; abuse-friendly hosting
— record but do not auto-attribute).

Output is a JSON envelope per IOC with `classification` populated and
`enrichment: {}` to be filled in Step 3.

### Step 3 — Pull reputation via host-exec

Every reputation query runs through `vigil assess host-exec` with a
uniform envelope; only the tool and target change. Canonical envelope:

```bash
vigil assess host-exec \
  --tool <whois|dig|curl> \
  --intent "<source> reputation for <ioc-kind> <value>" \
  --technique IOC-ENRICH \
  --phase verify \
  --scope-host <tenant-slug> \
  --target-host <ioc-value> \
  -- <tool argv>
```

Per-IOC tool argv (substitute into the envelope above):

| IOC kind | Tool argv | Source |
|----------|-----------|--------|
| `ip` | `whois <ip>` | WHOIS ASN + abuse contacts |
| `ip` | `curl -s -G -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json" "https://api.abuseipdb.com/api/v2/check" --data-urlencode "ipAddress=<ip>" --data-urlencode "maxAgeInDays=90"` | AbuseIPDB |
| `ip` | `curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/<ip>"` | VirusTotal |
| `domain` | `whois <domain>` | WHOIS registrar + age |
| `domain` | `dig +noall +answer <domain> A AAAA MX NS TXT SOA` | DNS resolution |
| `domain` | `curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/<domain>"` | VirusTotal |
| `url` | `curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/urls/$URL_ID"` where `URL_ID=$(printf '%s' "<url>" \| base64 -w0 \| tr -d '=' \| tr '/+' '_-')` | VirusTotal (URL ID is base64-url of the URL) |
| `hash` | `curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/<hash>"` | VirusTotal (SHA256 / SHA1 / MD5 all accepted) |
| `email` | Split `domain=$(printf '%s' "<email>" \| cut -d@ -f2)`, then run domain-reputation queries against `$domain` | Domain enrichment of email's domain part |
| `asn` | `whois <asn>` | WHOIS ownership; third-party ASN reputation is inconsistent — WHOIS + prior-engagement cross-reference is the durable signal |

Save each raw response to `$ENGAGEMENT_DIR/ir/evidence/ioc-<kind>-<value>.json`
or `.txt`. Each saved file becomes a registered artifact in Step 7.

### Step 4 — Tenant-ref cross-check

Before recording the IOC as adversarial intel, walk the tenant ref's
allowlist sections:

- "Documented egress IP ranges" — the customer's own NAT exits,
  satellite-office gateways, partner-shared NATs. An IP in this list
  is NOT adversarial even if public reputation tags it.
- "Partner / vendor domain allowlist" — domains the customer
  legitimately receives mail or OAuth grants from. A domain here is
  NOT phishing even if VT shows recent registration.
- "Known-vendor IOC list" — file hashes from legitimate vendor
  software, OAuth client IDs from vendor integrations. A hash here is
  NOT malware even if VT flagged it (false-positive on VT happens for
  niche enterprise software).

Tenant-ref-matched IOCs record as intel WITHOUT an adversarial tag —
the record exists for audit, not for finding evidence. Use
`--intent "<ioc> matches tenant ref allowlist — recorded for audit"`
on the intel record step.

### Step 5 — Record findings to `intel_*` tables

Reputation results land in the existing intel schema. There is **no**
`intel_iocs` table; map by IOC kind to the appropriate existing table:

| IOC kind | Table | intel record verb |
|----------|-------|--------------------|
| `domain` | `intel_domains` | `intel record domain` |
| `ip` / URL | `intel_domains` (`kind: "ip"`) | `intel record domain` |
| `dns_record` (raw RR: A/CNAME/MX/TXT/NS) | `intel_dns_records` | `intel record dns-record` |
| `email` (address) | `intel_emails` | `intel record email` |
| `breach-record` (credential leak) | `intel_breach_records` | `intel record breach-record` |
| `cve` (vendor advisory hit, e.g., on a hash that matches a known CVE-affected binary) | `intel_cves` | `intel record cve` |
| `social-profile` (sender-reputation cross-ref to Twitter/LinkedIn) | `intel_social_profiles` | `intel record social-profile` |
| `org-fact` (ASN ownership → company name) | `intel_org_facts` | `intel record org-fact` |
| `note` (free-form reputation summary; ASN reputation; hash reputation; anything that doesn't fit a structured row) | `intel_notes` | `intel record note` |

The intel schema is documented in `orchestrator/backend/app/db.py:2145-2413`
(the `CREATE TABLE` blocks). The schema files in `agent/schemas/intel-*.schema.json`
describe the JSON payload shape per type.

**Example — IP recorded as a domain-table asset** (`intel_domains` is
the IP / ASN slot; `intel record dns-record` is for raw resolver RRs and
requires an RR `record_type` plus the owner `name`):

```bash
cat > /tmp/ip-intel.json <<JSON
{
  "identity": "198.51.100.42",
  "kind": "ip",
  "value": "AS64500 Example Network",
  "source_name": "abuseipdb+virustotal+whois",
  "live_status": "up",
  "notes": "AbuseIPDB confidence 47; VirusTotal 3/91 malicious; classification commercial-vpn-exit; tenant-ref allowlist match: no. Multi-source reputation, no tenant-specific attribution.",
  "provenance": {
    "agent_name": "osint-analyst",
    "captured_at": "2030-01-02T14:22:00Z",
    "evidence_quote": "abuseConfidenceScore: 47"
  }
}
JSON

vigil assess intel record domain /tmp/ip-intel.json
```

Every `intel-*` schema is `additionalProperties: false`, so an unlisted
key fails client-side validation before the POST. Run
`vigil assess contract intel record <type>` for the allowed keys of the
type you are about to write. In particular: only `intel record cve`
accepts a `details` object and a `linked_finding_slug`; the other types
carry their context in `notes` and their audit trail in `provenance`,
and findings are linked in Step 6 instead.

A domain's WHOIS+VT profile (registrar, registration date, age,
virustotal_malicious_count, otx_pulse_count, category) goes in `notes`
on an `intel record domain` row with `kind: "domain"`. ASN reputation
uses the same verb with `kind: "asn"` and `identity: "AS14618"` — there
is no dedicated ASN table, and `intel record note` (`title` +
`body_markdown`) is the fallback only for reputation that fits no
structured row at all.

### Step 6 — Link enriched IOCs back to the finding

After `intel record` returns the intel row's ID, link it to the
finding:

```bash
vigil assess finding link <finding-slug> --intel <intel-id> \
  --reason "IP <ip> recorded as intel_domains row; reputation supports adversarial classification"
```

`--intel` may be repeated to attach multiple intel ids in one call.
The verb reads the finding's current `details.related_intel_ids[]`,
merges the new ids (dedupe + preserve order), and PATCHes the finding.

### Step 7 — Closing sequence

1. **Register raw IOC dumps** as artifacts:

   ```bash
   vigil assess artifact register \
     "$ENGAGEMENT_DIR/ir/evidence/ioc-ip-198.51.100.42.json" \
     --kind ioc_dump \
     --finding <finding-slug> \
     --agent-id <runtime-agent-id>
   ```

   IOC dumps that include sender email addresses, internal user references, or
   full URL paths with tokens remain fully indexed and visible.

2. **Record the activity entry**:

   ```bash
   vigil assess log <agent-id> \
     "IOC enrichment for <finding-slug>" \
     "Enriched <N> IOCs via VT/AbuseIPDB/OTX/WHOIS; <M> matched tenant-ref allowlist; <K> recorded as adversarial intel" \
     "intel-ids: <id-1>,<id-2>,<id-3>" \
     --actor-kind agent
   ```

   `metadata_json` carries `ioc_kind` (the kinds enriched in this
   pass), `enrichment_source` (the reputation sources queried),
   `intel_ids` (the recorded intel rows), `tenant_ref_allowlist_hits`,
   `finding_slug`.

3. **Emit the handoff JSON** with `evidence_refs` (artifact IDs of the
   IOC dumps), `coverage_gaps` (sources where API keys were missing or
   rate-limited), and a one-sentence per-IOC reputation summary in
   `next_steps`.

## Activity Log Convention

Every IOC enrichment pass produces activity entries with `metadata_json`:

```json
{
  "tier": "support",
  "finding_slug": "<slug>",
  "ioc_kind": ["ip", "domain", "url"],
  "enrichment_source": ["virustotal", "abuseipdb", "otx", "whois"],
  "intel_ids": [<id-1>, <id-2>, <id-3>],
  "tenant_ref_allowlist_hits": 0,
  "adversarial_iocs": 3,
  "benign_iocs": 0,
  "ambiguous_iocs": 0
}
```

`enrichment_source` is the list of TI providers actually queried in
this pass; missing providers (no API key, rate-limited) surface as
`coverage_gaps` on the handoff, not in this field.

## Common Failure Modes

- **Recording reputation as a finding instead of intel.** This skill
  produces intel; the L2 investigator records findings. Calling
  `finding record` from IOC enrichment violates the no-theoretical-
  findings rule analog (red mode's `agent/rules/hunting.md`; blue
  mode's `agent/rules/triage.md` rule 1 — outcome before theory).
- **Skipping the tenant-ref allowlist check.** Public reputation flags
  customer-egress IPs as VPN exits, partner domains as recently
  registered, vendor binaries as suspicious. The tenant ref is the
  authority on what is benign-in-context.
- **Citing a vendor verdict without a query-timestamp + source URL.**
  VT reputation changes; AbuseIPDB confidence scores age out. Every
  recorded reputation includes `last_verified_utc` so the staleness
  decision is auditable.
- **Querying TI services without host-exec.** Bypasses the audit
  pipeline. The downstream verifier cannot cite "the enrichment that
  drove the Check 1 outcome" because the query is invisible.
- **Hardcoding API keys in commands.** The `--intent` field gets
  audited; keys must live in env vars sourced from the secrets file.

## Reference Block

- `agent/rules/triage.md` — symmetric evidence bar applies to TI
  citations; outcome-before-theory applies to IOC-driven findings.
- `agent/shared-constraints-blue.md` — host-exec audit envelope (§6),
  cross-tenant prohibition (§7), artifact chain of custody (§3).
- `agent/skills/osint-recon/SKILL.md` — red-mode analog of this skill;
  enrichment shape and OSINT API patterns are deliberately parallel
  so a specialist crossing modes recognizes the structure.
- `agent/skills/alert-fp-verification/SKILL.md` — the L3 consumer of
  this skill's intel; Check 1 and Check 2 cite the IOC reputation
  recorded here.
- `agent/skills/incident-containment/SKILL.md` — the L4 consumer; IOC
  reputation is a precondition for network-layer containment proposals
  (firewall block, DNS sinkhole, API key rotation against the
  reputation-verified key).
- `agent/scripts/assess/lib/intel_types.py` — canonical intel-type ↔
  schema-file mapping; the list there is the source of truth for
  `intel record <type>` verbs.
- `orchestrator/backend/app/db.py:2145-2413` — schema source of truth
  for `intel_*` tables (intel_tech_components, intel_people,
  intel_emails, intel_domains, intel_cves, intel_dns_records,
  intel_social_profiles, intel_breach_records, intel_org_facts,
  intel_notes).
- `agent/references/tenants/<customer>-<platform>.md` — the tenant
  ref's "Documented egress IP ranges" and "Partner / vendor allowlist"
  sections drive Step 4's cross-check.
