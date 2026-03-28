# Threat Hunt Skill — Reference Guide

This file contains templates, methodology details, and detection patterns used by the `/threat-hunt` skill.

---

## State File Templates

### `<WORKDIR>/state.md` Template

```markdown
# Threat Hunt State — {{TARGET}}
## Last Updated: <timestamp>

## Scope
- Target: {{TARGET}}
- Engagement type: <External/Purple/API-Only/Internal/Full>
- Subdomain enum: YES/NO
- Rate limiting: Stealth/Normal/Aggressive
- Enabled modules: <list>
- Hosts in scope: <list all confirmed in-scope hosts/IPs>

## Current Phase
- Phase: <0|1|2|3|3-EXT|4|5|6|7|8|9>
- Step: <what you are currently doing>
- Next: <what comes after the current step>

## Progress Notes
<Append timestamped entries as you work. Keep each entry to 1-2 lines.>

## Attack Chain Notes
<Running notes on potential chains between findings>

## Behavioral Hunt Notes
<Running notes on IOC-to-TTP pivots and behavioral hypotheses>

## Blockers / Anomalies
<Anything unexpected — WAF blocks, timeouts, rate limits, errors, ambiguous results>
```

### `<WORKDIR>/assets.json` Template

```json
{
  "target": "{{TARGET}}",
  "engagement_type": "external",
  "subdomain_enum": false,
  "rate_mode": "normal",
  "enabled_modules": [],
  "last_updated": "<timestamp>",
  "subdomains": [
    {"name": "sub.example.com", "ip": "1.2.3.4", "status": "live", "cname": null}
  ],
  "hosts": [
    {
      "host": "example.com",
      "ip": "1.2.3.4",
      "ports": [
        {"port": 443, "service": "https", "version": "nginx/1.18", "notes": ""}
      ],
      "technologies": ["nginx", "React"],
      "cms": null,
      "paths_discovered": [
        {"path": "/api", "status": 200, "notes": "JSON response, no auth required"}
      ],
      "tested": {
        "port_scan": false,
        "dir_enum": false,
        "nikto": false,
        "security_headers": false,
        "cors": false,
        "http_methods": false,
        "auth_bypass": false,
        "tls_ssl": false,
        "tech_fingerprint": false,
        "sqli": false,
        "rate_limiting": false,
        "ssrf_indicators": false,
        "business_logic": false,
        "behavioral_hunt": false
      }
    }
  ],
  "findings": [
    {
      "id": 1,
      "severity": "high",
      "title": "Example finding",
      "host": "example.com",
      "evidence_file": "/tmp/threat-hunt/raw/p3-nikto-example.com.txt",
      "phase_found": 3,
      "category": "OWASP A05:2021",
      "mitre_technique": "T1190",
      "details": "Brief description of what was found",
      "remediation": "Specific fix recommendation"
    }
  ]
}
```

---

## Final Markdown Report Template

Use this for `<WORKDIR>/final-report.md`. This structure is the default final-report format and should be treated as non-negotiable unless the user explicitly asks for something different.

```markdown
---
title: "<Assessment Title>"
date: "<YYYY-MM-DD>"
---

# <Assessment Title>

**Target:** `<host / environment>`  
**Assessment Window:** `<YYYY-MM-DD> through YYYY-MM-DD>`  
**Assessment Type:** `<external / purple team / live validation / code review / log investigation / combined>`  
**Status:** This document is the authoritative investigation record for this assessment.

---

## Executive Summary

<3-6 sentences on the overall risk, highest-impact findings, and whether exploitation was confirmed, probable, absent, or inconclusive>

## Risk Snapshot

- Final register: `<count>` findings (`<critical>` Critical, `<high>` High, `<medium>` Medium, `<low>` Low, `<info>` Informational).
- Highest-risk exposure families: <short list of the internet-facing or breach-level defect families>.
- Final finding IDs use the `<PREFIX>-XX` scheme. Legacy finding aliases remain only in `Absorbs` lines, anchors, or appendix validation artifacts where they still add value.

## Scope And Evidence

- **Live-confirmed** means the behavior was reproduced directly on the assessed host.
- **Live + code confirmed** means the behavior was reproduced and source materially supports the final finding.
- **Code-confirmed** means the defect was confirmed in source or build artifacts but not fully reproduced live.
- **Auth-required** means exploitation starts from any authenticated foothold rather than anonymous internet access.
- **Remediated** means later validation showed the earlier issue no longer reproduced on the tested host.

Evidence in this report comes from <live testing / source review / raw artifacts / log analysis>. The detailed findings below distinguish those evidence types directly in each finding instead of relying on a separate reconciliation section.

## Priority Conclusions

1. <Breach-level or business-critical conclusion>
2. <Second most important engineering/security conclusion>
3. <Third conclusion>

## Detailed Findings And Attack Chains

## Critical Findings (Detailed)

### <PREFIX>-01: <Concise Final Finding Title>
**Severity**: Critical | **CVSS**: 9.8 | **Category**: OWASP A01:2021 Broken Access Control
**Absorbs**: `<legacy IDs>` 

<Short opening paragraph explaining the full defect family and why related issues were merged here.>

| Surface | Endpoint | Validation | Why it matters |
|---|---|---|---|
| <surface> | `<method route>` | <Live-confirmed / Live + code confirmed> | <business or attacker impact> |

**Proof**

```bash
curl -sk "https://target.example/api/endpoint"
# HTTP 200
# <decisive response lines>
```

**Source-Code References**

- `<path/to/file>`
- `<path/to/file>`

**Impact**

- <attacker impact>
- <business impact>

**Remediation**

1. <first fix>
2. <second fix>

**References**: CWE-xxx, CWE-yyy

---

## High Findings (Detailed)

### <PREFIX>-02: <High-severity Finding>
**Severity**: High | **CVSS**: 8.1 | **Category**: <OWASP category>

<same pattern as above>

---

## Medium Findings (Detailed)

### <PREFIX>-03: <Medium-severity Finding>
**Severity**: Medium | **CVSS**: 5.3 | **Category**: <OWASP category>

<same pattern, kept concise>

---

## Low Findings

### <PREFIX>-04: <Low-severity Finding>
**Severity**: Low | **CVSS**: 3.4 | **Category**: <OWASP category>

<short proof, impact, remediation>

---

## Informational Findings

### <PREFIX>-05: <Informational Finding>
**Severity**: Informational | **CVSS**: 0.0 | **Category**: <OWASP category>

<short proof, impact, remediation>

---

## Coverage, Telemetry, And Hunt Gaps

- Coverage reviewed: <what data sources or test areas were actually covered>
- Gaps: <blocked tests, missing logs, rate limits, timeouts, missing code, retention gaps>
- Conclusion: <what can and cannot be asserted because of those gaps>

## Root Cause Summary

- <architectural root cause>
- <deployment/configuration root cause>
- <authorization or trust-boundary root cause>

## Test Artifacts Requiring Cleanup

| Artifact | Why it matters | Action |
|---|---|---|
| `<order ID / fake user / queue message / document>` | <assessment-created side effect> | <rollback / review / delete> |

## Appendix A: Validation Artifacts

### Verification Note A-01 (Former Finding <legacy id>)

```bash
<supporting command or excerpt>
```

### Final Report Rules

- Do not include consolidation notes, changelog language, or reconciliation-only sections in the main body.
- Collapse overlapping issues into authoritative parent findings.
- Sort by final severity, then by exposure model.
- Keep top-level summary sections concise; put detail in the findings.
- Include decisive proof in the body and use appendices only for supporting artifacts.
- When code materially informed a finding, cite the path directly in that finding.

---

## Methodology Sources & Philosophy

### Pyramid of Pain (David Bianco)

Detection value hierarchy — hunt at the TOP:

| Level | Adversary Change Time | Hunt Value |
|-------|----------------------|------------|
| Hash Values | Seconds | Very Low — AVOID |
| IP Addresses | Minutes | Low — AVOID |
| Domain Names | Hours | Low-Medium — AVOID |
| Network/Host Artifacts | Days | Medium |
| Tools | Weeks | High |
| **TTPs (Behaviors)** | **Months-Years** | **Highest — PRIMARY FOCUS** |

### PEAK Framework (Splunk SURGe)

Three hunt types with three phases:

**Hunt Types:**
- **Hypothesis-Driven (H)**: Specific threat behavior → research → test
- **Baseline (B)**: New data source → data dictionary → find outliers
- **Model-Assisted (M-ATH)**: Complex patterns → ML algorithms → analyze

**Phases:**
- **Prepare**: Select topic, research, plan, scope with ABLE
- **Execute**: Gather data, analyze, find patterns, refine
- **Act**: Document, create detections, communicate
- **Knowledge**: Flows through all phases bidirectionally

### ABLE Scoping Methodology

| Field | Description |
|-------|-------------|
| **Actor** | (Optional) Threat actor. Behavior-first, not actor-first. |
| **Behavior** | (Required) TTPs at top of Pyramid of Pain |
| **Location** | Where to hunt — endpoints, network, cloud |
| **Evidence** | Data sources + key fields + examples of malicious activity |

### PEAK Hunt Report Template

```markdown
# Threat Hunting Report — PEAK Framework

## Hunt ID: H/B/M-XXXX

## Hunt Title: <concise name>

## PREPARE: Define the Hunt

| Field | Details |
|-------|---------|
| Hypothesis | <what and why> |
| Hunter Name | <name> |
| Date | <date> |
| Requestor | <team/person> |
| Timeframe | <duration> |

### ABLE Scope
| Field | Input |
|-------|-------|
| Actor | <threat actor or N/A> |
| Behavior | <TTPs with technique IDs> |
| Location | <where to hunt> |
| Evidence | <data sources, key fields, examples> |

### Threat Intel & Research
- MITRE ATT&CK: <techniques>
- Related sources: <links>
- Historical prevalence: <context>

## EXECUTE: Run the Hunt

### Queries
<initial query, refined query, rationale>

### Visualization / Analytics
<dashboards, charts, observations>

### Detection Logic
<how to turn this into a detection rule>

## ACT: Findings & Response

### Hypothesis Result: CONFIRMED / DISPROVED

### Findings
| Finding | Ticket | Description |
|---------|--------|-------------|
| ... | ... | ... |

## K — Knowledge

### Lessons Learned
- What worked well
- What to improve
- Should this become a detection?
- Follow-up hunts
- Feedback for other teams

### References
<links>
```

---

## Expert Pentesting Checklists

### OWASP WSTG Key Tests (Commonly Missed)

| Test ID | Category | Description |
|---------|----------|-------------|
| WSTG-CONF-10 | Config | Subdomain takeover |
| WSTG-CONF-12 | Config | Content Security Policy testing |
| WSTG-IDNT-04 | Identity | Account enumeration via response differences |
| WSTG-ATHN-07 | Auth | Weak password policy |
| WSTG-ATHZ-04 | AuthZ | IDOR (Insecure Direct Object Reference) |
| WSTG-SESS-03 | Session | Session fixation |
| WSTG-SESS-06 | Session | CSRF testing |
| WSTG-INPV-05 | Input | SQL injection (all DB types) |
| WSTG-INPV-07 | Input | Server-Side Template Injection (SSTI) |
| WSTG-INPV-15 | Input | HTTP Request Smuggling |
| WSTG-INPV-19 | Input | Server-Side Request Forgery (SSRF) |
| WSTG-INPV-21 | Input | Mass Assignment |
| WSTG-BUSL-* | Business Logic | Workflow bypass, function abuse, trust violations |
| WSTG-CLNT-06 | Client | WebSocket security |
| WSTG-CLNT-12 | Client | Browser storage exposure |
| WSTG-APIT-01 | API | GraphQL security testing |

### PTES-Inspired Threat Modeling Checklist

Before exploitation, consider:
- What are the crown jewels? (databases, credentials, PII, financial data)
- What threat actors target this industry?
- What are the most likely attack paths from discovered assets?
- What would maximize business impact with minimum effort?

### PortSwigger Advanced Checks

| Category | Test |
|----------|------|
| Request Smuggling | CL.TE, TE.CL, TE.TE, 0.CL variants |
| Web Cache Poisoning | Unkeyed headers, query param normalization |
| Web Cache Deception | Path confusion, static file caching of dynamic responses |
| Prototype Pollution | `__proto__`, `constructor.prototype` in JSON |
| Race Conditions | Single-packet attack technique (concurrent requests) |
| JWT Attacks | Algorithm confusion, key injection, none algorithm |
| GraphQL | Introspection, batching attacks, nested query DoS |
| LLM Integration | Prompt injection via web inputs to AI features |

### Active Directory Attack Paths (if Internal Assessment)

| Category | Technique |
|----------|-----------|
| Credential Theft | LSASS dump, SAM/LSA, DCSync, GPP passwords, cached creds |
| Kerberos | ASREProasting, Kerberoasting, Pass-the-Hash/Ticket, Golden/Silver tickets |
| Coercion/MITM | LLMNR/NBT-NS poisoning, PetitPotam, PrinterBug, WPAD |
| AD-CS | Template abuse, CA misconfiguration, ESC1-ESC8 |
| Delegation | Unconstrained, constrained, RBCD abuse |
| Persistence | DC Shadow, SID History, Skeleton Key, AdminSDHolder |

---

## Behavioral Detection Patterns Library

### Credential Access (T1003)

**LSASS Memory Dumping (T1003.001)**
```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where GrantedAccess IN ("0x1010", "0x1410", "0x1438")
| where NOT SourceImage IN ("*\\taskmgr.exe", "*\\procexp64.exe")
| stats count by SourceImage, SourceUser, Computer_Name
```
*Catches: Mimikatz, ProcDump, custom tools. Behavior persists across tool changes.*

### Process Injection (T1055)

**Remote Thread Creation**
```spl
index=sysmon EventCode=8
| eval suspicious_target=if(match(TargetImage, "(?i)(explorer|svchost|winlogon|csrss|lsass)"), 1, 0)
| where suspicious_target=1
| stats count by SourceImage, TargetImage, Computer_Name
```
*Catches: Cobalt Strike, Metasploit, custom malware.*

### Lateral Movement (T1021)

**Remote Service Execution**
```spl
index=windows EventCode=4624 Logon_Type IN (3,10)
| eval auth_key=Source_Network_Address."|".Target_User_Name
| join auth_key type=inner max=0
    [search index=sysmon EventCode=1
    | eval auth_key=Computer_Name."|".User]
| timechart span=5m count by auth_key
| where count > threshold
```
*Catches: PsExec, WMI, PowerShell Remoting, SMB, RDP.*

### C2 Beaconing (T1071)

**Regular Interval Detection**
```spl
tag=dns message_type="QUERY"
| streamstats current=f last(_time) as last_time by query
| eval gap=last_time - _time
| stats count avg(gap) AS AverageBeaconTime var(gap) AS VarianceBeaconTime BY query
| where VarianceBeaconTime < 60 AND count > 2
```

### Living-off-the-Land (T1059)

**PowerShell Download Cradles**
```spl
index=powershell OR index=sysmon EventCode=1 Image="*powershell.exe"
| regex CommandLine="(?i)(downloadstring|downloadfile|webclient|invoke-webrequest|iwr|net\.webclient)"
| stats count by Computer_Name, User, CommandLine
```

### Persistence (T1547)

**Registry Run Key Modifications**
```spl
index=sysmon EventCode=13
    (TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*")
| where NOT Image IN ("*\\msiexec.exe", "*\\setup.exe")
| stats count values(Details) as values by Computer_Name, Image, TargetObject
```

### macOS-Specific: Script Editor LOLBin Chain (T1059.002)

```spl
index=macos sourcetype=process_events
parent_process_name="Script Editor"
| where process_name IN ("curl", "wget", "bash", "sh", "python")
| eval severity=case(
    process_name IN ("curl", "wget") AND match(process_cmd, "http"), "CRITICAL",
    process_name IN ("bash", "sh") AND match(process_cmd, "-c"), "HIGH",
    1=1, "MEDIUM"
)
| stats count by host, user, process_name, severity
```

---

## IOC-to-Behavior Pivot Table

When you find an IOC during external assessment, pivot to behavioral hunting:

| IOC Type | Behavioral Alternative | MITRE Technique | Detection Focus |
|----------|----------------------|-----------------|-----------------|
| Malware Hash | Execution behavior patterns | T1059.* | Process chains, parent-child anomalies |
| C2 IP Address | Beaconing patterns | T1071.* | Regular intervals, consistent sizes |
| C2 Domain | DNS tunneling patterns | T1071.004 | Unusual subdomain patterns |
| Malicious URL | Download cradle patterns | T1105 | Network download + execution |
| Registry Key | Autorun modifications | T1547.* | Persistence location changes |
| File Path | Persistence locations | T1053.*, T1543.* | Service/task creation |
| Tool Name | Tool capabilities | T1003, T1021, T1055 | What the tool DOES, not what it IS |

---

## MITRE ATT&CK Tactic Coverage Reference

14 Enterprise Tactics — use for mapping findings and identifying coverage gaps:

| ID | Tactic | Key Detection Chokepoints |
|----|--------|--------------------------|
| TA0043 | Reconnaissance | Hard to detect externally |
| TA0042 | Resource Development | Mostly pre-attack |
| TA0001 | Initial Access | Perimeter monitoring, email gateway |
| TA0002 | Execution | Process creation, script logging |
| TA0003 | Persistence | Autorun monitoring, scheduled tasks |
| TA0004 | Privilege Escalation | Token manipulation, UAC bypass |
| TA0005 | Defense Evasion | 47 techniques — largest category |
| TA0006 | Credential Access | LSASS monitoring, auth event correlation |
| TA0007 | Discovery | Internal recon commands, AD queries |
| TA0008 | Lateral Movement | 9 techniques — narrow chokepoint, ideal for detection |
| TA0009 | Collection | File access monitoring, clipboard |
| TA0011 | Command & Control | Network beaconing, protocol anomalies |
| TA0010 | Exfiltration | 9 techniques — narrow chokepoint, ideal for detection |
| TA0040 | Impact | Destruction/encryption of data |

**Key Insight**: Lateral Movement (9 techniques) and Exfiltration (9 techniques) are the narrowest chokepoints — ideal detection focus areas.

---

## Cognitive Bias Checks for Threat Hunting

### Confirmation Bias
- Are you only looking for evidence that supports your hypothesis?
- Have you considered benign explanations for every finding?
- Is your evidence balanced (positive AND negative indicators)?

### Anchoring Bias
- Has your hypothesis changed since the beginning?
- Are you stuck on your initial assessment despite new evidence?
- Would a fresh analyst reach the same conclusion?

### Availability Bias
- Are recent news/incidents overly influencing your assessment?
- Are you focusing on well-known attack types while ignoring unusual ones?
- Is your threat model based on your experience or the target's actual risk?

### Mitigation: Analysis of Competing Hypotheses (ACH)
For each significant finding, generate:
1. The malicious explanation (your hypothesis)
2. A benign explanation (legitimate business activity)
3. An alternative malicious explanation (different attack)

Score each against ALL evidence. The explanation best supported by the totality of evidence wins.

---

## Attack Chain Escalation Patterns

These patterns frequently produce Critical findings. Test when applicable:

| Pattern | Seeds | Escalation Target |
|---------|-------|-------------------|
| API spec + unsecured read endpoints | Documentation exposure + missing auth | Bulk PII extraction via IDOR |
| API spec + unsecured write endpoints | Documentation exposure + missing auth | Unauthorized data modification |
| Config endpoints + credential fields | API enum + missing auth | Infrastructure credential theft |
| IDOR read + expanded modules | Single IDOR + API documentation | Cross-module data harvesting |
| No rate limiting + auth endpoint | Rate limit finding + auth testing | Credential brute force feasibility |
| Debug pages + internal references | Debug exposure + URL parameters | Internal service access, metadata |
| Version disclosure + CVE database | Tech fingerprint findings | Framework-level exploitation |
| Session mgmt + cookie flags + no HSTS | Multiple low-severity findings | Session hijacking via MITM |

---

## Severity & Scoring Reference

### CVSS v3.1 Estimation Guide

| Scenario | CVSS Range | Severity |
|----------|-----------|----------|
| Unauthenticated RCE | 9.0-10.0 | Critical |
| SQLi with data access | 8.0-9.8 | Critical |
| Subdomain takeover | 7.5-9.0 | Critical/High |
| Auth bypass on admin | 7.5-8.5 | High |
| SSRF to internal services | 7.0-8.5 | High |
| Exposed credentials/secrets | 7.0-8.0 | High |
| CORS with credentials | 5.5-7.0 | Medium |
| Missing HSTS | 4.0-5.5 | Medium |
| Verbose error disclosure | 4.0-5.5 | Medium |
| IDOR on non-sensitive data | 4.0-6.0 | Medium |
| Missing security headers | 2.0-4.0 | Low |
| Server version disclosure | 2.0-3.5 | Low |
| Information leakage | 2.0-3.5 | Low |

### OWASP Top 10 (2021) Mapping

| ID | Category |
|----|----------|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification and Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging and Monitoring Failures |
| A10 | Server-Side Request Forgery |

---

## Tool Execution Strategy

### Parallel Execution (Different Hosts)
- Phase 1: DNS queries, WHOIS, cert transparency — different services
- Phase 2: Port scans against different IPs
- Phase 2: Gobuster against different hosts

### Sequential Execution (Same Host)
- Multiple scans against the same host
- Any test where prior result determines next step
- Phase 3: Nikto, header checks, CORS checks, method testing against a single host

### Rate Limiting Response
If you receive 429 responses, WAF blocks, or connection resets:
1. Note it in state.md Blockers section
2. Add 2-5 second delays between requests
3. Reduce parallelism
4. If persistent, skip that host/test and document the block
5. Do NOT retry aggressively — a slower scan that completes is better than getting blocked

---

## Hunting Maturity Model (HMM)

Track and report the maturity level demonstrated:

| Level | Description | Characteristics |
|-------|-------------|-----------------|
| HMM0 | Initial | Relies on automated alerting only |
| HMM1 | Minimal | Threat intel indicator searches |
| HMM2 | Procedural | Follows established hunt procedures |
| HMM3 | Innovative | Creates new hunt procedures, uses M-ATH |
| HMM4 | Leading | Automates hunts into detections, continuous improvement |

This skill operates at HMM3-HMM4 by generating novel behavioral hypotheses and creating detection rules from findings.

---

## Key Metrics to Track

Report these in the final report:

1. **Detections proposed**: New detection rules recommended
2. **Findings by severity**: Critical / High / Medium / Low / Info counts
3. **Attack chains confirmed**: Number of validated multi-finding chains
4. **MITRE techniques covered**: Which ATT&CK techniques were tested
5. **Coverage gaps identified**: Data sources or controls found missing
6. **Behavioral pivots made**: IOCs successfully pivoted to TTP-based hunts
7. **Hosts tested**: Total hosts assessed vs. discovered
8. **Tests executed**: Total tool executions and test types

---

## HEARTH Community Integration (if available)

If the threat-hunting MCP server is configured, use these tools during Phase 6:

- `search_community_hunts(tactic, tags, keyword)` — Search 50+ curated hypotheses
- `recommend_hunts(tactics, keywords, environment)` — AI-powered recommendations
- `suggest_hunts_for_incident(description)` — Incident-driven suggestions
- `analyze_tactic_coverage()` — Gap analysis across MITRE ATT&CK
- `create_behavioral_hunt(...)` — Generate PEAK framework hunt reports
- `suggest_behavioral_hunt_from_ioc(ioc, ioc_type)` — Pivot IOCs to behavioral hunts

### Hunt Type Categories
- **Flames**: Hypothesis-driven hunts from real-world attack scenarios
- **Embers**: Baseline hunts for environmental baselining
- **Alchemy**: Model-assisted hunts using ML/algorithmic detection

---

## Exploitation Investigation — Query Templates

These templates are generalized from real-world WAF log forensics against AWS Security Lake (OCSF format via Athena/Iceberg). Adapt field names to your log source (Splunk, Elasticsearch, CloudWatch, etc.).

### Log Source Field Mapping

| Concept | AWS Security Lake (Athena) | Splunk | Elasticsearch |
|---------|---------------------------|--------|---------------|
| Timestamp | `time_dt` | `_time` | `@timestamp` |
| URL Path | `http_request.url.path` | `uri_path` | `url.path` |
| Query String | `http_request.args` | `uri_query` | `url.query` |
| HTTP Method | `http_request.http_method` | `http_method` | `http.request.method` |
| Source IP | `src_endpoint.ip` | `src_ip` | `source.ip` |
| Status Code | `http_status` | `status` | `http.response.status_code` |
| User Agent | `http_request.user_agent` | `http_user_agent` | `user_agent.original` |
| Referrer | `http_request.referrer` | `http_referrer` | `http.request.referrer` |
| Headers Array | `http_request.http_headers` | (extracted fields) | `http.request.headers` |
| Account ID | `accountid` | `aws_account_id` | `cloud.account.id` |

### Category 1: Unauthenticated Access to Sensitive Endpoints

Detects requests to API endpoints that should require authentication but arrive without auth tokens. Adapt the endpoint paths to match findings from earlier phases.

```sql
-- AWS Security Lake / Athena
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.http_method AS method,
    src_endpoint.ip AS source_ip,
    http_status AS status_code,
    http_request.user_agent AS user_agent
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND NOT any_match(
        http_request.http_headers,
        h -> lower(h.name) IN ('authorization', 'x-xsrf-token')
    )
    AND (
        -- Substitute vulnerable endpoints discovered in earlier phases
        http_request.url.path LIKE '/api/{{MODULE_1}}/%'
        OR http_request.url.path LIKE '/api/{{MODULE_2}}/%'
    )
    AND http_status BETWEEN 200 AND 299
ORDER BY time_dt DESC
LIMIT 500;
```

**Key logic**: Filter OUT authenticated requests (those carrying `Authorization` or session tokens), then filter IN sensitive endpoint paths. A 2xx response without auth = confirmed unauthenticated access.

### Category 2: PII / Data Exfiltration via Sequential ID Enumeration

Detects attackers walking sequential IDs to harvest records. Look for high request volume from single IPs hitting parameterized endpoints.

```sql
-- AWS Security Lake / Athena
-- Query A: Volume by IP on PII endpoints
SELECT
    src_endpoint.ip AS source_ip,
    http_request.url.path AS url_path,
    COUNT(*) AS request_count,
    MIN(time_dt) AS first_seen,
    MAX(time_dt) AS last_seen,
    COUNT(DISTINCT http_request.url.path) AS unique_paths
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND http_request.url.path LIKE '/api/{{PII_ENDPOINT}}/%'
    AND http_status BETWEEN 200 AND 299
GROUP BY src_endpoint.ip, http_request.url.path
HAVING COUNT(*) > 50
ORDER BY request_count DESC;

-- Query B: Sequential ID pattern detection
SELECT
    time_dt,
    http_request.url.path AS url_path,
    src_endpoint.ip AS source_ip,
    http_status AS status_code
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND src_endpoint.ip = '{{SUSPECT_IP}}'
    AND http_request.url.path LIKE '/api/{{PII_ENDPOINT}}/%'
ORDER BY time_dt ASC
LIMIT 1000;
-- Then inspect: are the numeric IDs in url_path incrementing sequentially?
```

**Indicators**: >50 requests to parameterized endpoint from single IP; sequential or near-sequential IDs in path; short time windows; no auth headers.

### Category 3: Credential Stuffing / Brute Force

Detects high-volume authentication attempts against login or password validation endpoints.

```sql
-- AWS Security Lake / Athena
SELECT
    src_endpoint.ip AS source_ip,
    COUNT(*) AS attempt_count,
    COUNT(CASE WHEN http_status = 200 THEN 1 END) AS success_count,
    COUNT(CASE WHEN http_status IN (401, 403) THEN 1 END) AS fail_count,
    MIN(time_dt) AS first_attempt,
    MAX(time_dt) AS last_attempt
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND (
        http_request.url.path LIKE '%/validate-password%'
        OR http_request.url.path LIKE '%/login%'
        OR http_request.url.path LIKE '%/authenticate%'
        OR http_request.url.path LIKE '%/get-user-by-username%'
    )
    AND http_request.http_method = 'POST'
GROUP BY src_endpoint.ip
HAVING COUNT(*) > 10
ORDER BY attempt_count DESC;
```

**Indicators**: High fail:success ratio from single IP; requests faster than human typing speed; multiple usernames attempted; no browser fingerprint headers (Sec-Fetch-*).

### Category 4: MFA/Auth Bypass Chain Detection

Detects attempts to brute-force MFA codes or bypass multi-step authentication flows.

```sql
-- AWS Security Lake / Athena
-- Step 1: MFA code submission volume
SELECT
    src_endpoint.ip AS source_ip,
    COUNT(*) AS code_attempts,
    COUNT(CASE WHEN http_status = 200 THEN 1 END) AS accepted,
    MIN(time_dt) AS first_attempt,
    MAX(time_dt) AS last_attempt,
    -- Calculate attempt rate
    CAST(COUNT(*) AS DOUBLE) /
        NULLIF(date_diff('minute',
            MIN(time_dt), MAX(time_dt)), 0) AS attempts_per_minute
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND (
        http_request.url.path LIKE '%/validate-code%'
        OR http_request.url.path LIKE '%/verify-mfa%'
        OR http_request.url.path LIKE '%/confirm-otp%'
    )
GROUP BY src_endpoint.ip
HAVING COUNT(*) > 5
ORDER BY code_attempts DESC;

-- Step 2: Correlate send-code with validate-code for full chain
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.http_method AS method,
    src_endpoint.ip AS source_ip,
    http_status AS status_code
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND src_endpoint.ip = '{{SUSPECT_IP}}'
    AND (
        http_request.url.path LIKE '%/send-code%'
        OR http_request.url.path LIKE '%/validate-code%'
    )
ORDER BY time_dt ASC;
-- Pattern: 1 send-code followed by many validate-code = brute force
```

### Category 5: HTTP Verb Tampering

Detects use of `X-HTTP-Method-Override` header or query parameter to convert GET requests into write operations, bypassing WAF method-based rules.

```sql
-- AWS Security Lake / Athena
-- Query A: GET requests to write-only endpoints (verb override likely)
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.http_method AS method,
    src_endpoint.ip AS source_ip,
    http_status AS status_code
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND http_request.http_method = 'GET'
    AND (
        -- Substitute write-only endpoints from findings
        http_request.url.path LIKE '%/void%'
        OR http_request.url.path LIKE '%/delete%'
        OR http_request.url.path LIKE '%/update%'
        OR http_request.url.path LIKE '%/create%'
    )
ORDER BY time_dt DESC
LIMIT 200;

-- Query B: X-HTTP-Method-Override in headers
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.http_method AS method,
    src_endpoint.ip AS source_ip,
    http_status AS status_code,
    http_request.http_headers AS headers
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND any_match(
        http_request.http_headers,
        h -> lower(h.name) = 'x-http-method-override'
    )
ORDER BY time_dt DESC
LIMIT 200;

-- Query C: X-HTTP-Method-Override in query string
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.args AS query_string,
    src_endpoint.ip AS source_ip,
    http_status AS status_code
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND lower(http_request.args) LIKE '%x-http-method-override%'
ORDER BY time_dt DESC
LIMIT 200;
```

**Why this matters**: Frameworks like ServiceStack process `X-HTTP-Method-Override` as both header and query param, silently converting GET→DELETE/PUT/PATCH. WAF rules matching on HTTP method are completely bypassed.

### Category 6: Format Parameter Abuse & Open Redirect

Detects abuse of `?format=` parameters to render API data as browsable HTML (creating XSS sinks and easy exfil) and exploitation of open redirect endpoints.

```sql
-- AWS Security Lake / Athena
-- Query A: ?format= abuse on sensitive endpoints
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.args AS query_string,
    src_endpoint.ip AS source_ip,
    http_status AS status_code
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND lower(http_request.args) LIKE '%format=%'
    AND (
        http_request.url.path LIKE '/api/{{SENSITIVE_MODULE_1}}/%'
        OR http_request.url.path LIKE '/api/{{SENSITIVE_MODULE_2}}/%'
    )
ORDER BY time_dt DESC
LIMIT 200;

-- Query B: Open redirect exploitation
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.args AS query_string,
    src_endpoint.ip AS source_ip,
    http_status AS status_code,
    http_request.user_agent AS user_agent,
    http_request.referrer AS referrer
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND (
        http_request.url.path LIKE '%/redirect%'
        OR http_request.url.path LIKE '%/Login/R%'
        OR lower(http_request.args) LIKE '%continue=%'
        OR lower(http_request.args) LIKE '%returnurl=%'
        OR lower(http_request.args) LIKE '%redirect_uri=%'
    )
ORDER BY time_dt DESC
LIMIT 200;
```

**Indicators for format abuse**: `?format=html` renders JSON API data as sortable HTML tables; `?format=csv` enables bulk download; presence on PII endpoints = data exfiltration vector.

### Category 7: Unauthenticated Write Operations

Detects POST/PUT/DELETE/PATCH requests to sensitive write endpoints that arrive without authentication headers. A write operation without auth is strong evidence of active exploitation.

```sql
-- AWS Security Lake / Athena
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.http_method AS method,
    src_endpoint.ip AS source_ip,
    http_status AS status_code,
    http_request.user_agent AS user_agent
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND http_request.http_method IN ('POST', 'PUT', 'DELETE', 'PATCH')
    AND NOT any_match(
        http_request.http_headers,
        h -> lower(h.name) IN ('authorization', 'x-xsrf-token')
    )
    AND (
        -- Substitute write endpoints from findings
        http_request.url.path LIKE '/api/{{WRITE_ENDPOINT_1}}%'
        OR http_request.url.path LIKE '/api/{{WRITE_ENDPOINT_2}}%'
        -- Infrastructure config operations
        OR http_request.url.path LIKE '%/configurations%'
        -- Password/account operations
        OR http_request.url.path LIKE '%/reset-password%'
        OR http_request.url.path LIKE '%/set-password%'
        -- Admin operations
        OR http_request.url.path LIKE '%/unlock%'
    )
    AND http_status BETWEEN 200 AND 299
ORDER BY time_dt DESC
LIMIT 500;
```

**Severity**: Any 2xx response here is a **Critical** finding — it confirms the write endpoint processed an unauthenticated mutation.

### Triage Decision Matrix

After running queries, classify each IP/session using this matrix:

| Signal | Benign (Legitimate) | Suspicious (Investigate) | Malicious (Confirmed) |
|--------|--------------------|--------------------------|-----------------------|
| Auth headers | Present (valid session) | Intermittent/partial | Absent on sensitive endpoints |
| Request pattern | Normal app navigation | Unusual paths/params | Sequential enumeration |
| Source IP | Known office/VPN range | Cloud provider/VPN | Known bad / Tor exit |
| User-Agent | Standard browser | Uncommon but valid | `python-requests`, `curl`, empty |
| Response codes | Mixed (200, 302, 404) | Mostly 200s | All 200s on auth endpoints |
| Volume | <50/hour per endpoint | 50-500/hour | >500/hour or >100 unique IDs |
| Timing | Business hours | Off-hours | Sustained automated pace |
| Write operations | With auth tokens | — | Without auth tokens + 2xx |

### Suspect IP Deep Dive Query

When triage flags a suspicious IP, pull full request history with headers for auth state analysis:

```sql
-- AWS Security Lake / Athena
SELECT
    time_dt,
    http_request.url.path AS url_path,
    http_request.http_method AS method,
    src_endpoint.ip AS source_ip,
    http_status AS status_code,
    http_request.user_agent AS user_agent,
    http_request.http_headers AS all_headers
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
    AND src_endpoint.ip = '{{SUSPECT_IP}}'
    AND time_dt BETWEEN TIMESTAMP '{{START}}' AND TIMESTAMP '{{END}}'
ORDER BY time_dt ASC
LIMIT 500;
```

**Auth state determination from headers:**

| Header Pattern | Indicates |
|---------------|-----------|
| `Authorization: Bearer ...` | Authenticated API call |
| Session cookie + CSRF token | Authenticated user session |
| `Sec-Fetch-Mode: cors` + `same-origin` | AJAX from app UI — normal flow |
| `Sec-Fetch-Mode: navigate` with no cookies | Direct browser nav — manual probing |
| No auth headers, no cookies | Fully unauthenticated — tooling or API abuse |
| `User-Agent: curl/*`, `python-requests/*` | Automated tooling |
| Browser UA but no cookies/session | Automated mimicry — high suspicion |

### Log Infrastructure Assessment Queries

Run these to evaluate log coverage and identify gaps:

```sql
-- Date range coverage: when do logs start and end?
SELECT
    MIN(time_dt) AS earliest_log,
    MAX(time_dt) AS latest_log,
    COUNT(*) AS total_records
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}';

-- Daily volume: identify gaps in logging
SELECT
    DATE(time_dt) AS log_date,
    COUNT(*) AS daily_count
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
GROUP BY DATE(time_dt)
ORDER BY log_date ASC;
-- Look for: days with 0 or abnormally low counts = logging gaps

-- Header availability: can we determine auth state?
SELECT
    CARDINALITY(http_request.http_headers) AS header_count,
    COUNT(*) AS request_count
FROM {{WAF_TABLE}}
WHERE accountid = '{{ACCOUNT_ID}}'
GROUP BY CARDINALITY(http_request.http_headers)
ORDER BY header_count;
-- If header_count is consistently 0, auth state analysis is impossible
```

**Common log gap causes**: WAF logging pointed at non-existent CloudWatch log group; S3 delivery disabled; Security Lake not configured for the region; log retention policy expired data. Document all gaps — they are findings themselves.
