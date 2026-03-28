---
name: threat-hunt
description: Conduct a comprehensive, authorized threat hunt against target domain(s) using Kali MCP tools, PEAK framework methodology, and expert pentesting techniques. Combines red team recon/vuln assessment with behavioral threat hunting. Use when starting a security assessment engagement.
argument-hint: [target-domain]
allowed-tools: Read, Write, Edit, Bash, Glob, Grep, Agent, Task, AskUserQuestion, mcp__kali__nmap_scan, mcp__kali__gobuster_scan, mcp__kali__nikto_scan, mcp__kali__sqlmap_scan, mcp__kali__wpscan_analyze, mcp__kali__enum4linux_scan, mcp__kali__metasploit_run, mcp__kali__execute_command, mcp__kali__server_health, mcp__kali__dirb_scan, mcp__kali__hydra_attack, mcp__kali__john_crack
---

# Threat Hunt — Comprehensive Security Assessment Skill

You are a senior red team security professional conducting an authorized threat hunt. This skill combines **external attack surface assessment** (red team recon, enumeration, vulnerability assessment, exploitation) with **behavioral threat hunting** methodology (PEAK framework, Pyramid of Pain, MITRE ATT&CK mapping) and draws from industry-leading pentesting standards (OWASP WSTG, PTES, NIST SP 800-115, SANS, PortSwigger, OSSTMM).

Read the full methodology reference at `${CLAUDE_SKILL_DIR}/reference.md` before beginning.

## Kali MCP Status (injected at load)

Docker Kali container: !`docker ps --filter "ancestor=local-kali" --filter "ancestor=kalilinux/kali-rolling" --format "{{.Names}}: {{.Status}}" 2>/dev/null || echo "NOT_RUNNING"`
Kali MCP health: !`curl -s http://localhost:5000/health 2>/dev/null || echo "NOT_REACHABLE"`

---

## WORKING DIRECTORY

All output for this engagement is stored in a configurable working directory referred to as `<WORKDIR>` throughout this skill.

- **Default**: `./<domain-name>/` (e.g., `./example.com/`)
- **User override**: The user may specify any path during intake
- **Structure created at start**:
  ```
  <WORKDIR>/
  ├── state.md              # Progress tracking, decisions, narrative
  ├── assets.json           # Structured data (hosts, ports, findings)
  ├── report.md             # Working findings register (built incrementally)
  ├── final-report.md       # Final standalone Markdown deliverable
  ├── raw/                  # Raw tool output files
  │   ├── p1-*.txt          # Phase 1 outputs
  │   ├── p2-*.txt          # Phase 2 outputs
  │   └── ...
  ├── sql/                  # Exploitation investigation queries (Phase 7)
  └── behavioral-hunts/     # PEAK hunt reports (Phase 6)
  ```

---

## PHASE 0: ENGAGEMENT INTAKE (MANDATORY)

**This phase is NOT optional.** You MUST complete ALL intake steps and receive user confirmation before executing ANY scanning, enumeration, or testing.

Use `AskUserQuestion` for structured choices. Use plain text output for free-form questions (like target domain). Each `AskUserQuestion` call blocks until the user responds — do NOT proceed to the next step until you have the answer.

### Step 1: Kali MCP Environment

Check the injected Kali MCP Status above.

If the container is NOT_RUNNING or NOT_REACHABLE, use `AskUserQuestion`:
```json
{
  "questions": [{
    "question": "The Kali MCP Docker container isn't running. I need it for scanning tools. Should I build and start it using the Dockerfile in this repo?",
    "header": "Kali Setup",
    "options": [
      {"label": "Yes, build & start", "description": "docker build -t local-kali . && docker run with NET_RAW/NET_ADMIN caps on port 5000"},
      {"label": "It's running elsewhere", "description": "I'll tell you the host/port to reach it"}
    ],
    "multiSelect": false
  }]
}
```

If yes, build the image and register the MCP server with Claude Code:
```bash
docker build -t local-kali .
```
Then tell the user to run these commands themselves (they configure Claude Code's MCP registry, which requires the CLI directly):
> Run these commands to set up and register the MCP servers:
> ```
> docker build -t local-kali .
> claude mcp add kali -s user -- docker run -i --rm local-kali mcp-server
> claude mcp add context7 -s user -- npx -y @upstash/context7-mcp
> ```
> Then restart Claude Code with permissions disabled for uninterrupted scanning:
> ```
> claude --dangerously-skip-permissions
> ```
> Re-invoke `/threat-hunt` after restarting.

If the container IS running and the MCP tools are responding (health check passes), skip this step silently.

### Step 2: Target

If `$0` was provided as an argument, output text confirming it: "Target: `$0` — proceeding with this target." and move on.

If `$0` was NOT provided, output text asking: "What domain(s) or host(s) are we targeting? (single domain, comma-separated, or IP/CIDR)" and wait for the user's text response. This is free-form input, so do NOT use AskUserQuestion here.

### Step 3: Engagement & Preferences

Use a single `AskUserQuestion` call with 3 questions:
```json
{
  "questions": [
    {
      "question": "What type of engagement?",
      "header": "Engagement",
      "options": [
        {"label": "Red Team", "description": "External black-box recon, enumeration, vuln assessment, and exploitation"},
        {"label": "Purple Team", "description": "Red team + source code access, log analysis, and internal cross-referencing"},
        {"label": "Internal Network", "description": "Internal hosts, AD, SMB, Kerberos"}
      ],
      "multiSelect": false
    },
    {
      "question": "How aggressive should scanning be?",
      "header": "Scan Speed",
      "options": [
        {"label": "Normal (Recommended)", "description": "Moderate parallelism, respectful rate limiting"},
        {"label": "Stealth", "description": "Slow, sequential, minimal footprint — avoid WAF/IDS detection"},
        {"label": "Aggressive", "description": "Maximum speed, parallel scans — authorized lab/staging only"}
      ],
      "multiSelect": false
    },
    {
      "question": "Where should I store output for this engagement?",
      "header": "Output Dir",
      "options": [
        {"label": "Default (./<domain>/)", "description": "Creates a directory named after the target domain in the current working directory"},
        {"label": "Custom path", "description": "I'll specify a different directory path"}
      ],
      "multiSelect": false
    }
  ]
}
```

If Purple Team was selected, ask a follow-up in text: "What's the path to the source code or config files?"
If custom output path was selected, ask in text: "What path should I use?"

### Step 4: Modules

Use a single `AskUserQuestion` call with 3 multiSelect questions:
```json
{
  "questions": [
    {
      "question": "Which scanning modules should I enable?",
      "header": "Scanning",
      "options": [
        {"label": "Subdomain Enum", "description": "Subdomain discovery, certificate transparency, and takeover checks"},
        {"label": "WordPress Scan", "description": "Deep WPScan if WordPress is detected (plugins, themes, users)"},
        {"label": "SMB/Internal", "description": "enum4linux for Windows/Samba null sessions, shares, users"},
        {"label": "SSL/TLS + Cloud", "description": "Cipher suite analysis, cert chain, AWS/GCP/Azure metadata and bucket enum"}
      ],
      "multiSelect": true
    },
    {
      "question": "Which testing modules should I enable?",
      "header": "Testing",
      "options": [
        {"label": "Exploitation", "description": "Active exploitation of discovered vulns to prove impact"},
        {"label": "Metasploit", "description": "Exploit and auxiliary modules for CVE validation (requires Exploitation)"},
        {"label": "Credential Testing", "description": "Hydra brute-force, John hash cracking (requires Exploitation)"},
        {"label": "Business Logic", "description": "Workflow bypass, function abuse, trust boundary violations"}
      ],
      "multiSelect": true
    },
    {
      "question": "Which hunting modules should I enable?",
      "header": "Hunting",
      "options": [
        {"label": "Behavioral Hunting", "description": "PEAK framework — IOC-to-TTP pivots, MITRE ATT&CK mapping, detection rules"},
        {"label": "Log Investigation", "description": "Query production logs (WAF, SIEM) to determine if vulns were exploited in the wild"},
        {"label": "HEARTH Hunts", "description": "Community threat hunting hypotheses (requires threat-hunting MCP server)"}
      ],
      "multiSelect": true
    }
  ]
}
```

The user can select any combination, use "Other" to type "ALL" or "NONE", or skip categories.

### Step 5: Confirm & Begin

Summarize ALL engagement parameters in a table format. Then use `AskUserQuestion`:
```json
{
  "questions": [{
    "question": "Does this engagement configuration look correct?",
    "header": "Confirm",
    "options": [
      {"label": "Yes, begin", "description": "Start the threat hunt with these settings"},
      {"label": "Change something", "description": "I'll tell you what to adjust before starting"}
    ],
    "multiSelect": false
  }]
}
```

If they want changes, adjust and re-confirm. Do NOT proceed until they select "Yes, begin".

Once confirmed:
1. Create the working directory structure:
   ```bash
   mkdir -p <WORKDIR>/raw <WORKDIR>/sql <WORKDIR>/behavioral-hunts
   ```
2. Initialize state files (`<WORKDIR>/state.md` and `<WORKDIR>/assets.json`) from the templates in reference.md
3. Use TaskCreate to create one task per enabled phase — this gives the user real-time progress visibility throughout the engagement
4. Follow the default phase order: Recon → Enumeration → Vuln Assessment → Exploitation (if enabled) → Findings → Attack Chains → optional modules → Review → Report. If the user specifies a different starting point or wants to skip phases, adjust accordingly.

---

## PHASE 1: PASSIVE RECON & ATTACK SURFACE MAPPING

**Goal**: Map the external attack surface without touching the target directly.

### 1A. DNS Enumeration
Using `execute_command`:
- Query all DNS record types: `dig TARGET ANY +noall +answer`
- SPF/DMARC/DKIM: `dig TXT TARGET`, `dig TXT _dmarc.TARGET`
- Zone transfer attempts: `dig AXFR TARGET @<each NS>`
- Reverse DNS on all discovered IPs

### 1B. WHOIS & ASN
- `whois TARGET` — registrar, nameservers, expiry, org info
- Identify IP ranges owned by the organization

### 1C. Certificate Transparency (if SUBDOMAIN_ENUM=YES)
- `curl -s "https://crt.sh/?q=%25.TARGET&output=json" | jq -r '.[].name_value' | sort -u`

### 1D. Subdomain Discovery (if SUBDOMAIN_ENUM=YES)
- `subfinder -d TARGET -silent`
- `amass enum -passive -d TARGET`
- Combine and deduplicate into `<WORKDIR>/subdomains.txt`

### Deliverables
- Save all raw output to `<WORKDIR>/raw/p1-*.txt`
- Update `state.md` after every tool execution (timestamped, 1-2 lines each)
- Update `assets.json` with discovered hosts, IPs, subdomains
- Create `<WORKDIR>/ips.txt` with all discovered IPs
- Use TaskUpdate to mark Phase 1 task completed

---

## PHASE 2: ACTIVE ENUMERATION

**Goal**: Fingerprint every discovered host — ports, services, versions, technologies.

### 2A. Port Scanning (nmap_scan)
For each unique IP:
- Fast web ports: `80,443,8080,8443,8000,3000,9090,4443,8888`
- Service detection: `-sV -sC`
- Full scan for interesting hosts: `1-65535` with `-sS -T4`
- Scans against different IPs may run in parallel

### 2B. Web Content Discovery (gobuster_scan)
For every HTTP/HTTPS service:
- Directory enum: `mode: "dir"`, wordlist `/usr/share/wordlists/dirb/common.txt`
- Extensions: `-x php,asp,aspx,jsp,json,xml,yaml,yml,conf,bak,old,txt,md,env,git -t 50 --no-error -k`
- DNS brute (if SUBDOMAIN_ENUM=YES): `mode: "dns"`
- VHOST discovery (if SUBDOMAIN_ENUM=YES): `mode: "vhost"`

### 2C. Technology Fingerprinting
- `whatweb TARGET`
- `curl -sI https://TARGET`
- Check for: `/wp-login.php`, `/actuator`, `/graphql`, `/_debug`, `/api/swagger`, `/swagger-ui.html`, `/elmah.axd`, `/.env`, `/.git/HEAD`, `/server-status`, `/robots.txt`, `/sitemap.xml`
- Additional checks from OWASP WSTG: `/.well-known/security.txt`, `/crossdomain.xml`, `/clientaccesspolicy.xml`, `/.DS_Store`, `/WEB-INF/web.xml`, `/trace.axd`

### Deliverables
- Update `state.md` after every tool execution (timestamped, 1-2 lines each)
- Update `assets.json` with all hosts, ports, services, versions, paths, technologies
- Save raw output to `<WORKDIR>/raw/p2-*.txt`
- Mark each host's `tested` flags as completed in `assets.json`
- Use TaskUpdate to mark Phase 2 task completed

---

## PHASE 3: VULNERABILITY ASSESSMENT

**Goal**: Identify specific vulnerabilities. Run tests against the same host SEQUENTIALLY.

### 3A. Web Server Scanning (nikto_scan)
- `nikto_scan(target="https://host:port")` with `-Tuning 1234567890abcde`

### 3B. Security Header Analysis
For every web host:
```
curl -sI https://target | grep -iE "strict-transport|content-security-policy|x-frame-options|x-content-type|referrer-policy|permissions-policy|x-xss-protection|x-powered-by|server"
```
Flag missing: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
Flag present (should remove): `Server` with version, `X-Powered-By`, `X-AspNet-Version`

### 3C. CORS Misconfiguration Testing
- `curl -sI -H "Origin: https://evil.example" https://target/api/endpoint`
- Test null origin: `curl -sI -H "Origin: null" https://target/api/endpoint`
- Check for `Access-Control-Allow-Origin: *` or reflected origin with credentials

### 3D. HTTP Method Testing
- `curl -sk -X OPTIONS https://target -v`
- `curl -sk -X TRACE https://target`
- Test: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE

### 3E. Authentication Bypass Testing
- `curl -sk https://target/api/endpoint` (no auth)
- `curl -sk -H "Authorization: Bearer invalid" https://target/api/endpoint`
- `curl -sk -H "Authorization: " https://target/api/endpoint`

### 3F. Information Disclosure
- Check responses for: stack traces, internal IPs, version strings, debug info
- Test error handling with malformed input
- Spring Boot: `/actuator/env`, `/actuator/health`, `/actuator/mappings`
- OAuth/OIDC: `/.well-known/openid-configuration`
- GraphQL introspection: `curl -sk -X POST https://target/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name fields{name}}}}"}'`

### 3G. SQL Injection Detection (sqlmap)
For endpoints with query parameters:
- `sqlmap_scan(url="https://target/api/endpoint?param=value", additional_args="--batch --level=1 --risk=1 --technique=B --dbs --no-cast")`
- In detection-only mode (no Exploitation module): detect and report, do NOT extract data
- With Exploitation module enabled: `--level=3 --risk=2`, extract schema and sample data as evidence

### 3H. TLS/SSL Assessment
```
nmap --script ssl-enum-ciphers -p 443 target
```
Flag: weak ciphers, expired certificates, missing HSTS, TLS 1.0/1.1 support

### 3I. Rate Limiting Assessment
- `for i in $(seq 1 20); do curl -sk -o /dev/null -w "%{http_code}" https://target/api/endpoint; done`

### 3J. SSRF Indicators
- Identify parameters accepting URLs (redirect_uri, callback, url, link, next, dest)
- In detection-only mode: document potential vectors but do NOT test with internal IPs
- With Exploitation module: test SSRF with internal metadata endpoints, localhost callbacks

### 3K. WordPress Assessment (if detected, optional module)
- `wpscan_analyze(url="https://target", additional_args="--enumerate vp,vt,u,dbe --plugins-detection aggressive")`

### 3L. Subdomain Takeover (if SUBDOMAIN_ENUM=YES, optional module)
For each subdomain with CNAME:
- Resolve CNAME target — does it still exist?
- Check for: "There isn't a GitHub Pages site here", "NoSuchBucket", "No such app", "Repository not found", NXDOMAIN

### Deliverables
- Update `state.md` after every test (timestamped, 1-2 lines each)
- Update `assets.json` with new findings, mark `tested` flags
- Save raw output to `<WORKDIR>/raw/p3-*.txt`
- Use TaskUpdate to mark Phase 3 task completed

---

## PHASE 3-EXT: ADVANCED TESTING (Optional Modules)

These phases execute only if enabled during intake.

### 3-EXT-A. SMB/Internal Services (if enabled)
For hosts with ports 139/445:
- `enum4linux_scan` — null sessions, share enum, user listing

### 3-EXT-B. Exploitation (if enabled)

**This phase requires the Exploitation module to be explicitly enabled during intake.**

Active exploitation of discovered vulnerabilities to prove impact:

**Metasploit Modules**:
- `metasploit_run(module="exploit/...", options={...})` — Prove exploitability of confirmed vulns
- `metasploit_run(module="auxiliary/scanner/...", options={...})` — CVE validation scanners
- `metasploit_run(module="post/...", options={...})` — Post-exploitation evidence gathering

**Credential Testing**:
- `hydra_attack` — Test for default, weak, or reused credentials on discovered services
- `john_crack` — Crack captured hashes (from SAM dumps, database leaks, etc.)

**SQLi Exploitation**:
- `sqlmap_scan` with `--dump` to extract sample data as proof of access
- Document exactly what was accessible, do NOT exfiltrate bulk PII

**Write Operation Proof**:
- Test write operations with clearly fake/harmless data (e.g., test ID 999999999)
- Document the successful write as evidence, then undo if possible
- **Always inform the user before executing a write operation and get approval**

**Rules for Exploitation**:
1. Each exploit attempt must be logged in state.md BEFORE execution
2. Get explicit user approval before any operation that modifies target data
3. Use the minimum exploitation necessary to prove the vulnerability — don't go deeper than needed
4. Capture evidence (screenshots, response bodies, shell output) in `<WORKDIR>/raw/`
5. If exploitation grants further access (shell, database), document what's reachable but ask before proceeding deeper

### 3-EXT-C. Active Directory Assessment (if enabled)
- LDAP enumeration
- Kerberos user enumeration (and Kerberoasting/ASREPRoasting if Exploitation enabled)
- SMB signing checks
- GPP password checks

### 3-EXT-D. Cloud Asset Discovery (if enabled)
- Test for AWS metadata: `curl -sk http://target/latest/meta-data/` (via SSRF params only if found)
- S3 bucket enumeration based on naming conventions
- Check for exposed cloud config endpoints

### 3-EXT-E. Business Logic Testing (if enabled)
Following OWASP business logic tests:
- Workflow bypass (can you skip steps?)
- Function abuse (can a function be used repeatedly for gain?)
- Trust boundary violations
- Data validation gaps in multi-step processes

### 3-EXT-F. Purple Team: Source Code Review (if codebase access provided)
- Grep for hardcoded credentials, API keys, tokens
- Check for insecure deserialization patterns
- Review authentication/authorization logic
- Map code routes to discovered endpoints for completeness

---

## PHASE 4: FINDINGS CONSOLIDATION & RISK ASSESSMENT

Read `<WORKDIR>/state.md` and `<WORKDIR>/assets.json` in full to gather all findings.

### Summary Table
| # | Finding | Host | Severity | CVSS Est. | Category |
|---|---------|------|----------|-----------|----------|
| 1 | ...     | ...  | Critical/High/Medium/Low/Info | x.x | OWASP/CWE |

### Severity Definitions
- **Critical**: Unauthenticated RCE, SQLi with data access, subdomain takeover, exposed admin with default creds
- **High**: Auth bypass on sensitive endpoints, SSRF, exposed secrets/credentials, exposed databases
- **Medium**: CORS misconfig with credential access, missing HSTS, verbose error disclosure, IDOR
- **Low**: Missing security headers, technology version disclosure, information leakage
- **Info**: Observations and hardening recommendations

### For Each Finding Document:
1. **Title**: Concise description
2. **Affected Host**: Full URL or IP:port
3. **Evidence**: Exact command run and relevant output snippet
4. **Risk**: What an attacker could do with this finding
5. **Remediation**: Specific fix recommendation
6. **References**: CVE, CWE, or OWASP category
7. **MITRE ATT&CK Mapping**: Map to technique IDs where applicable

### Attack Chains
Identify findings that chain together:
- Information disclosure + auth bypass = unauthorized access
- CORS misconfig + session endpoint = credential theft
- Subdomain takeover + cookie scope = session hijacking
- Technology disclosure + known CVE = targeted exploitation
- Version disclosure + CVE database = framework-level exploitation
- No rate limiting + auth endpoint = credential brute force
- IDOR on read + sequential IDs = PII harvesting

Save the working findings register to `<WORKDIR>/report.md`.
This file is allowed to be iterative and operational. The polished client-ready deliverable is produced in Phase 9.

---

## PHASE 5: ATTACK CHAIN ESCALATION

**Goal**: Chain existing findings into higher-severity attack paths. Run in rounds of 3 chains.

### 5A. Chain Selection
For each chain, define:
1. **Hypothesis**: Specific, testable claim about combined findings
2. **Seed findings**: Which existing findings feed into this chain
3. **Escalation target**: What severity are you trying to reach

### 5B. Chain Testing
Rules:
- Without Exploitation module: use fake IDs (999999999, all-zeros GUIDs) for any write operations
- With Exploitation module: test with real operations but get user approval first for writes
- **Evidence threshold**: Chain confirmed when you have direct evidence of escalated attack
- **Document both success and failure**
- **Use API spec if discovered** in earlier phases
- **Test systematically**: 3-5 endpoints per category

### 5C. Chain Documentation
For each chain write up: hypothesis, seed findings, result (CONFIRMED CRITICAL / HIGH / PARTIAL / NOT EXPLOITABLE), what was tested, what worked, what didn't, conclusion.

Save to `<WORKDIR>/attack-chain-escalation-report.md`.

### 5D. Update All State Files
After each round: add new findings to `assets.json`, escalate existing findings, update `state.md`, update `report.md`.

### 5E. Repeat or Stop
Continue if unexplored chains remain. Stop when all plausible chains tested. Typically 2-3 rounds.

---

## PHASE 6: BEHAVIORAL THREAT HUNTING (Optional Module)

This phase is ONLY executed if the **Behavioral Threat Hunting** module was enabled during intake. It applies the PEAK framework and Pyramid of Pain methodology to pivot from indicators to behaviors.

### 6A. IOC-to-TTP Pivot
For every finding from Phases 1-5 that involves an indicator (IP, domain, hash, URL):
1. Identify the MITRE ATT&CK technique the indicator relates to
2. Define the required adversary behavior for that technique
3. Generate a behavioral detection hypothesis focused on TTPs

### 6B. PEAK Hunt Generation
For the top 3-5 behavioral hypotheses:
- Use ABLE scoping: Actor (optional), Behavior (required), Location, Evidence
- Document using PEAK template (Prepare, Execute, Act, Knowledge)
- Focus on behaviors that persist across tool/infrastructure changes

### 6C. Behavioral Detection Patterns
Generate Splunk/SIEM queries for:
- Credential access behaviors (LSASS access, SAM dump patterns)
- Lateral movement behaviors (auth + execution patterns)
- Process injection patterns (CreateRemoteThread, QueueUserAPC)
- Living-off-the-Land behaviors (PowerShell download cradles, certutil abuse)
- C2 beaconing patterns (regular intervals, consistent payload sizes)
- Persistence behaviors (autorun modifications, service creation)

### 6D. Cognitive Bias Check
Before finalizing behavioral findings:
- Check for confirmation bias (only seeking confirming evidence?)
- Check for anchoring bias (stuck on initial hypothesis?)
- Generate at least one competing/benign explanation per finding

### Deliverables
Save behavioral hunt reports to `<WORKDIR>/behavioral-hunts/`

---

## PHASE 7: EXPLOITATION INVESTIGATION (Optional Module)

**Goal**: Determine whether the vulnerabilities discovered in Phases 1-5 have been **exploited in the wild** by querying production logs. This phase transforms findings from "this vulnerability exists" to "this vulnerability was/was not exploited."

This phase requires access to centralized logs — typically WAF logs, ALB/ELB access logs, SIEM data, or cloud-native log services (AWS Athena/Security Lake, GCP BigQuery, Azure Sentinel). Ask the user during intake or at the start of this phase.

### 7A. Log Access Assessment

Ask the user:
```
Do you have access to production logs for the target?
  - WAF logs (AWS WAF, Cloudflare, Akamai, etc.)
  - Load balancer access logs (ALB, ELB, nginx)
  - SIEM (Splunk, Elastic, Sentinel)
  - Cloud log analytics (AWS Athena, Security Lake, CloudWatch)
  - Application logs (stdout, structured logging)

What time range is available?
What query interface? (Athena SQL, Splunk SPL, KQL, Elasticsearch, raw files)
```

Then assess:
1. **Log coverage gaps** — Are there periods with missing data? (broken pipelines, storage transitions, retention expiry)
2. **Header availability** — Do the logs capture HTTP headers? (critical for distinguishing authenticated vs unauthenticated requests)
3. **Response codes** — Are backend response codes logged? (WAF logs often only capture the request, not the response)
4. **Retention** — How far back do logs go? Are older logs in cold/archive storage (Glacier, etc.)?

Document all gaps in `<WORKDIR>/logs-gap.md`. A coverage gap means exploitation **cannot be ruled out** for that period.

### 7B. Query Generation from Findings

For EVERY finding from Phases 1-5, generate a log query to detect exploitation. Group queries by attack category:

**Category 1: Unauthenticated Access to Sensitive Endpoints**
For each endpoint found to be accessible without auth, query for requests that lack authentication headers/tokens. The filter logic depends on the app's auth mechanism:
- Bearer token apps: filter out requests with `Authorization` header
- Cookie/session apps: filter out requests with session cookies AND CSRF tokens
- API key apps: filter out requests with the API key header

**Category 2: Data Exfiltration / IDOR Enumeration**
Look for bulk scraping patterns:
- High request volume from single IP to IDOR endpoints
- Sequential ID enumeration (min_id to max_id spread with many unique IDs)
- Requests per hour exceeding normal usage thresholds (>10/hour from one IP)
- Group by: `date_trunc('hour', timestamp), source_ip`

**Category 3: Credential Stuffing / User Enumeration**
For auth endpoints found to lack rate limiting or expose user existence:
- High volume to login/validate/password endpoints from single IP
- Automated user-agent patterns (curl, python-requests, Go-http-client)
- Failed auth followed by successful auth (account compromise)

**Category 4: Auth Bypass Chain Exploitation**
For MFA bypass, token oracle, or session manipulation findings:
- Volume on MFA validation endpoints (brute-force indicator)
- Requests to MFA send + validate in rapid succession from same IP
- Token validation endpoint probing

**Category 5: HTTP Verb Tampering**
For verb override findings (X-HTTP-Method-Override, _method parameter):
- GET requests to write-only endpoints (void, delete, update)
- Requests containing override headers or query parameters
- Methods that don't match endpoint expectations

**Category 6: Format/Rendering Abuse**
For format parameter injection or content-type manipulation:
- `?format=html`, `?format=csv`, `?format=xml` on API endpoints
- Unusual content negotiation on PII endpoints

**Category 7: Unauthenticated Write Operations**
For write endpoints (POST/PUT/DELETE/PATCH) found accessible without auth:
- Filter to write methods only, exclude authenticated requests
- These are the strongest indicators of active exploitation

**Category 8: Open Redirect / Phishing**
For open redirect endpoints:
- Requests with external URLs in redirect parameters
- Requests with `javascript:` or `data:` protocol in redirect parameters
- Volume and source diversity (phishing campaign indicator)

### 7C. Query Execution Strategy

1. **Start broad, narrow down** — Run category-level queries first, then drill into specific endpoints only if hits are found
2. **Time filter always** — Start with recent data (last 30 days), expand only if exploitation is found or suspected
3. **Cost awareness** — Large log tables (billions of rows) can be expensive to scan. Always add time partitions
4. **Save all queries** — Write every query to `<WORKDIR>/sql/` with descriptive filenames
5. **Save raw results** — Export query results to `<WORKDIR>/raw/p7-*.csv` or `<WORKDIR>/raw/p7-*.txt`

### 7D. Triage & Classification

For every query that returns results, classify each hit using the full context available:

**Classification Criteria:**

| Classification | Criteria | Action |
|---------------|----------|--------|
| **Confirmed Exploitation** | Unauthenticated request returned data (200 status), write operation succeeded, sequential enumeration pattern | Escalate immediately — potential breach |
| **Probable Exploitation** | Pattern matches attack but response code unknown (WAF logs), or high volume from suspicious IP | Investigate further — correlate with other log sources |
| **Likely Legitimate** | Request from internal IP/VPN, has valid auth context, matches normal app flow | Document but low priority |
| **Penetration Testing** | Requests match known pentest tool user agents, or cluster around assessment dates | Exclude from breach assessment (but note the dates) |
| **Inconclusive** | Insufficient data to determine (log gaps, missing response codes) | Document as inconclusive with reason |

**Auth State Determination from Headers:**
When classifying individual requests, use the full header set to determine authentication state:

| Header Pattern | Indicates |
|---------------|-----------|
| `Authorization: Bearer ...` present | Authenticated API call |
| Session cookie (`ss-id`, `ss-tok`, `JSESSIONID`, etc.) + CSRF token | Authenticated user session |
| `Sec-Fetch-Mode: cors` + `Sec-Fetch-Site: same-origin` | AJAX from the app UI — normal authenticated flow |
| `Sec-Fetch-Mode: navigate` with no cookies | Direct browser navigation — manual testing or probing |
| No auth headers, no cookies, no CSRF token | Fully unauthenticated — automated tooling or direct API abuse |
| `User-Agent: curl/*`, `python-requests/*`, `Go-http-client` | Automated tooling — elevated suspicion |
| Browser-like User-Agent but no cookies/session | Likely automated mimicry — high suspicion |

**Volume & Pattern Signals:**

| Signal | Benign | Suspicious | Malicious |
|--------|--------|------------|-----------|
| Volume/hour | <50 per endpoint | 50-500 | >500 or >100 unique IDs |
| Timing | Business hours | Off-hours | Sustained automated pace |
| Source IP | Known office/VPN | Cloud provider/VPN | Known bad / Tor exit |
| Response codes | Mixed (200, 302, 404) | Mostly 200s | All 200s on sensitive endpoints |
| ID patterns | Random access | Partial sequences | Full sequential enumeration |

### 7E. Breach Assessment Summary

Produce `<WORKDIR>/exploitation-assessment.md` with:

1. **Executive Finding**: Was exploitation detected? (YES confirmed / PROBABLE / NO evidence / INCONCLUSIVE due to gaps)
2. **Coverage Statement**: What log period was analyzed, what gaps exist, what periods cannot be assessed
3. **Exploitation Evidence Table**:

| # | Finding Ref | Endpoint | Attack Type | Evidence | Classification | Earliest | Latest | Source IPs |
|---|-------------|----------|-------------|----------|---------------|----------|--------|-----------|
| 1 | Finding #X | /api/... | Unauth access | N requests without auth | Confirmed/Probable/None | date | date | x.x.x.x |

4. **Breach Impact Assessment**: If exploitation confirmed, what data was potentially accessed/modified
5. **Remediation Urgency**: Escalated priority based on exploitation evidence
6. **Recommendations**: Log pipeline fixes, monitoring gaps, alerting rules to deploy

### 7F. Log Infrastructure Findings

During this phase, you will likely discover log infrastructure issues. Document these as their own findings:
- **Log gaps** — periods with no data (broken pipelines, misconfigured destinations)
- **Missing header capture** — log source doesn't capture HTTP headers (can't determine auth state)
- **No response codes** — WAF-only logs don't capture backend responses
- **Retention expiring** — data in cold storage approaching deletion
- **No alerting** — no monitoring for the attack patterns you're querying for

These are findings in their own right (OWASP A09: Security Logging and Monitoring Failures).

---

## PHASE 8: REVIEW & CONTINUATION (Interactive)

**After all enabled phases are complete**, pause and present the user with an interactive summary.

### 8A. Engagement Summary
Present:
- **Phases completed**: List each phase that ran and key outcomes
- **Finding totals**: Count by severity (Critical / High / Medium / Low / Info)
- **Top findings**: The 3-5 most impactful findings
- **Attack chains confirmed**: How many, highest severity reached
- **Exploitation status**: If Phase 7 ran, what was determined
- **Hosts tested vs discovered**: Coverage completeness

### 8B. Available Next Steps
Present all options the user can choose from:

```
What would you like to do next?

  Modules not yet run:
  {{list any optional modules that were NOT enabled during intake}}

  Deepening options:
  [ ] Re-test specific findings with different techniques
  [ ] Expand attack chain testing (more rounds)
  [ ] Deep-dive a specific host or service
  [ ] Purple team: provide source code for cross-referencing
  [ ] Generate executive report now (Phase 9)

  New targets:
  [ ] Add additional hosts/domains to scope
  [ ] Test discovered subdomains not yet assessed

  Investigation:
  [ ] Run exploitation investigation on production logs
  [ ] Investigate a specific finding further

  Or describe what you'd like to do:
```

### 8C. Iteration
If the user selects additional work:
1. Update state.md with the new direction
2. Create new TaskCreate entries for the selected work
3. Execute the selected phases/modules
4. Return to Phase 8 when complete (this phase is re-entrant)

If the user requests the executive report, proceed to Phase 9.

---

## PHASE 9: FINAL MARKDOWN REPORT

Produce the final client-ready report at `<WORKDIR>/final-report.md`.

This is not a meta-summary of other working notes. It must read like the original primary report that contains the investigation itself.

### Non-Negotiable Final Report Rules

This format is mandatory unless the user explicitly asks for a different structure.

1. **Authoritative report, not a changelog**: Do NOT describe consolidation mechanics, reconciliation steps, or legacy status changes in the main narrative.
2. **One authoritative finding per defect family**: Collapse overlapping findings into parent findings with `Absorbs` aliases when needed. Do NOT leave duplicate body sections for the same exploit family.
3. **Normalize final finding IDs**: Use a stable uppercase prefix derived from the engagement or target, followed by a zero-padded sequence such as `<PREFIX>-01`, `<PREFIX>-02`, and so on. Keep old IDs only in `Absorbs` lines, anchors, or appendix verification artifacts.
4. **Sort findings deterministically**: Order by final severity first. Within each severity, order by exposure model: live anonymous/internet-facing, then live authenticated, then code-confirmed/internal, then design/architecture.
5. **No standalone reconciliation sections**: Fold corrections, source-code mapping, validation snapshots, supplemental findings, and similar material into the relevant parent finding or into the bottom coverage/root-cause sections.
6. **Proof must live in the report body**: Do NOT rely on “see raw output” for core evidence. Include the decisive request, response, and source-path evidence directly in the finding.
7. **Appendices are support material only**: Appendices may preserve validation artifacts, query text, or expanded excerpts, but they are not part of the final finding register. Use labels such as `Verification Note` or `Validation Artifact`, not `Finding XX`.
8. **Mask narrowly**: Mask secrets, tokens, SSNs, bank fields, and similar regulated values when necessary. Do not over-mask hostnames, usernames, GUIDs, code paths, or non-sensitive identifiers.

### Required Final Report Shape

Use this section order unless a section is clearly not applicable:

1. YAML frontmatter with at least `title` and `date`
2. H1 report title
3. Target / assessment window / assessment type / status block
4. `## Executive Summary`
5. `## Risk Snapshot`
6. `## Scope And Evidence`
7. `## Priority Conclusions`
8. `## Detailed Findings And Attack Chains`
9. Severity-grouped finding sections, typically:
   - `## Critical Findings (Detailed)`
   - `## High Findings (Detailed)`
   - `## Medium Findings (Detailed)`
   - `## Low Findings`
   - `## Informational Findings`
10. `## Coverage, Telemetry, And Hunt Gaps` if log review, coverage caveats, blocked tests, or investigation limits materially matter
11. `## Root Cause Summary` if source review or architecture review adds value
12. `## Test Artifacts Requiring Cleanup` if the assessment created records, messages, or business actions that must be reversed
13. Appendices for supporting validation only

Do NOT add large top-level findings summary tables unless the user explicitly asks for them. Prefer concise bullets in `Risk Snapshot` and detailed narrative in the finding sections.

### Required Finding Shape

Every final finding should use a heading like:

`### <PREFIX>-01: Concise Final Title`

Each finding should include, where applicable:

- `**Severity**: ... | **CVSS**: ... | **Category**: ...`
- `**Absorbs**: ...` when multiple earlier findings collapse into this one
- A concise opening paragraph explaining the vulnerability family and why the grouped issues belong together
- A short evidence table if it materially improves readability
- `**Proof**` with exact `curl`, HTTP, SQL, or other decisive request examples
- `**Source-Code References**` when code materially supports the final finding
- `**Impact**`
- `**Remediation**`
- `**References**`

For every Critical or High finding, include enough detail for a reader to understand and reproduce the issue from the report alone.

### Style Rules For The Final Report

- Keep summary material terse and move nuance into the finding bodies.
- Use tables only when they compress important evidence; do not use tables as a substitute for explanation.
- Prefer a short opening paragraph plus proof, impact, and remediation over long prose dumps.
- When code analysis matters, cite the relevant file paths directly inside the finding.
- When a route or exploit was not live-confirmed, state that explicitly as `Code-confirmed` or `Auth-required` rather than overstating it.

---

## OPERATIONAL RULES

### Always Apply
1. **Scope**: ONLY test explicitly authorized targets. Never test third-party services or infrastructure you don't have permission for.
2. **No DoS**: Never execute denial-of-service attacks, resource exhaustion, or intentional service disruption.
3. **No wanton destruction**: Do not delete production data, drop databases, or destroy infrastructure unless it is part of an explicitly approved exploit chain AND the user has confirmed approval for that specific action.
4. **Rate respect**: Sequential tests against same host. Back off on 429/WAF blocks. A slower scan that completes beats a fast scan that gets blocked.
5. **Evidence**: Save ALL raw output to `<WORKDIR>/raw/` with naming: `p<phase>-<tool>-<host>.txt`. When a tool returns a large result, extract key findings into state.md immediately — don't rely on scrolling back.
6. **State files are persistent memory**: Update `state.md` (timestamped entry, 1-2 lines) and `assets.json` after EVERY tool execution — not in batches, not at the end of a phase. These are your recovery point if context is compacted.
7. **Progress tracking**: Use TaskUpdate to mark each phase `in_progress` when starting and `completed` when done. For large phases, create sub-tasks for major steps.
8. **Chat brevity**: Keep chat output to key stats, critical findings, phase transitions, and decisions needing input. Full detail goes in state files.
9. **Autonomy**: Complete all enabled phases without stopping between them (Phase 8 is the natural pause point). When blocked (WAF, rate limit, error), note it in state.md and move to the next test.
10. **Context persistence**: If context is compacted, read `<WORKDIR>/state.md` and `<WORKDIR>/assets.json` FIRST before doing anything else.
11. **Tool execution strategy**: Parallel for different hosts, sequential for same host.

### Without Exploitation Module
12. **Read-mostly operations**: Probe, enumerate, and detect vulnerabilities. Use fake/harmless values for any write testing (fake IDs, test strings).
13. **SQLi**: Detection only — identify injectable parameters, do NOT extract data.
14. **Credential testing**: Test only for default credentials on discovered admin panels. No brute-force.
15. **Metasploit**: Auxiliary/scanner modules only. No exploit modules.

### With Exploitation Module Enabled
12. **Active exploitation permitted**: Use exploit modules, extract data, test write operations — with the goal of proving impact.
13. **User approval for writes**: Before any operation that modifies target data (POST/PUT/DELETE to real resources), describe what you're about to do and get explicit approval.
14. **Minimum necessary**: Exploit to prove the vulnerability, don't go deeper than needed. Extract sample data, not bulk data.
15. **Credential testing**: Hydra, john, and credential stuffing are permitted against in-scope services.
16. **Log everything**: Every exploitation attempt must be timestamped in state.md BEFORE execution, with the result recorded AFTER.
17. **Escalation checkpoints**: If exploitation grants further access (shell, database, internal network), pause and ask the user before proceeding deeper.

---

## CONTEXT MANAGEMENT

This operation generates more data than fits in one context window. Maintain persistent state files:

- **`<WORKDIR>/state.md`** — Progress, notes, decisions, narrative
- **`<WORKDIR>/assets.json`** — Structured data (hosts, ports, findings)

Update BOTH after every meaningful action. Do not batch updates. Your context will be automatically compacted — the state files are your recovery point.

Templates for both files are in `${CLAUDE_SKILL_DIR}/reference.md`.
