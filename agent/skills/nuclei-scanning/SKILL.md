---
name: nuclei-scanning
description: Template-based vulnerability scanning with nuclei for CVEs, misconfigs, and exposures
origin: AI Threat Hunting
---

# Nuclei Scanning

> **Kali MCP audit header:** set `X-Technique` per the template-tag focus — `CVE-VALIDATION` for `-tags cve` runs, `DISCOVERY` for tech-detect and fingerprint templates, `INFO-DISCLOSURE` for exposure templates, and `OTHER` for mixed sweeps spanning many classes.

## When to Activate

- After recon/collect phases when live targets and tech stacks are identified
- When known CVEs match discovered software versions
- Broad vulnerability sweep before targeted manual testing
- Checking for common misconfigurations and exposures across many endpoints

## Tools

- `nuclei` — template-based vulnerability scanner (community templates updated weekly)

## Methodology

The shared Kali runtime does not mount `$ENGAGEMENT_DIR` at `/engagement`. Use `/tmp` for runtime-local
input/output, then persist durable artifacts into `$ENGAGEMENT_DIR/scans/` on the host before triage,
ingestion, or handoff.

### 1. Update Templates
```bash
nuclei -update-templates
```
Always update before an engagement to get the latest CVE and misconfiguration checks.

### 2. Targeted Severity Scan
```bash
# Critical and high severity only (fast, high-signal)
nuclei -u https://TARGET -severity critical,high -o /tmp/nuclei_crithigh.txt

# All severities for thorough coverage
nuclei -u https://TARGET -o /tmp/nuclei_full.txt
```

### 3. Technology-Specific Scanning
```bash
# Scan by technology tags (from recon fingerprinting)
nuclei -u https://TARGET -tags apache,nginx,php,wordpress,spring
nuclei -u https://TARGET -tags cve -severity critical,high

# Specific CVE template
nuclei -u https://TARGET -t cves/2024/ -severity critical,high
```

### 4. Bulk Target Scanning
```bash
# Scan all live targets from recon
nuclei -l /tmp/live_targets.txt -severity critical,high \
  -rate-limit 100 -o /tmp/nuclei_bulk.txt -jsonl

# With concurrency control
nuclei -l /tmp/live_targets.txt -c 25 -rate-limit 50
```

### 5. Misconfiguration and Exposure Checks
```bash
# Common misconfigs: exposed panels, debug endpoints, default creds
nuclei -u https://TARGET -tags misconfig,exposure,default-login

# Specific checks
nuclei -u https://TARGET -tags takeover       # Subdomain takeover
nuclei -u https://TARGET -tags tech           # Technology detection
nuclei -u https://TARGET -tags file           # Sensitive file exposure
```

### 6. Output and Triage
```bash
# JSON lines for structured processing
nuclei -u https://TARGET -severity critical,high -jsonl -o /tmp/nuclei.jsonl

# Parse results
cat /tmp/nuclei.jsonl | jq '.info.name, .info.severity, .matched-at'
```

## Triage Rules

- **Critical/High nuclei hits**: Validate manually before recording as findings. Nuclei templates can have false positives.
- **Medium/Low hits**: Log as intelligence or surface candidates. Only promote to findings after manual confirmation.
- **Info-level detections**: Use for tech stack enrichment and hypothesis generation, not findings.

## What to Record

- Validated vulnerabilities with exact nuclei template ID and manual confirmation
- False positives identified (helps future template selection)
- Tech stack detections that inform further testing choices

## Extended Resources

- `agent/references/tools/recon/nuclei.md` — nuclei flags, template management, output formats
