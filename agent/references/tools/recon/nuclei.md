# nuclei

**Purpose:** Vulnerability scanning with community templates
For live engagement targets, prefer `nuclei` through the Kali MCP command-execution tool.

**Basic scan:** `nuclei -u https://target`
**Specific template:** `nuclei -u https://target -t cves/2021/CVE-2021-44228.yaml`
**By severity:** `nuclei -u https://target -severity critical,high`
**By tag:** `nuclei -u https://target -tags cve,rce`
**Multiple targets:** `nuclei -l /engagement/scans/targets.txt`
**Update templates:** `nuclei -update-templates`
**Output:** `-o results.txt`, `-jsonl` (JSON lines)
**Rate limit:** `-rate-limit 100`
