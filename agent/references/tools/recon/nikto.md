# nikto

**Purpose:** Web server vulnerability scanner
For live engagement targets, run Nikto through the Kali MCP command-execution tool with `nikto`.

**Basic scan:** `nikto -h https://target`
**Specific port:** `nikto -h target -p 8080`
**With SSL:** `nikto -h https://target -ssl`
**Tuning (specific tests):** `nikto -h target -Tuning 123bde`
**Output:** `-o report.html -Format html`
