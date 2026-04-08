# nmap

**Purpose:** Port/service discovery and enumeration
For live engagement targets, run Nmap through the Kali MCP command-execution tool with `nmap`.
The Kali MCP also provides a dedicated `nmap_scan` tool — check MCP tool discovery.

## Discovery Scans

**Quick (with host discovery skip):** `nmap -sV -sC -Pn -T4 target`
**Full port scan:** `nmap -sV -sC -Pn -T4 -p- target`
**Top 1000 ports (default):** `nmap -sV -sC -Pn target`
**Specific ports:** `nmap -sV -sC -Pn -p 80,443,8080,8443 target`
**UDP top ports:** `nmap -sU --top-ports 50 -Pn target`

`-Pn` is required when ICMP is blocked by firewall (common in lab/engagement environments).

## Scan Types

**SYN scan (default, needs root):** `-sS` (stealthy, half-open)
**TCP connect (no root):** `-sT` (full handshake, logged)
**Version detection:** `-sV` with `--version-intensity 5` (0=light, 9=deep)
**OS detection (needs root):** `-O`
**Aggressive:** `-A` (combines -O, -sV, -sC, --traceroute)

## NSE Scripts

**Default scripts:** `-sC` (same as `--script=default`)
**Vuln category:** `--script=vuln`
**Specific script:** `--script=http-enum`
**Script args:** `--script-args='http-enum.basepath=/api/'`

Common categories: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`

## Speed & Evasion

**Timing:** `-T0` (paranoid) to `-T5` (insane). Default: `-T3`
**Min rate:** `--min-rate 1000`
**Max retries:** `--max-retries 2`
**Fragment packets:** `-f`
**Source port spoof:** `--source-port 53`

## Output

`-oN file.txt` — normal text
`-oX file.xml` — XML (for parsing)
`-oG file.gnmap` — greppable
`-oA basename` — all formats at once

## Common Port Quick Reference

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | Check anonymous login |
| 22 | SSH | Version → CVE check |
| 25 | SMTP | Open relay check |
| 53 | DNS | Zone transfer |
| 80/443 | HTTP/HTTPS | Web application |
| 139/445 | SMB | EternalBlue, null session |
| 3306 | MySQL | Remote auth |
| 3389 | RDP | BlueKeep, NLA check |
| 5432 | PostgreSQL | Remote auth |
| 8080/8443 | HTTP alt | Admin panels |
