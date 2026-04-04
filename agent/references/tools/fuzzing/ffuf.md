# ffuf

**Purpose:** Web fuzzing (directories, parameters, vhosts)
For live engagement targets, use `ffuf` through the Kali MCP command-execution tool.

## Directory Fuzzing

**Basic:** `ffuf -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
**With extensions:** `ffuf -u https://target/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak`
**Recursive:** `ffuf -u https://target/FUZZ -w wordlist.txt -recursion -recursion-depth 2`
**Auto-calibrate (reduce noise):** `ffuf -u https://target/FUZZ -w wordlist.txt -ac`

## Parameter Fuzzing

**Parameter name discovery:** `ffuf -u https://target/page?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`
**Parameter value fuzzing:** `ffuf -u https://target/page?id=FUZZ -w values.txt`
**POST body fuzzing:** `ffuf -u https://target/api -X POST -d '{"id":"FUZZ"}' -H "Content-Type: application/json" -w values.txt`
**Multi-keyword (clusterbomb):** `ffuf -u https://target/FUZZ1/FUZZ2 -w dirs.txt:FUZZ1 -w files.txt:FUZZ2 -mode clusterbomb`

## Vhost / Subdomain

**Vhost fuzzing:** `ffuf -u https://target -H "Host: FUZZ.target.example" -w subdomains.txt`

## Filters & Matchers

**Filter by status code:** `-fc 404,403,500`
**Filter by response size:** `-fs 1234`
**Filter by word count:** `-fw 42`
**Filter by line count:** `-fl 10`
**Filter by regex:** `-fr "not found"`
**Match by status code:** `-mc 200,301,302`
**Match by regex:** `-mr "admin|password|token"`
**Auto-calibrate:** `-ac` (auto-detects and filters default responses)

## Auth & Headers

**Cookie:** `-b "session=abc123"`
**Custom header:** `-H "Authorization: Bearer token123"`
**Multiple headers:** `-H "Cookie: x=1" -H "X-Custom: value"`

## Rate Limiting & Tuning

**Threads:** `-t 40` (default)
**Delay between requests:** `-p 0.1` (seconds)
**Rate limit:** `-rate 100` (requests/second)
**Timeout:** `-timeout 10`
**TLS skip verification:** (not built-in; use target without cert check or proxy through a tool that skips)

## Output

**JSON output:** `-o results.json -of json`
**CSV output:** `-o results.csv -of csv`
**Replay matches through Burp:** `-replay-proxy http://127.0.0.1:8080`
**Ignore wordlist comments:** `-ic`

## Wordlist Escalation (Kali Paths)

```
L1 (fast):  /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
L2 (medium): /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
L3 (deep):  /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
Params:     /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
Subdomains: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
