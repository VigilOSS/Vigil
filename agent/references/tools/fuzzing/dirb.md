# dirb

**Purpose:** Web directory brute-forcing

For live engagement targets, prefer `ffuf` or `gobuster` first. If you
need `dirb`, run it through the Kali MCP command-execution tool with `dirb`.

**Basic:** `dirb https://target`
**Custom wordlist:** `dirb https://target /path/to/wordlist.txt`
**Explicit cookie override:** `dirb https://target -c "session=alternate-user"`
**Custom agent:** `dirb https://target -a "Mozilla/5.0"`
**Ignore specific codes:** `dirb https://target -N 403`
**Output:** `-o results.txt`
