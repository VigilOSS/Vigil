---
description: Semantic context escaping, multi-stage sanitization failures, protocol injection
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS, Java
---

# Injection — Semantic Context Escaping

The question is whether data was escaped for the context that finally consumes it, not whether user
data reaches a sink. ORM escape hatches, NoSQL operators, SSTI, and web deserialization sinks live
in `web-app-injection.md`.

## What You're Hunting (LLM-Advantage Patterns)

### 1. Escaping for the wrong context

Each stage is correct and the composition is not: URL-encode applied after HTML-escape leaves a
literal `&amp;` after the consumer decodes; HTML-escaped data dropped into a JavaScript string
literal; SQL string escaping inside a `LIKE` pattern, where `%` and `_` stay live. Identify the
consuming context first, then the nearest escaper.

### 2. Protocol injection

User data in a protocol field without its control characters stripped: CR/LF in HTTP header values
built with `"%s: %s\r\n"` (validate the value, not just the name), SMTP `MAIL FROM:` or `RCPT TO:`
addresses carrying `\r\nDATA\r\n`, FTP URL paths whose `%0d%0a` decodes into control-channel
commands, NUL bytes in DNS names. Each protocol has its own control set; check every boundary the
data crosses.

### 3. Shell commands assembled across functions

```c
void add_arg(strbuf *cmd, const char *arg) {
    strbuf_addf(cmd, " %s", shell_escape(arg));   /* escapes ' and \ only */
}
/* later: system(cmd->buf); */
```

The escaper handles quotes but not `$(...)`, backticks, `;`, or newlines; or it targets `sh` while
the command runs under `bash`. `snprintf(cmd, ..., "git clone '%s'", url)` is broken by a URL
containing `'`. Enumerate the full metacharacter set — ``; | & $ ` ( ) { } < > \n \r ! # ~ * ? [ ]``
— against what the escaper actually handles.

### 4. Second-order injection

Stored safely, re-used unsafely: a username stored with correct SQL escaping is later concatenated
into an admin-panel query, or a value written to `.gitconfig` is trusted on read and expanded by a
hook's shell command. The database launders the taint for input-to-sink trackers. A value truncated
or split by a fixed-size read on the way back in (git's CVE-2023-29007 split an over-long
`.gitmodules` URL into an injected config line) is the same shape.

### 5. XPath injection

`xpath.compile("//user[username/text()='" + username + "' ...]")` (Java `javax.xml.xpath`),
`tree.xpath(f"//account[@id='{account_id}']")` (Python lxml), and .NET `XPathExpression` built from
strings: `' or '1'='1` returns every node. SQL-tuned SAST rarely treats these as sinks; the fix is
variable binding (`XPathVariableResolver`, lxml `$var` arguments).

### 6. Server-Side Includes

Tainted text written into a file the web server parses for SSI (`.shtml`, `.shtm`, `.stm`, or any
path with `mod_include`): `<!--#exec cmd="id" -->`, `<!--#include virtual="/etc/passwd" -->`. An
app that appends comments to `comments/latest.shtml` has a sink outside its own template engine.
The sink exists only if the server config enables it for that path (Apache `Options +Includes`,
`AddHandler server-parsed .shtml`), so check config and code together.

### 7. CSV / formula injection

Export paths (`csv.writer`, `openpyxl`, `xlsxwriter`, ExcelJS) writing user fields that begin with
`=`, `+`, `-`, `@`, tab, or CR become live formulas (`=HYPERLINK(...)` exfiltration, DDE depending
on the application). HTML or SQL escaping does nothing here; neutralize with a leading `'` or space.

## C/C++ Specifics

`system()` and `popen()` run `/bin/sh -c`. `execvp()`/`execlp()` resolve a user-influenced program
name through `PATH`, and arguments built from user data allow option injection. Even `execve()` is
exposed when the environment (`LD_PRELOAD`, `PATH`, `IFS` for scripts) is attacker-controlled.

## Python Specifics

- `subprocess` with `shell=True` and an f-string; the list form without a shell is the fix.
  `shlex.quote()` is sound for POSIX `sh` but not for Windows `cmd`, or when its output is
  re-split or nested inside another quoting layer.
- `compile(user_input, '<string>', 'eval')` followed by `eval()` slips past rules that only flag
  `eval(user_input)`.
- `pickle` and YAML loaders: `web-app-injection.md` §4.

## JavaScript Specifics

- `new Function(str)`, and the string forms of `setTimeout`/`setInterval`, execute code and are often
  missed next to `eval`.
- `child_process.exec(`git log --author="${input.replace(/"/g, '\\"')}"`)`: quote replacement does
  not stop `$(...)` or backticks; `execFile`/`spawn` with an argv array and a `--` separator does.
- Prototype pollution to code execution: pollution in one library (`lodash.merge`, `deep-extend`)
  sets `Object.prototype.shell` or `Object.prototype.env = {NODE_OPTIONS: '--require=...'}`, and
  `child_process.spawn` or a template engine (handlebars, pug) in another library picks up the
  defaults.

## Real CVE Examples

- **CVE-2023-27533 (cURL TELNET).** Options set through the URL reached TELNET negotiation with
  sanitization fit for the URL context only, letting control bytes inject TELNET commands.
- **CVE-2021-21300 (git delayed checkout).** On case-insensitive filesystems, a crafted repository
  combining a symlink with a case-colliding path, checked out through a delayed-checkout filter
  (Git LFS), wrote a file into `.git/hooks` that then ran: a path collision turned into command
  execution on `git clone`.
