---
description: Indirect format control, multi-source format construction, callback chains
skill: code-vulnerability-analysis
languages: C/C++, Python, JS
---

# Format String Vulnerabilities — Indirect Format Control

> Target: Format string bugs that survive SAST because the user-controlled data does not
> directly appear as the format argument. Instead, it reaches the format argument through
> indirection — constructed across functions, passed through logging wrappers, or assembled
> from multiple sources.

---

## Baseline Patterns (Single-Function / Single-Scope)

Toolchain-catchable patterns. Record as findings if encountered during orientation —
on unaudited codebases these are real, exploitable bugs that no prior tool run has caught.
Invest primary analysis time in the LLM-advantage patterns below.

- `printf(user_input)` — direct user data as format string
- `fprintf(fp, user_buf)` — same pattern with file pointer
- `syslog(priority, user_input)` — direct syslog format control
- Any single-function case where a taint-tracked variable is the first arg to a printf-family function

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Format Strings Constructed Across Functions

Function A builds a log prefix from config, function B appends user-controlled data,
function C passes the combined string to a printf-family function. No single function
shows "user data → format argument."

```c
// Module A: builds message template from config
void build_template(char *tmpl, const char *prefix) {
    snprintf(tmpl, TMPL_SIZE, "%s: %%s", prefix);  // tmpl = "INFO: %s"
}

// Module B: builds full message — user_msg may contain %n, %x
void build_message(char *msg, const char *tmpl, const char *user_msg) {
    snprintf(msg, MSG_SIZE, tmpl, user_msg);  // fine IF tmpl is "INFO: %s"
}

// But what if prefix contains format specifiers from a config file?
// tmpl becomes "INFO %s %s: %s" — now user_msg fills the first %s,
// and remaining %s reads stack garbage
```

The vulnerability depends on what `prefix` contains — which comes from a config file
or environment variable that SAST tools don't model as tainted.

### 2. Logging Wrappers That Accept Pre-Formatted Data

Custom logging functions that look safe but pass their arguments unsafely:

```c
// Custom logger — appears safe at call sites
void log_error(const char *module, const char *msg) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "[%s] %s", module, msg);
    syslog(LOG_ERR, buf);  // BUG: buf used as format string to syslog
}

// Caller — looks fine in isolation
log_error("http", response_header);  // response_header contains %n
```

SAST sees `log_error("http", response_header)` and the function signature takes
`const char *msg` — it doesn't trace that `msg` ends up as a format argument
inside the wrapper, especially when the wrapper is in a different compilation unit.

### 3. Callback Chains With Format String Assembly

Error handling callbacks that accumulate messages:

```c
typedef void (*error_cb)(void *ctx, const char *fmt, ...);

// Registration
set_error_handler(my_handler);

// Deep in library code — constructs format string from error context
void report_error(error_cb cb, void *ctx, int code, const char *detail) {
    char fmt[256];
    snprintf(fmt, sizeof(fmt), "Error %d: %s", code, detail);
    cb(ctx, fmt);  // if cb is printf-like AND detail has format specifiers...
}
```

The `detail` string may originate from user input (e.g., a filename, URL, or
protocol response) and end up embedded in a format string passed to a variadic
callback.

### 4. Template Systems Where User Data Becomes Format

In server-side C programs or protocol handlers, error messages or response templates
may incorporate user data into a template that's later processed by a printf-like
function.

```c
// URL or path from request embedded into error template
snprintf(err_page, sizeof(err_page),
    "<h1>Not Found</h1><p>The page %s was not found.</p>",
    request_path);
// Safe: request_path is an argument, not the format.

// But the anti-pattern:
char template[1024];
snprintf(template, sizeof(template), "Error accessing %s", request_path);
syslog(LOG_WARNING, template);  // template IS the format string
```

### 5. Internationalization / Localization Format Strings

Translated message strings loaded from `.po` files, `.mo` files, or resource databases.
If an attacker can control or influence the translation files (supply-chain, config
override, writable locale directory), they control the format string.

```c
const char *msg = gettext("Connection from %s failed");
syslog(LOG_INFO, msg, client_ip);
// If gettext returns a string with extra format specifiers: RCE
```

---

## C/C++ Specific Patterns

### printf Family Coverage
`printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `vfprintf`, `vsprintf`,
`vsnprintf`, `syslog`, `vsyslog`, `err`, `errx`, `warn`, `warnx`, and any custom
function that passes a va_list to one of these.

### Custom Variadic Formatters
Many C projects implement their own printf-like functions. In git: `strbuf_addf`.
In cURL: `Curl_infof`, `Curl_failf`. These may or may not have format-checking
attributes (`__attribute__((format(printf, ...)))`). If they lack the attribute,
the compiler won't warn and SAST may not trace format arguments through them.

### gcc -Wformat-security Gaps
`-Wformat-security` only warns when a non-literal format is passed to a function
with a `format` attribute. Custom wrappers without the attribute are invisible.
Functions called through function pointers are invisible. Format strings loaded from
external sources (files, env vars, gettext) are invisible.

---

## Python Specific Patterns

### f-string + eval
```python
template = f"result = {user_input}"
eval(template)  # code injection, not format string per se, but same root cause
```

### str.format with User-Controlled Format Spec
```python
# User controls the format string, not just the values
user_template = request.args.get('template')
output = user_template.format(name=username, balance=balance)
# Attacker: "{name.__class__.__mro__[1].__subclasses__()}"
# → attribute access on arbitrary objects → information disclosure or RCE
```

This is the Python equivalent of a format string vulnerability. SAST tools look for
`eval()` and `exec()` but often miss `.format()` with user-controlled templates.

### logging Module Format String
```python
import logging
logging.info(user_controlled_message)  # user_controlled_message IS the format string
# If it contains %(something)s, the logging module tries to interpolate
# Usually causes KeyError, but if extra= dict is attacker-influenced: info leak
```

The safer pattern is `logging.info("%s", user_controlled_message)` — but many
codebases use the direct form.

---

## JavaScript Specific Patterns

### Template Literal Injection
```javascript
// If eval is used on a constructed template:
const query = `SELECT * FROM users WHERE name = '${userInput}'`;
// Not a format string bug but follows the same pattern: user data in template
```

### console.log Format Bypass
Node.js `console.log` supports `%s`, `%d`, `%j` format specifiers. While not
exploitable for memory corruption, `%j` (JSON stringify) can be used to leak
object contents if the format string is user-controlled.

### util.format Misuse
```javascript
const msg = util.format(userInput);  // userInput as format string
// %s, %d, %j consume subsequent arguments from the stack
// In Node.js this doesn't cause memory corruption but can cause
// unexpected behavior if userInput contains format specifiers
```

### Server-Side Template Injection (SSTI)
The JavaScript equivalent of format string attacks: user data flowing into template
engines (EJS, Pug, Handlebars) as template code rather than template data.
```javascript
// Anti-pattern:
const template = ejs.compile(userInput);  // user controls template
// Should be:
const template = ejs.compile('<%= data %>');
template({ data: userInput });
```

---

## Detection Questions

1. **"Does any function take a `const char *` and pass it as the format argument to a
   printf-family function?"**
   Search for functions that receive a string parameter and use it as the first argument
   to any printf-family call. Trace what the callers pass to that parameter.

2. **"Are there custom logging/error functions without `__attribute__((format(...)))`?"**
   Find all variadic functions. Check if they have format attributes. If not, they are
   SAST-invisible for format string analysis.

3. **"Can the format string be influenced by external files, configs, or translations?"**
   Trace format arguments back to their source. If they come from gettext, config files,
   template files, or database queries, an attacker may control them.

4. **"Is user data concatenated into a string that's later used as a format argument?"**
   This is the cross-function pattern. String concatenation in function A, printf in
   function B. The concatenated result becomes the format.

5. **"Are there callback-based APIs where the callback signature matches printf?"**
   Error callbacks, log callbacks, notification callbacks — if the callback is variadic
   or takes a format string, anything passed to it is a potential format string bug.

---

## Real CVE Examples

### CVE-2012-0809 (sudo — format string in sudo_debug)
The sudo utility passed the program name (argv[0]) directly as the format argument to
a printf-family function inside the `sudo_debug` logging path. An attacker could create
a symlink to the sudo binary with a name containing format specifiers (e.g., `%s%s%s`).
When executed through the symlink, the crafted name flowed from argv[0] through the
debug initialization function and into a printf call as the format string. The argv
parsing and the format-consuming debug function were in separate compilation units.

### CVE-2012-3569 (VMware OVF Tool — format string in error handler)
The VMware OVF Tool passed user-supplied OVF filenames into an error-handling function
that used the filename as a format argument to a printf-family call. The filename was
read and validated in the OVF parser module, but on parse failure, the error reporting
function in a separate module received the raw filename and used it directly as the
format string. Format specifiers embedded in the filename caused memory corruption,
enabling arbitrary code execution.

### CVE-2018-16842 (cURL — format string in warning message)
The `curl` command-line tool's warning message construction used user-supplied URL
data in a context where it was eventually passed as a format string to a vfprintf-like
function. The URL was processed through multiple transformation functions before
reaching the format-string-consuming function, so no single-function taint analysis
identified the flow.
