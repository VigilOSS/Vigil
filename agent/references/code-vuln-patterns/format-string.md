---
description: Indirect format control, multi-source format construction, callback chains
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Format String Vulnerabilities — Indirect Format Control

User data reaches the format argument through indirection: built across functions, passed through a
logging wrapper, or assembled from several sources, so no single call site shows it.

## What You're Hunting (LLM-Advantage Patterns)

1. **Format built across functions.** A builds a template from config (`"%s: %%s"` with a prefix),
   B fills it, C prints it. A config or environment prefix containing specifiers is taint SAST does
   not model.
2. **Logging wrappers that re-format.** The decisive idiom:
   ```c
   void log_error(const char *module, const char *msg) {
       char buf[1024];
       snprintf(buf, sizeof buf, "[%s] %s", module, msg);
       syslog(LOG_ERR, buf);   /* buf is now the format */
   }
   ```
   Call sites (`log_error("http", response_header)`) look safe, and the wrapper often lives in
   another compilation unit.
3. **Printf-shaped callbacks.** Library code embeds a detail string (filename, URL, protocol
   response) into a buffer and passes it as `fmt` to a registered variadic error or log callback.
4. **Localized format strings.** `gettext()`/`.mo`/resource-database strings are formats; whoever
   can write the locale directory, override config, or ship a translation controls them.

## C/C++ Specifics

- Sinks: `printf`, `fprintf`, `sprintf`, `snprintf`, the `v*` variants, `syslog`, `vsyslog`, `err`,
  `errx`, `warn`, `warnx`, and any function forwarding a `va_list` to them.
- Project formatters: git `strbuf_addf`, cURL `Curl_infof`/`Curl_failf`. Without
  `__attribute__((format(printf, ...)))` the compiler does not check their call sites.
- `-Wformat-security` only covers functions with the `format` attribute and literal-vs-non-literal
  format arguments; wrappers without the attribute, calls through function pointers, and formats
  loaded from files, environment, or gettext are invisible to it.

## Python Specifics

- `str.format` with a user-controlled template cannot call methods, but attribute and index
  traversal reaches secrets: `{0.__init__.__globals__[SECRET_KEY]}`. Impact is information
  disclosure, not code execution; `format_map` with a rich object is the same sink.
- `logging`: a message with no args is never %-interpolated (`LogRecord.getMessage` formats only
  when `args` is set). The real footguns are user text as the message *with* args, and a
  user-controlled `Formatter` format string.
- f-string plus `eval` is code injection; see `injection.md`.

## JavaScript Specifics

`util.format(userInput, ...rest)` and `console.log` treat `%s %d %j %o` in the first argument as
specifiers that consume the following arguments: no memory impact, but they can reshape or expose
other logged values. User-controlled template source in EJS, Pug, or Handlebars is SSTI; see
`web-app-injection.md`.

## Detection Questions

- Which variadic or format-taking functions lack `__attribute__((format(...)))`?
- Which callback APIs have a printf-like signature, and what reaches their format argument?

## Real CVE Examples

- **CVE-2012-0809 (sudo `sudo_debug`).** The program name, `argv[0]` (set by the caller directly or
  via a symlink), became part of the format passed to `fprintf()`; the taint enters at process
  start and reaches a printf call in another function, so no review of the `fprintf()` call site
  shows it. Yields root without a sudoers entry. sudo 1.8.0-1.8.3p1, fixed in 1.8.3p2.
- **CVE-2012-3569 (VMware OVF Tool).** Content from a crafted OVF file reached a printf-family
  format argument, giving code execution when a user opened the file — file-format parsers are
  format-string sources too.
