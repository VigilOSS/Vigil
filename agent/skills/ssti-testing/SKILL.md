---
name: ssti-testing
description: Detect and exploit server-side template injection for code execution
origin: Vigil
vuln_class: ssti
---

# Server-Side Template Injection (SSTI) Testing

## When to Activate

- Input renders through a server-side template (pages, emails, PDFs, SMS, report templates,
  error pages), reflected input behaves like a template, or an error names an engine.

`--technique SSTI`; deliver via `vigil assess kali exec --technique SSTI --intent "<purpose>"
--probe-kind payload --phase consume-test --timeout 30 -- curl …`. The universal probe, the
error fingerprint, and per-engine sandbox escapes and RCE gadgets (Jinja2, Twig,
Freemarker, Pebble, Thymeleaf, ERB, Smarty, Mako, Velocity, Pug, Handlebars, EL/OGNL):
`agent/references/payloads/ssti-payloads.md`.

## Method

1. **Evaluate:** `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`, `@(7*7)` — 49 vs literal.
   A `#set`, `<%`, `{%`, `${…}` or `#{…}` token that changes the output's shape (not just its
   content) is partial parsing: push engine gadgets even without arithmetic.
2. **Fingerprint by differential** before choosing a payload: `{{7*'7'}}` is `7777777` in Jinja2,
   `49` in Twig, an error in Freemarker.
3. **Escalate through the engine's sandbox-escape chain** (`__class__.__mro__`/`__globals__` for
   Jinja2, `_self.env.registerUndefinedFilterCallback("exec")` then `getFilter` for Twig 1.x,
   `freemarker.template.utility.Execute`); run only a benign command (`id`, `hostname`).
4. **Blind** (PDF, email, background job): time-based, error-based, or OOB per
   `agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure (mint→poll→correlate)".
   The gadget must put an evaluated value in the callback (`$(hostname).$OOB_HOST`, or the
   arithmetic result as a label): mail and link scanners fetch literal URLs in rendered emails, so
   a bare-host hit does not show the template ran. An empty `matched` with healthy OOB is a target
   result; fall back to timing and errors.
5. **Client-side templates** (AngularJS 1.x, Vue 2, Handlebars in the browser) reflecting input in
   template scope escalate to XSS even when SSTI fails (`{{constructor.constructor('alert(1)')()}}`;
   `agent/skills/xss-testing/SKILL.md`).

## What to Record

Parameter and endpoint, engine and version, the proof payload and its output, whether a sandbox
was present and bypassed, and RCE evidence. Severity:
`agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`. Evaluation inside a sandbox that held
is still a finding at the information-disclosure level, with the remaining escape research as the
next test.

## Kill Signals

- Every probe variant renders literally across every parameter and render surface → no template
  injection; record the negative with its run ids (`agent/rules/hunting.md` §13).
- RCE on one parameter → check the other render surfaces fed by the same template
  (`agent/rules/hunting.md` §6).
