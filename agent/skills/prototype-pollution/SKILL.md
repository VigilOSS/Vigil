---
name: prototype-pollution
description: Test for JavaScript prototype pollution leading to XSS, RCE, or denial of service
origin: Vigil
vuln_class: prototype-pollution
---

# Prototype Pollution Testing

## When to Activate

- JavaScript apps (Node back-ends, SPAs) that deep-merge, clone or path-assign user-controlled
  objects: JSON bodies, nested query strings, URL hashes, config imports.

`--technique PROTOTYPE-POLLUTION`; send via `vigil assess kali exec --technique
PROTOTYPE-POLLUTION --intent "<purpose>" --probe-kind payload --phase consume-test --timeout 30 --
curl …`, and render client-side checks with `vigil assess kali browser`. Detection probes, merge
sinks, filter bypasses, and XSS/RCE/DoS gadgets (EJS, Pug, Handlebars, `child_process` via
`argv0`/`NODE_OPTIONS`): `agent/references/payloads/prototype-pollution-payloads.md`.

## Method

1. **Server-side pollution is process-wide** and lasts until restart, so it affects every user.
   Detect with a benign property whose effect shows up in later responses (Express `json spaces`
   changing indentation, a polluted `status` on an error path), via `__proto__`,
   `constructor.prototype` and nested forms. Do not probe with `isAdmin`, `shell` or similar on a
   shared target: properties that change authorization or execution, and DoS gadgets, need operator
   approval (`agent/shared-constraints.md` §1). Note the benign pollution in your handoff.
2. **Client-side:** `?__proto__[x]=y`, `?constructor[prototype][x]=y` and hash variants, then
   check `({}).x` in the rendered page; find the merge sink in the bundle (lodash, jQuery
   `extend(true)`, deep-extend and others) and look for a script gadget.
3. **Escalate through a gadget** in the code that runs after pollution: a template engine (EJS,
   Pug, Handlebars), `child_process` spawning node, an authorization check reading a default
   property, or a NoSQL query object inheriting an operator key
   (`agent/skills/nosql-injection/SKILL.md`). Framework entry points worth trying: Express
   body-parser and Koa bodyparser nesting, Fastify schema pass-through, Next.js/Nuxt API routes
   and `getServerSideProps`.

## What to Record

Vector (body, query, hash), the payload, the observable proof of pollution, the gadget and the
outcome it reaches (`agent/rules/hunting.md` §2: script execution in another user's browser, `id`
output, an authorization check flipped), the library and version, and any process-wide state left
behind. Pollution with no reachable gadget is a chain component
(`agent/references/finding-fp-and-severity-gate.md`). Format:
`agent/references/runtime-guides/web-finding-recording.md`.
