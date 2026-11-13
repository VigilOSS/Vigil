---
name: nosql-injection
description: Detect and exploit NoSQL injection in MongoDB, CouchDB, and Elasticsearch-backed applications
origin: Vigil
vuln_class: nosqli
---

# NoSQL Injection Testing

## When to Activate

- JSON APIs or query strings feed a document store (Mongo/Mongoose behind Express is the main
  target; CouchDB and Elasticsearch also), especially login, search, filter and bulk endpoints.

The game is operator injection through type confusion: an object arrives where the code expects
a string. If the database is unknown, start with Mongo operator probes: they confirm or rule out
quickly. Server-side JavaScript (`$where`, `$function`, `$accumulator`) still exists in MongoDB
but is deprecated in 8.0 and is off where `javascriptEnabled: false`.

`--technique NOSQLI`; deliver via `vigil assess kali exec --technique NOSQLI --intent "<purpose>"
--probe-kind payload --phase consume-test --timeout 30 -- curl …`. Operators, auth-bypass
shapes, `$regex` length/character extraction, `$where` timing, `$exists`/`$type`, WAF bypasses:
`agent/references/payloads/nosql-injection-payloads.md`. Seed variants with
`vigil assess classify-payload <value> --mutations`; rank boolean populations with
`vigil assess anomaly-score <responses.jsonl>`.

## Where the bypasses are

- **Content-type switch** (the most effective): apps that sanitise form fields often pass
  `express.json()` bodies straight to the query, so `{"password": {"$gt": ""}}` becomes a real
  operator object. Retest every parameter in both encodings.
- **`qs` brackets on `req.query`:** `?username[$ne]=&role[$ne]=`, `password[$regex]=^a&
  password[$options]=i` create operator objects even on "flat" filter parameters. `app.set('query
  parser', 'simple')` stops this for the query string only; the JSON body still parses.
- **Defence gaps:** `mongo-sanitize` covers only the object passed to it (sanitised `req.body`,
  unsanitised `req.query`) and does not stop a value passed whole to `$where`; Mongoose `strict`
  governs writes, not query filters on defined fields. Type checks (`typeof … !== 'string'`) are
  the real fix, and are often missing on search, filter and bulk endpoints even when login has
  them.
- **Prototype pollution chain:** a polluted `Object.prototype` operator key flows into later
  query objects (`agent/skills/prototype-pollution/SKILL.md`).
- **`$where` timing** blocks a Mongo query thread: short delays, sparingly, because it degrades a
  shared database.
- **CouchDB:** `/_utils/` (Fauxton), `/_all_dbs`, `/<db>/_all_docs?include_docs=true`, Mango
  `_find` selectors with `$regex`, user input in view map functions. Configuration lives at
  `/_node/<node>/_config` and 3.x has no admin party; creating an admin is a persistent change
  that needs operator approval (`agent/shared-constraints.md` §1).
- **Elasticsearch:** if `search=*` widens results or `_exists_:<field>` changes them, Lucene
  syntax is live; switch to `agent/skills/elasticsearch-injection/SKILL.md`.

## What to Record

Injection point (endpoint, parameter, the content-type variant that worked), the operator syntax
accepted, extraction rate and feasibility, version indicators, and the attacker outcome
(`agent/rules/hunting.md` §2): the session gained through the bypass and what it reaches, or the
recovered secret shown to work through the normal flow. Severity:
`agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`. Slow or rate-limited blind extraction
is still a confirmed injection: record it with the remaining extraction as the next test.

## Kill and escalate

- Type validation on every parameter (objects and arrays rejected) → move on, with the negative
  bracketed per `agent/rules/hunting.md` §13.
- A confirmed auth bypass on one route → walk every operator against every auth-surface parameter
  (password reset, 2FA verify), not stop.
- Escalate when: `{"$ne": null}` or `field[$ne]=x` differs from the literal string; always-true vs
  always-false operators change length or count; a JSON body is accepted where form data was
  expected (or the reverse); `$regex` backtracking or `$where` produces a timing delta.
