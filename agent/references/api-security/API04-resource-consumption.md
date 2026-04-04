# API4:2023 — Unrestricted Resource Consumption

> Skill: `business-logic-testing`

## Rate Limiting on Auth Endpoints
- [ ] Brute-force login endpoint — 100+ requests: `for i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}" -X POST -d '{"user":"admin","pass":"'$i'"}' https://api/auth/login; done`
- [ ] Test OTP verification without rate limiting: brute-force 4-6 digit codes
- [ ] Check if rate limits are per-IP only — bypass with `X-Forwarded-For` rotation
- [ ] Test rate limit reset: does waiting 60 seconds reset the counter?

## GraphQL Query Complexity Abuse
- [ ] Send deeply nested queries (10+ levels) to test depth limiting:
  ```
  query { users { friends { friends { friends { friends { name } } } } } }
  ```
- [ ] Test query complexity: request many fields and relations in a single query
- [ ] Send batch queries: `[{query1}, {query2}, ..., {query100}]` in a single request
- [ ] Test alias-based amplification: `{ a1: users { name } a2: users { name } ... a100: users { name } }`
- [ ] Check for introspection query cost — `__schema` queries can be expensive

## Pagination Bypass
- [ ] Test oversized page: `?page_size=999999` or `?limit=99999999`
- [ ] Test offset-based exhaustion: `?offset=0&limit=1000000`
- [ ] Test cursor-based pagination bypass: manipulate cursor values
- [ ] Check if API returns total count without pagination — `?count_only=true` with no limit

## Large Payload DoS
- [ ] Send oversized JSON body (10MB+): is there a request size limit?
- [ ] Send deeply nested JSON (100+ levels): does parsing time increase?
- [ ] Upload oversized files through API: test file size limits on upload endpoints
- [ ] Send very long string values in fields: 100K+ character strings

## Regex DoS (ReDoS)
- [ ] Test user input processed by regex: send strings known to cause catastrophic backtracking
- [ ] Example payload for email validation: `aaaaaaaaaaaaaaaaaaaaaaaa!`
- [ ] Test in search parameters, validation fields, pattern-matching endpoints

## Batch Operation Abuse
- [ ] Test bulk endpoints with excessive item counts: `POST /api/bulk {"items": [1..10000]}`
- [ ] Test batch email/SMS triggers: `/api/notify {"recipients": [1000 emails]}`
- [ ] Check if batch endpoints have separate rate limits from single-item endpoints

## Timeout & Long-Running Operations
- [ ] Test for missing timeouts on export/report generation endpoints
- [ ] Submit complex search queries that could trigger slow database operations
- [ ] Test file processing endpoints with crafted slow-to-process files (zip bombs, large PDFs)

---
> Cross-reference: A06 checklist, `business-logic-testing` skill
