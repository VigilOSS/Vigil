# IDOR/BOLA Identifier Prediction & Harvesting

> Skill: `idor-testing`

When the object ID isn't a bare incrementing integer, you have two routes to a foreign object. **PREDICT** it when the scheme has exploitable entropy or ordering (time-ordered IDs, ObjectId counters, UUIDv1 MAC+timestamp), or **HARVEST** it when the ID is opaque/random but observable somewhere else (list responses, JWT claims, exports, side-channels). This reference is the deeper companion to `vigil assess classify-payload <value> --mutations`: that tool types a captured value and emits neighbor/boundary/escalation/format/empty variants, but it does not structurally decompose time-ordered ID schemes — that decomposition, plus the harvesting playbook, lives here.

## Identifier-scheme prediction table

| ID scheme | Structure | What's predictable | How to enumerate |
|---|---|---|---|
| **Auto-increment / sequence** | Integer. | Everything — value, neighbors, range. | ±1 sweep / `vigil assess classify-payload <id> neighbor`. |
| **MongoDB ObjectId** (24 hex) | 4B unix-seconds timestamp · 3B machine · 2B PID · 3B counter. | Timestamp (exact second); machine+PID constant per running instance; counter increments system-wide. | Decode timestamp+machine+PID from one observed ObjectId, brute the 3-byte counter around a seed value (`mongo-objectid-predict` → ~1000 probable IDs). Noisy on high-traffic instances (counter advances fast between requests). |
| **UUIDv1 / v6** | 60-bit Gregorian 100-ns timestamp + 14-bit clock-seq + 48-bit node (MAC). | Timestamp precise; node = server MAC (often constant / leaked); clock-seq constant per host. | Pin MAC+clock-seq from one observed UUID, sweep timestamp ticks across the known creation window. v6 reorders the timestamp to be sortable but leaks identically. **Sandwich attack:** request a token, capture the victim's, request another → bracket the victim between two attacker-generated tokens, generate every candidate in the time window, `ffuf` the reset/confirm endpoint. |
| **UUIDv7** | 48-bit unix-ms timestamp + 74 random bits. | The ms timestamp (creation time, sortable). | Random tail blocks naive ±1, but creation-time + ordering enable window-bounded guessing; weak/seeded PRNG tails are bruteable. Increasingly the default for chat THREAD IDs. |
| **ULID** | 48-bit unix-ms timestamp (10 Crockford-base32 chars) + 80 random. | Timestamp. | Time window narrows the search. In MONOTONIC mode the random part increments within the same ms → same-ms neighbors are ±1 (treat like a sequence inside one ms). |
| **Snowflake** (Twitter / Discord / Instagram) | 41-bit ms timestamp (custom epoch — Twitter `2010-11-04`, Discord `2015-01-01`) + 10-bit machine + 12-bit sequence. | Timestamp (once you have the epoch); machine constant; sequence increments per ms. | Decode timestamp; for a target time brute the 12-bit sequence (0–4095) × known machine IDs. Discord IDs are publicly decodable. |
| **KSUID** | 32-bit second timestamp (epoch `2014-05-13`) + 128 random. | Second-precision timestamp → ordering. | Timestamp gives ordering + a time window that narrows the search; the 128 random bits otherwise resist ±1. |
| **Stripe-style prefixed** (`cus_…`, `pi_…`) | Human prefix + random body (often NanoID / base62). | The prefix reveals the OBJECT TYPE (targeted fuzzing) and sometimes length/charset. | Use the prefix to scope which endpoints/fuzz space to hit; body predictability depends on its entropy (see NanoID). |
| **NanoID** | Configurable alphabet × length, CSPRNG. | Nothing if defaults. | Entropy COLLAPSES with a too-small or duplicate-char alphabet (RUSTSEC-2024-0343). Check the alphabet and length; short length / weak alphabet → feasible enumeration. |
| **Hash-as-ID** (MD5/SHA of a guessable value) | Digest of some seed. | The seed, if guessable. | If the ID is `md5(sequential_int)` / `md5(email)` / `md5(timestamp)`, recompute it for other users; or crack via rainbow tables / hashcat. **Hashing is not authorization.** |

**General rule (2025–2026):** any k-sortable / time-ordered scheme — UUIDv7, ULID, Snowflake, KSUID, ObjectId — leaks creation time and supports **window-bounded enumeration** even when the random portion blocks ±1. Only full-entropy random IDs (UUIDv4, a properly-configured NanoID) resist prediction — and even then access control is still required: **secrecy ≠ authorization**, so always re-test the harvested/known ID for a missing object-level check.

## UUID version fingerprinting

The version is the **13th hex character** (the 1st nibble of the 3rd dash-group): `xxxxxxxx-xxxx-Vxxx-yxxx-xxxxxxxxxxxx`.

- **V=1 / V=6** → predictable (timestamp + MAC). Go to the sandwich / timestamp-bracket attack.
- **V=4** → random. Switch to HARVEST.
- **V=7** → time-ordered. Window-bounded enumeration.

```bash
# Extract the version nibble from a captured UUID
echo "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" | cut -c15   # -> 7
```

## Harvesting opaque / unguessable IDs

When prediction fails (UUIDv4, well-configured NanoID), the ID is rarely secret in practice — observe it elsewhere:

1. **Cross-endpoint over-sharing** — list / search / `/me` / dashboard responses leak other users' IDs. The most common chain primitive: harvest an ID here, then replay it against the unprotected object endpoint.
2. **Bulk / aggregate query echo** — GraphQL list queries, or a Salesforce Aura bulk record query returning thousands of `ContentDocument` IDs, hand you the ID space wholesale.
3. **Export / report metadata** — CSV/PDF headers and metadata leak foreign IDs even when the row data is correctly scoped.
4. **GraphQL global-ID decode** — base64-decode `gid://...` / Relay node IDs to recover the underlying type + numeric/UUID identifier.
5. **JWT payload claims** — `sub` / `user_id` / `org_id` in the (base64, unsigned-readable) payload reveal your own and sometimes adjacent identifiers.
6. **Public / shared artifacts** — shareable links, public profiles, invite links, embedded form UUIDs; plus Wayback / CommonCrawl / URLScan, bundled JS, and source maps.
7. **Autocomplete / mention / typeahead / recipient-picker APIs** — these resolve names to internal IDs by design.
8. **Activation / bulk-action endpoints (ID oracle)** — feed a candidate ID and the endpoint echoes object metadata, confirming existence and leaking attributes.
9. **Error-message / injection leakage** — verbose errors, stack traces, and injection sinks spill IDs of objects you can't see directly.
10. **Notification side-channel** — a write (comment, share, assign) that triggers a victim notification confirms the target ID exists and is valid.
11. **404-vs-403 / Content-Length / timing oracle** — distinguishes valid foreign IDs from random ones even without response bodies. Sort Burp Intruder / `vigil assess anomaly-score` results by length/status to surface the valid-but-forbidden bucket.

## Enumeration & ranking recipe

1. **Build a candidate set** — either `classify-payload` variants for typed values, or a scheme-specific generator (ObjectId counter sweep, Snowflake sequence brute, UUIDv1 timestamp window):
   ```bash
   vigil assess classify-payload <id> --mutations --json \
     | jq -r '.intents | to_entries[].value[]' | sort -u > /tmp/values.txt
   ```
2. **Sweep** via `vigil assess kali` (httpx / ffuf / curl), capturing one `{url,status,content_length,title}` record per candidate ID into JSONL:
   ```bash
   ffuf -u "https://TARGET/api/objects/FUZZ" -w /tmp/values.txt -o /tmp/sweep.json -of json
   jq -c '.results[] | {url, status, content_length: .length, title}' /tmp/sweep.json > /tmp/sweep.jsonl
   ```
3. **Rank** to surface the leak — a 200 among 403s, or a distinct (larger) body bucket:
   ```bash
   vigil assess anomaly-score /tmp/sweep.jsonl --top 10
   ```

Notes: respect rate-limit / audit-logging exposure — window-bounded schemes still mean hundreds-to-thousands of probes; throttle and prefer the smallest candidate set the structure allows. GraphQL aliasing/batching (see the modern-architectures reference) can enumerate at scale within a single request, sidestepping per-request rate limits.

## Related

- `agent/skills/idor-testing/SKILL.md` (parent skill)
- `agent/references/access-control/idor-modern-architectures.md` (sibling)
- `agent/skills/parameter-fuzzing/SKILL.md`
- `agent/skills/user-enumeration/SKILL.md`
- `agent/references/api-security/API01-broken-object-level-authz.md`
