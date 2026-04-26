# wfuzz

**Purpose:** Web fuzzing with advanced filtering and payload encoding
For live engagement targets, run wfuzz via `aith assess kali exec -- wfuzz ...` with the standard audit-flag set.

## Basic Usage

**Directory fuzzing:** `wfuzz -c -w wordlist.txt https://target/FUZZ`
**POST parameter:** `wfuzz -c -w wordlist.txt -d "user=FUZZ&pass=test" https://target/login`
**Header fuzzing:** `wfuzz -c -w wordlist.txt -H "X-Custom: FUZZ" https://target/`
**Cookie:** `-b "session=abc123"`
**Auth header:** `-H "Authorization: Bearer token"`

## Multiple Payloads

FUZZ = first `-w`, FUZ2Z = second `-w`:
```
wfuzz -c -w users.txt -w passes.txt -d "user=FUZZ&pass=FUZ2Z" https://target/login
```

**Iterator modes:** `--mode zip` (parallel), `--mode chain` (sequential), `--mode product` (all combinations)

## Filters

### Hide Filters (exclude from results)
`--hc 404,403` — hide by status code
`--hw 12` — hide by word count
`--hh 1234` — hide by char count
`--hl 5` — hide by line count
`--hs "Not Found"` — hide by regex in response

### Show Filters (include only matching)
`--sc 200,301` — show by status code
`--sw 42` — show by word count
`--sh 5000` — show by char count
`--ss "admin"` — show by regex in response

## Encoders (wfuzz's differentiator)

`-z file,wordlist.txt,encoder` — apply encoding to payloads:

| Encoder | Effect |
|---------|--------|
| `urlencode` | URL-encode payload |
| `double_urlencode` | Double URL-encode |
| `base64` | Base64-encode |
| `html_escape` | HTML entity encode |
| `hexlify` | Hex-encode |
| `md5` | MD5 hash |

**Chained encoding:** `-z file,wordlist.txt,urlencode-double_urlencode`
**Example:** `wfuzz -c -z file,payloads.txt,urlencode --hc 404 https://target/page?q=FUZZ`

## Tuning

**Threads:** `-t 20`
**Delay:** `-s 0.5` (seconds between requests)
**Proxy:** `-p http://127.0.0.1:8080`
**Follow redirects:** `-L`
**Output:** `-o json` or `-f results,json`
**Recursion:** `-R 2` (depth)

## When to Use

Use wfuzz when you need payload encoding/transformation (its encoder system is unmatched).
For standard directory fuzzing, prefer ffuf (faster, simpler filters). For recursive content
discovery, prefer feroxbuster.
