# References Index

On-demand reference library. Read specific files when needed — do NOT load everything at once.

## How to Use

1. Check this index to find the relevant reference file
2. Use the listed path under `references/` to load only the specific file you need
3. Example: testing for SQL injection? Read `references/payloads/sqli-payloads.md`

---

## api-security/ — OWASP API Security Top 10:2023

API-specific testing checklists. Used by: vulnerability-analyst, exploit-developer.

| File | Category |
|------|----------|
| `api-security/API01-broken-object-level-authz.md` | IDOR on API endpoints |
| `api-security/API02-broken-authentication.md` | Missing auth, token validation flaws |
| `api-security/API03-broken-property-authz.md` | Excessive data exposure, mass assignment |
| `api-security/API04-resource-consumption.md` | Rate limiting, oversized payloads |
| `api-security/API05-broken-function-authz.md` | Admin endpoint access with user tokens |
| `api-security/API06-business-flow-abuse.md` | Missing bot detection on critical flows |
| `api-security/API07-ssrf.md` | SSRF via URL parameters, webhooks |
| `api-security/API08-security-misconfiguration.md` | CORS, debug endpoints, verbose errors |
| `api-security/API09-improper-inventory.md` | Undocumented endpoints, deprecated versions |
| `api-security/API10-unsafe-consumption.md` | SSRF via third-party integrations |

## offensive-tactics/ — Red Team TTPs (from ired.team)

Attack techniques organized by kill chain phase. Used by: operator, exploit-developer, vulnerability-analyst.

### offensive-tactics/initial-access/

| File | Techniques |
|------|-----------|
| `offensive-tactics/initial-access/phishing-macros.md` | VBA macros, DDE, XLM 4.0, remote .dotm template injection |
| `offensive-tactics/initial-access/phishing-vectors.md` | OLE+LNK, HTML forms, SLK files, embedded IE |
| `offensive-tactics/initial-access/credential-harvesting.md` | NetNTLMv2 stealing, OWA spraying, forced auth (.SCF/.URL) |

### offensive-tactics/credential-access/

| File | Techniques |
|------|-----------|
| `offensive-tactics/credential-access/lsass-dumping.md` | mimikatz, procdump, comsvcs.dll, MiniDumpWriteDump |
| `offensive-tactics/credential-access/sam-ntds-dumping.md` | SAM registry dump, NTDS.dit via vssadmin, secretsdump |
| `offensive-tactics/credential-access/credential-theft-misc.md` | LSA secrets, WDigest, DPAPI, registry creds, password filter DLL |

### offensive-tactics/lateral-movement/

| File | Techniques |
|------|-----------|
| `offensive-tactics/lateral-movement/smb-wmi-lateral.md` | PsExec, WMI, WinRM, DCOM, SMB relay |
| `offensive-tactics/lateral-movement/rdp-lateral.md` | RDP hijacking (tscon), SharpRDP headless |
| `offensive-tactics/lateral-movement/tunneling-relaying.md` | SSH tunneling, netcat relay, NTLM relay, port forwarding |

### offensive-tactics/ (shell handling & tunneling)

| File | Techniques |
|------|-----------|
| `offensive-tactics/shell-handling.md` | pwncat-vl listeners, tmux session management, reverse shell payloads, log tailing for LLM visibility |
| `offensive-tactics/frp-tunneling.md` | frp SSH tunnel setup (HTTP + TCP modes), interactsh OOB callback servers, tunnel logging, standard engagement tunnels (reverse shell, OOB DNS/HTTPS/HTTP) |

### offensive-tactics/persistence/

| File | Techniques |
|------|-----------|
| `offensive-tactics/persistence/service-persistence.md` | Service DLL, schtasks, BITS jobs |
| `offensive-tactics/persistence/hijacking-persistence.md` | DLL proxying, COM hijacking, .lnk modification |
| `offensive-tactics/persistence/other-persistence.md` | Sticky keys, IFEO, WMI subscriptions, PS profile, Office templates |

### offensive-tactics/privilege-escalation/

| File | Techniques |
|------|-----------|
| `offensive-tactics/privilege-escalation/privesc-windows.md` | DLL hijacking, unquoted paths, weak services, token manipulation, named pipes |

### offensive-tactics/defense-evasion/

| File | Techniques |
|------|-----------|
| `offensive-tactics/defense-evasion/av-edr-bypass.md` | API unhooking, direct syscalls, AV bypass, UPX packing |
| `offensive-tactics/defense-evasion/evasion-techniques.md` | PPID spoofing, timestomping, ADS, Sysmon unloading, PS obfuscation |

### offensive-tactics/code-execution/

| File | Techniques |
|------|-----------|
| `offensive-tactics/code-execution/lolbins-execution.md` | MSBuild, regsvr32, mshta, cmstp, installutil, forfiles |
| `offensive-tactics/code-execution/powershell-bypass.md` | CLM bypass, PowerShdll, AMSI bypass, download cradles |

### offensive-tactics/red-team-infra/

| File | Techniques |
|------|-----------|
| `offensive-tactics/red-team-infra/c2-frameworks.md` | Cobalt Strike, PowerShell Empire, redirectors |
| `offensive-tactics/red-team-infra/infra-setup.md` | Terraform, GoPhish, Modlishka reverse proxy, SMTP |

## active-directory/ — AD & Kerberos Attacks (from ired.team)

Active Directory attack techniques. Used by: exploit-developer, operator.

| File | Techniques |
|------|-----------|
| `active-directory/kerberos-attacks.md` | Kerberoasting, AS-REP roasting, Golden/Silver Tickets, delegation abuse, RBCD, detection via Event ID 4769, hashcat modes |
| `active-directory/ad-enumeration.md` | BloodHound, PowerView, AD module, ACL/ACE abuse |
| `active-directory/ad-persistence.md` | DCSync, DCShadow, AdminSDHolder, shadow credentials, trust abuse, DCSync detection via replication GUIDs |
| `active-directory/adcs-attacks.md` | Certificate template abuse (ESC1), PetitPotam + NTLM relay, Certify/Certipy |
| `active-directory/ad-detection.md` | AD attack detection: Pass-the-Ticket, Pass-the-Hash, Golden Ticket, Kerberoasting, DCSync — Event IDs, Splunk queries, Sigma rules |

## payloads/ — Attack Payload Library (from PayloadsAllTheThings)

Copy-pasteable payloads organized by attack type. Used by: exploit-developer, vulnerability-analyst, fuzzer.

| File | Category |
|------|----------|
| `payloads/sqli-payloads.md` | UNION, blind, error-based, time-based, WAF bypass, auth bypass per DB type |
| `payloads/nosql-injection-payloads.md` | MongoDB operators ($gt, $ne, $regex, $where), auth bypass, blind extraction |
| `payloads/xss-payloads.md` | DOM XSS, reflected, stored, filter bypass, CSP bypass, polyglots |
| `payloads/ssti-payloads.md` | Per-engine detection and RCE (Jinja2, Twig, Pug, Freemarker, ERB, etc.) |
| `payloads/command-injection-payloads.md` | Blind detection, filter bypass, Linux/Windows, argument injection |
| `payloads/xxe-payloads.md` | File read, OOB/blind XXE, DoS, context-specific (SOAP, SVG, DOCX) |
| `payloads/ssrf-payloads.md` | URL schemas, IP bypass, cloud metadata (AWS/GCP/Azure) |
| `payloads/jwt-payloads.md` | alg:none, key confusion (RS256→HS256), JWK/kid injection, weak secret brute-force |
| `payloads/file-inclusion-payloads.md` | Path traversal, PHP wrappers, null byte, log poisoning, interesting files |
| `payloads/directory-traversal-payloads.md` | Encoding variants, null byte, double URL encoding, OS-specific paths |
| `payloads/upload-payloads.md` | Extension bypass, Content-Type bypass, magic bytes, SVG XSS, zip slip |
| `payloads/deserialization-payloads.md` | Java (ysoserial), PHP, Python (pickle), Node.js, .NET |
| `payloads/cors-payloads.md` | Null origin, subdomain wildcard, pre-flight bypass |
| `payloads/csrf-payloads.md` | Auto-submit forms, JSON CSRF, token bypass techniques |
| `payloads/graphql-payloads.md` | Introspection, batching, field suggestion, injection in variables |
| `payloads/request-smuggling-payloads.md` | CL.TE, TE.CL, TE.TE obfuscation, HTTP/2 downgrade |
| `payloads/race-condition-payloads.md` | HTTP/2 single-packet, limit overrun, multi-endpoint race |
| `payloads/open-redirect-payloads.md` | URL parsing confusion, protocol-relative, unicode normalization |
| `payloads/business-logic-payloads.md` | Negative quantity, coupon abuse, payment bypass, mass assignment |
| `payloads/info-disclosure-probes.md` | Standard endpoints checklist (/metrics, /.env, /actuator, cloud metadata) |
| `payloads/rate-limit-bypass-payloads.md` | IP spoofing headers by CDN, path variation, account rotation, parameter pollution |
| `payloads/yara-cobalt-strike.md` | YARA rules for Cobalt Strike beacon config, default cert, shellcode stager, XOR keys |

## code-vuln-patterns/ — SAST-Surviving Vulnerability Patterns

Source code vulnerability patterns that require multi-function reasoning and semantic understanding.
Used by: code-vuln-hunter, code-variant-hunter, code-vuln-verifier, code-fuzz-engineer.

These are NOT traditional SAST patterns. They focus on bugs that survive CodeQL, Semgrep, and OSS-Fuzz —
multi-function chains, combinatorial arithmetic, state machine bugs, and incomplete patches.

| File | Focus | Languages |
|------|-------|-----------|
| `code-vuln-patterns/buffer-overflow.md` | Cross-function size propagation, incomplete bounds checks, realloc chains | C/C++, Python, JS |
| `code-vuln-patterns/integer-overflow.md` | Combinatorial arithmetic, signed/unsigned confusion across boundaries, encoding expansion | C/C++, Python, JS |
| `code-vuln-patterns/format-string.md` | Indirect format control, multi-source format construction, callback chains | C/C++, Python, JS |
| `code-vuln-patterns/use-after-free.md` | Cross-module lifetime reasoning, refcount errors, async cleanup races | C/C++, Python, JS |
| `code-vuln-patterns/injection.md` | Semantic context escaping, multi-stage sanitization failures, protocol injection | C/C++, Python, JS |
| `code-vuln-patterns/race-condition.md` | State machine bugs, async refactoring artifacts, signal handler races | C/C++, Python, JS |
| `code-vuln-patterns/crypto-misuse.md` | Subtle mode/parameter misuse, timing leaks, non-obvious randomness issues | C/C++, Python, JS |
| `code-vuln-patterns/auth-bypass.md` | Generic/C auth gaps, fallback bypasses, token validation gaps. Framework-specific → see `web-app-auth.md` | C/C++ (frameworks → web-app-auth) |
| `code-vuln-patterns/path-traversal.md` | Canonicalization bypass, archive extraction writes, symlink and separator confusion | C/C++, Python, JS |
| `code-vuln-patterns/ssrf.md` | URL parser confusion, DNS rebinding, internal metadata reachability, cross-protocol fetches | C/C++, Python, JS |
| `code-vuln-patterns/open-redirect.md` | Redirect validation bypass, OAuth redirect theft, local-vs-absolute URL confusion | Python, JS, Java, Go |
| `code-vuln-patterns/file-upload.md` | Validation/storage drift, archive smuggling, upload-to-parser and upload-to-execution chains | Python, JS, Java, Go |
| `code-vuln-patterns/xxe.md` | External entity fetches, SSRF/file-read pivots, parser configuration regressions | Python, JS, Java, Go |
| `code-vuln-patterns/deserialization.md` | Trust-boundary object materialization, type-tag abuse, post-decode gadget reachability | C/C++, Python, JS, Java |
| `code-vuln-patterns/uninitialized-memory.md` | Conditional initialization, cross-function partial init, stack/heap info leaks | C/C++, Python, JS |
| `code-vuln-patterns/type-confusion.md` | void* casts, union abuse, tagged union errors, inheritance downcasts | C/C++, Python, JS |
| `code-vuln-patterns/null-dereference.md` | Cross-function NULL propagation, optional field assumptions, race-to-NULL | C/C++, Python, JS |
| `code-vuln-patterns/algorithmic-dos.md` | Hash collision, ReDoS, parser bombs, unbounded allocation, zip bombs | C/C++, Python, JS |
| `code-vuln-patterns/error-handling.md` | Fail-open, unchecked returns, cleanup double-free, exception swallowing, resource leaks | C/C++, Python, JS |
| `code-vuln-patterns/web-app-auth.md` | Middleware ordering, decorator bypass, role check logic, path normalization, OAuth implementation flaws | C/C++, Python, JS, Java, Go |
| `code-vuln-patterns/web-app-injection.md` | ORM bypass, second-order injection, template injection, deserialization in web contexts, NoSQL injection | Python, JS, Java, Ruby |
| `code-vuln-patterns/web-app-data-exposure.md` | IDOR in ORM queries, mass assignment, serializer over-exposure, GraphQL field auth, bulk endpoints | Python, JS, Java, Ruby, Go |
| `code-vuln-patterns/ai-ml-security.md` | Prompt injection, MCP tool poisoning, RAG poisoning, unsafe tool execution, cross-user context leakage | Python, JS, Java |
| `code-vuln-patterns/fuzz-harness-patterns.md` | libFuzzer/AFL++ harness templates, sanitizer flag reference, seed corpus construction, harness antipatterns, crash triage checklist | C/C++ |

## tools/ — CLI Tool Cheatsheets

Quick-reference per tool, organized by usage phase.

### tools/recon/ — Used by: recon-specialist, operator

| File | Tool |
|------|------|
| `tools/recon/nmap.md` | Port/service discovery and enumeration |
| `tools/recon/whatweb.md` | Web technology fingerprinting |
| `tools/recon/httpx.md` | HTTP probing, tech detection, live host confirmation |
| `tools/recon/nuclei.md` | Template-based vulnerability scanning (CVEs, misconfigs, exposures) |
| `tools/recon/wafw00f.md` | WAF identification and fingerprinting |
| `tools/recon/curl.md` | HTTP request crafting and testing |
| `tools/recon/puredns.md` | Active DNS brute-force with wildcard filtering |
| `tools/recon/dnsx.md` | Bulk DNS resolution and record enumeration |
| `tools/recon/gau.md` | Historical URL discovery (Wayback, OTX, Common Crawl, URLScan) |
| `tools/recon/gf.md` | URL parameter-pattern classifier (xss, ssrf, redirect, idor, sqli, lfi, debug) with 1ndianl33t patterns |
| `tools/recon/trufflehog.md` | Secret scanner (filesystem mode, 800+ detectors, v3 positional-path syntax, `--no-verification` default) |

### tools/fuzzing/ — Used by: fuzzer, recon-specialist

| File | Tool |
|------|------|
| `tools/fuzzing/ffuf.md` | Web fuzzing (parameters, vhosts, targeted directory work) |
| `tools/fuzzing/feroxbuster.md` | Recursive content discovery (primary for directory scanning) |
| `tools/fuzzing/dirb.md` | URL brute-forcing with wordlists |
| `tools/fuzzing/gobuster.md` | Directory/file, DNS, and vhost brute-forcing |
| `tools/fuzzing/wfuzz.md` | Web fuzzer for parameters, headers, and paths |

### tools/exploitation/ — Used by: exploit-developer, vulnerability-analyst

| File | Tool |
|------|------|
| `tools/exploitation/sqlmap.md` | SQL injection detection and exploitation |
| `tools/exploitation/hydra.md` | Online password brute-forcing |
| `tools/exploitation/dalfox.md` | XSS scanning with parameter analysis and blind XSS |

### tools/proxy/ — Used by: operator

| File | Tool |
|------|------|
| `tools/proxy/mitmproxy.md` | Mitmproxy session capture: setup, CA cert install, FoxyProxy config, login capture workflow, troubleshooting |

### tools/reporting/ — Used by: report-writer, operator

| File | Tool |
|------|------|
| `tools/reporting/jira-api.md` | Jira REST API v3: authentication, issue CRUD, ADF formatting for security findings |

### tools/cracking/ — Used by: exploit-developer

| File | Tool |
|------|------|
| `tools/cracking/john.md` | Offline password hash cracking (CPU) |
| `tools/cracking/hashcat.md` | Offline password hash cracking (GPU) |

## gf-patterns/ — GF Pattern Library

Per-bucket reference files for the gf URL classifier, keyed to the buckets that
`agent/scripts/assess/commands/classify_work.py` recognizes. Used by: surface-collector,
gau-triage, operator.

Each file documents what the bucket classifies, the parameter keys and path fragments that
match, the baseline `priority_score` weight, representative examples, and false-positive
surface to keep operator calibration honest. Skills cite these files with a "Load because X"
reason before invoking a bucket.

| File | Bucket | Baseline weight | What it classifies |
|------|--------|-----------------|--------------------|
| `gf-patterns/rce.md` | `rce` | 50 | Command-exec parameters (`cmd`, `exec`) and `/exec/`, `/cmd/`, `/shell/` paths |
| `gf-patterns/ssrf.md` | `ssrf` | 45 | URL-fetch parameters (`url`, `callback`, `feed`) and `/proxy/`, `/fetch/` paths |
| `gf-patterns/sqli.md` | `sqli` | 40 | Query/identifier parameters (`id`, `q`, `sort`, `filter`) |
| `gf-patterns/lfi.md` | `lfi` | 40 | File-handling parameters (`file`, `path`, `template`, `include`) |
| `gf-patterns/idor.md` | `idor` | 35 | Object-reference parameters (`id`, `user`, `account`, `order`) |
| `gf-patterns/debug_logic.md` | `debug_logic` | 30 | Privileged paths (`/admin`, `/actuator`, `/.git`, `/.env`) |
| `gf-patterns/redirect.md` | `redirect` | 25 | Return-URL parameters (`next`, `redirect_uri`, `return`) |
| `gf-patterns/ssti.md` | `ssti` | 25 | Template-resolver parameters (`template`, `theme`, `view`) |
| `gf-patterns/xss.md` | `xss` | 20 | Reflected-input parameters (`q`, `message`, `comment`) |
| `gf-patterns/interestingparams.md` | `interestingparams` | 15 | Credential parameters (`api_key`, `token`, `password`) |
| `gf-patterns/interestingsubs.md` | conceptual | n/a | Subdomain conventions (`staging.`, `internal.`) — surfaces via subdomain-enumeration, not a direct classify-work bucket |
| `gf-patterns/interestingEXT.md` | conceptual | n/a | Backup/config extensions (`.bak`, `.env`, `.sql`) — surfaces via `path:` cluster fallback plus trufflehog body scan |

## runtime-guides/ — Shared Runtime References

Shared operator/runtime references. Used by: operator, Claude, Codex.

| File | Purpose |
|------|---------|
| `runtime-guides/engagement-methodology.md` | Engagement style, PEAK/Pyramid/MITRE mindset, escalation expectations, and optional Athena final phase |
| `runtime-guides/subagent-registry.md` | `agent-registry.json` schema and its role as the engagement audit trail; how to hand off state between dispatches by carrying prior output and durable-state pointers forward in the new dispatch prompt |
| `runtime-guides/command-history-auditing.md` | How to read `assess.py list-command-runs` as a coverage map — use it to pick variants that haven't been probed, not to gate-keep reruns; includes field-interpretation guide for retention/suppression |
| `handoff-protocols.md` | Agent-to-agent handoff rules and expected downstream actions |
| `subdomain-enumeration.md` | Subdomain enumeration (when `*.domain` in hosts), prioritization, and sliding-window execution rules |

## reporting/ — Disclosure & Reporting Formats

| File | Purpose |
|------|---------|
| `disclosure-email-format.md` | Email disclosure format for vendor security teams: structure, rules, anti-patterns |
| `bugbounty-submission-format.md` | Bug bounty submission format for Bugcrowd/HackerOne: per-finding submissions with POC, VRT, evidence |
| `examples/disclosure-email-fast-import.txt` | Example: multi-sub-issue disclosure with control test and CI/CD framing |
| `examples/bugbounty-submission-ldap-injection.md` | Example: LDAP injection bug bounty submission with working POC |
