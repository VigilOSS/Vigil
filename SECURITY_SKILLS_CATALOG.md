# Exhaustive Catalog: Public AI Security Analysis Skills, Prompt Templates & Knowledge Bases

> Compiled 2026-04-03. All items are publicly available on GitHub unless otherwise noted.

---

## TABLE OF CONTENTS

1. [Category 1: Claude Code / Codex Security Skills](#category-1-claude-code--codex-security-skills)
2. [Category 2: LLM Security Prompt Templates](#category-2-llm-security-prompt-templates)
3. [Category 3: Vulnerability Knowledge Bases for AI](#category-3-vulnerability-knowledge-bases-for-ai)
4. [Category 4: Code Security Agent Skills (Any AI Platform)](#category-4-code-security-agent-skills-any-ai-platform)
5. [Category 5: Specialized Vulnerability Class Skills](#category-5-specialized-vulnerability-class-skills)
6. [Category 6: Full Security Audit Frameworks](#category-6-full-security-audit-frameworks)
7. [Summary Matrix](#summary-matrix)

---

## CATEGORY 1: Claude Code / Codex Security Skills

### 1.1 trailofbits/skills (GOLD STANDARD)
- **URL:** https://github.com/trailofbits/skills
- **Stars:** 2400+
- **Platform:** Claude Code plugins + Codex skills
- **Vuln Classes Covered:**
  - Smart contract security: Solana (6 patterns), Algorand (11 patterns), Cairo, Cosmos/CosmWasm (IBC, EVM, state vulns), Substrate, TON
  - Timing side-channels: constant-time analysis across 11+ languages (KyberSlash, Lucky Thirteen, RSA timing)
  - CI/CD security: Agentic Actions Auditor with 9 attack vectors (env var intermediary, direct expression injection, CLI data fetch, PR target checkout, error log injection, subshell expansion, eval of AI output, dangerous sandbox configs, wildcard allowlists) covering Claude Code Action, Gemini CLI, OpenAI Codex, GitHub AI Inference
  - Static analysis: Semgrep rule creation/variant creation, CodeQL integration, SARIF parsing
  - Fuzzing: AFL++, libFuzzer, libAFL, Atheris, Ruzzy, cargo-fuzz, OSS-Fuzz harness writing
  - Supply chain: supply-chain-risk-auditor
  - Crypto: crypto-protocol-diagram, Wycheproof, zeroize-audit, mermaid-to-proverif
  - Code auditing: audit-context-building, audit-prep-assistant, differential-review, variant-analysis, code-maturity-assessor, entry-point-analyzer, sharp-edges, insecure-defaults
  - Burp Suite: project file parser
  - YARA: rule authoring
  - Other: mutation-testing, property-based-testing, coverage-analysis, fuzzing-dictionary, fuzzing-obstacles
- **Prompt/Skill Detail Level:** EXTREMELY DETAILED. Each skill has a SKILL.md (under 500 lines) plus references/ subdirectory with deep technical content. Security skills include mandatory "Rationalizations to Reject" section documenting dangerous mental shortcuts auditors must avoid.
- **Includes Payloads/References:** Yes - vulnerability pattern databases per blockchain, timing attack examples, reference exploit chains, tool-specific configuration templates.

### 1.2 utkusen/sast-skills
- **URL:** https://github.com/utkusen/sast-skills
- **Platform:** Claude Code (.claude/skills/) + Codex/Agents (.agents/skills/)
- **Vuln Classes Covered (15 skills):**
  1. `sast-analysis` - Architecture reconnaissance and mapping (Phase 0)
  2. `sast-sqli` - SQL injection (direct interpolation, f-strings, unsafe ORM, dynamic identifiers, second-order)
  3. `sast-xss` - XSS (reflected, stored, DOM-based across Jinja2, Django, EJS, Handlebars, React dangerouslySetInnerHTML, jQuery .html(), eval/setTimeout)
  4. `sast-ssrf` - SSRF (HTTP clients, webhooks, DNS lookups, file fetchers, image proxies, PDF renderers; notes IP blocklists insufficient due to DNS rebinding)
  5. `sast-idor` - IDOR (horizontal privilege escalation, ownership verification gaps)
  6. `sast-rce` - RCE (OS command injection, code injection via eval/exec, unsafe deserialization via pickle/ObjectInputStream/unserialize)
  7. `sast-ssti` - SSTI (Jinja2, EJS, Handlebars, FreeMarker, Twig, ERB, Mako, Velocity)
  8. `sast-fileupload` - File upload (extension bypass, case-sensitive validation, double-extension, MIME spoofing, path traversal via filename)
  9. `sast-graphql` - GraphQL injection (document assembly, unsafe persisted queries)
  10. `sast-businesslogic` - Business logic (12 attack categories: price manipulation, quantity limits, workflow bypass, coupon abuse, race conditions, refund abuse, reward abuse, subscription bypass, auction logic, inventory logic, time/date logic, transfer/balance logic)
  11. `sast-jwt` - JWT (alg:none, RS256-to-HS256 confusion, disabled signature verification, weak HMAC secrets, embedded JWK, JKU/X5U injection, kid injection with SQLi/path traversal, missing claim validation)
  12. `sast-missingauth` - Missing authentication & broken function-level authorization (unauthenticated endpoints, missing role checks, bypassable authorization)
  13. `sast-pathtraversal` - Path traversal (../ sequences, URL-encoded variants, ZipSlip, archive extraction)
  14. `sast-xxe` - XXE (Java DocumentBuilder/SAX/StAX, Python lxml, PHP SimpleXML/DOMDocument, .NET, Node.js libxmljs, Ruby Nokogiri)
  15. `sast-hardcodedsecrets` - Hardcoded secrets (AWS AKIA keys, Google API keys, GitHub tokens, Slack creds, Stripe keys, private crypto keys, DB connection strings) scoped to publicly accessible code paths
  16. `sast-report` - Report generation consolidating all findings
- **Prompt/Skill Detail Level:** EXTREMELY DETAILED. Each skill uses a 3-phase orchestrated approach: (1) Recon subagent finds all candidate sinks, (2) parallel batched verification subagents (3 sites per batch) perform backward taint tracing, (3) merge phase consolidates with classification (Vulnerable/Likely Vulnerable/Not Vulnerable/Needs Manual Review). Each skill includes precise safe-pattern recognition and explicit "what is NOT this vuln" boundary definitions.
- **Includes Payloads/References:** Not raw payloads but extremely detailed detection patterns, language-specific sink/source catalogs, and framework-specific safe/unsafe pattern dictionaries.

### 1.3 SunWeb3Sec/llm-sast-scanner
- **URL:** https://github.com/SunWeb3Sec/llm-sast-scanner
- **Platform:** Any AI coding agent (Claude Code, Codex, Cursor, etc.)
- **Vuln Classes Covered (34 reference files):**
  SQL injection, XSS, SSTI, NoSQL injection, GraphQL injection, XXE, RCE/command injection, expression language injection, IDOR, privilege escalation, authentication/JWT, default credentials, brute force, business logic, HTTP method tampering, verification code abuse, session fixation, weak crypto/hash, information disclosure, insecure cookies, trust boundary violations, SSRF, path traversal/LFI/RFI, insecure deserialization, arbitrary file upload, JNDI injection, race conditions, CSRF, open redirect, HTTP smuggling/desync, denial of service, CVE patterns, PHP security, mobile security (Android/iOS)
- **Prompt/Skill Detail Level:** VERY DETAILED. Main SKILL.md defines a 6-step workflow: scope clarification, selective reference loading, source-to-sink taint tracking, business logic & auth review, adversarial judge re-verification (4-checkpoint system: source reachability, sanitization effectiveness, exploitability, tag precision), and structured finding delivery. Each reference file contains detection patterns, DBMS-specific primitives, exploitation techniques, evasion bypasses, language-specific code patterns, and classification frameworks.
- **Includes Payloads/References:** YES - 34 reference files with exploitation techniques, DBMS-specific payloads (MySQL OOB via LOAD_FILE, MSSQL xp_dirtree DNS, PostgreSQL JSON operators), evasion techniques (whitespace tricks, keyword splitting, encoding), and language-specific vulnerable code patterns.

### 1.4 EresusSecurity/appsec-skills
- **URL:** https://github.com/EresusSecurity/appsec-skills
- **Platform:** Claude Code
- **Skills (5):**
  1. `eresus-sast-scanner` - Same 34 vuln classes as SunWeb3Sec (shares reference library), 6-step workflow with judge re-verification
  2. `eresus-pr-security-review` - Security-focused PR review: attack surface mapping, source-sink-guard analysis, data flow tracing, risk pattern detection, exploit verification, structured reporting
  3. `eresus-remediator` - Converts findings to production-ready patches: vulnerability path reconstruction, fix layer selection, minimal implementation, verification tests, post-fix review
  4. `eresus-serialization-review` - Serialization/deserialization security: Java ObjectInputStream, Jackson polymorphic typing, Fastjson auto-type, .NET BinaryFormatter, PHP unserialize(), Python pickle, Node.js prototype revival, session cookies, view state, message queues
  5. `eresus-threat-modeler` - Threat modeling: scope definition, actor/entry point mapping, trust boundary drawing, abuse case enumeration, scan priority mapping, actionable model output
- **Prompt/Skill Detail Level:** VERY DETAILED. Each skill follows structured multi-step workflows with explicit guardrails against weak mitigations.
- **Includes Payloads/References:** Yes - 34 reference files for SAST scanner (same as SunWeb3Sec).

### 1.5 AgentSecOps/SecOpsAgentKit
- **URL:** https://github.com/AgentSecOps/SecOpsAgentKit
- **Platform:** Claude Code
- **Skills (25+ organized by category):**
  - **AppSec:** sast-semgrep, sast-bandit, sast-horusec (18+ languages), sca-blackduck, dast-nuclei, dast-zap, dast-ffuf, api-spectral, api-mitmproxy
  - **DevSecOps:** container-grype, container-hadolint, iac-checkov (750+ built-in policies), sca-trivy, secrets-gitleaks
  - **Compliance:** policy-opa (GDPR, PCI-DSS, SOC2 Rego policies)
  - **Incident Response:** detection-sigma (MITRE ATT&CK mapped rule templates), forensics-osquery, ir-velociraptor
  - **Offensive Security:** recon-nmap, webapp-nikto, webapp-sqlmap, crack-hashcat, network-netcat, pentest-metasploit, analysis-tshark
  - **Secure SDLC:** reviewdog (CI/CD integration), sbom-syft
  - **Threat Modeling:** pytm (Python-based threat modeling)
- **Prompt/Skill Detail Level:** DETAILED. Each skill includes SKILL.md, reference guides (OWASP mappings, CWE mappings, remediation guides, false positive handling), asset templates (CI/CD configs for GitHub Actions, GitLab CI, Jenkins), and workflow checklists.
- **Includes Payloads/References:** Yes - OWASP/CWE mapping files, compliance framework mappings, MITRE ATT&CK rule templates, tool-specific configs.

### 1.6 transilienceai/communitytools
- **URL:** https://github.com/transilienceai/communitytools
- **Platform:** Claude Code (skills + agents + slash commands)
- **Skills (20+ pentest skills):**
  - `injection` - SQL, NoSQL, command, SSTI, XXE, LDAP/XPath injection testing
  - `server-side` - SSRF, HTTP smuggling, path traversal, file upload, deserialization, host header injection
  - `client-side` - XSS (reflected/stored/DOM/framework-specific), CSRF, CORS, clickjacking, prototype pollution
  - `authentication` - Auth bypass, JWT attacks, OAuth weaknesses, password attacks, 2FA evasion, CAPTCHA bypass, bot detection evasion
  - `api-security` - GraphQL, REST BOLA/IDOR/mass assignment, WebSocket hijacking, Web-LLM prompt injection
  - `ai-threat-testing` - OWASP LLM Top 10 testing across 10 dedicated agents (prompt injection, insecure output, training poisoning, resource exhaustion, supply chain, excessive agency, model extraction, vector poisoning, overreliance, logging bypass)
  - `cloud-containers`, `infrastructure`, `reconnaissance`, `osint`, `social-engineering`
  - `cve-poc-generator`, `source-code-scanning`, `web-app-logic`, `coordination`
  - `techstack-identification` (20+ sub-skills: DNS intel, HTTP fingerprinting, JS DOM analysis, TLS cert analysis, CDN/WAF fingerprinting, cloud infra detection, etc.)
  - `hackerone` - HackerOne platform integration
  - `hackthebox` - HackTheBox integration
- **Agents:** pentester-orchestrator, pentester-executor, pentester-validator, recon agents, report writer, patt-fetcher, skiller
- **Benchmarks:** xbow integration for skill evaluation
- **Prompt/Skill Detail Level:** VERY DETAILED. Each skill includes extensive reference libraries with cheat sheets, quickstart guides, bypass techniques, and exploitation resources.
- **Includes Payloads/References:** YES - comprehensive payload collections, bypass techniques, tool commands, exploitation chains for each vulnerability class.

### 1.7 shuvonsec/claude-bug-bounty
- **URL:** https://github.com/shuvonsec/claude-bug-bounty
- **Platform:** Claude Code
- **Skills (8 domains):**
  1. `web2-vuln-classes` - 20 vulnerability classes with detection patterns, bypass techniques, and real paid bounty examples (IDOR variants, broken auth, XSS, SSRF with 11 IP bypass techniques, business logic, race conditions, SQLi, OAuth/OIDC, file upload with 10 bypass techniques, GraphQL, LLM/AI features with OWASP ASI 2026, API misconfig, ATO taxonomy with 9 paths, SSTI with engine-specific payloads, subdomain takeover, cloud/infra misconfigs, HTTP request smuggling, cache poisoning, MFA/2FA bypass with 7 patterns, SAML/SSO attacks)
  2. `security-arsenal` - Payload library covering XSS (CSP bypass methods, mXSS), SSRF (cloud metadata endpoints for AWS/GCP/Azure), SQLi (union/blind/WAF evasion), XXE (OOB exfiltration), path traversal, IDOR, command injection, SSTI (engine-specific RCE chains), HTTP smuggling (CL.TE/TE.CL/TE.TE/H2.CL), WebSocket exploitation, MFA bypass, SAML attacks. Also includes explicit "never submit" and "conditionally valid" finding guidelines.
  3. `bb-methodology` - Bug bounty methodology
  4. `bug-bounty` - General bug bounty workflow
  5. `report-writing` - Report writing templates
  6. `triage-validation` - Triage and validation
  7. `web2-recon` - Web2 reconnaissance
  8. `web3-audit` - Web3 smart contract auditing
- **Agents:** autopilot, chain-builder, recon-agent, recon-ranker, report-writer, validator, web3-auditor
- **Prompt/Skill Detail Level:** EXTREMELY DETAILED. The web2-vuln-classes skill alone covers 20 vulnerability classes with specific payloads, real-world examples from HackerOne, CVSS scores, and chaining techniques.
- **Includes Payloads/References:** YES - extensive payload collections per vuln class, cloud metadata endpoints, engine-specific RCE chains, bypass techniques with encoding variations, submission guidelines with anti-patterns.

### 1.8 shuvonsec/public-skills-builder
- **URL:** https://github.com/shuvonsec/public-skills-builder
- **Platform:** Claude Code
- **Description:** Generates 18 ready-to-use Claude Code skill files from 500+ public HackerOne bug bounty reports. Reads disclosed reports and community writeups to extract real-world techniques, payloads, and bypass patterns.
- **Vuln Classes:** 18 vulnerability classes derived from actual paid bounties
- **Prompt/Skill Detail Level:** Generated from real reports; quality depends on source material.
- **Includes Payloads/References:** Yes - real-world payloads extracted from disclosed reports.

### 1.9 anthropics/claude-code-security-review (OFFICIAL)
- **URL:** https://github.com/anthropics/claude-code-security-review
- **Platform:** GitHub Action + Claude Code `/security-review` command
- **Vuln Classes:** Injection attacks, authentication flaws, data exposure, cryptographic weaknesses, XSS. Diff-aware scanning of changed files only.
- **Prompt/Skill Detail Level:** MODERATE. Configurable with custom scanning instructions. Uses semantic code understanding rather than pattern matching.
- **Includes Payloads/References:** No raw payloads. Provides finding-level comments on PRs.
- **Note:** Official Anthropic tool. "Not hardened against prompt injection attacks" per their documentation.

### 1.10 agamm/claude-code-owasp
- **URL:** https://github.com/agamm/claude-code-owasp
- **Platform:** Claude Code skill
- **Vuln Classes:** OWASP Top 10:2025 (all 10 categories), ASVS 5.0 (3 levels), Agentic AI Security ASI01-ASI10 (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, agent communication spoofing, cascading failures, trust exploitation, rogue agents), 20+ language-specific security quirks.
- **Prompt/Skill Detail Level:** DETAILED. ~17,000 characters covering secure code patterns, code review checklists (input handling, auth/sessions, access control, data protection, error handling), language-specific vulnerabilities with safe alternatives.
- **Includes Payloads/References:** No raw payloads, but includes secure code pattern examples and anti-pattern identifiers per language.

### 1.11 McGo/claude-code-security-audit
- **URL:** https://github.com/McGo/claude-code-security-audit
- **Platform:** Claude Code skill
- **Vuln Classes:** Source code (injection, deserialization, hardcoded secrets, weak crypto), auth/authz (tokens, sessions, credential leakage), Docker/containers, CI/CD, dependencies/CVEs, configuration, network/transport.
- **3-Phase Process:** Analysis -> Epic creation (managing tickets across severity levels) -> PDF report generation (with scoring formula: 100 - Critical*20 - High*10 - Medium*4 - Low*1).
- **Prompt/Skill Detail Level:** DETAILED. Each finding gets ID, title, file/line, description, code excerpt, fix, OWASP mapping, and CWE number. Includes multi-language support.
- **Includes Payloads/References:** No raw payloads; generates PDF reports with OWASP/CWE references.

### 1.12 GlamgarOnDiscord/claude-security-skills
- **URL:** https://github.com/GlamgarOnDiscord/claude-security-skills
- **Platform:** Claude Code
- **Description:** "Professional-grade security skills. SAST, infra audit, active pentest & automated reports. OWASP 2025, 100+ CWEs, zero config."
- **Prompt/Skill Detail Level:** Claims 100+ CWE coverage.
- **Includes Payloads/References:** TBD - limited file structure visible.

### 1.13 sfonsecardev/owasp-auditor
- **URL:** https://github.com/sfonsecardev/owasp-auditor
- **Platform:** Claude Code / any agent
- **Vuln Classes:** OWASP Top 10 2025 (emphasis A10, A03), OWASP API Security Top 10 2023 (BOLA, BOPLA), web security hardening, HTTP headers, SSL/TLS, cookie security.
- **3-Phase Workflow:** Reconnaissance (structure mapping, high-risk file identification) -> Deep static analysis (access control, supply chain, data flow, exception handling) -> Reporting with vulnerability codes.
- **Prompt/Skill Detail Level:** MODERATE. Role-based principal AppSec engineer persona. Each finding includes vuln code, location, severity, context, and remediation patches.
- **Includes Payloads/References:** No raw payloads; references OWASP standards.

### 1.14 Eyadkelleh/awesome-claude-skills-security
- **URL:** https://github.com/Eyadkelleh/awesome-claude-skills-security
- **Platform:** Claude Code plugin
- **Content:**
  - **7 Plugin Categories:** Fuzzing (SQLi, NoSQL, LDAP, command injection, special chars), Passwords (100k+, darkweb lists), Pattern Matching (PHP auditing, dangerous Angular functions, malicious patterns), Payloads (anti-virus test, directory traversal, exec payloads, null byte, Flash XSS), Usernames (default usernames, names), Web Shells (PHP, JSP, ASP, CFM, WordPress bypass), LLM Testing (bias, data leakage, divergence attacks, memory recall)
  - **3 Agents:** Pentest Advisor, CTF Assistant, Bug Bounty Hunter
  - **5 Commands:** /sqli-test, /xss-test, /wordlist, /webshell-detect, /api-keys
- **Source:** Curated from SecLists (6000+ files, 4.5GB original)
- **Prompt/Skill Detail Level:** MODERATE. Agent definitions and command shortcuts, with the heavy lifting done by the curated SecLists reference data.
- **Includes Payloads/References:** YES - extensive payload files. SQLi auth bypass, generic SQLi, MySQL-specific, NoSQL injection, command injection, LDAP fuzzing, special characters, web shells (PHP/JSP/ASP/CFM), directory traversal payloads, EICAR test strings, default credentials.

### 1.15 netresearch/security-audit-skill
- **URL:** https://github.com/netresearch/security-audit-skill
- **Platform:** Claude Code / any agent
- **Vuln Classes:** XXE, SQLi, XSS, CSRF, command injection, path traversal, file uploads, deserialization, SSRF, type juggling, SSTI, JWT flaws, LDAP injection, email header injection, session fixation. CVSS v3.1 and v4.0 scoring.
- **Reference Library:** 19 reference documents covering OWASP Top 10, CWE Top 25 2025, prevention guides (XXE, deserialization, path traversal, file uploads, input validation), architecture guides, DevSecOps integration, incident response.
- **Prompt/Skill Detail Level:** VERY DETAILED. 80+ checkpoints, PHP/TYPO3 deep scanning, automated tools integration (semgrep, trivy, gitleaks, composer audit).
- **Includes Payloads/References:** Yes - 19 reference files with detection patterns and prevention guides.

### 1.16 freeman983/cc-skill-security-scan
- **URL:** https://github.com/freeman983/cc-skill-security-scan
- **Platform:** Claude Code
- **Description:** Comprehensive security scanning - SAST, SCA, and AI-powered authorization analysis.
- **Prompt/Skill Detail Level:** MODERATE.

### 1.17 justice8096/sast-dast-scanner
- **URL:** https://github.com/justice8096/sast-dast-scanner
- **Platform:** Claude Code
- **Description:** SAST/DAST security scanning with OWASP Top 10 coverage.

### 1.18 tx2z/claude-code-security-scan
- **URL:** https://github.com/tx2z/claude-code-security-scan
- **Platform:** Claude Code
- **Description:** OWASP-based vulnerability analysis using specialized AI agents.

### 1.19 4nshumaan/Skill-scanner
- **URL:** https://github.com/4nshumaan/Skill-scanner
- **Platform:** Claude Code
- **Description:** Performs SAST scans on skills that can be added to Claude (meta-security).

### 1.20 mukul975/Anthropic-Cybersecurity-Skills
- **URL:** https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- **Platform:** Claude Code, GitHub Copilot, OpenAI Codex CLI, Cursor, Gemini CLI, 20+ platforms
- **Description:** 753+ structured cybersecurity skills mapped to MITRE ATT&CK framework. Covers penetration testing, DFIR, threat intel, cloud security. Uses agentskills.io open standard.
- **Coverage:** MITRE ATT&CK mapped, NIST CSF aligned, OWASP mapped.
- **Prompt/Skill Detail Level:** EXTENSIVE. Each skill has SKILL.md, references/, scripts/agent.py. Covers: disk imaging, AD ACL abuse, Android malware analysis, API gateway log analysis, APT group analysis, Azure threat analysis, bootkit/rootkit analysis, browser forensics, Cobalt Strike beacon config, C2 communication analysis, cyber kill chain, DNS exfiltration, Docker forensics, email header phishing investigation, Ethereum smart contracts, Ghidra malware analysis, heap spray exploitation, IoC analysis, iOS app security, Kubernetes audit logs, and many more.
- **Includes Payloads/References:** Yes - API reference files, workflow standards, analysis templates per skill.

---

## CATEGORY 2: LLM Security Prompt Templates

### 2.1 jagan-raj-r/appsec-prompt-cheatsheet
- **URL:** https://github.com/jagan-raj-r/appsec-prompt-cheatsheet
- **Vuln Classes:** All OWASP Top 10 categories with dedicated prompt templates:
  - broken-access-control.md (IDOR, horizontal/vertical bypass, function-level auth, URL traversal, role validation)
  - broken-auth.md (authentication review)
  - cryptographic-failures.md
  - injection.md (SQL, NoSQL, LDAP, OS command, XML, XPath, SSTI, dynamic code execution, HTTP/email header injection)
  - insecure-design.md
  - integrity-failures.md
  - logging-monitoring.md
  - security-misconfiguration.md
  - ssrf.md
  - vulnerable-components.md
  - xss.md
  - General code-review.md
- **Prompt/Skill Detail Level:** STRUCTURED TEMPLATES. Each prompt provides scope of analysis, deliverable format (vulnerability table with location, type, severity, attack examples, damage, remediation), and methodology instructions. Ready to paste into any LLM.
- **Includes Payloads/References:** No raw payloads; structured review framework with code-fix examples.

### 2.2 Jeffallan/claude-skills (Security Reviewer)
- **URL:** https://github.com/Jeffallan/claude-skills
- **Website:** https://jeffallan.github.io/claude-skills/skills/security/security-reviewer/
- **Description:** Part of a 66-skill collection for full-stack developers. Security Reviewer skill covers SAST, dependency scanning, secrets detection, manual auth/input/crypto review.
- **Tools Referenced:** OWASP Top 10, CWE, Semgrep, Bandit, ESLint Security, gosec, npm audit, gitleaks, trufflehog, CVSS scoring, nmap, Burp Suite, sqlmap, Trivy, Checkov, HashiCorp Vault, AWS Security Hub, CIS benchmarks, SOC2, ISO27001.
- **Prompt/Skill Detail Level:** MODERATE. Structured workflow: Scope -> Scan -> Manual review -> Findings validation -> CVSS rating.

---

## CATEGORY 3: Vulnerability Knowledge Bases for AI

### 3.1 SunWeb3Sec/llm-sast-scanner Reference Library
- **URL:** https://github.com/SunWeb3Sec/llm-sast-scanner/tree/main/llm-sast-scanner/references
- **34 Reference Files:** Each is a comprehensive knowledge base designed for AI consumption:
  - `sql_injection.md` - 11 major sections: detection surfaces, DBMS primitives (MySQL/PostgreSQL/MSSQL/Oracle), exploitation techniques (UNION, blind, OOB), evasion/bypass (whitespace, keyword splitting, encoding), source code detection rules (Java/Python/JS/PHP), classification framework
  - `race_conditions.md` - Attack surfaces (payment flows, coupons, quotas, auth tokens), synchronization techniques (HTTP/2 multiplexing, last-byte sync), vulnerability categories (atomicity gaps, idempotency bypass, cross-service races), confirmation requirements, language-specific patterns
  - `insecure_deserialization.md` - CWE-502/CWE-915, technology-specific risks (Java ObjectInputStream, Fastjson autoType, Jackson polymorphic typing, SnakeYAML, XMLDecoder, XStream), detection patterns, severity context (CVSS 9.0-10.0 for Java native), mitigation strategies
  - `xss.md`, `ssrf.md`, `business_logic.md`, `csrf.md`, `cve_patterns.md`, `default_credentials.md`, `denial_of_service.md`, `expression_language_injection.md`, `graphql_injection.md`, `http_method_tamper.md`, `idor.md`, `information_disclosure.md`, `insecure_cookie.md`, `jndi_injection.md`, `mobile_security.md`, `nosql_injection.md`, `open_redirect.md`, `path_traversal_lfi_rfi.md`, `php_security.md`, `privilege_escalation.md`, `rce.md`, `session_fixation.md`, `smuggling_desync.md`, `ssti.md`, `trust_boundary.md`, `verification_code_abuse.md`, `weak_crypto_hash.md`, `xxe.md`, `authentication_jwt.md`, `brute_force.md`, `arbitrary_file_upload.md`
- **Format:** Designed specifically for AI agent consumption with structured sections, detection heuristics, language-specific patterns, and false positive guardrails.

### 3.2 Eyadkelleh/awesome-claude-skills-security (SecLists-derived)
- **URL:** https://github.com/Eyadkelleh/awesome-claude-skills-security
- **Content:** Curated subset of SecLists packaged for AI consumption:
  - SQLi payloads (Generic-SQLi.txt, MySQL.fuzzdb.txt, NoSQL.txt, quick-SQLi.txt, sqli.auth.bypass.txt)
  - Command injection (command-injection-commix.txt)
  - LDAP fuzzing
  - Special characters
  - Password lists (100k, 10k, darkweb, probable-v2)
  - Username lists
  - Web shells (PHP, JSP, ASP, CFM, WordPress)
  - LLM Testing (bias, data leakage, divergence attacks, pre-training data extraction, session recall)
  - Pattern matching (PHP auditing, dangerous Angular functions, malicious patterns, repo scanning)

### 3.3 aiaudittool/AI-Audit-Checklists
- **URL:** https://github.com/aiaudittool/AI-Audit-Checklists-eu-ai-act-owasp-compliance-checklists
- **Content:** Compliance checklists and mapping documents:
  - EU-AI-Act-Checklist.md
  - NIST-AI-RMF-Mapping.md
  - OWASP-LLM-Top10-Mapping.md
- **Format:** Structured checklists designed for audit workflows.

### 3.4 OWASP Official Resources
- **URL:** https://github.com/OWASP/www-project-top-10-for-large-language-model-applications
- **Content:** OWASP LLM Top 10 2025 vulnerability definitions (LLM01-LLM10), OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/)
- **Format:** Markdown vulnerability descriptions with examples and mitigations.

### 3.5 wearetyomsmnv/Awesome-LLMSecOps
- **URL:** https://github.com/wearetyomsmnv/Awesome-LLMSecOps
- **Content:** Curated resource list covering LLM architecture security, vulnerabilities, tools, defense mechanisms, threat modeling, jailbreaks, RAG security, PoCs, datasets for testing, operational security, frameworks, best practices.
- **Related:** wearetyomsmnv/Awesome-LLM-agent-Security (agent-specific threats)
- **Format:** Curated link collection with descriptions, emphasizing practical implementation.

### 3.6 requie/LLMSecurityGuide
- **URL:** https://github.com/requie/LLMSecurityGuide
- **Content:** OWASP GenAI Top-10, OWASP Top 10 for Agentic Applications 2026, prompt injection, adversarial attacks, real-world incidents, red-teaming tools, guardrails, mitigation strategies. Covers Agentic AI Security, RAG Vulnerabilities, System Prompt Leakage, Vector/Embedding Weaknesses.

### 3.7 netrunnersrun/vulnerable-test-cases
- **URL:** https://github.com/netrunnersrun/vulnerable-test-cases
- **Description:** Intentionally vulnerable test cases for SAST scanner validation covering traditional, AI/LLM, and agentic vulnerabilities. Useful as a benchmark dataset.

### 3.8 netresearch/security-audit-skill References
- **URL:** https://github.com/netresearch/security-audit-skill/tree/main/skills/security-audit/references
- **19 Reference Documents:** api-key-encryption, authentication-patterns, automated-scanning, ci-security-pipeline, cryptography-guide, cve-patterns, cvss-scoring, cwe-top25, deserialization-prevention, error-message-sanitization, file-upload-security, framework-security, gha-security, input-validation, modern-attacks, owasp-top10, path-traversal-prevention, php-security-features, security-headers, security-logging, supply-chain-incident-response, supply-chain-security, xxe-prevention

---

## CATEGORY 4: Code Security Agent Skills (Any AI Platform)

### 4.1 SecureCodeWarrior/ai-security-rules
- **URL:** https://github.com/SecureCodeWarrior/ai-security-rules
- **Platform:** Any AI coding tool (Cursor, Copilot, Claude, etc.)
- **Files:** backend.md, frontend.md, mobile.md, language-specific/javascript.md, language-specific/python.md
- **Coverage:** Input/output validation, injection prevention, authentication, secret management, API security, cookie/session security, CSRF protection, error handling, rate limiting, monitoring.
- **Prompt/Skill Detail Level:** MODERATE. Focused on secure coding guidelines rather than vulnerability detection. Lightweight and concise.
- **Includes Payloads/References:** No; guideline-based.

### 4.2 matank001/cursor-security-rules
- **URL:** https://github.com/matank001/cursor-security-rules
- **Platform:** Cursor IDE (.cursor/rules)
- **Coverage:** 5 domains: Secure development principles, Secure MCP usage, Python security best practices, No secrets in frontend, No unsafe system commands.
- **Prompt/Skill Detail Level:** MODERATE. Focused on preventing AI-generated insecure code.

### 4.3 cisco-ai-defense/skill-scanner
- **URL:** https://github.com/cisco-ai-defense/skill-scanner
- **Platform:** Multi-platform (Claude Code, OpenAI Codex, Cursor, Windsurf)
- **Description:** Security scanner for AI agent skills. Includes rules for both Cursor (.cursor/rules/) and Windsurf (.windsurf/rules/):
  - codeguard-0-additional-cryptography
  - codeguard-0-framework-and-languages
  - codeguard-0-iac-security
  - codeguard-0-mobile-apps
  - codeguard-0-supply-chain-security
  - codeguard-1-crypto-algorithms
  - codeguard-1-digital-certificates
  - codeguard-1-hardcoded-credentials
- **Prompt/Skill Detail Level:** DETAILED. Multi-analyzer architecture (static, behavioral, LLM-based, meta-analysis).
- **Includes Payloads/References:** Architecture documentation for writing custom rules.

### 4.4 snyk/agent-scan
- **URL:** https://github.com/snyk/agent-scan
- **Platform:** Multi-platform (AI agents, MCP servers, agent skills)
- **Description:** Security scanner for AI agents by Snyk.

### 4.5 Snyk Fix Skill (via Snyk)
- **URL:** Referenced at https://snyk.io/articles/top-claude-skills-cybersecurity-hacking-vulnerability-scanning/
- **Description:** Official Snyk Claude Skill (~19,000 characters) with 7-phase workflow: parse request, scan with Snyk, analyze findings, fix vulnerability, validate fix, summarize results, optionally create PR. Handles both code vulnerabilities (SAST) and dependency vulnerabilities (SCA).

### 4.6 VoltAgent/awesome-agent-skills
- **URL:** https://github.com/VoltAgent/awesome-agent-skills
- **Platform:** Claude Code, Codex, Antigravity, Gemini CLI, Cursor, and others
- **Description:** 1000+ curated agent skills from official dev teams and community. Security category includes various security review, vulnerability scanning, and penetration testing skills.
- **Related:** VoltAgent/awesome-claude-code-subagents (includes security-engineer, penetration-tester subagent templates)

### 4.7 travisvn/awesome-claude-skills
- **URL:** https://github.com/travisvn/awesome-claude-skills
- **Description:** Curated list of Claude Skills with security category.

### 4.8 BehiSecc/awesome-claude-skills
- **URL:** https://github.com/BehiSecc/awesome-claude-skills
- **Description:** Curated list including vibesec for secure coding (IDOR, XSS, SQLi, SSRF, weak auth prevention).

---

## CATEGORY 5: Specialized Vulnerability Class Skills

### Summary Table of Coverage by Repo

| Vuln Class | utkusen | SunWeb3Sec | Transilience | shuvonsec | EresusSec | netresearch |
|---|---|---|---|---|---|---|
| SQL Injection | sast-sqli (3-phase taint analysis) | sql_injection.md (DBMS primitives, payloads) | injection/SKILL.md | web2-vuln-classes + security-arsenal | eresus-sast-scanner ref | security-audit ref |
| XSS | sast-xss (reflected/stored/DOM) | xss.md | client-side/SKILL.md (6 variant types) | 20 classes + payload library | eresus-sast-scanner ref | security-audit ref |
| IDOR/Access Control | sast-idor + sast-missingauth | idor.md + privilege_escalation.md | authentication/SKILL.md | 8 IDOR variants + ATO taxonomy | eresus-sast-scanner ref + eresus-pr-review | security-audit ref |
| SSRF | sast-ssrf (DNS rebinding aware) | ssrf.md | server-side/SKILL.md | 11 IP bypass techniques | eresus-sast-scanner ref | security-audit ref |
| Auth Bypass | sast-jwt + sast-missingauth | authentication_jwt.md | authentication/SKILL.md (OAuth, JWT, 2FA, CAPTCHA) | OAuth/OIDC + MFA/2FA bypass 7 patterns | eresus-sast-scanner ref | security-audit ref |
| File Upload | sast-fileupload (5 bypass vectors) | arbitrary_file_upload.md | server-side/SKILL.md | 10 bypass techniques | eresus-sast-scanner ref | file-upload-security ref |
| SSTI | sast-ssti (7 engines) | ssti.md | injection/SKILL.md | Engine-specific RCE chains | eresus-sast-scanner ref | -- |
| Deserialization | Part of sast-rce | insecure_deserialization.md | server-side/SKILL.md | -- | eresus-serialization-review (dedicated) | deserialization-prevention ref |
| Race Conditions | sast-businesslogic | race_conditions.md | web-app-logic implied | TOCTOU patterns | eresus-sast-scanner ref | -- |
| Business Logic | sast-businesslogic (12 categories) | business_logic.md | web-app-logic | Fast-path skips, negative values, double-spending | eresus-sast-scanner ref | -- |
| GraphQL | sast-graphql | graphql_injection.md | api-security/SKILL.md | Introspection, node() IDOR, batching | eresus-sast-scanner ref | -- |
| WebSocket | -- | -- | api-security/SKILL.md | CSWSH, message manipulation | -- | -- |
| XXE | sast-xxe (6 languages) | xxe.md | injection/SKILL.md | SVG, DOCX vectors | eresus-sast-scanner ref | xxe-prevention ref |
| Path Traversal | sast-pathtraversal (ZipSlip) | path_traversal_lfi_rfi.md | server-side/SKILL.md | Encoding variations | eresus-sast-scanner ref | path-traversal-prevention ref |
| HTTP Smuggling | -- | smuggling_desync.md | server-side/SKILL.md | CL.TE/TE.CL/TE.TE/H2.CL | -- | -- |
| API Security | -- | http_method_tamper.md | api-security/SKILL.md (GraphQL, REST, WebSocket, LLM) | Mass assignment, prototype pollution | -- | -- |
| NoSQL Injection | -- | nosql_injection.md | injection/SKILL.md | MongoDB operator injection | -- | -- |
| CSRF | -- | csrf.md | client-side/SKILL.md | Token validation, SameSite | -- | -- |
| CORS | -- | -- | client-side/SKILL.md | Misconfigured origins, null origin | -- | -- |
| Clickjacking | -- | -- | client-side/SKILL.md | Frame attacks, drag-and-drop | -- | -- |
| Prototype Pollution | -- | -- | client-side/SKILL.md | Client+server gadget chains | `__proto__`/constructor payloads | -- |
| SAML/SSO | -- | -- | -- | XSW, comment injection, signature stripping | -- | -- |
| Subdomain Takeover | -- | -- | -- | Dangling CNAME fingerprints | -- | -- |
| Cache Poisoning | -- | -- | -- | Unkeyed header injection, parameter miner | -- | -- |
| Timing Side-Channels | -- | -- | -- | -- | -- | -- |

**Trail of Bits covers timing side-channels exclusively** via constant-time-analysis skill (11+ languages, KyberSlash/Lucky Thirteen/RSA patterns).

---

## CATEGORY 6: Full Security Audit Frameworks

### 6.1 usestrix/strix
- **URL:** https://github.com/usestrix/strix
- **Description:** Open-source AI hackers for penetration testing. Autonomous AI agents that run code dynamically, find vulnerabilities, and validate through actual PoCs. Supports HTTP proxy manipulation, browser-driven testing (XSS, CSRF), terminal sessions for command injection, Python environment for custom exploits.
- **Platform:** Standalone tool, GitHub Actions/CI/CD integration
- **Methodology:** Multi-agent system where agents share learnings and adjust tasks dynamically.
- **Note:** Strix itself is open source and this catalog aims to identify public alternatives to its proprietary skill/prompt internals.

### 6.2 yacwagh/FAAST (Full Agentic Application Security Testing)
- **URL:** https://github.com/yacwagh/FAAST
- **Description:** SAST + DAST + LLM agents combined. Agent performs static analysis to find vulns (SQLi, command injection), understands how to reach them dynamically, then exploits them in the live environment with a browser.
- **Status:** Proof of concept, goal to generalize.

### 6.3 msoedov/agentic_security
- **URL:** https://github.com/msoedov/agentic_security
- **Description:** Agentic LLM Vulnerability Scanner / AI red teaming kit. Multimodal attacks across text, images, and audio. Includes adaptive attack modules and attack rule datasets.
- **Platform:** Standalone

### 6.4 perplext/LLMrecon
- **URL:** https://github.com/perplext/LLMrecon
- **Description:** Enterprise-grade LLM security testing framework implementing OWASP LLM Top 10. Attack techniques: direct prompt injection, Unicode smuggling, privilege escalation, roleplay-based bypass, covert exfiltration (steganographic, linguistic, timing-based, side-channel). Maps to both OWASP LLM Top 10 2025 and OWASP Agentic Top 10 2026.
- **Platform:** Standalone Go application with YAML attack templates

### 6.5 5h1Vm/Secure-Pipe
- **URL:** https://github.com/5h1Vm/Secure-Pipe
- **Description:** Open-source AI-augmented security pipeline: SAST, DAST, VAPT, MCP security scanner, prompt injection detector. 18 tools, 10 free LLMs, zero cost.

### 6.6 9M6/vulnsink
- **URL:** https://github.com/9M6/vulnsink
- **Description:** CLI tool wrapping SAST scanners with LLMs to filter false positives and automatically fix security issues.

### 6.7 ari034/DeepSAST-Scanner
- **URL:** https://github.com/ari034/DeepSAST-Scanner
- **Description:** Hybrid SAST scanner combining deterministic taint analysis with DeepSeek LLM-assisted reasoning to minimize false positives.

### 6.8 Armur-Ai/vibescan
- **URL:** https://github.com/Armur-Ai/vibescan
- **Description:** Security scanner for AI-generated code. SAST, DAST, sandboxed exploit simulation across 15+ languages using 30+ tools. AI-powered fixes and PR review integration.

### 6.9 strobes-co/strobes-sast-ai
- **URL:** https://github.com/strobes-co/strobes-sast-ai
- **Description:** CLI tool automating SAST vulnerability patching using OpenAI GPT, processing SARIF output from SAST tools.

### 6.10 OpenAI Codex Security (Commercial, Research Preview)
- **URL:** https://developers.openai.com/codex/security
- **Description:** Scanned 1.2M+ commits, found 792 critical and 10,561 high-severity findings. Evolution of Aardvark. Commercial product, not open-source skills, but represents the frontier of AI SAST.

### 6.11 huifer/skill-security-scan
- **URL:** https://github.com/huifer/skill-security-scan
- **Description:** Meta-security tool: scans Claude Skills themselves for malicious code before installation. Prevents data theft and system compromise from malicious skills.

---

## SUMMARY MATRIX

### Tier 1: Most Comprehensive (Use These First)

| Repo | Vuln Classes | Skill Depth | Payloads | Best For |
|---|---|---|---|---|
| **trailofbits/skills** | Smart contracts, timing, CI/CD, fuzzing, crypto, code audit | Extremely detailed + reference libraries | Yes | Professional security auditing, smart contracts, side-channels |
| **utkusen/sast-skills** | 15 web vuln classes + report | Extremely detailed (3-phase taint analysis) | Detection patterns | SAST scanning of web apps |
| **SunWeb3Sec/llm-sast-scanner** | 34 vuln classes | Very detailed (6-step with judge verification) | Yes (exploitation techniques) | Broadest SAST coverage |
| **transilienceai/communitytools** | 20+ pentest skill domains | Very detailed with reference libraries | Yes (cheat sheets, payloads) | Active penetration testing |
| **shuvonsec/claude-bug-bounty** | 20 web2 classes + web3 + AI/LLM | Extremely detailed with real bounty examples | Yes (extensive payloads per class) | Bug bounty hunting |

### Tier 2: Excellent Specialized Coverage

| Repo | Best For |
|---|---|
| **EresusSecurity/appsec-skills** | PR review, remediation, threat modeling, serialization |
| **AgentSecOps/SecOpsAgentKit** | Full DevSecOps pipeline (25+ tools) |
| **netresearch/security-audit-skill** | PHP/TYPO3 security with 80+ checkpoints |
| **agamm/claude-code-owasp** | OWASP standards reference (Top 10 + ASVS + Agentic AI) |
| **mukul975/Anthropic-Cybersecurity-Skills** | 753+ MITRE ATT&CK mapped skills (DFIR, threat intel, cloud) |
| **McGo/claude-code-security-audit** | Audit with PDF report generation and epic tracking |
| **Eyadkelleh/awesome-claude-skills-security** | Raw payload libraries from SecLists |

### Tier 3: Valuable Supplementary Resources

| Repo | Best For |
|---|---|
| **SecureCodeWarrior/ai-security-rules** | Secure coding rules for any AI IDE |
| **cisco-ai-defense/skill-scanner** | Scanning skills for malicious content (Cursor + Windsurf rules) |
| **jagan-raj-r/appsec-prompt-cheatsheet** | Copy-paste prompt templates for OWASP review |
| **anthropics/claude-code-security-review** | Official Anthropic PR security review |
| **perplext/LLMrecon** | LLM-specific attack templates (prompt injection, exfiltration) |
| **msoedov/agentic_security** | AI red teaming with multimodal attacks |
| **yacwagh/FAAST** | Combined SAST+DAST agentic testing |

### Knowledge Base Resources

| Resource | Best For |
|---|---|
| **SunWeb3Sec reference library** (34 files) | Most comprehensive AI-formatted vuln knowledge base |
| **Eyadkelleh SecLists curation** | Raw payload files for fuzzing/testing |
| **netresearch 19 reference docs** | PHP-focused prevention guides |
| **aiaudittool checklists** | EU AI Act / OWASP LLM compliance |
| **wearetyomsmnv/Awesome-LLMSecOps** | LLM security operations resource collection |
| **OWASP LLM Top 10 / Agentic Top 10** | Authoritative LLM/Agent vulnerability taxonomy |

---

## SOURCES

- [trailofbits/skills](https://github.com/trailofbits/skills)
- [utkusen/sast-skills](https://github.com/utkusen/sast-skills)
- [SunWeb3Sec/llm-sast-scanner](https://github.com/SunWeb3Sec/llm-sast-scanner)
- [EresusSecurity/appsec-skills](https://github.com/EresusSecurity/appsec-skills)
- [AgentSecOps/SecOpsAgentKit](https://github.com/AgentSecOps/SecOpsAgentKit)
- [transilienceai/communitytools](https://github.com/transilienceai/communitytools)
- [shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
- [shuvonsec/public-skills-builder](https://github.com/shuvonsec/public-skills-builder)
- [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review)
- [agamm/claude-code-owasp](https://github.com/agamm/claude-code-owasp)
- [McGo/claude-code-security-audit](https://github.com/McGo/claude-code-security-audit)
- [GlamgarOnDiscord/claude-security-skills](https://github.com/GlamgarOnDiscord/claude-security-skills)
- [sfonsecardev/owasp-auditor](https://github.com/sfonsecardev/owasp-auditor)
- [Eyadkelleh/awesome-claude-skills-security](https://github.com/Eyadkelleh/awesome-claude-skills-security)
- [netresearch/security-audit-skill](https://github.com/netresearch/security-audit-skill)
- [freeman983/cc-skill-security-scan](https://github.com/freeman983/cc-skill-security-scan)
- [justice8096/sast-dast-scanner](https://github.com/justice8096/sast-dast-scanner)
- [tx2z/claude-code-security-scan](https://github.com/tx2z/claude-code-security-scan)
- [4nshumaan/Skill-scanner](https://github.com/4nshumaan/Skill-scanner)
- [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
- [jagan-raj-r/appsec-prompt-cheatsheet](https://github.com/jagan-raj-r/appsec-prompt-cheatsheet)
- [Jeffallan/claude-skills](https://github.com/Jeffallan/claude-skills)
- [SecureCodeWarrior/ai-security-rules](https://github.com/SecureCodeWarrior/ai-security-rules)
- [matank001/cursor-security-rules](https://github.com/matank001/cursor-security-rules)
- [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)
- [snyk/agent-scan](https://github.com/snyk/agent-scan)
- [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills)
- [travisvn/awesome-claude-skills](https://github.com/travisvn/awesome-claude-skills)
- [BehiSecc/awesome-claude-skills](https://github.com/BehiSecc/awesome-claude-skills)
- [usestrix/strix](https://github.com/usestrix/strix)
- [yacwagh/FAAST](https://github.com/yacwagh/FAAST)
- [msoedov/agentic_security](https://github.com/msoedov/agentic_security)
- [perplext/LLMrecon](https://github.com/perplext/LLMrecon)
- [5h1Vm/Secure-Pipe](https://github.com/5h1Vm/Secure-Pipe)
- [9M6/vulnsink](https://github.com/9M6/vulnsink)
- [ari034/DeepSAST-Scanner](https://github.com/ari034/DeepSAST-Scanner)
- [Armur-Ai/vibescan](https://github.com/Armur-Ai/vibescan)
- [strobes-co/strobes-sast-ai](https://github.com/strobes-co/strobes-sast-ai)
- [huifer/skill-security-scan](https://github.com/huifer/skill-security-scan)
- [netrunnersrun/vulnerable-test-cases](https://github.com/netrunnersrun/vulnerable-test-cases)
- [aiaudittool/AI-Audit-Checklists](https://github.com/aiaudittool/AI-Audit-Checklists-eu-ai-act-owasp-compliance-checklists)
- [wearetyomsmnv/Awesome-LLMSecOps](https://github.com/wearetyomsmnv/Awesome-LLMSecOps)
- [requie/LLMSecurityGuide](https://github.com/requie/LLMSecurityGuide)
- [OWASP LLM Top 10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications)
- [Snyk Top 9 Claude Skills](https://snyk.io/articles/top-claude-skills-cybersecurity-hacking-vulnerability-scanning/)
- [Snyk ToxicSkills Study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
