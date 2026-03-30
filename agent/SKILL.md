# AI Threat Hunting Skill Index

Use this file when you need to decide which skill to load before starting specialist work.

## Core workflow skills

- `agent/skills/web-recon/SKILL.md`
  Initial web and service fingerprinting for recon-specialist.
- `agent/skills/source-analysis/SKILL.md`
  Client-source route, API, and secret analysis for source-analyzer.
- `agent/skills/case-dispatching/SKILL.md`
  Work-buffer coordination loop for operator-led batching.
- `agent/skills/report-generation/SKILL.md`
  Report structure and remediation framing for report-writer.
- `agent/skills/osint-recon/SKILL.md`
  External intel gathering for osint-analyst.
- `agent/skills/athena-log-investigation/SKILL.md`
  Optional final log-review phase when telemetry is available.

## Targeted testing skills

Load the relevant vuln-class skill before custom methodology:

- `agent/skills/auth-bypass/SKILL.md`
- `agent/skills/business-logic-testing/SKILL.md`
- `agent/skills/command-injection/SKILL.md`
- `agent/skills/cors-testing/SKILL.md`
- `agent/skills/csrf-testing/SKILL.md`
- `agent/skills/deserialization-testing/SKILL.md`
- `agent/skills/directory-fuzzing/SKILL.md`
- `agent/skills/file-inclusion/SKILL.md`
- `agent/skills/file-upload-testing/SKILL.md`
- `agent/skills/graphql-testing/SKILL.md`
- `agent/skills/idor-testing/SKILL.md`
- `agent/skills/info-disclosure-testing/SKILL.md`
- `agent/skills/jwt-testing/SKILL.md`
- `agent/skills/open-redirect-testing/SKILL.md`
- `agent/skills/parameter-fuzzing/SKILL.md`
- `agent/skills/port-scanning/SKILL.md`
- `agent/skills/race-condition-testing/SKILL.md`
- `agent/skills/request-smuggling/SKILL.md`
- `agent/skills/sensitive-data-detection/SKILL.md`
- `agent/skills/sqli-testing/SKILL.md`
- `agent/skills/ssrf-testing/SKILL.md`
- `agent/skills/ssti-testing/SKILL.md`
- `agent/skills/subdomain-enumeration/SKILL.md`
- `agent/skills/user-enumeration/SKILL.md`
- `agent/skills/websocket-testing/SKILL.md`
- `agent/skills/xss-testing/SKILL.md`
- `agent/skills/xxe-testing/SKILL.md`

## Selection rule

1. Load the shared operator constraints first.
2. Load the most relevant skill from this index.
3. Consult `agent/references/INDEX.md` only when the skill does not cover the target well enough.
