---
description: GitHub OSINT pipelines for the osint-recon "Org-name Pattern Enumeration" step — GITHUB_TOKEN in the runtime env, audit-flag placement, org-variant search, members, commit-author email mining, code and contractor cross-search, secondary-rate-limit pacing, intel record types
skill: osint-recon
---

# GitHub OSINT — Org Enumeration & Commit-Author Email Mining

Pipelines for `agent/skills/osint-recon/SKILL.md` "Org-name Pattern Enumeration", which owns what
to enumerate. No probe reaches the target's own infrastructure.

**Running it.** Each call is `vigil assess kali exec` with every audit flag before the trailing
`-- bash -c '...'`; anything after `--` belongs to the command, so a flag placed there never reaches
vigil. The token comes from the container environment: set `GITHUB_TOKEN` in `<install>/.env` and
re-run `vigil runtime start` (an `export` inside one `kali exec` dies with that call). Use a PAT
with no extra scopes for public resources, and never echo it into stdout or `scans/`. Anonymous
rate is 60 requests/hour, authenticated 5,000; check budget with `/rate_limit` before a long run.

## Org variants, members, code cross-search

```bash
vigil assess kali exec --technique OSINT \
  --intent "GitHub org-name pattern enumeration for Acme variants" \
  --probe-kind fingerprint --phase recon --timeout 600 -- bash -c '
  for variant in acme acme-corp acme-internal acme-tools acme-research acme-oss Acme-Inc; do
    curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://api.github.com/search/users?q=${variant}+type:org" \
      | jq -c --arg v "$variant" "{variant: \$v, total_count, hits: [.items[] | {login, html_url, avatar_url}]}"
    sleep 1
  done
'
```

- The `sleep 1` keeps clear of GitHub's secondary rate limit, which throttles bursty automation for
  5-10 minutes once tripped. In longer loops, read `X-RateLimit-Remaining` and pause below 100.
- `avatar_url` often resolves to the parent organisation's logo, which separates real target
  orgs from look-alike squatters.
- `/orgs/<org>/members?per_page=100` returns public members only; profiles often link LinkedIn or
  a personal site.
- `/search/code?q=%22<org>%22` finds the org slug in other repos (forks, README links, CI configs
  pulling private packages), exposing internal repo names, deployment hostnames and registry URLs.
- `/orgs/<contractor>/repos` filtered on a target keyword finds contractor repos with
  target-specific configuration, deployment scripts and hard-coded internal URLs.

## Commit-author email mining

`author.email` and `committer.email` on recent commits carry the corporate email format unless the
developer enabled GitHub's email privacy.

```bash
vigil assess kali exec --technique OSINT \
  --intent "GitHub commit-author emails across <org> top 30 repos" \
  --probe-kind fingerprint --phase recon --timeout 600 -- bash -c '
  for repo in $(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://api.github.com/orgs/<org>/repos?per_page=30&sort=updated" | jq -r ".[].name"); do
    curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://api.github.com/repos/<org>/${repo}/commits?per_page=50" \
      | jq -r "[.[].commit | .author.email, .committer.email] | unique | .[]"
    sleep 1
  done | sort -u
'
```

Keep the corporate-domain addresses; the dominant shape (`first.last@`, `flast@`, ...) is the email
convention, a high-confidence input for later password-spray candidate lists.

## Recording

Orgs → `vigil assess intel record org-fact`; confirmed emails → `email`; named developers →
`person`; relationship context (e.g. a contractor runs the deployment pipeline, per repo Z) →
`note`. The schemas reject guessed aliases; `vigil assess contract intel record <type>` prints the
accepted fields.
