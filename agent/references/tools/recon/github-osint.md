---
description: GitHub OSINT — org-name pattern enumeration (literal/parent/contractor variants), public-member listing, commit-author email mining, code-search cross-reference; rate-limit etiquette and `GITHUB_TOKEN` pattern
skill: osint-recon
---

# GitHub OSINT — Org Enumeration & Commit-Author Email Mining

GitHub's Search and REST APIs expose enough public data that an org-name pattern
enumeration plus a commit-author email mining pass can confirm an organization's
GitHub footprint, sibling orgs, named developers, and corporate email format
without sending a single probe at the target's own infrastructure. This file
carries the concrete curl + jq pipelines that `agent/skills/osint-recon/SKILL.md`
references from its "Org-name pattern enumeration" section.

All examples wrap the HTTP probe in `vigil assess kali exec` so the run lands
in the audit pipeline. Place every audit flag (`--technique OSINT --intent
"<concise>" --probe-kind fingerprint --phase <current> --timeout <seconds>`)
BEFORE the trailing `-- bash -c '...'`. Flags after the heredoc go to bash
itself and are silently dropped by vigil.

## Authentication

GitHub anonymous rate is **60 requests / hour**. Authenticated rate is **5,000
requests / hour**. A pattern enumeration that issues 50–200 lookups in a session
will exhaust the anonymous budget within minutes; pass a personal access token
via `Authorization: Bearer $GITHUB_TOKEN` so the call counts against the
authenticated bucket instead.

```bash
# Set once per session inside the runtime
export GITHUB_TOKEN="<personal-access-token-with-public_repo-scope>"

# Sanity-check the token's remaining budget before a long enumeration run
vigil assess kali exec --technique OSINT --intent "GitHub rate-limit sanity check" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    https://api.github.com/rate_limit \
    | jq ".rate"
'
```

The token never leaves the runtime container; it is read from the container's
environment at probe time. Do not echo it into stdout or commit it to scans/.

## 1. Org Enumeration via Pattern Variants

When one org is known, the rest of the family is usually nearby under a
predictable suffix family. Enumerate variants on the literal name and the
parent name with `/search/users?q=<pattern>+type:org`.

```bash
# Variants on the literal name "Acme"
vigil assess kali exec --technique OSINT \
  --intent "GitHub org-name pattern enumeration for Acme variants" \
  --probe-kind fingerprint --phase recon --timeout 600 -- bash -c '
  for variant in acme Acme ACME acme-corp acmegov acme-internal acme-tools acme-research acme-oss Acme-Inc; do
    curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://api.github.com/search/users?q=${variant}+type:org" \
      | jq -c --arg v "$variant" "{variant: \$v, total_count, hits: [.items[] | {login, html_url, avatar_url}]}"
    sleep 1
  done
'
```

The `sleep 1` between requests keeps the call rate well below the 5,000/hr
authenticated ceiling and avoids tripping GitHub's secondary rate-limit
heuristic, which throttles bursty automation for several minutes.

For each hit, capture `login`, `html_url`, and `avatar_url`. The avatar URL
often resolves to the parent organization's public corporate logo, which
disambiguates legitimate target-related orgs from squatters using a similar
name.

## 2. Public Member Listing per Org

Once an org is confirmed, list its public members:

```bash
vigil assess kali exec --technique OSINT --intent "GitHub public-member listing for <org>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/orgs/<org>/members?per_page=100" \
    | jq "[.[] | {login, html_url}]"
'
```

`/orgs/<org>/members` returns only public members; private membership is not
exposed. Cross-reference each `login` against LinkedIn (the `html_url` carries
the GitHub profile, which often links to LinkedIn or a personal site).

## 3. Commit-author Email Mining

The richest source of corporate email patterns is the per-commit `author.email`
and `committer.email` fields on recent commits. These are not hidden behind
GitHub's email-privacy toggle if the developer has not enabled it.

```bash
vigil assess kali exec --technique OSINT \
  --intent "GitHub commit-author email mining for <org>/<repo>" \
  --probe-kind fingerprint --phase recon --timeout 120 -- bash -c '
  curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/repos/<org>/<repo>/commits?per_page=100" \
    | jq -r "[.[].commit | .author.email, .committer.email] | unique | .[]"
'
```

Aggregate across the org's most-active repos:

```bash
vigil assess kali exec --technique OSINT \
  --intent "GitHub commit-author emails across <org>'s top 30 repos" \
  --probe-kind fingerprint --phase recon --timeout 1200 -- bash -c '
  REPOS=$(curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/orgs/<org>/repos?per_page=30&sort=updated" \
    | jq -r ".[].name")
  for repo in $REPOS; do
    curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://api.github.com/repos/<org>/${repo}/commits?per_page=50" \
      | jq -r "[.[].commit | .author.email, .committer.email] | unique | .[]"
    sleep 1
  done | sort -u
'
```

Filter on the corporate domain to drop personal/no-reply emails and emit the
canonical email pattern:

```bash
# Pipe the previous output through this to keep only emails that match the corp domain
vigil assess kali exec --technique OSINT --intent "Filter commit-author emails to corp domain" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  cat /tmp/raw_emails.txt | grep -iE "@(<corp>\\.com|<subsidiary>\\.com)$" | sort -u
'
```

The dominant pattern (e.g. `FirstName.LastName@<corp>.com`,
`flastname@<corp>.com`, `firstname_lastname@<corp>.com`) is the corporate
email convention. Confirming it gives osint-analyst a high-confidence input
for `vigil assess record-intel email` and feeds password-spray candidate
lists in later phases.

## 4. Cross-search Public Code for Discovered Org Names

A confirmed org name often appears in OTHER public repos (forks, contributor
README links, CI configuration that pulls private packages by org slug).
GitHub's code search exposes those references:

```bash
vigil assess kali exec --technique OSINT --intent "GitHub code search cross-reference for <org>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=%22<org>%22&per_page=50" \
    | jq "[.items[] | {repo: .repository.full_name, path, html_url}]"
'
```

Hits in third-party repos surface internal repo names, deployment hostnames,
and CI registry URLs that the org's owner page hides behind private visibility.

## 5. Contractor / Vendor Cross-search

When procurement records, public case studies, or LinkedIn show a consulting
firm working with the target, search GitHub for tagged forks or affiliated
repos under the contractor's org slug:

```bash
vigil assess kali exec --technique OSINT \
  --intent "Contractor org repo cross-search for target-keyword" \
  --probe-kind fingerprint --phase recon --timeout 300 -- bash -c '
  for contractor_slug in <contractor1> <contractor2>; do
    curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://api.github.com/orgs/${contractor_slug}/repos?per_page=100" \
      | jq -c --arg c "$contractor_slug" "{contractor: \$c, repos: [.[] | select(.name | test(\"<target-keyword>\"; \"i\")) | {name, html_url, description}]}"
    sleep 1
  done
'
```

Contractor repos often contain target-specific configuration, deployment
scripts, or proof-of-concept code with hardcoded internal URLs and credentials
— grep the matching repos for `<target-keyword>` and fingerprint any
references back to the target's infrastructure before recording findings.

## Output Recording

Translate the discovered orgs, emails, and developer names into structured
intel writes:

- Each org → `vigil assess record-intel org-fact <json-file>`
- Each confirmed email → `vigil assess record-intel email <json-file>`
- Each named developer → `vigil assess record-intel person <json-file>`
- Free-form prose context (e.g. "contractor X manages target Y's deployment
  pipeline based on repo Z") → `vigil assess record-intel note <json-file>`

Run `vigil assess contract record-intel <type>` first to confirm field names
before authoring the JSON; intel schemas reject guessed aliases.

## Rate-limit Etiquette

- Respect GitHub's published 5,000 req/hr authenticated ceiling. A typical
  pattern enumeration plus per-org member + commit pass runs 200–500 requests;
  well within budget but enough to stack onto a parallel automation run.
- The `sleep 1` interval between requests in the pattern-enumeration loop is
  there to avoid the secondary rate-limit heuristic, which throttles bursty
  automation for 5–10 minutes once tripped.
- For the org-repo `for` loop, pull the rate-limit header on each response
  (`X-RateLimit-Remaining`) and pause if it drops below 100 before continuing.

## Cross-references

- `agent/skills/osint-recon/SKILL.md` — methodology section "Org-name pattern enumeration"
- `agent/references/payloads/version-fingerprint-probes.md` — package-registry probes for vendor exact-version triangulation
- `vigil assess list-references` — the reference library index (run it; `--skill <name>` filters to a skill's paired refs)
