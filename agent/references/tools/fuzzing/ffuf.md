---
description: ffuf through the typed kali verb, runtime wordlist tiers, SaaS API namespace prefixes, and rate calibration
skill: directory-fuzzing
---

# ffuf

Run target-facing ffuf through `vigil assess kali ffuf`. `vigil assess kali ffuf --help` lists the
typed flags and `vigil assess contract kali ffuf --notes` holds the wrapper mechanics; any other ffuf
flag (`-e`, `-X`, `-d`, `-mode`, `-replay-proxy`) goes through `--extra-args`, which is shlex-split,
so quote a JSON body inside it. Live ffuf help: `vigil assess kali tool-help ffuf`.

Runtime quirks:

- ffuf skips TLS certificate verification by default, so self-signed and mismatched-name origins
  need no extra flag.
- Several `-w list:KEYWORD` lists run in clusterbomb mode unless `-mode` says otherwise; size the
  product against the rate budget before starting.
- `-maxtime` is the whole-job cap; the wrapper raises `--timeout` to fit it, so a long fuzz is not
  killed early and read as a clean negative.

## Wordlist Escalation (Kali Paths)

```
L1 (fast):   /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt
L2 (medium): /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
L3 (deep):   /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
Params:      /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
Subdomains:  /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

L1 plus the stack's extensions is the recon minimum (`agent/skills/web-recon/SKILL.md` Step 5).
Escalate to L2 or L3 when the L1 pass surfaces admin, API or backup hits and the budget allows it.

## SaaS API Namespace Fuzzing

Multi-product SaaS hosts nest APIs under per-product and versioned prefixes. This prefix list came
from real engagements; probe each one, then fuzz endpoints under every prefix that answers
(`agent/skills/directory-fuzzing/SKILL.md` "Method" covers the follow-up and the header reads):

```bash
vigil assess kali exec --technique DISCOVERY \
  --intent "SaaS API namespace prefix enumeration" \
  --probe-kind fingerprint --phase consume-test --timeout 120 \
  --identity-env USER=<identity> -- bash -c '
for prefix in /api/v1 /api/v2 /api/v3 /api/internal /api/admin /api/lotus /api/private \
  /sc/v1 /sc/v2 /admin/api /admin/api/v2 /rosetta/api /theming/api /wfm/api /qa/api \
  /sell/api /explore/api /embeddable/api /collaboration; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: $VIGIL_AUTH_USER" "https://TARGET$prefix")
  [ "$code" != "404" ] && echo "$code $prefix"
done
'
```

## Rate guidance for cautious-tier / WAF-fronted targets

Take `-rate` from the dir-fuzz column of the `agent/references/recon/rate-calibration.md` row the
wafw00f result picks (`agent/references/tools/recon/wafw00f.md` "WAF-tier rate adjustment table"),
with `-t` at or below it. ffuf's default `-t 40` with no `-rate` trips a cautious-tier WAF lockout
that lasts the rest of the engagement, which is why the web-recon skill runs wafw00f first.
