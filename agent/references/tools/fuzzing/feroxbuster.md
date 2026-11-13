---
description: Recursive content discovery through kali exec, its per-directory rate quirk, and wordlist/rate calibration
skill: directory-fuzzing
---

# feroxbuster

feroxbuster has no typed verb; run it through `vigil assess kali exec --technique RECON --intent
"<why>" --probe-kind fingerprint --phase <phase> --timeout <seconds> -- feroxbuster ...` with the
standard audit-flag set. Live help: `vigil assess kali tool-help feroxbuster`. Use it for recursive
discovery; use `vigil assess kali ffuf` for parameters, vhosts and single-directory work.

## Wordlist tier and cautious-tier rate guidance

The recon minimum is the L1 wordlist
(`/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt`) plus the stack's
extensions (`agent/skills/web-recon/SKILL.md` Step 5). Take `--rate-limit` from the dir-fuzz column
of the `agent/references/recon/rate-calibration.md` row the wafw00f result picks
(`agent/references/tools/recon/wafw00f.md` "WAF-tier rate adjustment table"), with `-t` at or below
it. Run wafw00f first: the default `-t 50` trips cautious-tier rate-limit profiles in seconds.

`--rate-limit` applies per directory scan, and recursion runs directory scans concurrently, so the
aggregate rate is the limit times the live scan count. Add `--scan-limit 1` (or divide the row's
rate by the scan limit) so the calibrated ceiling holds. `--smart` turns on `--auto-tune`, which
lowers the rate on excessive errors or 429s.

## Output

`--json -o <file>` writes JSON lines that mix configuration, log and statistics entries with results; select
`type == "response"` before ranking hits. `--resume-from ferox-<epoch>.state` resumes a scan
from the state file feroxbuster writes when it is interrupted.
