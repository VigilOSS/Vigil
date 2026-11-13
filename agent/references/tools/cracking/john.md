---
description: Offline hash cracking with John the Ripper in the runtime; *2john converters on PATH, wordlist paths, engagement-scoped pot files
---

# john (John the Ripper)

Run john via `vigil assess kali exec --technique AUTH --intent "<why>" --probe-kind payload
--phase <phase> --timeout <seconds> -- john ...` with the standard audit-flag set. It sends no
target traffic, but the run is still audited. Live help: `vigil assess kali tool-help john`;
`john --list=formats` names the formats.

Use john over hashcat (`agent/references/tools/cracking/hashcat.md`) for format auto-detection and
for hashes extracted from files. The runtime has the full `*2john` converter set on PATH
(`ssh2john`, `zip2john`, `keepass2john`, `office2john`, `pdf2john`, `gpg2john`, `bitlocker2john`,
`kirbi2john`, `pfx2john`, `ansible2john` and many more; the Python and Perl sources are in
`/usr/share/john/`), so a recovered key, archive, vault or config file goes straight to a
crackable hash.

Wordlists are under `/usr/share/wordlists/SecLists/Passwords/`; rockyou ships compressed there
(`Leaked-Databases/rockyou.txt.tar.gz`), so extract it into the engagement directory first. Keep
the pot file with the engagement (`--pot=/engagements/$ENGAGEMENT_KEY/scans/john.pot`, and the same
`--pot` on `--show`), so one engagement's cracks never surface in another's.
