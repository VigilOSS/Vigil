---
name: gf-patterns:lfi
description: File-handling parameter patterns that signal local file inclusion and path traversal surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: lfi
weight: 40
---

# gf: lfi

## What this bucket classifies

Parameters whose values are used as filesystem paths, template names, or include targets.
These are the raw surfaces for LFI, path traversal, log poisoning, and PHP wrapper abuse.

## Load this reference when

- The corpus has `?file=`, `?path=`, `?doc=`, `?page=`, `?template=`, or `?include=` keys
- Operator is hunting for `/etc/passwd`, `php://filter`, and log-injection pivots on a PHP stack
- Static downloads of `.pdf`, `.doc`, `.xml` via path params appear in the crawl

## Parameter keys that match

`file, path, doc, document, page, pg, template, load, include, read`

## Path patterns that match

None — lfi is keyed entirely off parameter names. Leaked config paths (`.git`, `.env`) are
covered by `debug_logic`.

## Weight and priority interpretation

- Baseline priority score: 40 (tied with sqli)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/render?template=welcome.tmpl` — template inclusion
- `https://target.example/docs/view?doc=../../../../etc/passwd` — classic traversal
- `https://target.example/downloads?file=invoice.pdf` — file-parameter download
- `https://target.example/legacy/page?page=php://filter/convert.base64-encode/resource=config` — PHP wrapper
- `https://target.example/api/v2/read?path=/var/log/app.log` — absolute-path read

## What it does NOT classify

- Upload endpoints writing files — those need the `file_handling` surface type plus file-upload-testing, not gf buckets
- Template engines for SSTI — those are in the `ssti` bucket
- Archive extraction paths — out of gf bucket scope; see the file-upload test skill

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

## Related

- `agent/skills/file-inclusion/SKILL.md` — the follow-up test skill
- `agent/references/payloads/file-inclusion-payloads.md` — PHP wrappers, traversal, log poisoning
- `agent/references/gf-patterns/ssti.md` — adjacent bucket (`template` keys overlap)
