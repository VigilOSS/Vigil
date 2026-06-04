---
name: gf-patterns:rce
description: Command-execution parameter patterns that signal remote code execution surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: rce
weight: 50
---

# gf: rce

## What this bucket classifies

Parameters whose names suggest the server is invoking a shell, spawning a subprocess, or
feeding an `eval()`-style interpreter. These are the highest-weight bucket because a real
hit usually translates to direct pre-auth RCE.

## Load this reference when

- The corpus has `?cmd=`, `?exec=`, `?run=`, or `?execute=` keys — classic command-injection signals
- Path fragments `/exec/`, `/cmd/`, or `/shell/` appear in the crawl
- Operator is prioritizing which routes to send to command-injection fuzzing ahead of everything else

## Parameter keys that match

`cmd, exec, command, shell, run, execute`

## Path patterns that match

`/exec/`, `/cmd/`, `/shell/`

## Weight and priority interpretation

- Baseline priority score: 50 (highest bucket — rce trumps everything else)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/debug/exec?cmd=whoami` — on-by-accident debug command surface
- `https://target.example/tools/run?command=ping%20127.0.0.1` — tooling wrapper
- `https://target.example/api/v1/shell/execute?shell=/bin/sh&run=id` — combined parameter surface
- `https://target.example/admin/cmd/status?execute=true` — path fragment plus parameter
- `https://target.example/plugin/exec?cmd=cat%20/etc/passwd` — CMS/plugin-style exec handler

## What it does NOT classify

- Generic `/admin` or `/internal` paths with no command-style parameter — those land in `debug_logic`
- SSTI-style template execution (`{{7*7}}` surfaces) — those are in `ssti`
- File-read-only primitives that happen to end in RCE — still belong in `lfi` at classification time, with the chain written up separately

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

## Related

- `agent/references/payloads/command-injection-payloads.md` — payload library (blind detection, filter bypass)
- `agent/references/gf-patterns/ssti.md` — adjacent bucket (both are code-execution classes)
- `agent/references/gf-patterns/debug_logic.md` — adjacent bucket (admin/debug path exposure often precedes rce)
