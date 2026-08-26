# ADR 0010 — Fail-closed attribution for required-header engagements

- Status: Superseded
- Date: 2026-06-30

> **Superseded (2026-07-28):** required-header injection remains, but the
> host-membership-dependent Layer 2 refusal described below has been removed.
> `scope.json` may shape collected datasets and supply headers, but it does not
> admit or refuse outbound execution. An injector that cannot safely add a
> marker now warns and lets the command run. The remainder of this ADR records
> the former decision for history.

## Context

Some programs (notably federal / managed bug-bounty programs) MANDATE a request
attribution header on every probe — e.g. `X-Bug-Bounty: <handle>` — so the
defender can distinguish authorized research traffic from a real attack. On those
programs, traffic to an in-scope host WITHOUT the marker is not a quality
nicety: it is a **ban-risk**. An un-attributed scan can get the researcher (or
the whole platform's egress) blocked, and removed from the program.

The runtime already injects the marker into a curated set of HTTP-to-target tools
(`_apply_required_headers` in `kali_output.py`), including the `sh -c`/`bash -c`
best-effort sub-command injection (W5). But that mechanism was deliberately
**best-effort and never fail-closed**. Its own comment stated the posture:

> BEST-EFFORT, NEVER fail-closed: a missing attribution header is a REDUCED
> REWARD, not a ban-risk, and a hard block would stall a legitimate multi-curl
> probe mid-hunt and hurt performance.

Two gaps follow from that posture, both of which let un-attributed traffic reach
an in-scope host (the I-8 / I-3 backlog items, Appendix C #1 and #2):

1. **Tools the curated injector does not cover.** `_REQUIRED_HEADER_INJECTABLE`
   only knew the curl-style `-H` tools. `whatweb`, `nikto`, and `arjun` use
   *different* header flags, so they WARNed and went out un-attributed.
2. **Shell-wrapped commands the W5 injection could not reach.** A `bash -c "curl
   <in-scope>"` whose script could not be safely lexed, or which wrapped a tool
   W5 does not recognize, fell through to a WARN and ran un-attributed — the tool
   name resolves to the inner tool but no `-H` ever landed.

The best-effort stance was correct when a missing header only cost reward. It is
the WRONG stance for a program where a missing header is a ban-risk. This ADR
records the posture reversal and the design that enforces it.

## Decision

For an engagement that has `required_headers` configured in `scope.json`, an
HTTP command that **reaches an in-scope host without carrying the marker is
REFUSED** (the run does not exec) rather than sent un-attributed. The design is
two complementary layers:

### Layer 1 — extend the curated auto-injector (I-3)

`_apply_required_headers` gains a small tool → header-flag map
(`_REQUIRED_HEADER_FLAG_SPECS`) for HTTP-to-target tools whose flag is NOT the
curl-style `-H`. The flags were **verified in-container**, not taken on faith —
the original backlog note had one wrong (it claimed nikto `-H`, which is
actually `-Help`):

| Tool | Verified inject flag | Multiplicity |
|---|---|---|
| `whatweb` | `--header "K: V"` (`-H` is an alias) | repeatable, one header per flag |
| `nikto` | `-Add-header "K: V"` | repeatable, one header per flag |
| `arjun` | `--headers "K: V"` | **single** flag, multiple headers newline-joined |

`arjun` is special-cased: its `--headers` is store-once under argparse, so
multiple required headers ride a single newline-joined value, and a marker is
*merged into* an operator-supplied `--headers` block rather than appended as a
second flag that would clobber it.

`wafw00f` is deliberately EXCLUDED from Layer 1: its `-H`/`--headers` flag reads
a **file path**, not an inline `Name: Value` (verified — an inline value errors
`Headers file "..." does not exist`), so it cannot carry an inline marker and
relies on Layer 2.

Because Layer 1 lives in the shared `kali_output._apply_required_headers`, BOTH
the container path (`kali.kali_exec`) and the audited host path
(`web_discovery` / `dns_discovery` host-dispatch) get the new flags for free.

### Layer 2 — dynamic fail-closed backstop (no per-tool knowledge)

After the FINAL argv (and any shell-script text) is assembled — past identity
injection and Layer-1 required-header injection — `kali_exec` calls
`required_header_attribution_gap`. It REFUSES the run when ALL of:

- the engagement configured `required_headers`;
- the derived tool is NOT a passive/archive/DNS/L3-L4 skip-set tool (those query
  the archive/DNS, not the in-scope host, so the in-scope token is their query
  subject, not a host they connect to — reusing the existing passive
  classification, not new per-tool header knowledge);
- the command REACHES an in-scope host (an in-scope host/URL token is present in
  the argv OR the shell-script text — matched with the shared `scope.py`
  matchers; purely lexical, no DNS/HTTP); AND
- at least one required marker's `Name: Value` literal is ABSENT from the command
  text.

Because it inspects the final assembled command with no per-tool knowledge, it
catches every gap Layer 1 leaves: the `bash -c "curl <in-scope>"` case where W5
could not inject (I-8), an unknown/future tool, and `wafw00f`. The refusal
message tells the operator exactly how to fix it (the tool's own header flag, or
call curl directly instead of wrapping it in `bash -c`).

### Unaffected paths (the gate is fail-OPEN for everything else)

The refusal is narrow by construction:

- **Engagements with no `required_headers`** — the backstop never runs.
- **Local / non-target commands** — a command that reaches no in-scope host
  (localhost, an out-of-scope host, a tool with no target) is never refused.
- **Passive skip-set tools** — `gau`/`waybackurls`/`subfinder`/`dnsx`/`nmap`/… are
  never refused for lacking attribution, and the handle is still never injected
  into them (it must not leak to the public archive / DNS).

## Consequences

- On a required-headers program, an un-attributed in-scope probe can no longer
  run — the single most consequential compliance failure (ban-risk) is now
  fail-closed, while the common case (an injectable tool) is transparently
  attributed by Layer 1 and never sees the backstop.
- `whatweb`/`nikto`/`arjun` now carry the marker automatically on both the
  container and host paths; `wafw00f` and any unknown tool are caught by Layer 2.
- A refused run returns a `KaliResult(status="refused")` with the actionable
  message on stderr and as the result's `stderr_preview`, and does NOT write a
  command-run audit row (the command never ran). It is surfaced loudly so the
  operator re-issues it with the marker rather than silently losing the probe.
- The change is confined to `kali_output.py` (Layer 1 map + Layer 2 detector) and
  `kali.py` (the `kali_exec` gate). No prompt/generated file changes; no schema
  regen (no new persisted field). The detector is a pure function, unit-tested
  directly, with one end-to-end test asserting `kali_exec` refuses without exec.

## Alternatives considered

- **Keep best-effort + bake per-dispatch injection into recon guidance**
  (Appendix C #2 option B). Rejected: a prompt instruction is advisory; on a
  ban-risk program the enforcement must bite at the exec boundary, not rely on
  the operator remembering. The two are complementary, not substitutes.
- **Hard-block ALL un-attributed commands, including local/passive.** Rejected:
  over-refusal would stall legitimate local tooling and passive recon (which
  correctly must NOT carry the handle), and the skip-set already encodes which
  tools don't send attributable HTTP. The gate stays fail-open for everything but
  un-attributed in-scope traffic.
- **Force the non-`-H` tools into `_REQUIRED_HEADER_INJECTABLE`.** Rejected: that
  set is curl/`-H`-shaped, and appending `-H` to whatweb/nikto/arjun would
  produce a malformed command. A separate tool→flag map keeps each tool's real
  flag (which is why verifying nikto's flag in-container — `-Add-header`, not the
  backlog's claimed `-H`/`-Help` — was load-bearing).

## Relationship to other items

- This ADR resolves the live posture conflict recorded in `workflow specification.md`
  Appendix C #1 (I-8 / PT-§7-I9) and #2 (I-3) — the injection halves were already
  done; this is the fail-closed half and the non-`-H` tool extension.
- The identity host-cookie jar (I-22), landed alongside this work in the same
  files, is a separate concern (sending the right captured session per host) and
  is documented in code, not here.
