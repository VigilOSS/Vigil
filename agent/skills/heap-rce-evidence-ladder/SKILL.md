---
name: heap-rce-evidence-ladder
description: Disclosure-grade evidence methodology for heap-OOB-to-RIP-control chains — the rung ladder, per-rung evidence bar, and lab-assist-to-production-equivalent disclosure pattern
origin: AI Threat Hunting
---

# Heap RCE Evidence Ladder

## Identity

A skill for structuring evidence on heap-OOB → indirect-call-hijack → RCE chains so the resulting disclosure survives third-party triage (BugCrowd, GHSA, CERT/CC VINCE). Most heap-OOB findings get downgraded at triage because the reporter conflated "primitive proven" with "exploit chain proven" — the rung ladder is an explicit decomposition that lets a triager check each link independently.

This skill is generic across heap-allocators (glibc malloc, jemalloc, tcmalloc, mimalloc), architectures (x86_64, aarch64, riscv), and target classes (network daemons, file parsers, plugin loaders). The specific calibration constants belong in the finding's evidence bundle; the rung framework belongs here.

## When to Activate

- An exploit-developer dispatch is about to claim "RCE" or "code execution" from a heap-corruption primitive
- A code-vulnerability-analysis dispatch identifies a heap-OOB write that the agent suspects reaches a sink (function pointer, vtable, GOT entry, finalizer, callback)
- A report-writer dispatch is structuring evidence for a critical-severity heap-corruption finding and needs to enumerate what is and isn't proven
- An adversarial re-verification is being done on a heap-RCE claim that may be overstated

The rung ladder is not specific to msgpack-c, fluent-bit, or any particular finding — it's the general structure a heap-OOB-to-RCE chain decomposes into, and the per-rung evidence bar is the calibration that lets a triager believe each step.

## The Rung Ladder

A heap-OOB primitive becomes a disclosure-grade RCE chain by climbing six rungs. Each rung is independently provable; each subsumes the rung below.

| Rung | What it proves | Typical artifact |
|------|----------------|-------------------|
| 1 — primitive | The OOB write exists and writes attacker-controlled bytes past the allocation | AddressSanitizer report on release-config build, or a minimal harness invoking the allocator path |
| 1B — sink reachable | The byte sequence written by the primitive lands on a struct field whose later use is an indirect call, vtable dispatch, GOT lookup, or finalizer | Harness with statically-linked allocator, deterministic uid=0/RIP-control proof on the harness binary |
| 2 — live crash | The live release binary (not harness, not debug build) crashes deterministically when fed the primitive over its real entry point | Network-delivered SIGSEGV/SIGABRT, 3× deterministic on the unmodified release binary |
| 2.5 — adjacency + heap shape | The OOB write lands at the predicted offset relative to the sink struct, in the live binary's heap state | Per-replay measurement of `sink_addr - alloc_addr`, identical across 3 replays |
| 1A — live RIP control | Live release binary, network-delivered, attacker-chosen function pointer fires with attacker-chosen argument; observable side effect (file written, command output captured, callback URL hit) | 3× deterministic `system("id")` output or equivalent on the live release binary |
| 0 — no-assist | All of 1A but with no LD_PRELOAD instrumentation on the victim, no `/proc/PID/maps` reads from the attacker process, no debugger attach | Same 1A evidence + explicit negative controls showing each assist's production equivalent is sufficient |

Climb in numerical order until you reach the rung that matches the claim you want to make. **Stop honestly at the highest rung you can prove**; don't claim higher.

## Per-Rung Evidence Bar

Each rung has a calibration that a triager checks. If the bar isn't met, the rung doesn't count.

### Rung 1 — primitive

- AddressSanitizer report taken from a **release-config build** (`-DNDEBUG`, optimization on, asserts compiled out). Debug-build ASan reports don't count because they may not match what production hits.
- Or: minimal harness that invokes only the allocator path, with statically-linked allocator matching the production target's. Demonstrate the OOB byte count and the destination offset.

### Rung 1B — sink reachable

- Identify the specific struct field that the OOB bytes land on. Name it (e.g., `msgpack_zone_finalizer.func`, `Object::vtable`, `link_map::l_addr`).
- Demonstrate the field is consulted via indirect call, vtable dispatch, or callback. Trace the call path from corruption-site to sink-fire in source code with file:line refs.
- Harness binary, 3× deterministic invocation of the planted function pointer with planted data argument. Capture a side effect that proves it's the planted pointer (e.g., the planted address is `libc!system` and the planted data is a string the attacker chose).

### Rung 2 — live crash

- Real entry point of the live release binary (network port, file format parser, plugin loader). No LD_PRELOAD shim. No debug build.
- 3× deterministic crash, same signal, same stack frame at the inner-most fault.
- Capture stderr/stdout, signal info, brief stack trace. Negative control: same input WITHOUT the precondition (memory pressure, race, etc.) → binary survives.

### Rung 2.5 — adjacency + heap shape

- Measure the offset of the sink struct relative to the corrupted allocation at fault time. Should be deterministic per heap state (allocator, thread arena, recent allocation history).
- 3× deterministic measurement showing the same offset. If the offset varies, the chain has a heap-shape problem that must be solved before climbing further.
- Document the offset, the allocator version, the architecture, and any size-class constants the chain depends on (e.g., glibc chunk header bits for the target size class).

### Rung 1A — live RIP control

- Live release binary, network-delivered, attacker-chosen function pointer fires.
- 3× deterministic observable side effect — preferred order: command output captured in target's stdout/stderr/log, OOB callback (HTTP/DNS), file written to a known path. The side effect must be one the attacker chose at payload-build time.
- The pointer planted must be **derived per-cycle** (not hardcoded). If addresses are hardcoded, the chain is brittle to ASLR; document that.

### Rung 0 — no-assist

- Every LD_PRELOAD-injected condition has a production-equivalent network-only or deployment-realistic primitive proven separately.
- Every `/proc`-read primitive has a network-only equivalent (info-leak via response echo, signal-handler self-leak via captured stderr, brute-force on bounded entropy, etc.).
- Composite chain runs end-to-end with **none** of the lab assists, 3× deterministic. Negative controls confirm each removed assist isn't quietly substituted by something else.

## Lab Assists and Production Equivalents

A "lab assist" is anything in the PoC that does not generalize to the target's production deployment: LD_PRELOAD shims, debugger attachment, `/proc/PID/maps` reads from the attacker, hardcoded ASLR bases, manual interrupt-and-resume, kernel parameters that aren't deployment defaults.

For every assist present in the PoC, document:

1. **What the assist does** in the PoC — exact mechanism (e.g., "fault-injects `malloc(N)` to return NULL").
2. **What the production equivalent is** — the network-only or deployment-realistic primitive that achieves the same condition (e.g., "Kubernetes cgroup memory cap at Helm chart default + attacker-controlled allocation pattern saturates the heap; the same `realloc` returns NULL naturally").
3. **A negative control proving the production equivalent suffices** — a 3× deterministic reproduction of the same condition without the assist.
4. **An honest acknowledgment if the production equivalent is unproven** — say so. "Plausible but unverified" is acceptable disclosure; "proven equivalent" without the negative control is not.

A disclosure that ships with assists undisclosed gets downgraded by triagers as soon as they notice. A disclosure that names every assist and its production equivalent gets believed.

## Output Contract

A heap-RCE finding using this skill's framework includes, in its evidence bundle:

| Item | Where it lives |
|------|-----------------|
| Rung-ladder status table | Top of the finding's writeup, one line per rung with status + evidence pointer |
| Per-rung evidence directories | `tools/exploit-state/<slug>-rung-1/`, `-rung-1b/`, `-rung-2/`, `-rung-2.5/`, `-rung-1a/`, `-rung-0/` (or merged if rungs share artifacts) |
| Calibration constants table | Allocator version, architecture, size-class constants, offset measurements — all values empirically measured, not assumed |
| Lab-assist disclosure | For every assist in the PoC: mechanism, production equivalent, negative control reference |
| Three deterministic replays per claimed rung | At minimum, the highest claimed rung has 3× deterministic evidence |
| Negative controls | For Rung 2 and above, controls demonstrating the precondition is necessary |

The rung-ladder status table is the document a triager reads first. If the highest-claimed rung is Rung 2 (live crash), the chain is a DoS, not an RCE — write the finding as a DoS regardless of the underlying primitive's RIP-control potential.

## Severity Calibration Against Rungs

CVSS framing should match the highest proven rung:

- Rung 1 / 1B only (primitive + harness sink) — claim CWE-787 / out-of-bounds write with "exploitability theorized." CVSS 6.5–7.5 (high) depending on attacker context. Do not claim 9.x.
- Rung 2 (live crash) — DoS chain. CVSS up to 7.5 (AV:N AC:L/H A:H, no C/I impact).
- Rung 2.5 (live adjacency) — DoS + RCE structurally complete. CVSS 8.0–8.5 (AC:H) if RIP-control requires a separately-unproven primitive (timing window, info-leak).
- Rung 1A (live RIP control) — full RCE. CVSS 9.8 if the chain composes pre-auth with no improbable preconditions.
- Rung 0 (no-assist) — same CVSS as 1A, but disclosure framing shifts from "lab-assisted RCE with production equivalents documented" to "fully unauthenticated network RCE." Triagers weight Rung 0 chains higher.

If a triager pushes back on a 9.x claim, the rung ladder is the document that defends the score. If you can't point to Rung 1A evidence for a 9.8 claim, the score is overstated.

## Methodology Notes

- **Climb rungs in order.** Skipping a rung because the next one seems easier almost always produces a chain with a hidden assumption. Rung 2.5 (adjacency in the live heap) is the most commonly skipped rung, and the most common source of overstatement.
- **Save artifacts per rung in a separate directory.** Rung evidence ages differently — a Rung 1 ASan report stays valid across allocator upgrades, but Rung 2.5 adjacency data is glibc-version-specific. Separate directories make staleness obvious.
- **Use the same payload across rungs whenever possible.** If the Rung 2 crash payload and the Rung 1A RIP-control payload differ, the chain has a hidden discontinuity that a triager will surface.
- **Reuse instrumentation across rungs, not bug knowledge.** Calibration constants (offsets, size-class bits, ASLR bases) are bug-specific; instrumentation (LD_PRELOAD harnesses, supervisor restart loops, log capture) is reusable across heap-RCE chains.

## Extended Resources

- `agent/skills/exploit-playbook-authoring/SKILL.md` — playbook conventions; reference this for the per-rung replay scripts
- `agent/skills/code-vulnerability-analysis/SKILL.md` — used at Rung 1B to trace the corruption-site-to-sink call path
- `agent/skills/code-finding-verification/SKILL.md` — used when the rung-ladder status table is generated as part of adversarial re-verification
- `agent/agents/exploit-developer.md` — the role that builds the rung evidence
- `agent/rules/reporting.md` — disclosure-language rules; per-rung status feeds the "Steps to Reproduce" and "Evidence" sections of the finding
