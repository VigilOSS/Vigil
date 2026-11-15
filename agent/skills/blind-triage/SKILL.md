---
name: blind-triage
description: Blind pre-submission triage (phase 8 step d) that stops false-positive / overclaimed / over-severity submissions. It runs after the in-context reviews (writer authoring, independent report-writer QC, cold reproduction and claim check — Pass 1) on the same packet, as a decisive BLIND zero-context review (Pass 2, read ONLY the submission bytes, like a real Bugcrowd reviewer) that gates final export — anything other than Accept blocks submission. Run on EVERY Medium-or-above.
origin: Vigil
---

# Blind Triage — pre-submission review gate

## When to Activate

Run this gate on every Medium-or-above finding before it is submitted or published, to stop
false-positive, overclaimed, and over-severity submissions. It is step d of the per-finding closeout
in `agent/phases/phase-8-report.md`, which owns the order: the writer authors and builds the triage
packet (a) → an independent report-writer QC records `submission_qc_verdict` (b) → a cold verifier
records `repro_rehearsal`, then `claim_equivalence` when pending (c) → this blind triage on the same
packet (d) → final export (e).

Steps a–c are Pass 1. They have full engagement context and check the submission against its finding:
the `agent/references/submission-format.md` checklist (format, AI-tells, PoC hygiene, CVSS consistent
with the claimed severity, repro traceability, claimed-vs-proven impact), the QC review in
`agent/agents/report-writer.md` "Closing verbs (submission QC)", and the cold rehearsal. Pass 1
reliably catches presentation, traceability, and reproduction problems; it does not reliably catch
whether impact was actually demonstrated to a reader without context. Pass 2, this blind review, has
zero context and judges only the bytes an external reviewer would see. Keep them separate, because the
blind isolation is what gives Pass 2 its value.

## What the packaged rubric binds

`vigil assess export triage-packet` embeds this file verbatim as the packet's `## Verdict rubric
(verbatim)` section, digested under `inputs.verdict_rubric`. It binds the reviewer to the review
request, the verdict table, and the FP/overclaim bar below; that vocabulary and that bar are what the
reviewer answers in. The operator's sections — Pass 1 above, "Running the review", and "Gating rule" —
say what the operator does with the verdict and are not instructions to the reviewer;
`agent/agents/blind-reviewer.md` ("Your Return") holds that line.

## Running the review (operator)

**Build the packet.** `vigil assess export triage-packet <slug> [--attachment-id <id> ...]`, with
exactly the attachment IDs intended for export. Hand over bytes, not a path: the command prints the
packet directory and the reviewer makes no tool call, so paste `packet.md`'s contents into the
dispatch prompt and attach each file under `attachments/` to the launch message. A reviewer handed the
printed path has no submission to judge and no way to say so.

**Register the reviewer.** Before native launch, run `vigil assess agent start` with a fresh ID,
`--role blind-reviewer`, `--dispatch-mode deep-manual`, and `--no-target-traffic`, on the strongest
available model; the reviewer is neither the report-writer nor the analyst who found the issue.
`blind-reviewer` is the registered zero-context reviewer role (`agent/agents/blind-reviewer.md`): its
`## Load First` is empty by design, while any investigative role's packet orders it to read its role
file and mandatory references, which carry engagement-shaped instruction this reviewer must not have.
Bind the returned native handle to that registered ID.

**Name no skills on this dispatch, not even this one.** `agent start` turns each named skill into an
order to read its repository path ahead of the packet, which on the one role that must open nothing is
an instruction to read the repository; naming this skill would also hand the reviewer the operator's
half of the gate. `export triage-packet` already packages this file as the rubric, and `blind-reviewer`
is exempt from the skill-audit requirement for this reason, so `agent start` asks for no skills and warns
about none, and the handoff written from the return names none either.

**Keep the first pass blind.** The reviewer receives the program brief, the rubric, the external
submission body, and the selected attachments: no OPERATOR DETAILS and no other engagement state. A
claim not proven inside those bytes is unproven for triage purposes. Packet generation records
`process_isolation_enforced=false`: it proves which bytes were packaged, not what the reviewer's
process could reach, so that isolation is the operator's responsibility. After a recorded miss the
reviewer may inspect the canonical finding solely to diagnose the gap; the writer or analyst makes the
correction, then a fresh packet and a fresh blind reviewer judge the changed submission.

**Record the verdict.** After the reviewer returns the table, record one decision row per finding,
naming the reviewer dispatch and the report-writer dispatch that authored the reviewed packet. Both
must be recorded dispatches of this engagement, and the reviewer must differ from the finding author
and the writer. These identities establish attribution; native context isolation stays the operator's
and reviewer's responsibility, not a backend-proven fact.

```bash
vigil assess agent decision --kind blind_triage_verdict --payload-json \
  '{"finding_slug":"<slug>","packet_id":"<64-char packet id>","reviewer_dispatch_agent_id":"<reviewer-id>","writer_dispatch_agent_id":"<writer-id>","verdict":"<Accept@P1..P5|Need-More-Info|Not-Applicable-Informational|Out-of-Scope|Duplicate>","claimed_severity":"<sev>","weak_points":"..."}'
```

Then preserve the reviewer's actual reasoning, weak points, uncertainty, and suggested next tests in
the handoff fields and run the ordinary `agent close` sequence for that reviewer; do not reduce its
return to the word `Accept`.

## Gating rule

`vigil assess transition-phase complete` blocks with `missing_blind_triage` for any Medium-or-above
finding in a submittable workflow state whose latest verdict is not `Accept@P1`..`Accept@P5` on a
packet, so an unrecorded verdict reads the same as no triage. Final export also checks that the latest
Accept's packet covers the current external body, selected attachments, platform, program brief, and
rubric; any changed input needs a new packet and review.

Any verdict other than `Accept` (at any priority) blocks submission. Route the finding back to the
report-writer or operator with the reviewer's weak points, fix or kill it, and send the rebuilt packet
back through QC and a new blind pass, recording the new verdict.

## Review request (verbatim in the dispatch prompt)

> You are an independent bug-bounty triager. You have ZERO context on how this
> finding was produced. Read ONLY the submission text below — do not read any
> repository file, do not run any command, do not query any database, do not
> assume anything not proven in these bytes. Here are the program brief facts
> [in-scope assets / triage bar / severity-band policy]. Here is the submission
> [the `.md` bytes]. Judge it as a real reviewer would: is the impact actually
> demonstrated in what you can see, at the severity claimed?

## Verdict table

The reviewer returns:

| Field | Value |
|---|---|
| **Verdict** | one of: `Accept@P1` / `Accept@P2` / `Accept@P3` / `Accept@P4` / `Accept@P5` / `Need-More-Info` / `Not-Applicable-Informational` / `Out-of-Scope` / `Duplicate` |
| **Priority vs claimed severity** | the triaged priority next to the severity the submission claimed (and the delta) |
| **Triage reasoning** | why this verdict — what is proven vs. asserted in the bytes |
| **Weak points** | the specific gaps a real reviewer would push back on |

`P1`..`P5` is Bugcrowd's scale; for HackerOne, direct and GHSA submissions the reviewer maps the
program's own severity bands onto it (Critical→P1 … Informational→P5) so the recorded verdict stays
comparable.

## What this gate catches — recurring FP / overclaim patterns

The blind reviewer's bar. A submission that rests on any of these should not get an `Accept`:

1. **Self-induced precondition presented as real** — the attacker manufactured
   the trigger condition (disabled a protection they control, supplied their own
   input/id, set the state) and reports it as a naturally occurring weakness.
2. **Inference-based proof using fabricated IDs** — an IDOR/BOLA "proven" against
   made-up ids (`99999999`, `-1`, `abcdefgh`) instead of a **real cross-object
   read or write**. BOLA/IDOR must show a real object owned by someone else being
   read or written, not a `success` response to a garbage id.
3. **`C:L` with no actual data crossing the boundary** — a confidentiality claim
   where nothing sensitive actually crossed a trust boundary (opaque surrogate
   that resolves to nothing, existence/oracle-only signal, attacker-supplied
   value echoed back).
4. **Info-disclosure / stack-trace framed as Medium** — missing headers, stack
   traces, schema/version/path leakage dressed up as a Medium when it is
   informational unless it directly enables a proven higher-impact attack.
5. **Out-of-scope class in disguise** — a rate-limiting / DoS / third-party issue
   re-skinned as access control (or another in-scope class) to smuggle it past
   scope. Classify by the actual primitive, not the chosen label.
6. **"Useful for an attacker mapping internals" hand-wave** — "this would help an
   attacker map the system" with no proven exploit consequence is not impact.
7. **By-design behavior called a vuln** — anonymous/public-by-design flows (public
   intake, self-registration, password-reset *request*, public search) where the anonymity
   is the intended UX, not a bug.
8. **Documented capability with no proven boundary break** — the vendor's own docs
   describe the exact behavior demonstrated, and the submission does not show a
   boundary the docs mark as protected actually being crossed. "The docs say
   this is possible, and it sounds dangerous" is not the same as "the docs say
   this must not happen, and it happened."

## Cross-references

- `agent/references/finding-fp-and-severity-gate.md` — the in-context C1–C7 FP/severity-downgrade
  gate the vulnerability-analyst runs at verification; the same overclaim catalog applied earlier,
  with context. This blind gate is the late, zero-context safety net before submission.
