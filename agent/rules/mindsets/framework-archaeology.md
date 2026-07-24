# Framework Archaeology

This lens is for **generating the hypothesis list before you probe anything**, and for **re-opening
verdicts other people already closed**. Load it alongside the baseline (`hunting.md` +
`adversarial-mindset.md`), and alongside `developer.md` when the dispatch asks you to originate
your own ideas rather than test a named one.

Where `developer.md` asks *"what was the developer assuming when they wrote this?"*, this lens asks
two different questions: *"what exactly is this thing built out of, down to the version?"* and
*"under what conditions was that old negative actually measured?"*

## Why this exists

A generic vuln-class brainstorm produces ideas that are plausible in the abstract and worthless
against a specific program's severity model. On one engagement a 36-idea list drove 12 dispatches
and returned exactly one Low — not because the target was hard, but because every idea was a
same-org authorization variant, a class that program capped at Low by policy. The list was not
lazy. It was **mis-aimed**.

The corrective is to derive hypotheses from the *actual stack* and weight them by the *actual
severity model*, then to treat every prior "dead" verdict as scoped to the conditions it was
measured under.

## Part 1 — Ground the hypotheses in the real stack

**Fingerprint to a version, not a name.** "Rails" generates nothing. "Rails + a JSON:API layer +
an in-house vertex/action authorizer + Doorkeeper + ActiveStorage/MiniMagick + an EOL rich-text
editor pinned at a 2017 build" generates real, testable hypotheses. A version pin converts
*"is there an XSS?"* into *"does this sanitizer version have a published bypass, and is this
deployment inside its window?"*

**Name the developer assumption before you name the bug.** Write down the belief the code embodies
— *"a request's organization is unambiguous"*, *"it's signed, therefore it's authorized"*, *"the
filter allowlist is the security boundary"*. The vulnerability is that assumption's failure mode;
the payload is an implementation detail that follows from it.

**Prefer in-house components over famous ones.** A bespoke realtime bus, an internal query runner,
a homegrown capability-token library, a private deploy tool — these have no CVE feed, no public
research, and no hardening from outside scrutiny. Named third-party components have all three.
Hunt where nobody else has looked.

**Decode before you brute-force.** When something looks like an opaque token, spend the *offline*
effort to learn what it actually is. Two load-bearing "secrets" on one engagement turned out to be
semantically meaningful low-entropy values — one was a gem's documented `Marshal`-over-HMAC format,
the other was literally the organization's creation timestamp, publicly readable. Both fell to
analysis, not traffic. Entropy analysis over a corpus of captured tokens costs zero requests and
routinely kills or confirms a whole lead.

**Mine first-party client bundles as design documents.** Route tables, capability flags, feature
gates and developer comments describe the *server's* model. A comment reading `// symmetric with
<server_file>` is a map. This produces zero target traffic and is where most leads originate.

**Read the severity model first and weight by it.** Enumerate where High/Critical actually lives
for this program, and de-prioritise whole classes that cannot reach those bands however elegant the
bug. Then invert it: for each confirmed finding, the two axes that raise severity are usually
**PR** (what is the *lowest* role that reaches this?) and **C** (what is the *most sensitive field*
it returns?) — not a new endpoint.

## Part 2 — Every negative is scoped to its measurement conditions

This half is where most of the recoverable findings live, because closed verdicts are rarely
re-read.

**A verdict inherits the conditions it was measured under, and nothing more.** A negative measured
same-org says nothing cross-org. A severity floor measured on one product's role ladder says
nothing about another's. A test that probed one endpoint per role says nothing about the other
eleven endpoints. Record *conditions*, not just outcomes — and when you read someone else's
verdict, reconstruct its conditions before trusting it.

**Blocked-technique records rot.** Each one encodes a fact that was true once: an identity that did
not exist yet, a fixture nobody had built, a role that could not be granted. Re-derive the premise
before accepting the block. On one engagement a single stale sentence — *"product not provisioned
for this user"* — hid an entire product's attack surface for weeks after a second identity had
gained access to it.

**A test that never reached the handler is not a negative.** Watch for: foreign-object tests using
ids that do not exist (they 404 at record lookup *before* authorization runs); tests run against an
account owning zero of the target object, so no positive control ever existed; edge/WAF blocks
recorded as application verdicts; and a wrong-route 404 read as a denial. Each of these produces a
"clean negative" that is structurally incapable of being one.

**Bracket every negative with a live positive control** on the same route, verb, identity and
gateway, in the same window. Without it you cannot distinguish "denied" from "blocked", "not found",
"not provisioned", or "not reached".

**Adjudicate on body content, never on status code alone.** A `200` that returns *your own* object
is not a bypass. A `403` from an edge appliance is not an authorization decision. A `500` means the
request reached the handler and crashed — which is a lead, not a wall.

**A wrapper is not a render. Push through to the artifact the feature actually produces.** The most
expensive negative on one engagement was a report-rendering surface filed as *"empty render,
correctly scoped"* on the strength of a 1.3 KB response — which was the *iframe wrapper*, not the
report. No render had ever been reached, so no authorization decision had ever been measured. Mining
the page source for the real route did show authorization enforced — but following the redirect that
a successful render issues led to an **unauthenticated** PDF service on production infrastructure the
engagement had never touched. Generalise it: when a feature's output is a document, PDF, export,
email, job result or rendered page, a negative measured on the *request* rather than on the *produced
artifact* has not measured the feature. Follow the redirect. Open the file. Read the generated bytes.
The interesting authority is often the one at the far end of the pipeline, and it is frequently a
different service with a different — or absent — auth model.

**Verify the effect, not the acknowledgement.** An operation can succeed structurally while being
empty of the thing you actually needed, and every surface check will pass. Two instances from one
engagement, one day apart: a re-verification returned HTTP 200 with a response byte-identical
between a privileged and a denied identity — perfect-looking proof — except the async cache had not
filled yet, so **no data had crossed at all**; and a write to clear a stale field returned success
without clearing it, leaving a report pointing at an artifact that was deliberately not attached.
A 200 carrying nothing and a write changing nothing both pass every check except *did the thing I
wanted actually happen?* Re-read the artifact, not the API's acknowledgement of it.

**The shared trigger is worth naming, because it predicts where this bites:** in every instance
*the check was cheap and the thing being checked was expensive*, so the cheap signal got trusted.
A one-line `grep` stands in for "did foreign data survive the import." A render command stands in
for "did my write land." A status code stands in for "did the authorization boundary hold."

**The habit that catches it: before reading the output, ask what a FALSE result would look like.**
One engagement ran `grep ATTENDEE` against an import result, got a hit, and nearly upgraded a
finding on it — the pattern had matched the lane's *own event name*. If the check can match
something you put there yourself, it cannot answer the question, and you know that before you run
it rather than after. When a result looks unusually clean, that is the moment to ask what it would
look like if the operation had silently done nothing.

**Attribute a rejection to the right control before you build on it.** A response tells you that you
were refused, not *why*. One engagement recorded a `401` as a CSRF rejection and left two whole
privilege ladders unmeasured for days; it was actually a per-product access gate — reproducible with
a plain tokenless GET, and it cleared the instant the identity held any tier in that product. The
distinction was decisive: a CSRF wall is a technique problem you route around, while an access gate
is a *structural* fact about how privilege bootstraps — and that fact turned out to be the reason an
entire finding family's severity floor held. Name the control you believe refused you, then falsify
that attribution with a probe that isolates it.

## Part 3 — The tell worth hunting for

**Two authorities disagreeing about the same identity, in the same window.** When subsystem A says
*"this principal may not read X"* and subsystem B hands X over, you have a confused deputy and the
evidence is self-proving — no argument required, because the target's own code contradicts itself.

This generalises far past authorization. Look for any two components that independently derive the
same decision: a permission model and a search controller; an API gateway and a web route; a
sanitizer at write-time and a renderer at read-time; a client-side gate and its server counterpart.
Where two derivations exist, one of them is usually wrong, and the disagreement is both the finding
and the proof.

## Working rhythm

1. Fingerprint the stack to versions; list the in-house components separately.
2. Write the assumptions the design embodies, one line each.
3. Read the severity model; weight and prune.
4. Pull the prior verdicts for the surface and reconstruct each one's measurement conditions.
5. Probe where an assumption and an unmeasured condition intersect.
6. Bracket everything with positive controls; adjudicate on bodies.
