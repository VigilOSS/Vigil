# ADR 0019 — Vigil does not defend against its own operator

- Status: Accepted
- Date: 2026-09-11

## Context

Vigil is operator-run tooling. It executes on the operator's own machine, under
the operator's own account, against targets the operator is authorized to test,
using credentials the engagement itself provisioned. Every byte it stores was
either produced by the operator or captured from a target the operator is
permitted to attack.

There is no adversary on the operator's side of that boundary. An operator who
can open the run-audit view can also open the commands view, read the SQLite
database, `cat` the artifact files, and run `vigil auth export`. Nothing is
withheld from them by any mechanism, and nothing sensibly could be.

A masking layer was nevertheless built for the run-audit UI. It cost real
evidence fidelity and bought nothing. A greedy end-of-line pattern applied to
free-text audit fields truncated whole records:

    in : curl -H 'Cookie: sess=abc' https://target.test/private -o out.bin
    out: curl -H 'Cookie: [masked]

The target URL, the output path and the rest of the analysis were destroyed —
in an audit view whose entire purpose is faithful reconstruction of what ran.
The same layer masked nothing at all on `sh -c '…'` argv, which is the exact
shape Vigil's own identity-header injector produces, so the forms most likely
to carry live credentials were the ones it missed. Both defects passed a green
test suite that included nine assertions which could not fail.

That outcome is not a bug in one regex. It follows from applying a
confidentiality control where there is no confidentiality boundary: the control
has no true positive to find, so only its false positives are observable.

## Decision

**Vigil does not hide, mask, redact, truncate, summarize or otherwise degrade
its own data on the way to the operator or to an operator-dispatched agent.**

Credentials, tokens, cookies, `Authorization` headers, proxy URLs, signed-URL
signatures and raw argv render verbatim in the frontend, in CLI output, in
`--json` output, in agent-readable stdout, and in exports. This is expected
behavior, not a leak, and it needs no reveal toggle, profile or opt-in.

Do not add:

- masking, redaction or `[masked]`/`***` substitution in any renderer or export;
- "sensitive value" detection, key-name allowlists or secret-shaped regexes;
- reveal/unreveal toggles, redaction profiles or per-view confidentiality modes;
- projections that reduce a real value to a length, prefix or shape (for example
  `Bearer (length=40)`) on any path an operator or agent reads.

A future change that proposes one of these must first name the adversary it
excludes and explain what that adversary can reach without it. On present
architecture there is no such adversary, so the answer is that the control is
theater and the evidence cost is the only real effect.

### What this ADR does not touch

Three existing controls are security mechanisms with a real adversary and a real
boundary. They are explicitly out of scope and must not be removed, weakened or
deleted by citing this ADR:

1. **Engagement-policy enforcement** (`exploit_policy: pause`, tool denylists,
   required scope declarations, and scope-backed recon/attribution/coverage).
   These controls keep the operator workflow aligned with the recorded ROE.
   They do not form a destination firewall: an undeclared host in an argv is not
   rejected, because custom clients, raw sockets, and dynamic code make lexical
   destination admission incomplete. Authorization and destination discipline
   remain the operator's responsibility. An earlier revision of this list also
   named `scope-check.sh` and its destructive-command blocks here. That was
   wrong on the facts: every filter in that hook guarded the operator's own
   machine, not a third party, and the hook has since been removed (see below).
2. **Proof and evidence integrity** (artifact digest revalidation, receipt
   health, transactionally immutable producer attribution, terminal-state
   immutability). These make evidence *trustworthy*. They add information rather
   than removing it, which is the precise inverse of masking.
3. **The untrusted-target-text boundary** (ADR 0018). The adversary is the
   target, whose text can carry instructions for an agent or forge structure in
   an export. Prompt-facing renderers delimit it and receiving instructions deny
   it authority; HTML, Markdown, link, image, and export renderers keep their
   technical containment. This does not require repetitive visible warning labels
   in the operator frontend, and it never deletes or rewrites the underlying data.

### PreToolUse command-filtering hooks are not reintroduced

`scope-check.sh` was a `PreToolUse` hook that string-matched every shell command
against four destructive shapes. It is removed and must not come back in that
form. Two separate reasons, and the second is the one that settles it.

It did not do what this ADR claimed. All four filters protected local state from
the operator's own agent. That is a defensible goal, but it is not the
third-party boundary the list above is for.

And it could not do it. A command filter that reads a command *string* is
defeated by every ordinary way of spelling the same command. Measured against
the shipped hook: `rm -rf /tmp/x` blocked, `bash -c "rm -rf /tmp/x"` allowed;
`git clean -fd` blocked, `eval`/`sh -c`/`$(echo git)`/a `subprocess.run` list all
allowed. `find . -delete` and `git reset --hard` were never covered at all. This
is the same wrapped-shell blind spot that condemned the masking layer described
above, and it is not a regex bug: string matching cannot see through the shell.

The cost was not theoretical either. The `git clean` guard alone grew to 40% of
the file and produced two defects — one that missed four of six flag orderings,
one that silently disabled the guard for every repository path containing a
space. Both passed review. A guard whose failure mode is *silence* is worse than
no guard, because it is trusted.

A future agent-error guardrail must therefore act where the command is executed
rather than where it is spelled — the client's own permission layer, or a
constrained execution surface Vigil owns. [Issue #35](https://github.com/vigil-oss/vigil/issues/35)
carries the scoping.

The distinguishing question is always the same: *who is the adversary, and what
does this stop them reaching?* If the answer is "the operator, from their own
data", it is theater. If the answer names the target or a non-consenting third
party, it is a control and it stays.

## Consequences

- Audit and command views reconstruct exactly what ran, with no lossy rewriting
  between the record and the reader.
- No masking test suite to maintain, and no class of bug where a pattern eats an
  argument that carried finding-relevant signal.
- Credentials appear in screenshots, screen shares and recordings of the
  frontend. That is the operator's judgment call about their own screen, the
  same as any terminal. It is not Vigil's to make.
- This supersedes the closing line of ADR 0018's Consequences, which anticipated
  UI masking and export redaction as separate presentation choices. They are not
  available choices. ADR 0018 retains prompt and rendering containment while making
  clear that ambient frontend warning labels are not a security boundary.

## Alternatives considered

- **Fix the masker instead of deleting it.** Rejected. The truncation and the
  wrapped-shell bypass are both repairable, but repair leaves a permanent
  maintenance surface and a permanent risk of eating evidence, in exchange for
  concealing data from someone who can read it by four other routes.
- **Mask only on agent-readable paths, to keep credentials out of model
  context.** Rejected. The agent operates the engagement with those credentials;
  withholding them causes real failures, and token economy is a budgeting
  concern to solve by not dumping whole identity maps, not by corrupting the
  values that do get printed.
- **Keep masking behind an off-by-default flag.** Rejected as the worst option:
  the full maintenance and evidence-corruption surface, plus a second code path
  that nothing exercises.
