---
description: Web finding authoring, reproducible evidence and canonical recording
skill: finding-verification
---

# Web finding recording

Record every finding with `vigil assess finding record` before your task ends. A finding that
exists only in your output text is lost: the backend allocates IDs under a lock, and every later
gate, verifier and report reads the recorded row. Findings are always JSON (converted from
markdown before recording):

```
vigil assess finding record <agent-name> <finding-json-file> --agent-id <your-agent_id>
```

`--agent-id` is your dispatch id from the Runtime Identity block (e.g. `VA-RUN-3`), not the role
name carried by the positional `<agent-name>`. `vigil assess contract finding record` owns the ID
prefixes, the CVSS/severity consistency check, the field list, the `details` keys (CVSS, remediation,
CWE, chain metadata), lifecycle defaults, the enforced dedup key, and what a missing or wrong
`--agent-id` does. Use the slug and score it returns.

**Deduplication.** Run `vigil assess finding list --search <endpoint path>` first. One vulnerability
class across many parameter values of the same endpoint is one finding, not one per value; that
judgment is yours. `--update <slug>` versus `finding link` is in the contract. When your lane reached
an already-recorded finding on its own and adds no new evidence, record
`vigil assess finding corroborate <slug> --dispatch <your agent_id> --reason '<how you reached it>'`
instead of a duplicate. A corroboration is an audited link, not proof: it never changes
verification status, and a verifier still needs its own receipts.

**The reproduction is yours to record, not the report-writer's to infer.** You hold the live
session and the exact argv, and nobody downstream can recover them. Write `steps_to_reproduce`
from what you actually ran, with concrete values (the real session cookie, object id, payload).
Put the `command-run` ids behind those steps in `repro_runs`, in step order;
`vigil assess command-run list --q "<url/param/payload>"` finds ids you didn't note, and
`export submission` renders their real argv and reports an id that doesn't resolve. A step with no
run id behind it was imagined, not executed. Keep exact values all the way through submission
(credentials and local state are self-owned, see `agent/shared-constraints.md` "Credentials and
Local State Are Self-Owned"). An unbound placeholder, or one placeholder reused across different
objects, makes the reproduction unfollowable.

Write the proof as readable Markdown while the session is live: one numbered `steps_to_reproduce`
string, fenced commands, requests and responses, and annotated `details.evidence` saying what each
excerpt proves. Large raw captures go in an artifact or `poc_request`/`poc_response`. The
report-writer edits the final submission, but it shouldn't have to recover structure from an
unformatted blob.

`notes` (up to 20 KB) is an operational replay log. It should hold the replayable commands
themselves, not a description: the curl with its headers, cookies and body, sqlmap with exact
flags, the gadget chain and target. Someone reproducing later should need nothing else.

A finding that is reportable only as part of a chain stays in the normal lifecycle with
`details.chain_required` / `chain_rationale` / `required_followup`, set at record time or later with
`vigil assess finding update <slug> --details-inline '{...}'`. There is no special status for it.

**Proof-not-collection — one minimal sample is sufficient.** Once you have proven access to a data
set, one minimal sample is the evidence. Bulk-pulling real user records, credentials or PII adds no
proof and is itself the harm (`agent/rules/hunting.md` §10).

Record every finding you report in a `#### Findings` block during your own session rather than
leaving it to the operator.
