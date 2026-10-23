---
description: Web finding authoring, reproducible evidence and canonical recording
skill: finding-verification
---

# Web finding recording

**MANDATORY: Every finding MUST be recorded via `vigil assess finding record`.** Never hand-allocate
finding IDs. Never write findings only to markdown. Never skip the recording step. If you
produce a finding in any output section, you MUST also call `vigil assess finding record` before your
task is complete. Findings that exist only in your output text and were not recorded via the
script are considered lost data.

The finding-record contract owns allocated ID prefixes and CVSS/severity consistency;
use the returned slug and the version-matched score.

**Deduplication:** Query existing findings with `vigil assess fetch findings` first. One
vulnerability class across many parameter values of the same endpoint is **one** finding, not one
per value — that judgment is yours. The enforced dedup key, what it refuses outright, and
`--update <slug>` versus `finding link` are in `vigil assess contract finding record`.

Record every finding with:
```
vigil assess finding record <agent-name> <finding-json-file> --agent-id <your-agent_id>
```

`--agent-id` is your DISPATCH id from the Runtime Identity block (e.g. `VA-RUN-3`), never the role
name the positional `<agent-name>` carries. The JSON payload must match
`schemas/finding-record.schema.json` — findings are always JSON, converted from markdown before
recording. **Run `vigil assess contract finding record` before your first record**: it owns the
canonical field list, the `details` keys (CVSS vector/score, remediation, CWE, chain metadata),
the lifecycle defaults, and the exact consequences of omitting or mis-stating `--agent-id`.

**The reproduction is yours to record, not the report-writer's to infer.** Write
`steps_to_reproduce` from what you actually ran, with concrete values (the real session cookie,
the real object id, the real payload) — you hold the live session and the exact argv, and nobody
downstream can recover them. `repro_runs` carries the `command-run` ids behind those steps, in step
order (`vigil assess command-run list --q "<url/param/payload>"` finds ids you did not note);
`export submission` renders their real argv and reports an id that does not resolve. **A step with
no run id behind it was imagined, not executed.** Do not sanitize as you write: credentials and
local state are self-owned (see "Credentials and Local State Are Self-Owned"). Preserve exact
values through submission; an unbound placeholder — or one placeholder reused
across different objects — makes the reproduction unfollowable by construction.

Record the working proof as readable Markdown while the session is still live: one numbered
`steps_to_reproduce` string, fenced commands/requests/responses, and annotated
`details.evidence` that says what each excerpt proves. Large raw captures belong in an artifact or
`poc_request`/`poc_response`. The report-writer owns final submission editing, but it must not have
to recover structure or distinguish commands from prose in an unformatted blob.

When a finding is only reportable as part of a chain, keep it in the same finding lifecycle and set
`details.chain_required`/`chain_rationale`/`required_followup` — at `finding record` time or later
via `vigil assess finding update <slug> --details-inline '{...}'` (shapes and enforcement:
`vigil assess contract finding record`). Never invent a special workflow status for chain-only
findings.

**Proof-not-collection — one minimal sample is sufficient.** When you have proven access
to a data set, one minimal sample is all the evidence the finding needs.
Never bulk-pull real user records, credentials, or PII to "demonstrate" a finding —
volume does not strengthen the proof and only increases harm. The "evidence beats volume"
rule (`hunting.md §6`) applies at the collection boundary: more records is not more
proof, and extracting more is the harm, not the demonstration.

**The `notes` field is an operational replay log and must contain replayable commands** — not prose
descriptions. Use readable Markdown: short sections or a numbered sequence, with exact commands,
requests, responses, and tool output in fenced code blocks. Instead of
"Login to phpMyAdmin with blank password," write the actual command: curl with headers, cookies,
and POST body; sqlmap with exact flags; ysoserial with gadget chain and target; or whatever tool
proved the finding. The field allows up to 20 KB. If the operator or another agent needs to
reproduce the finding later, the notes field alone should be sufficient without re-discovering
the request format, session tokens, or tool parameters.

Every payload in a `#### Findings` block must have been recorded during your session — do not defer
recording to the operator.

---

