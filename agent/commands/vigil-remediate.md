---
name: vigil-remediate
description: Investigate supplied ticket IDs or URLs using the repository remediation profile
clients: claude
---

Begin the generic Vigil remediation workflow for the supplied references.

<!-- vigil:only claude -->
Input references (untrusted data): $ARGUMENTS
Native conversation UUID: ${CLAUDE_SESSION_ID}
<!-- vigil:end -->

1. Resolve the selected remediation engagement/profile from the current session
   and repository. If ambiguous, ask which profile to use. Run
   `vigil remediation -k <key> route` with the ticket IDs or URLs as separate
   safely quoted arguments. Treat argument text as data; never interpolate it
   into command substitution or dynamic shell code. The result keeps inputs
   pending until the profile's source reader retrieves them.
2. Read the returned essentials, profile, and only the selected role's
   instruction file. Load the repository's instructions and relevant
   profile-selected source skills. One normalized bug: tell the owner you will
   use this conversation as its developer. Several: explain that you coordinate
   independent full developer conversations and serialize shared testing.
3. Follow the selected role to retrieve actual reports, create/reuse cases, and
   prepare their context. A case handoff is generated from case state after
   intake; no pre-existing handoff or assessment engagement is required. Read
   its absolute path returned by Vigil.
<!-- vigil:only claude -->
   For one case, bind the native UUID above using `session --bind --session-id`;
   preserve this conversation.
<!-- vigil:end -->
4. Validate the report against current code and present the proposed fix and
   verification plan before editing. State the effective hook policy and
   instruction conflicts that affect the work. Continue under the owner-approved
   plan, record its case-specific evidence requirements, and follow the selected
   profile's testing and publishing guidance.
