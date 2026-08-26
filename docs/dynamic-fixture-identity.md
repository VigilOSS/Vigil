# Dynamic fixture identity for engagement PoCs

Use the local manifest contract when a PoC creates or observes an organization,
person, subscription, or related session fixture. The manifest records IDs and
provenance only; cookies and tokens stay in the existing credential store.

```bash
printf '%s\n' '{"data":{"type":"Organization","id":"org-created"}}' \
  | vigil assess fixture observe org3.admin \
      --manifest scans/fixture-identities.json --json
vigil assess fixture resolve org3.admin.organization_id \
  --manifest scans/fixture-identities.json
```

`fixture observe` extracts recognized typed JSON:API IDs and explicit
`organization_id`, `person_id`, and `subscription_id` aliases. It rejects
ambiguous or non-scalar IDs, refuses to overwrite a changed binding unless
`--replace` is explicit, and saves atomically. `fixture resolve` accepts names
containing dots, so the final dot separates the field (`org3.admin` is a valid
alias).

Migration rule: after the create/login response, run `fixture observe` under a
stable alias; replace every hard-coded object ID, host tenant ID, and session
fixture path in later requests with `fixture resolve` (or the equivalent
`FixtureManifest.require` call). Keep the alias scoped to the session/fixture
owner, and use a fresh alias when testing rotation rather than silently
reusing an old binding.

## Active PoC migration backlog

The Acme Planner engagement under the installed Vigil working root is
separate from this canonical source checkout. The following engagement-local
files remain migration work; they were intentionally not edited here:

- `scripts/ex006_pwn.py` and `scripts/ex006_generalize_verify.py`: frozen
  organization anchors and core-secret/person IDs.
- `scripts/ex006_lab_victim.py`: fixed `scans/acme_session_org2_admin.json` and
  `scans/org2_csrf.txt` paths.
- `scripts/jolt_workflow_xtenant_0725c.py` and
  `scripts/jolt_people_workflow_subscribe.py`: fixed organization pair and
  legacy channel/subscription IDs.
- `scripts/ccwrite0731_services.py` and `scripts/ccwrite0731_directory.py`:
  fixed tenant hosts and person IDs.
- `scripts/va119_testb_subscribe_handshake.py`,
  `scripts/va119_passive_people_channel_retest.py`, related Jolt/VA119
  scripts, and `scripts/mo0728_webhooks.py`/`scripts/webhook_*`: fixed
  org/person/subscription IDs and session/fixture paths.

Migrate these in risk order: session/CSRF paths, Jolt/VA119 cross-tenant
organization and person IDs, webhook subscription/object IDs, then ex006 and
ccwrite calibration constants. This change supplies the shared primitive and
CLI; it does not claim those engagement artifacts are migrated.
