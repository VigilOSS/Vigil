---
name: athena-log-investigation
description: Use Athena-backed logs as an optional final validation phase to determine whether discovered attack paths or payloads show evidence of prior exploitation.
origin: Vigil
---

# Athena Log Investigation

## When to Activate

- The operator dispatched the optional post-exploit log investigation (before final report
  closure) and AWS Athena reaches the target's ALB, WAF, CloudTrail, application or custom
  security logs.
- Confirmed findings or chains from Phases 4-6 raise "has this been exploited before?"

It enriches the report; it never replaces technical validation.

## Inputs

Affected hosts, paths, endpoints and parameters; auth contexts or identity markers; payload
families and strings; the Athena database, table, region and time window.

**Exclude Vigil's own traffic.** Pull the engagement's own egress IPs, user agents, attribution
headers and minted OOB hosts from `vigil assess command-run list --phase <phase> --json` and
`vigil oob poll --client <name> --json` per engagement client, and filter them out (or label them) in every query; otherwise the
engagement's testing reads as prior exploitation.

## Mechanics

The runtime holds no AWS credentials, so Athena calls are signed on the host:
`vigil assess host-exec --tool aws --technique LOG-READ --phase <phase> --intent "<question>" --
aws athena start-query-execution …`, then `get-query-results`. Keep queries bounded to the
window and partitions you need: Athena bills by data scanned.

## Questions and query shape

Start broad (host, exact path, path prefix), then narrow by payload indicators (parameters,
fragments, callback domains, OOB markers), attacker behaviour (enumeration from one IP, bursts
across object IDs, auth failures then success, exploit path followed by admin or exfiltration
routes) and chain timing (precursor recon → exploit → follow-up).

## Output

For each result record the finding or chain investigated, the log source and table, the window,
the exact query, and one conclusion: `evidence of exploitation`, `evidence of attempts only`,
`no evidence in available logs`, or `inconclusive due to data gaps`. Write it to the finding with
`vigil assess finding update <slug> --payload-file <file>` (query and conclusion in its notes or
details) and register exported result files with `vigil assess artifact register <paths>
--finding <slug>`; investigation-wide observations go to `vigil assess intel record note`.

Report phrasing matches certainty: "Confirmed in logs" (strong and attributable), "Likely seen in
logs" (strong match, partial proof), "No evidence observed in available Athena logs" (searched
window only), "Could not determine" (retention, schema or access blocked the search).
