---
name: athena-log-investigation
description: Use Athena-backed logs as an optional final validation phase to determine whether discovered attack paths or payloads show evidence of prior exploitation.
---

# Athena Log Investigation

Use this skill after meaningful findings exist and Athena-accessible logs are available.

Best fit:
- AWS Athena over ALB, WAF, CloudTrail, application, or custom security logs
- validating whether a discovered path or payload family was already used
- answering "has this been exploited before?" before final report closure

## Inputs

Before using this skill, collect:
- affected hosts, paths, endpoints, and parameters
- auth contexts or identity markers involved
- payload families, strings, user agents, callback domains, and IPs used during testing
- Athena database, table, region, and time window

## Investigation Goals

Answer one or more of:
- Is there historical evidence of the same path or exploit attempt?
- Did anyone hit the vulnerable route with the same payload family?
- Are there suspicious spikes, enumeration patterns, or attacker-like sequences?
- Did exploitation appear to succeed or only get attempted?

## Query Strategy

Start broad, then narrow:

1. Search by route or host:
   - vulnerable hostnames
   - exact paths
   - path prefixes when variants exist

2. Search by payload indicators:
   - suspicious query parameters
   - payload fragments
   - callback domains
   - blind OOB markers

3. Search by attacker behavior:
   - repeated enumeration from one IP
   - bursts across many object IDs
   - auth failures followed by success
   - exploit path followed by admin or data-exfil routes

4. Search by chain timing:
   - precursor recon
   - exploit request
   - post-exploit follow-up requests

## Output Requirements

For each meaningful result, record:
- the finding or attack chain being investigated
- the log source and Athena table
- the time window searched
- the exact query used
- the conclusion:
  - `evidence of exploitation`
  - `evidence of attempts only`
  - `no evidence in available logs`
  - `inconclusive due to data gaps`

## Reporting Guidance

Do not overstate certainty.

Use this language model:
- `Confirmed in logs` when exploitation evidence is strong and attributable
- `Likely seen in logs` when behavior strongly matches but proof is partial
- `No evidence observed in available Athena logs` when nothing surfaced in the searched window
- `Could not determine` when retention, schema, or access blocked a meaningful search

When this affects finding state, prefer these report outcomes:
- `exploited in the wild`
- `likely exploited`
- `no evidence in available retention`
- `inconclusive due to coverage gap`

## Phase Placement

Treat Athena as an optional final phase:
- after recon, collection, validation, and exploit work
- before final report closure
- after checking whether the strongest findings or chains deserve log validation

It should enrich the report, not replace technical validation.
