# GF Pattern Drift Decisions

This file records the static bucket-review decisions behind `agent/scripts/assess/lib/classify_buckets.py`. Upstream GF pattern repositories are effectively stable; the Python classifier intentionally narrows URL triage to buckets that can route work-buffer items, so this rationale is maintained by review rather than a sync script.

## Current Intentional Python-Only Buckets

- `trust_surface` — path-only trust-boundary routes that upstream GF does not model directly. Keep this bucket because uploads, OAuth callbacks, reset flows, webhooks, imports, exports, downloads, previews, and render/convert flows are high-value even without parameter-key signal.

## Accepted Bucket-Expansion Decisions

- `idor` param-key + path expansion (2026-06): the original bucket was the thin upstream gf slice (`id,user,account,number,doc,email,group,profile,order,report`) keyed off parameter names only, with `Path patterns that match: None`. Expanded on two axes after a HackerOne/BugCrowd/CVE IDOR-tactics review:
  - **Param keys** broadened to the `*_id` family, tenant/org/workspace scoping keys (cross-tenant BOLA), generic object handles (`object_id`, `oid`, `uuid`, `gid`, `node`, …), domain objects (`invoice`, `payment`, `ticket`, …), and modern chat/agent refs (`conversation_id`, `thread_id`, `message_id`). These are object references an authenticated attacker can swap; the additions never *remove* a higher-weight bucket (idor weight 35 < rce/ssrf/sqli/lfi), they only add an idor route to the reason chain.
  - **Path-embedded ids** now matched via the `_PATH_OBJECT_REF_SEGMENT` regex in `classify_buckets.py` (numeric / UUID / long-hex segment), so `/users/1024/profile` and `/files/<uuid>` bucket as `idor` instead of dropping to the `path:` fallback. A regex (not a path-fragment substring list) was chosen so it generalizes to any collection name without enumerating routes. Accepted false-positive surface: numeric segments also match `/2024/...` year and `/page/2` pagination paths — tolerated because weight only affects ordering, never skip/include.
  - Regression tests: `test_classify_idor_path_embedded_numeric_id`, `test_classify_idor_path_embedded_uuid`, `test_classify_idor_expanded_param_key_workspace`, and `test_classify_non_object_path_is_not_idor` in `orchestrator/backend/tests/test_work_buffer.py`. Reference doc `gf-patterns/idor.md` updated to match.

## Upstream-Only Categories To Reassess Before Adding

- Secret or content-body categories (`aws_keys`, `base64`, `firebase`, `json_sec`, `strings`, `s3_buckets`) usually belong to body/artifact scanning skills such as `gau-triage`, not URL priority bucketing.
- Source-code categories (`go_functions`, `php_curl`, `php_errors`, `php_serialized`, `php_sinks`, `php_sources`) belong to source/code analysis rather than live URL dispatch.
- Infrastructure categories (`http_auth`, `interestingsubs`, `ip`, `servers`, `takeovers`, `urls`) may become separate recon or surface-collection signals, but should not be copied into `_BUCKETS` unless they produce a clear `work_items` dispatch cluster.
- `debug_pages`, `fw`, `meg_headers`, and `sec` need human review against existing `debug_logic`, `interestingparams`, and tool-output handling before becoming new buckets.

When adding a bucket, update `_BUCKETS`, add or update the matching `gf-patterns/*.md` reference, record the accept/skip rationale here when relevant, and add a focused classifier/dispatch regression test.
