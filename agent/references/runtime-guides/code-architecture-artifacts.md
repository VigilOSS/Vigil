---
description: Code-architect appendix — call-graph.json and entry-chain artifact shapes with edge_type semantics, and the cve-bug-shapes.jsonl field rules
skill: code-architecture-mapping
---

# Code Architecture Artifacts

Load this from `agent/skills/code-architecture-mapping/SKILL.md` when you write
`tools/analysis-state/call-graph.json`, the ranked entry-point chains, or
`tools/analysis-state/cve-bug-shapes.jsonl`. The skill's steps stay authoritative; these are the
shapes. No verb validates the call graph or chains; `vigil assess code-history check-shapes` checks
the bug shapes.

## Call graph

One flat edge per entry:

```json
{
  "edges": [
    {
      "caller_func": "handle", "caller_file": "daemon.c", "caller_line": 887,
      "callee_func": "run_service", "callee_file": "daemon.c", "callee_line": 740,
      "crosses_trust_boundary": false,
      "untrusted_data_label": "client_addr, req_buf",
      "edge_type": "direct"
    }
  ],
  "entry_points": [],
  "critical_targets": []
}
```

`edge_type` is `direct`, `callback` (function pointer or registered callback), or `vtable`, on every
edge: it is the only signal that an edge was inferred through indirection and deserves lower
confidence. When type analysis determines an indirect call's possible targets, name them in
`untrusted_data_label` or a sibling note. An edge you could not resolve goes in `audit_metadata`,
not in the graph.

## Entry-point chains

```json
{
  "chains": [
    {
      "entry": {"function": "handle", "file": "daemon.c", "trust_level": "untrusted_network"},
      "path": [
        {"function": "run_service", "file": "daemon.c", "untrusted_data": ["client_request"]},
        {"function": "upload_pack", "file": "upload-pack.c", "untrusted_data": ["pack_request"]},
        {"function": "receive_needs", "file": "upload-pack.c", "untrusted_data": ["shallow_lines"]}
      ],
      "target": {"function": "assign_shallow_commits_to_refs", "file": "shallow.c"},
      "target_type": "integer_arithmetic",
      "boundary_crossings": 2
    }
  ]
}
```

The entry's `trust_level` supplies reachability, `target_type` supplies impact severity, and
`boundary_crossings` the third ranking factor (skill Step 12).

## Historical CVE bug shapes

`tools/analysis-state/cve-bug-shapes.jsonl` holds one compact JSON object per physical line:

- `shape_id`, `cwe`
- `affected_paths` — every entry is a file the fix changed
- `vulnerable_revision` and `fixed_revision` — `fixed_revision` is the fixing commit and
  `vulnerable_revision` its first parent, exactly as the cited `code-history diff` receipt records
  them
- `bug_pattern` and `guard_delta` — the vulnerable code and the added guard described in words,
  derived from the diff
- `evidence_refs` — the receipt and its patch

Run `vigil assess code-history check-shapes <jsonl>` and fix every reported line before handoff.
Omit the file when no shape has a cited vulnerable-to-fixed diff, or when `history_status` is
`unavailable`.
