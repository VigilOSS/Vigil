// Committed dev fixture used when the report template has NOT had real data
// injected (i.e. `npm run dev`, or opening dist/template.html directly). The
// shape matches the backend payload contract in types.ts exactly so the app
// renders identically in dev and production.
//
// Coverage: one engagement, 6 findings spanning critical→info, one root-cause
// group (root + sibling), the rest standalone, and two attack chains.

import type { ReportData } from "./types";

function f(partial: Partial<ReportData["finding_groups"]["standalone"][number]>) {
  return {
    workflow_status: "active",
    verification_status: "confirmed",
    references: [],
    steps_to_reproduce: [],
    ...partial,
  };
}

const rootFinding = f({
  report_id: "001",
  slug: "VA-001",
  title: "Missing authorization on shared API guard",
  severity: "critical",
  workflow_status: "exploited",
  canonical_location: "https://acme.example/api/v1/admin/users",
  summary:
    "The shared `requireAuth` middleware is registered **after** the admin router, so every `/api/v1/admin/*` route is reachable unauthenticated.",
  impact:
    "An anonymous attacker can enumerate and modify all user records, including elevating their own role to `admin`.",
  evidence_detail:
    "GET /api/v1/admin/users returned the full user table (HTTP 200) with no session cookie present.",
  remediation:
    "Register the authorization guard at the router root before mounting admin sub-routes, and add a regression test asserting 401 for an unauthenticated admin request.",
  // One authored block, numbered by the author — the preferred shape, kept here
  // so the dev preview exercises it alongside the list form used below.
  steps_to_reproduce:
    "1. Open an incognito session (no auth cookie).\n" +
    "2. Issue `GET https://acme.example/api/v1/admin/users`.\n" +
    "3. Observe HTTP 200 with the full user list returned by step 2.",
  cwe_id: "CWE-862",
  owasp_category: "A01:2021 Broken Access Control",
  cvss_score: 9.8,
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  auth_context: "unauthenticated",
  evidence_type: "network-confirmed",
  poc_code: "curl -i https://acme.example/api/v1/admin/users",
  // The command-run ids behind the steps above, so the dev preview exercises the
  // backed-reproduction case alongside VA-003's unbacked one.
  repro_runs: ["56052", "56054"],
  // Structured HTTP proof. The quote and ampersand in the URL are deliberate:
  // they are what the synthesized curl's shell quoting has to survive.
  poc_request: {
    method: "GET",
    url: "https://acme.example/api/v1/admin/users?filter=role'+OR+1=1--+-&limit=500",
    headers: {
      Accept: "application/json",
      "X-Forwarded-For": "127.0.0.1",
    },
    body: "",
  },
  poc_response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body_excerpt: '{"users":[{"id":1,"email":"root@acme.example","role":"admin"}]}',
  },
  references: [
    { title: "CWE-862: Missing Authorization", url: "https://cwe.mitre.org/data/definitions/862.html" },
    "OWASP ASVS V4.1.1",
  ],
});

const siblingFinding = f({
  report_id: "002",
  slug: "VA-002",
  title: "Admin user export reachable through the auth-guard bypass",
  severity: "high",
  workflow_status: "exploited",
  canonical_location: "https://acme.example/api/v1/admin/export",
  summary:
    "The CSV export endpoint inherits the same missing-guard defect as VA-001 and leaks PII for every account.",
  impact: "Bulk exfiltration of names, emails, and hashed credentials.",
  remediation: "Fixed transitively by the VA-001 root-cause remediation.",
  cwe_id: "CWE-862",
  owasp_category: "A01:2021 Broken Access Control",
  cvss_score: 7.5,
  auth_context: "unauthenticated",
  evidence_type: "network-confirmed",
  root_cause_effect: "eliminates_attack_path",
  root_cause_slug: "VA-001",
  root_cause_note: "Reachable only because the VA-001 guard never runs; no separate authorization defect of its own.",
  sibling_order: 1,
});

const standalone = [
  f({
    report_id: "003",
    slug: "VA-003",
    title: "Reflected XSS in the search parameter",
    severity: "high",
    canonical_location: "https://acme.example/search?q=",
    summary:
      "The `q` parameter is reflected into the results page without contextual output encoding.",
    impact: "An attacker can run arbitrary JavaScript in a victim's session.",
    evidence_detail: '`q=<script>alert(document.domain)</script>` executed in the response.',
    remediation: "HTML-encode `q` on output; add a strict CSP as defense in depth.",
    steps_to_reproduce: [
      "Navigate to `/search?q=<script>alert(document.domain)</script>`.",
      "Observe the alert dialog.",
    ],
    cwe_id: "CWE-79",
    owasp_category: "A03:2021 Injection",
    cvss_score: 6.1,
    auth_context: "unauthenticated",
    evidence_type: "code-inferred",
    // Taint source and taint sink — the location of a code finding. Deliberately
    // left with no repro_runs so the dev preview also shows the draft-mode
    // "no command run is recorded behind these steps" case.
    entry_point: "src/routes/search.ts:34 (req.query.q)",
    sink: "src/views/results.ejs:18 (unescaped <%- %> interpolation)",
    poc_request: {
      method: "POST",
      url: "https://acme.example/search",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "q=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E",
    },
  }),
  f({
    report_id: "004",
    slug: "VA-004",
    title: "Session cookie missing Secure and HttpOnly flags",
    severity: "medium",
    canonical_location: "https://acme.example/login",
    summary: "The `sid` session cookie is set without `Secure` or `HttpOnly`.",
    impact: "Session token is exposed to JavaScript and to cleartext interception.",
    remediation: "Set `Secure; HttpOnly; SameSite=Lax` on the session cookie.",
    cwe_id: "CWE-614",
    cvss_score: 5.3,
  }),
  f({
    report_id: "005",
    slug: "VA-005",
    title: "Verbose server banner discloses framework version",
    severity: "low",
    canonical_location: "https://acme.example/",
    summary: "The `Server` header reveals the exact framework and patch level.",
    impact: "Aids an attacker in fingerprinting and targeting known CVEs.",
    remediation: "Suppress or genericize the `Server` response header at the proxy.",
    cwe_id: "CWE-200",
    cvss_score: 3.1,
  }),
  f({
    report_id: "006",
    slug: "VA-006",
    title: "Directory listing enabled on /static/",
    severity: "info",
    verification_status: "unreviewed",
    canonical_location: "https://acme.example/static/",
    summary: "Autoindex is enabled, exposing the static asset tree.",
    impact: "Low — discloses asset filenames; no sensitive files observed.",
    remediation: "Disable autoindex on the static location block.",
  }),
];

export const devData: ReportData = {
  generated_at: "2026-06-03T14:22:05Z",
  vigil_version: "0.1.0+dev",
  mode: "draft",
  engagement: {
    key: "2026-06-01-090000-acme-webapp",
    target: "https://acme.example",
    status: "in_progress",
    current_phase: "report",
    engagement_type: "red",
    customer: "Acme Corp",
    scope_hosts: ["acme.example", "api.acme.example"],
    created_at: "2026-06-01T09:00:00Z",
  },
  summary: {
    finding_count: 6,
    finding_severities: { critical: 1, high: 2, medium: 1, low: 1, info: 1 },
    finding_workflow_statuses: { exploited: 2, active: 4 },
    finding_verification_statuses: { confirmed: 5, unreviewed: 1 },
    attack_chain_count: 2,
    open_surface_count: 11,
    credential_count: 3,
    access_count: 2,
    target_count: 2,
    service_count: 4,
    coverage_count: 18,
    probe_count: 142,
    report_blocker_count: 0,
    coverage_blocker_count: 0,
  },
  finding_groups: {
    mode: "draft",
    groups: [
      {
        root: rootFinding,
        siblings: [siblingFinding],
        sibling_count: 1,
        residual_path_count: 1,
        highest_severity: "critical",
      },
    ],
    standalone,
    group_count: 1,
    standalone_count: standalone.length,
    finding_count: 6,
  },
  attack_chains: [
    {
      chain_key: "chain-admin-takeover",
      title: "Unauthenticated admin takeover",
      status: "validated",
      severity: "critical",
      narrative:
        "1. Reach `/api/v1/admin/users` unauthenticated (VA-001).\n2. Promote the attacker account to `admin`.\n3. Export all user PII via `/api/v1/admin/export` (VA-002).",
      updated_at: "2026-06-02T18:40:00Z",
    },
    {
      chain_key: "chain-session-theft",
      title: "Session theft via reflected XSS",
      status: "draft",
      severity: "high",
      narrative:
        "Steal a session via the reflected XSS in `q` (VA-003) because the session cookie lacks HttpOnly (VA-004).",
      updated_at: "2026-06-02T11:05:00Z",
    },
  ],
  report_readiness: {
    ready: false,
    blocker_count: 1,
    blockers: [
      {
        kind: "unreviewed_findings",
        detail: "VA-006 is still unreviewed; triage it or withdraw it before a final report.",
        slug: "VA-006",
      },
    ],
    advisory_count: 1,
    advisories: [
      {
        kind: "finding_repro_runs_missing",
        detail:
          "VA-003 has authored steps_to_reproduce but no details.repro_runs, so no command run stands behind the steps.",
        slug: "VA-003",
      },
    ],
  },
};
