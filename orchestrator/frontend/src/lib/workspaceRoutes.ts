export type WorkspaceParams = Record<string, string | number | boolean | null | undefined>;

export type WorkspaceRoute =
  | { kind: "index" }
  | { kind: "engagement" | "remediation"; key: string; params: URLSearchParams }
  | { kind: "invalid" };

export function parseWorkspaceRoute(hash: string): WorkspaceRoute {
  const route = hash.replace(/^#/, "") || "/engagements";
  if (route === "/engagements" || route === "/engagements/") return { kind: "index" };
  const match = route.match(/^\/(engagements|remediation)\/([^/?]+)(?:\?(.*))?$/);
  if (!match) return { kind: "invalid" };
  try {
    const key = decodeURIComponent(match[2]);
    if (!key.trim()) return { kind: "invalid" };
    return { kind: match[1] === "engagements" ? "engagement" : "remediation", key, params: new URLSearchParams(match[3] ?? "") };
  } catch {
    return { kind: "invalid" };
  }
}

export function engagementHref(key: string, values: WorkspaceParams = {}): string {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== "" && !(name === "tab" && value === "overview")) params.set(name, String(value));
  }
  const query = params.toString();
  return `#/engagements/${encodeURIComponent(key)}${query ? `?${query}` : ""}`;
}

export function remediationHref(key: string, caseId?: number): string {
  return `#/remediation/${encodeURIComponent(key)}${caseId ? `?case=${caseId}` : ""}`;
}

/** A record id from the URL: its canonical decimal form only, so no other spelling names the same record. */
export function positiveRouteId(params: URLSearchParams, name: string): number | undefined {
  const raw = params.get(name);
  if (raw === null || !/^[1-9]\d*$/.test(raw)) return undefined;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : undefined;
}

export function writeWorkspaceHash(href: string, mode: "push" | "replace" = "push"): void {
  if (window.location.hash === href) return;
  const state = { ...window.history.state, vigilReturnHash: window.location.hash };
  if (mode === "replace") window.history.replaceState(state, "", href);
  else window.history.pushState(state, "", href);
  window.dispatchEvent(new HashChangeEvent("hashchange"));
}
