// OAST view helpers over the probe ledger (`listOobProbes` / `getOobProbe` in
// lib/api.ts) and the operator verdict writer. Pure functions so the tab, its
// grid, and the workspace rail badge all read the same definitions.
import { request, type OobInteraction, type OobProbe, type OobProbeDetail, type OobVerdict } from "./api.ts";
import { compareServerTime, serverTimeMs } from "./serverTime.ts";

export function oobStatus(probe: Pick<OobProbe, "status">): string {
  return (probe.status || "pending").toLowerCase();
}

/**
 * A fired probe received at least one callback and has no recorded operator
 * verdict, so it is waiting for review ("Needs attention"). Recording a
 * verdict (`recordOobVerdict`) moves it to confirmed or ignored.
 */
export function isCallbackToReview(probe: Pick<OobProbe, "status">): boolean {
  return oobStatus(probe) === "fired";
}

/** Rail badge figure: probes with callbacks waiting for review. */
export function countCallbacksToReview(probes: Pick<OobProbe, "status">[]): number {
  return probes.filter(isCallbackToReview).length;
}

/** Callbacks to review, newest callback first. */
export function sortByLastHit<T extends Pick<OobProbe, "last_interaction_at" | "created_at">>(probes: T[]): T[] {
  return [...probes].sort((a, b) =>
    compareServerTime(a.last_interaction_at, b.last_interaction_at, "desc")
    || compareServerTime(a.created_at, b.created_at, "desc"));
}

/**
 * What the payload was planted against — target URL, parameter, technique —
 * in that order, skipping blanks. Empty when the probe records none of them,
 * so a callback cannot be tied back to a request ("Unattributed").
 */
export function linkedToParts(probe: Pick<OobProbe, "target_url" | "param" | "technique">): string[] {
  return [probe.target_url, probe.param, probe.technique]
    .map((value) => (value || "").trim())
    .filter(Boolean);
}

/**
 * True for addresses that cannot be a target's real egress: RFC 1918,
 * loopback, link-local, CGNAT, unique-local IPv6. OAST callbacks relayed
 * through a container bridge or NAT all arrive from such an address.
 */
export function isPrivateAddress(address: string | null | undefined): boolean {
  let value = (address || "").trim().toLowerCase();
  // Drop a port: "[v6]:port" or "v4:port".
  if (value.startsWith("[")) value = value.slice(1, value.indexOf("]") === -1 ? undefined : value.indexOf("]"));
  else if (/^[\d.]+:\d+$/.test(value)) value = value.slice(0, value.indexOf(":"));
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 10
      || a === 127
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 169 && b === 254)
      || (a === 100 && b >= 64 && b <= 127);
  }
  if (value.includes(":")) {
    return value === "::1" || /^f[cd][0-9a-f]{0,2}:/.test(value) || /^fe[89ab][0-9a-f]?:/.test(value);
  }
  return false;
}

export type CallbackGroup = { key: string; protocol: string; queryType: string; count: number };

/** Callbacks grouped by protocol + query type, largest group first. */
export function groupCallbacks(interactions: OobInteraction[]): CallbackGroup[] {
  const groups = new Map<string, CallbackGroup>();
  for (const item of interactions) {
    const protocol = (item.protocol || "").toLowerCase();
    const queryType = (item.query_type || "").toUpperCase();
    const key = `${protocol}|${queryType}`;
    const group = groups.get(key) ?? { key, protocol, queryType, count: 0 };
    group.count += 1;
    groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

export function callbackTime(item: Pick<OobInteraction, "observed_at" | "created_at">): string {
  return item.observed_at || item.created_at;
}

export type CallbackBucket = { start: number; end: number; count: number };

/** Callback counts in equal time buckets between the first and last callback. */
export function callbackHistogram(interactions: OobInteraction[], bucketCount = 24): CallbackBucket[] {
  const times = interactions
    .map((item) => serverTimeMs(callbackTime(item)))
    .filter((value): value is number => value != null);
  if (times.length === 0) return [];
  const first = Math.min(...times);
  const last = Math.max(...times);
  const span = Math.max(last - first, 1);
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    start: first + (span * index) / bucketCount,
    end: first + (span * (index + 1)) / bucketCount,
    count: 0,
  }));
  for (const time of times) {
    const index = Math.min(bucketCount - 1, Math.floor(((time - first) / span) * bucketCount));
    buckets[index].count += 1;
  }
  return buckets;
}

// ── Operator verdicts ─────────────────────────────────────────────────
// PATCH /oob-probes/{nonce} (backend `state_manager/oob.py`
// record_oob_probe_verdict): the status change and an operator audit-log
// entry commit together; GET /oob-probes/{nonce} returns the latest verdict.

/** Statuses that take a verdict: the probe has at least one callback. */
const VERDICT_SOURCE_STATUSES = new Set(["fired", "confirmed", "ignored"]);

/** Only a probe that called back can be confirmed or ignored; a verdict can be switched later. */
export function canRecordVerdict(probe: Pick<OobProbe, "status">): boolean {
  return VERDICT_SOURCE_STATUSES.has(oobStatus(probe));
}

export function recordOobVerdict(
  engagementKey: string,
  nonce: string,
  { verdict, note = "" }: { verdict: OobVerdict; note?: string },
) {
  return request<OobProbeDetail>(
    `/engagements/${encodeURIComponent(engagementKey)}/assessment/oob-probes/${encodeURIComponent(nonce)}`,
    { method: "PATCH", body: JSON.stringify({ verdict, note: note.trim(), actor: "operator" }) },
  );
}
