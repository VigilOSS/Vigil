// Canonical parsing and formatting for timestamps the backend returns.
//
// SQLite rows store UTC as zone-less text ("2026-10-20 14:07:07"), while
// event and receipt payloads use ISO-8601 with an explicit zone
// ("2026-10-20T14:07:07.129343Z"). `new Date()` / `Date.parse` read the
// zone-less form as LOCAL time, which shifts every database timestamp by the
// operator's UTC offset. Every server timestamp in the UI goes through this
// module instead; `<TimeStamp>` in components/formatting.tsx renders it.

const SERVER_TIME_RE =
  /^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:?\d{2})?)?$/i;

const RELATIVE_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

export type ServerTimeInput = string | null | undefined;

/**
 * Parse a backend timestamp. Zone-less `YYYY-MM-DD[ T]HH:MM[:SS[.ffffff]]`
 * (and a bare date) is UTC; `Z` and `±HH:MM` / `±HHMM` offsets are honored.
 * Anything else — including impossible calendar values — returns null so
 * callers can show the source text instead of a fabricated time.
 */
export function parseServerTime(value: ServerTimeInput): Date | null {
  if (typeof value !== "string") return null;
  const match = SERVER_TIME_RE.exec(value.trim());
  if (!match) return null;
  const [, y, mo, d, h = "0", mi = "0", s = "0", fraction = "", zone = ""] = match;
  const year = Number(y);
  const month = Number(mo);
  const day = Number(d);
  const hour = Number(h);
  const minute = Number(mi);
  const second = Number(s);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return null;
  const millis = Number(fraction.slice(0, 3).padEnd(3, "0"));
  const utc = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  const check = new Date(utc);
  // Date.UTC rolls 2026-02-30 into March; reject instead of silently moving it.
  if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) {
    return null;
  }
  let offsetMinutes = 0;
  if (zone && zone.toUpperCase() !== "Z") {
    const sign = zone.startsWith("-") ? -1 : 1;
    const digits = zone.slice(1).replace(":", "");
    const offsetHours = Number(digits.slice(0, 2));
    const offsetMins = Number(digits.slice(2, 4));
    if (offsetHours > 23 || offsetMins > 59) return null;
    offsetMinutes = sign * (offsetHours * 60 + offsetMins);
  }
  return new Date(utc - offsetMinutes * 60_000);
}

/** Epoch milliseconds for a backend timestamp, or null when unparseable. */
export function serverTimeMs(value: ServerTimeInput): number | null {
  return parseServerTime(value)?.getTime() ?? null;
}

/**
 * Chronological comparator for mixed-format timestamps (string comparison
 * misorders "2026-10-20 14:00:00" against "2026-10-20T13:00:00Z"). Missing or
 * unparseable values always sort last, whichever direction is requested.
 */
export function compareServerTime(
  a: ServerTimeInput,
  b: ServerTimeInput,
  direction: "asc" | "desc" = "asc",
): number {
  const ta = serverTimeMs(a);
  const tb = serverTimeMs(b);
  if (ta == null || tb == null) return ta == null ? (tb == null ? 0 : 1) : -1;
  return direction === "asc" ? ta - tb : tb - ta;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const MONTH_MS = 30.44 * DAY_MS;
const YEAR_MS = 365.25 * DAY_MS;

// Compact age inside the relative window; null beyond it.
function recentAge(elapsedMs: number): string | null {
  const seconds = Math.floor(elapsedMs / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  if (elapsedMs < RELATIVE_WINDOW_MS) return `${Math.floor(hours / 24)}d ago`;
  return null;
}

/**
 * Compact age ("27s ago", "4h ago", "3d ago") within 30 days, the UTC date
 * after that. Future values (clock skew) clamp to "just now". Returns "" when
 * the value is missing or unparseable.
 */
export function formatRelativeTime(value: ServerTimeInput, now: number = Date.now()): string {
  const time = serverTimeMs(value);
  if (time == null) return "";
  return recentAge(Math.max(0, now - time)) ?? new Date(time).toISOString().slice(0, 10);
}

/**
 * Age with no window ("4h ago", "28d ago", "3mo ago", "2y ago"), for text that
 * sits beside the absolute time, where a date would only repeat it. Returns ""
 * when the value is missing or unparseable.
 */
export function formatAge(value: ServerTimeInput, now: number = Date.now()): string {
  const time = serverTimeMs(value);
  if (time == null) return "";
  const elapsedMs = Math.max(0, now - time);
  const recent = recentAge(elapsedMs);
  if (recent !== null) return recent;
  if (elapsedMs < YEAR_MS) return `${Math.max(1, Math.floor(elapsedMs / MONTH_MS))}mo ago`;
  return `${Math.floor(elapsedMs / YEAR_MS)}y ago`;
}

/**
 * Grid time cells: relative while recent, the absolute minute once the age
 * would only show a bare date (older than the relative window), so the time
 * of day is never dropped.
 */
export function gridTimeMode(value: ServerTimeInput, now: number = Date.now()): "relative" | "absolute" {
  return /^\d{4}-\d{2}-\d{2}$/.test(formatRelativeTime(value, now)) ? "absolute" : "relative";
}

/**
 * ag-grid comparator for a date column whose value is a server time:
 * chronological, with missing or unparseable times last in both directions.
 * ag-grid negates a comparator's result for a descending sort and passes
 * `isDescending`, so the missing-last rule is pre-negated to survive it.
 */
export function gridTimeComparator(
  a: ServerTimeInput,
  b: ServerTimeInput,
  _nodeA?: unknown,
  _nodeB?: unknown,
  isDescending = false,
): number {
  const result = compareServerTime(a, b, isDescending ? "desc" : "asc");
  return isDescending ? -result : result;
}

/**
 * A measured duration: "412ms", "7.3s", "33s", "2m 5s", "1h 4m"; "—" when
 * nothing was measured. Rounding happens once, on the smallest unit shown, so
 * it carries ("2m 0s", never "1m 60s").
 */
export function formatDuration(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms) || ms <= 0) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const tenths = Math.round(ms / 100);
  if (tenths < 600) return tenths % 10 ? `${(tenths / 10).toFixed(1)}s` : `${tenths / 10}s`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const minutes = Math.round(ms / 60_000);
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export type AbsoluteTimePrecision = "minute" | "second" | "millisecond";

/**
 * Absolute UTC time ("2026-10-20 14:07 UTC"). Unparseable non-empty input is
 * returned unchanged so the operator still sees what the backend recorded.
 */
export function formatAbsoluteTime(
  value: ServerTimeInput,
  precision: AbsoluteTimePrecision = "minute",
): string {
  if (!value) return "";
  const time = parseServerTime(value);
  if (!time) return value;
  const iso = time.toISOString();
  const end = precision === "minute" ? 16 : precision === "second" ? 19 : 23;
  return `${iso.slice(0, 10)} ${iso.slice(11, end)} UTC`;
}
