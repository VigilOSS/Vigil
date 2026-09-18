// Reproduction-steps normalization for the report template.
//
// `details.steps_to_reproduce` is authored either as ONE block holding the whole
// reproduction (the preferred shape) or as a list of steps. The report payload
// normally arrives already normalized to a list by the backend projection
// (report_readiness._as_string_list), but this module does not depend on that:
// a renderer that assumed a list threw on a raw string, and the throw surfaced
// as a "Copy as Markdown" button that silently did nothing.
//
// Numbering is the author's. Prose in Summary or Impact cites step numbers, and
// those citations resolve only against numbers the author wrote — so nothing here
// imposes a counter or a list marker.

export function stepsText(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (Array.isArray(value)) {
    return value
      .map((item) => (typeof item === "string" ? item : String(item ?? "")))
      .filter((item) => item.trim().length > 0)
      .join("\n")
      .trim();
  }
  return "";
}

// `details.repro_runs` carries the command-run ids that actually produced the
// steps above, in step order (report_readiness._report_record projects it beside
// them). It is the only thing separating a transcribed reproduction from a
// plausible reconstruction — the two read identically as prose — which is why
// the backend raises `finding_repro_runs_missing` when steps arrive without it.
// Normalized here the same way as the steps themselves, because the projection's
// shape must never be the reason a renderer throws.
export function reproRunIds(value: unknown): string[] {
  const raw = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  return raw
    .map((item) => (typeof item === "string" ? item : String(item ?? "")).trim())
    .filter((item) => item.length > 0);
}
