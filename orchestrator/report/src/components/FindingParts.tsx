// Finding fragments that render identically in the Findings table's detail pane
// and in the Full Report document. Only the surrounding chrome differs between
// those two views (a <section> vs a .rpt-doc-block), so the chrome stays with
// each caller and the parts that must not drift live here.

import { useState } from "react";
import { Check, Copy } from "lucide-react";

import type { ReportFinding } from "../types";
import { referenceLink } from "../lib/format";
import { findingToMarkdown } from "../lib/findingMarkdown";

/**
 * Copy the whole finding as structured markdown.
 *
 * Section headings are `user-select: none` so that dragging across a
 * reproduction yields the command and nothing else — this button is where the
 * headings come back, for the reader who wants the finding as a document rather
 * than as something to paste into a shell.
 */
export function CopyMarkdownButton({ finding }: { finding: ReportFinding }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    const md = findingToMarkdown(finding);
    try {
      await navigator.clipboard.writeText(md);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard API unavailable (e.g. file:// without permission) — fall back
      // to a hidden textarea + execCommand so the button still works offline.
      const ta = document.createElement("textarea");
      ta.value = md;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1800);
      } catch {
        /* give up silently */
      }
      document.body.removeChild(ta);
    }
  };
  return (
    <button type="button" className="rpt-copy-btn no-print" onClick={onCopy}>
      {copied ? <Check size={13} /> : <Copy size={13} />}
      {copied ? "Copied" : "Copy as Markdown"}
    </button>
  );
}

/**
 * Provenance for the reproduction steps: the command runs that produced them.
 *
 * Steps that were executed and steps that were reconstructed afterwards read
 * exactly the same as prose, and only `details.repro_runs` tells them apart —
 * which is why the backend raises `finding_repro_runs_missing` when steps arrive
 * with nothing behind them. Naming the absence is gated on draft mode, mirroring
 * `vigil assess export submission`, which prints its own "[NEEDS: ...]" marker
 * only while drafting: the operator reviewing a draft is the reader who can
 * still go and get the run ids, and a delivered report should not be carrying
 * the note at all — the finding should have been sent back instead.
 */
export function ReproRunProvenance({ runIds, draft }: { runIds: string[]; draft: boolean }) {
  if (runIds.length > 0) {
    return (
      <p className="rpt-steps-runs">
        Command runs behind these steps:{" "}
        <span className="rpt-mono">{runIds.map((id) => `#${id}`).join(" · ")}</span>
      </p>
    );
  }
  if (!draft) return null;
  return (
    <p className="rpt-steps-runs rpt-steps-runs-missing">
      No command run is recorded behind these steps.
    </p>
  );
}

export function ReferenceList({ references }: { references?: unknown[] }) {
  if (!Array.isArray(references)) return null;
  const links = references.map(referenceLink).filter((link) => link !== null);
  if (links.length === 0) return null;
  return (
    <ul className="rpt-ref-list">
      {links.map((link, index) => (
        <li key={`${link.url}-${link.label}-${index}`}>
          {link.url ? (
            <a href={link.url} target="_blank" rel="noopener noreferrer">
              {link.label}
            </a>
          ) : (
            link.label
          )}
        </li>
      ))}
    </ul>
  );
}
