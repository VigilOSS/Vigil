// Rendered-markdown wrapper for finding prose (UI/UX adoption wave, Tier 1c).
//
// Our agents write markdown into notes/summary/impact/remediation, so
// the drawer offers a rendered view (this component) toggled against the
// existing mono <pre> raw view.
//
// SECURITY: finding text is attacker-influenced (it can echo target output,
// payloads, scraped page content). We deliberately do NOT enable rehype-raw
// or any raw-HTML pass — react-markdown's default behavior escapes embedded
// HTML, which is the sanitizer here. Do not add rehype-raw to this file.
//
// Styling lives in app.css under the `.md-body` family (see the
// "markdown body" section) and is driven entirely by theme vars so light
// and dark both read correctly inside the drawer.

import type { ComponentPropsWithoutRef } from "react";
import ReactMarkdown, { type Components, type ExtraProps } from "react-markdown";
import remarkGfm from "remark-gfm";

type HeadingTag = "h1" | "h2" | "h3" | "h4" | "h5" | "h6";
const HEADING_TAGS: HeadingTag[] = ["h1", "h2", "h3", "h4", "h5", "h6"];

// Each heading level rendered `offset` levels deeper (level 6 stays 6).
function shiftedHeadings(offset: number): Components {
  if (offset <= 0) return {};
  return Object.fromEntries(HEADING_TAGS.map((tag, index) => {
    const Shifted = HEADING_TAGS[Math.min(index + offset, HEADING_TAGS.length - 1)];
    return [tag, ({ node: _node, ...props }: ComponentPropsWithoutRef<HeadingTag> & ExtraProps) => <Shifted {...props} />];
  }));
}

/**
 * `headingOffset` renders the text's headings that many levels deeper, so a
 * document shown inside a page sits under the page's own headings (a
 * document's "# Title" becomes an h2 with an offset of 1).
 */
export function MarkdownBlock({ text, headingOffset = 0 }: { text: string; headingOffset?: number }) {
  if (!text || !text.trim()) return null;
  return (
    <div className="md-body">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          ...shiftedHeadings(headingOffset),
          // Open links in a new tab and harden the rel — react-markdown
          // already strips javascript: URLs, but noopener/noreferrer keeps
          // attacker-supplied links from reaching window.opener.
          a: ({ node: _node, ...props }) => (
            <a {...props} target="_blank" rel="noopener noreferrer" />
          ),
          // Markdown image targets are attacker-controlled. Rendering an
          // <img> would make the browser fetch them without operator intent,
          // so preserve the review context as inert text instead.
          img: ({ node: _node, alt, src }) => (
            <span className="md-image-reference">
              <span>Image reference</span>
              <strong>{alt?.trim() || "Unlabelled image"}</strong>
              <code>{src || "Source blocked by Markdown URL policy"}</code>
            </span>
          ),
          table: ({ node: _node, ...props }) => (
            <div
              className="md-table-scroll"
              role="region"
              aria-label="Scrollable table"
              tabIndex={0}
            >
              <table {...props} />
            </div>
          ),
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
