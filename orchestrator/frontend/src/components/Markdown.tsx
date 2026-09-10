// Rendered-markdown wrapper for finding prose (UI/UX adoption wave, Tier 1c).
//
// Ported pattern: the reference-project FindingDetailPanel's rendered/raw Description
// tabs. Our agents write markdown into notes/summary/impact/remediation, so
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

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export function MarkdownBlock({ text }: { text: string }) {
  if (!text || !text.trim()) return null;
  return (
    <div className="md-body">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
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
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
