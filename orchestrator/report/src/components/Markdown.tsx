// Rendered-markdown wrapper, mirroring
// orchestrator/frontend/src/components/Markdown.tsx.
//
// SECURITY: finding prose is attacker-influenced (it can echo target output,
// payloads, scraped page content). We deliberately do NOT enable rehype-raw or
// any raw-HTML pass — react-markdown's default behaviour escapes embedded HTML,
// which is the sanitizer here. Do not add rehype-raw to this file.

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export function Markdown({ text }: { text?: string }) {
  if (!text || !text.trim()) return null;
  return (
    <div className="md-body">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ node: _node, ...props }) => (
            <a {...props} target="_blank" rel="noopener noreferrer" />
          ),
          // Target-controlled image URLs must not trigger a fetch on report open.
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

export default Markdown;
