// Syntax-highlighted JSON viewer (Issue 3).
//
// Regex-tokenizes pretty-printed JSON and emits <span class="json-tok-*">
// for keys / strings / numbers / booleans / null / punctuation. CSS
// variables in app.css drive the actual colors, so dark/light mode
// switching applies without a round-trip through React state.
//
// Deliberately tiny: no external dep, ~1kb of tokenizer. Values come in
// as any JSON-serializable object and are JSON.stringify'd with 2-space
// indent so every string literal is properly escaped before tokenizing —
// this avoids the classic "key looks like a value because a quote lived
// in the string" class of bug.

import { useMemo, type ReactNode } from "react";
import { CopyInline } from "./formatting";

type Props = {
  value: unknown;
  /**
   * If the pretty-printed JSON has at least this many lines, render a
   * gutter with 1-based line numbers. Set to Infinity to never show the
   * gutter.
   */
  gutterThreshold?: number;
  /** Optional header label rendered above the block (e.g. "Raw record"). */
  label?: string;
  /** Show a Copy-JSON button in the header. */
  copyable?: boolean;
};

type Token = {
  kind: "key" | "string" | "number" | "boolean" | "null" | "punctuation" | "whitespace";
  text: string;
};

// JSON tokenizer. Order matters: strings must be matched before punctuation
// so a comma inside a string isn't split. Number regex explicitly allows
// exponent + leading minus. Whitespace is kept as-is so indentation
// survives.
const TOKEN_RE =
  /"(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b|[\s\n]+|[{}[\],:]/g;

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  const re = new RegExp(TOKEN_RE.source, "g");
  let m: RegExpExecArray | null;
  let lastIndex = 0;
  while ((m = re.exec(src)) !== null) {
    // Emit any gap between matches as punctuation so we never drop input.
    if (m.index > lastIndex) {
      tokens.push({ kind: "punctuation", text: src.slice(lastIndex, m.index) });
    }
    const text = m[0];
    lastIndex = m.index + text.length;
    if (/^\s+$/.test(text)) {
      tokens.push({ kind: "whitespace", text });
      continue;
    }
    if (text.startsWith('"')) {
      // A quoted string followed by `:` is a key, else it's a value.
      // The regex's first alternative uses lookahead so key matches land
      // here without the `:` consumed.
      const tail = src.slice(lastIndex).trimStart();
      const isKey = tail.startsWith(":");
      tokens.push({ kind: isKey ? "key" : "string", text });
      continue;
    }
    if (/^-?\d/.test(text)) {
      tokens.push({ kind: "number", text });
      continue;
    }
    if (text === "true" || text === "false") {
      tokens.push({ kind: "boolean", text });
      continue;
    }
    if (text === "null") {
      tokens.push({ kind: "null", text });
      continue;
    }
    tokens.push({ kind: "punctuation", text });
  }
  if (lastIndex < src.length) {
    tokens.push({ kind: "punctuation", text: src.slice(lastIndex) });
  }
  return tokens;
}

function renderTokens(tokens: Token[]): ReactNode[] {
  const out: ReactNode[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.kind === "whitespace" || t.kind === "punctuation") {
      // Whitespace is rendered as plain text to preserve indentation. Raw
      // punctuation (colons, commas, braces) gets the muted color so the
      // keys and values stand out.
      if (t.kind === "whitespace") {
        out.push(t.text);
      } else {
        out.push(
          <span key={i} className="json-tok-punctuation">
            {t.text}
          </span>,
        );
      }
      continue;
    }
    out.push(
      <span key={i} className={`json-tok-${t.kind}`}>
        {t.text}
      </span>,
    );
  }
  return out;
}

function safeStringify(value: unknown): string {
  const ancestors: object[] = [];
  try {
    return JSON.stringify(
      value,
      function (_key, v) {
        if (typeof v === "object" && v !== null) {
          while (ancestors.length && ancestors[ancestors.length - 1] !== this) ancestors.pop();
          if (ancestors.includes(v)) return "[Circular]";
          ancestors.push(v);
        }
        if (typeof v === "bigint") return v.toString();
        if (typeof v === "function") return "[Function]";
        if (typeof v === "undefined") return null;
        return v;
      },
      2,
    );
  } catch {
    return String(value);
  }
}

export function JsonView({
  value,
  gutterThreshold = 5,
  label,
  copyable = true,
}: Props) {
  const text = useMemo(() => safeStringify(value), [value]);
  const tokens = useMemo(() => tokenize(text), [text]);
  const lineCount = useMemo(() => text.split("\n").length, [text]);
  const showGutter = lineCount >= gutterThreshold;

  const rendered = renderTokens(tokens);

  return (
    <div>
      {(label || copyable) && (
        <div className="json-view-header">
          {label ? <span className="json-view-meta">{label}</span> : <span />}
          {copyable && (
            <CopyInline text={text} ariaLabel="Copy JSON to clipboard">Copy JSON</CopyInline>
          )}
        </div>
      )}
      <div className={`json-view ${showGutter ? "has-gutter" : ""}`}>
        {showGutter && (
          <div className="json-gutter" aria-hidden="true">
            {Array.from({ length: lineCount }, (_, i) => (
              <div key={i}>{i + 1}</div>
            ))}
          </div>
        )}
        <pre className="json-body">{rendered}</pre>
      </div>
    </div>
  );
}
