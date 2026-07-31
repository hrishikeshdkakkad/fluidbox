import Link from "next/link";
import React from "react";
import { parseMarkdown, type Block, type Inline } from "../lib/markdown";
import { CodeBlock } from "./CodeBlock";

// Server-rendered markdown for the developer docs. All parsing lives in
// lib/markdown.ts (pure, unit-tested); this file only maps blocks to JSX.

function InlineSpan({ parts }: { parts: Inline[] }) {
  return (
    <>
      {parts.map((p, i) => {
        switch (p.kind) {
          case "code":
            return <code key={i}>{p.text}</code>;
          case "strong":
            return <strong key={i}>{p.text}</strong>;
          case "em":
            return <em key={i}>{p.text}</em>;
          case "link": {
            // Guide cross-links were authored for the docs/ tree
            // (./governance.md, ../api/openapi.yaml). Rewrite them onto the
            // in-app routes; anything absolute passes through untouched.
            const href = rewriteHref(p.href);
            return href.startsWith("/") ? (
              <Link key={i} href={href}>
                {p.text}
              </Link>
            ) : (
              <a key={i} href={href} target="_blank" rel="noreferrer">
                {p.text}
              </a>
            );
          }
          default:
            return <React.Fragment key={i}>{p.text}</React.Fragment>;
        }
      })}
    </>
  );
}

/** Map docs-tree relative links onto /developer routes. Exported for reuse in
 *  tests if the mapping grows; today it is small enough to eyeball. */
export function rewriteHref(href: string): string {
  if (/^[a-z]+:\/\//.test(href) || href.startsWith("#") || href.startsWith("/")) {
    return href;
  }
  const m = href.match(/^(?:\.\/)?([a-z-]+)\.md(#.*)?$/);
  if (m) return `/developer/${m[1]}${m[2] ?? ""}`;
  if (/openapi\.yaml/.test(href)) return "/developer/reference";
  return href;
}

function BlockView({ block }: { block: Block }) {
  switch (block.kind) {
    case "heading": {
      const Tag = (`h${Math.min(block.level + 1, 6)}`) as "h2" | "h3" | "h4" | "h5" | "h6";
      // Source H1s were stripped by the sync script; source h2 renders as h3
      // under the PageHead h1 so the page keeps a single h1.
      return (
        <Tag id={block.id}>
          <a href={`#${block.id}`}>{block.text}</a>
        </Tag>
      );
    }
    case "paragraph":
      return (
        <p>
          <InlineSpan parts={block.inline} />
        </p>
      );
    case "code":
      return <CodeBlock lang={block.lang} text={block.text} />;
    case "quote":
      return (
        <blockquote>
          <InlineSpan parts={block.inline} />
        </blockquote>
      );
    case "rule":
      return <hr />;
    case "list": {
      const items = block.items.map((item, i) => (
        <li key={i}>
          <InlineSpan parts={item} />
        </li>
      ));
      return block.ordered ? <ol>{items}</ol> : <ul>{items}</ul>;
    }
    case "table":
      return (
        <div className="docs-table-wrap">
          <table>
            <thead>
              <tr>
                {block.header.map((cell, i) => (
                  <th key={i}>
                    <InlineSpan parts={cell} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row, r) => (
                <tr key={r}>
                  {row.map((cell, c) => (
                    <td key={c}>
                      <InlineSpan parts={cell} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
  }
}

export function MarkdownView({ md }: { md: string }) {
  const blocks = parseMarkdown(md);
  return (
    <div className="docs-body">
      {blocks.map((b, i) => (
        <BlockView key={i} block={b} />
      ))}
    </div>
  );
}
