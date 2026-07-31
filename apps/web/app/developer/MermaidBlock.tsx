"use client";

import { useEffect, useId, useState } from "react";

// Renders a ```mermaid fence as a diagram. The library is dynamically
// imported so its (large) chunk loads only on pages that actually contain a
// diagram; until it renders — and if it fails — the source stays visible as a
// plain code block, which is the same degradation the docs had before.
export function MermaidBlock({ text }: { text: string }) {
  const [svg, setSvg] = useState<string | null>(null);
  const reactId = useId();

  useEffect(() => {
    let alive = true;
    const dark = document.documentElement.dataset.theme !== "light";
    import("mermaid")
      .then(async ({ default: mermaid }) => {
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "strict",
          theme: dark ? "dark" : "neutral",
          fontFamily: "inherit",
        });
        // mermaid.render wants a DOM-safe unique id; useId emits colons.
        const { svg } = await mermaid.render(`mmd-${reactId.replace(/[^a-zA-Z0-9]/g, "")}`, text);
        if (alive) setSvg(svg);
      })
      .catch(() => {
        // Leave the code-block fallback in place.
      });
    return () => {
      alive = false;
    };
  }, [text, reactId]);

  if (svg === null) {
    return (
      <pre data-lang="mermaid">
        <code>{text}</code>
      </pre>
    );
  }
  return <div className="docs-mermaid" dangerouslySetInnerHTML={{ __html: svg }} />;
}
