"use client";

import { useEffect, useRef, useState } from "react";

// Copy-to-clipboard for docs code blocks. The copied state resets itself so
// the button reads "Copy" again after a beat.
export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  return (
    <button
      type="button"
      className="docs-copy"
      aria-label="Copy code"
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          if (timer.current) clearTimeout(timer.current);
          timer.current = setTimeout(() => setCopied(false), 1600);
        });
      }}
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}
