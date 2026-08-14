"use client";

import { useEffect, useRef, useState } from "react";

type CopyState = "idle" | "copied" | "failed";

const LABEL: Record<CopyState, string> = {
  idle: "Copy",
  copied: "Copied",
  failed: "Select it",
};

/**
 * Copy-to-clipboard for docs code blocks. The state resets itself so the
 * button reads "Copy" again after a beat.
 *
 * `navigator.clipboard` is only defined in a secure context, so on a plain-http
 * origin — a self-hosted docs mirror, a LAN preview — reading `.writeText` off
 * it throws a TypeError. It can also reject with NotAllowedError when the
 * document is not focused or the permission is denied. The previous version
 * had a bare `.then()`, so all three failed silently: the label never changed
 * and the reader believed they had copied the command. Now the failure is
 * reported AND the code is selected, so the keyboard shortcut still works.
 */
export function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<CopyState>("idle");
  const button = useRef<HTMLButtonElement | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const settle = (next: CopyState) => {
    setState(next);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), 2400);
  };

  /** Last resort: put the code under the user's selection so Cmd/Ctrl+C works. */
  const selectCode = () => {
    const code = button.current?.closest(".docs-code")?.querySelector("pre");
    const selection = window.getSelection();
    if (!code || !selection) return;
    const range = document.createRange();
    range.selectNodeContents(code);
    selection.removeAllRanges();
    selection.addRange(range);
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      settle("copied");
    } catch {
      selectCode();
      settle("failed");
    }
  };

  return (
    <button
      ref={button}
      type="button"
      className="docs-copy"
      data-state={state}
      aria-label={
        state === "failed"
          ? "Copy failed — the code is selected, press Cmd or Ctrl + C"
          : "Copy code"
      }
      onClick={() => void copy()}
    >
      <span aria-live="polite">{LABEL[state]}</span>
    </button>
  );
}
