"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { slugify } from "../../lib/markdown";
import { hrefFor } from "./nav";
import type { SearchSection } from "./generated/search";

// Full-text docs search: a rail trigger + a ⌘K dialog over the generated
// per-section index. The index ships as its own lazy chunk — nothing loads
// until the dialog first opens. Scoring is a plain AND-of-tokens with
// field weights; at this corpus size (dozens of sections) exactness beats
// cleverness, and there is no dependency to carry.
//
// All state resets live in the open/close event handlers — never in effects
// (react-hooks/set-state-in-effect) — so the only effect here is the global
// key listener, and the input focuses itself via autoFocus on mount.

type Hit = { section: SearchSection; score: number; href: string };

function rank(sections: SearchSection[], query: string): Hit[] {
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return [];
  const hits: Hit[] = [];
  for (const section of sections) {
    const title = section.title.toLowerCase();
    const heading = section.heading.toLowerCase();
    const text = section.text.toLowerCase();
    let score = 0;
    let matched = true;
    for (const token of tokens) {
      if (title.includes(token)) {
        score += title.startsWith(token) ? 6 : 4;
      } else if (heading.includes(token)) {
        score += heading.startsWith(token) ? 5 : 3;
      } else if (text.includes(token)) {
        score += 1;
      } else {
        matched = false;
        break;
      }
    }
    if (!matched) continue;
    const anchor = section.heading ? `#${slugify(section.heading)}` : "";
    hits.push({ section, score, href: `${hrefFor(section.slug)}${anchor}` });
  }
  return hits.sort((a, b) => b.score - a.score).slice(0, 12);
}

export function DocsSearch() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const [sections, setSections] = useState<SearchSection[] | null>(null);

  const openDialog = useCallback(() => {
    setQuery("");
    setSelected(0);
    setOpen(true);
    // Lazy: the index chunk loads on first open, never on page load.
    void import("./generated/search").then((m) => setSections(m.SEARCH_SECTIONS));
  }, []);
  const closeDialog = useCallback(() => setOpen(false), []);

  // Re-registers when `open` flips — a one-listener swap per toggle, which is
  // cheaper to reason about than a ref mirror (and lint-clean under React 19).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (open) closeDialog();
        else openDialog();
      } else if (e.key === "Escape" && open) {
        closeDialog();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, openDialog, closeDialog]);

  const hits = useMemo(() => rank(sections ?? [], query), [sections, query]);

  const go = (href: string) => {
    closeDialog();
    router.push(href);
  };

  return (
    <>
      <button
        type="button"
        className="docs-search-trigger"
        onClick={openDialog}
        aria-haspopup="dialog"
      >
        <span>Search docs…</span>
        <kbd>⌘K</kbd>
      </button>

      {open && (
        <div
          className="docs-search-overlay"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) closeDialog();
          }}
        >
          <div
            className="docs-search-panel"
            role="dialog"
            aria-modal="true"
            aria-label="Search documentation"
          >
            <input
              autoFocus
              className="docs-search-input"
              placeholder="Search the documentation…"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setSelected(0);
              }}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setSelected((s) => Math.min(s + 1, hits.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setSelected((s) => Math.max(s - 1, 0));
                } else if (e.key === "Enter" && hits[selected]) {
                  e.preventDefault();
                  go(hits[selected].href);
                }
              }}
              role="combobox"
              aria-expanded={hits.length > 0}
              aria-controls="docs-search-results"
              aria-activedescendant={
                hits[selected] ? `docs-hit-${selected}` : undefined
              }
            />
            <ul className="docs-search-results" id="docs-search-results" role="listbox">
              {query.trim() !== "" && hits.length === 0 && sections !== null && (
                <li className="docs-search-empty">No matches for “{query}”.</li>
              )}
              {hits.map((hit, i) => (
                <li
                  key={hit.href + i}
                  id={`docs-hit-${i}`}
                  role="option"
                  aria-selected={i === selected}
                  className={`docs-search-hit ${i === selected ? "active" : ""}`}
                  onMouseEnter={() => setSelected(i)}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    go(hit.href);
                  }}
                >
                  <span className="docs-search-hit-title">
                    {hit.section.title}
                    {hit.section.heading && (
                      <span className="docs-search-hit-heading">
                        {" "}
                        › {hit.section.heading}
                      </span>
                    )}
                  </span>
                  <span className="docs-search-hit-text">
                    {hit.section.text.slice(0, 130) || "—"}
                  </span>
                </li>
              ))}
            </ul>
            <div className="docs-search-foot">
              <span>
                <kbd>↑</kbd>
                <kbd>↓</kbd> navigate
              </span>
              <span>
                <kbd>↵</kbd> open
              </span>
              <span>
                <kbd>esc</kbd> close
              </span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
