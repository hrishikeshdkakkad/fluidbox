"use client";

import { useEffect, useState } from "react";

// "On this page" with scroll-spy: the entry whose heading was most recently
// scrolled past carries the active state. IntersectionObserver keeps this
// cheap — no scroll handler.
export function TocSpy({ items }: { items: { id: string; text: string }[] }) {
  const [active, setActive] = useState<string | null>(null);

  useEffect(() => {
    const headings = items
      .map((i) => document.getElementById(i.id))
      .filter((el): el is HTMLElement => el !== null);
    if (headings.length === 0) return;

    const visible = new Set<string>();
    const observer = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) visible.add(e.target.id);
          else visible.delete(e.target.id);
        }
        // Highlight the first visible heading; if none are in view, keep the
        // last heading above the viewport.
        const inView = items.find((i) => visible.has(i.id));
        if (inView) {
          setActive(inView.id);
        } else {
          let above: string | null = null;
          for (const h of headings) {
            if (h.getBoundingClientRect().top < 90) above = h.id;
          }
          if (above) setActive(above);
        }
      },
      { rootMargin: "-70px 0px -60% 0px" }
    );
    headings.forEach((h) => observer.observe(h));
    return () => observer.disconnect();
  }, [items]);

  if (items.length < 2) return null;

  return (
    <nav className="docs-toc" aria-label="On this page">
      <div className="docs-toc-title">On this page</div>
      {items.map((h) => (
        <a key={h.id} href={`#${h.id}`} className={active === h.id ? "active" : ""}>
          {h.text}
        </a>
      ))}
    </nav>
  );
}
