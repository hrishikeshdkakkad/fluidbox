"use client";

import { useEffect } from "react";

// One quiet, system-wide motion: marketing sections fade up as they enter
// the viewport. Classes are only ever added from here, so without JS (or
// with reduced motion) every section is simply visible. The hero is
// excluded — above-the-fold content never hides itself.
export function SectionReveal() {
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const sections = Array.from(
      document.querySelectorAll<HTMLElement>(".st > section")
    ).filter((s) => !s.classList.contains("st-hero"));
    if (sections.length === 0) return;
    for (const s of sections) s.classList.add("st-reveal");
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            e.target.classList.add("in");
            io.unobserve(e.target);
          }
        }
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
    );
    for (const s of sections) io.observe(s);
    return () => io.disconnect();
  }, []);
  return null;
}
