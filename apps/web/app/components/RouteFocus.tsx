"use client";

import { usePathname } from "next/navigation";
import { useEffect, useRef } from "react";

/** How long after a navigation a streamed-in <h1> may still claim focus. Past
 *  this, moving focus would interrupt whatever the user has started doing. */
const FOCUS_WINDOW_MS = 3000;

/**
 * After a CLIENT navigation, move focus to the new page's <h1> so keyboard and
 * screen-reader users land on the content they navigated to instead of staying
 * on the masthead link they clicked (2026-08-14 navigation-boundary design).
 * The first render is a full document load — the browser's own focus handling
 * is correct there and is left alone.
 *
 * The App Router commits the route's loading state FIRST and streams the page
 * in after, so the h1 usually does not exist when this effect fires — a
 * one-shot querySelector here silently did nothing. Watch for it instead,
 * bounded by FOCUS_WINDOW_MS, and never steal focus the user has already
 * moved into the new page themselves.
 */
export function RouteFocus() {
  const pathname = usePathname();
  const previousPathname = useRef<string | null>(null);

  useEffect(() => {
    const isInitialLoad = previousPathname.current === null;
    if (isInitialLoad || previousPathname.current === pathname) {
      previousPathname.current = pathname;
      return;
    }
    previousPathname.current = pathname;

    const focusUnclaimed = () => {
      const current = document.activeElement;
      // Focus is "unclaimed" while it still sits where the navigation left it:
      // the body, or the masthead link that was clicked.
      return (
        current === document.body ||
        current === null ||
        !!current.closest(".topbar, .sidenav, .sidenav-mobilebar")
      );
    };
    const focusHeading = (): boolean => {
      const heading = document.querySelector<HTMLElement>("main h1");
      if (!heading) return false;
      if (focusUnclaimed()) {
        // An h1 is not natively focusable; -1 lets script focus it without
        // adding it to the tab order.
        heading.tabIndex = -1;
        heading.focus();
      }
      return true;
    };

    if (focusHeading()) return;
    const observer = new MutationObserver(() => {
      if (focusHeading()) observer.disconnect();
    });
    observer.observe(document.querySelector("main") ?? document.body, {
      childList: true,
      subtree: true,
    });
    const deadline = window.setTimeout(() => observer.disconnect(), FOCUS_WINDOW_MS);
    return () => {
      observer.disconnect();
      window.clearTimeout(deadline);
    };
  }, [pathname]);

  return null;
}
