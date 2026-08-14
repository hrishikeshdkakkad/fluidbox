"use client";

import "./globals.css";
import "./kernel.css";
import { THEME_INIT_SCRIPT } from "./lib/theme";

/**
 * Replaces the ROOT LAYOUT when the layout itself throws, so per the Next 16
 * docs it must render its own <html>/<body> and pull in its own global styles —
 * nothing above it survives to provide them.
 *
 * Two consequences worth knowing:
 *  - next/font is not available here, so type falls back to the system stack.
 *    Deliberate: this page has to render precisely when the app cannot.
 *  - metadata exports are unsupported in global-error, so the title is the
 *    React <title> element instead.
 *
 * The theme-init script still runs, so a dark-mode user does not get flashed a
 * beige page at the worst possible moment.
 */
export default function GlobalError({
  error,
  unstable_retry,
  reset,
}: {
  error: Error & { digest?: string };
  unstable_retry?: () => void;
  reset?: () => void;
}) {
  const retry = unstable_retry ?? reset;
  return (
    <html lang="en" data-theme="light" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>
        <title>Something broke · fluidbox</title>
        <main className="main">
          <div className="panel launch-empty" role="alert">
            <div>
              <p className="mono">500</p>
              <h3>something broke</h3>
              <p>
                The dashboard could not render at all. Reloading usually clears it. Nothing
                you were running was affected — runs live in the control plane, not here.
              </p>
            </div>
            <div className="empty-actions">
              <button className="btn" type="button" onClick={() => retry?.()}>
                Reload
              </button>
            </div>
          </div>
          {error.digest && <p className="mono faint">digest {error.digest}</p>}
        </main>
      </body>
    </html>
  );
}
