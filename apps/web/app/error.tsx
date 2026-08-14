"use client";

import { StateError } from "./components/state";

/**
 * The root error boundary. Catches an uncaught render error anywhere below the
 * root layout, which previously fell to Next's built-in page.
 *
 * Next 16 renamed the recovery prop. `unstable_retry()` re-fetches AND
 * re-renders the segment; `reset()` only clears the error state "without
 * re-fetching the contents" (file-conventions/error.md), which is the wrong
 * behaviour for a failed read — the same content would simply throw again.
 * Both are accepted here and `unstable_retry` preferred, so if the `unstable_`
 * prefix is dropped in a later release this button degrades rather than
 * silently becoming inert.
 *
 * The body copy is fixed rather than taken from `error.message`: errors thrown
 * in a Server Component are replaced with a generic string plus a digest in
 * production, so rendering the message would show a person framework text.
 */
export default function AppError({
  error,
  unstable_retry,
  reset,
}: {
  error: Error & { digest?: string };
  unstable_retry?: () => void;
  reset?: () => void;
}) {
  return (
    <main className="main">
      <StateError
        error={error}
        body="This page failed to render. Retrying re-fetches it; if it keeps failing the digest below identifies it in the server logs."
        onRetry={unstable_retry ?? reset}
      />
      {error.digest && (
        <p className="mono faint" style={{ marginTop: 12 }}>
          digest {error.digest}
        </p>
      )}
    </main>
  );
}
