import { StateNotFound } from "./components/state";

// The root not-found boundary.
//
// Next routes two different things here: an explicit `notFound()` thrown in a
// segment with no closer boundary, AND any URL that matches no route at all
// ("the root app/not-found.js ... handle any unmatched URLs for your whole
// application" — node_modules/next/dist/docs/.../file-conventions/not-found.md).
// Until this file existed both fell through to Next's built-in page: white
// background, black system type, no chrome, and the root layout's default
// <title>. It links to the public home because an unmatched URL is more often
// a mistyped public address than a dashboard one; /app/* misses get their own
// boundary in app/app/not-found.tsx.
export default function NotFound() {
  return (
    <main className="main">
      <StateNotFound
        title="page not found"
        body="That address does not match anything here. It may have moved, or the link may be wrong."
        href="/"
        label="Back to fluidbox"
      />
    </main>
  );
}
