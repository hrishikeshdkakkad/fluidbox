import { StateNotFound } from "../components/state";

// The boundary the live `notFound()` calls in the docs actually reach —
// docs/[slug]/page.tsx and docs/api/page.tsx both call it, and without a
// not-found inside this route group they escaped to the root one, losing the
// marketing/docs chrome that (site)/layout.tsx provides.
export default function SiteNotFound() {
  return (
    <main className="main">
      <StateNotFound
        title="page not found"
        body="That page does not exist. It may have been renamed, or the link may be out of date."
        href="/docs"
        label="Back to docs"
      />
    </main>
  );
}
