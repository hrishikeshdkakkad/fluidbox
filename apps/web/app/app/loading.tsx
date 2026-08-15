import { LoadingRows } from "../components/bits";

// Suspense fallback for the dashboard segment. Reuses the hairline shimmer the
// pages already use for their own loading states, so a navigation and an
// in-page refresh look like the same thing rather than two different products.
export default function Loading() {
  return <LoadingRows rows={6} />;
}
