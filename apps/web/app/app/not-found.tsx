import { StateNotFound } from "../components/state";

// Dashboard not-found. Catches `notFound()` thrown inside /app/* and renders
// inside the dashboard shell, so the masthead stays put and the way back is a
// dashboard route rather than the marketing home.
export default function AppNotFound() {
  return (
    <StateNotFound
      title="not found in this workspace"
      body="This may have been deleted, or you may not have access to it."
      href="/app"
      label="Back to overview"
    />
  );
}
