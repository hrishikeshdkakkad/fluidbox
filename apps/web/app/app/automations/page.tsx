import { redirect } from "next/navigation";

// Automations live on the Activity workbench (2026-08-17); Overview no longer
// lists them. This stub keeps the /app/automations address working.
export default function AutomationsRedirect() {
  redirect("/app/activity#automations-heading");
}
