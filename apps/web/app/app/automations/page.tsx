import { redirect } from "next/navigation";

export default function AutomationsRedirect() {
  redirect("/app?view=automations");
}
