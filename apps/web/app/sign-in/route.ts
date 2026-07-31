import { redirect } from "next/navigation";
import { APP_HOME } from "../lib/auth-gate";
import { webAuthMode } from "../lib/web-auth";

// Stable sign-in entry point for the marketing nav. In workos mode it starts
// the AuthKit flow (getSignInUrl sets the PKCE cookie — sanctioned in a Route
// Handler, never in component render); otherwise it hands off to /app, where
// the fluidbox gate applies (admin: open; sso: /login wall).
export async function GET() {
  if (webAuthMode(process.env.FLUIDBOX_WEB_AUTH) === "workos") {
    const { getSignInUrl } = await import("@workos-inc/authkit-nextjs");
    redirect(await getSignInUrl({ returnTo: APP_HOME }));
  }
  redirect(APP_HOME);
}
